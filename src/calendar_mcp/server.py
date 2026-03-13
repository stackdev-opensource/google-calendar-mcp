"""MCP server setup and tool dispatch."""

import json
import logging
from datetime import UTC, datetime

from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from calendar_mcp.access_control import (
    get_attendee_settings,
    get_enabled_tools,
    get_required_scopes,
    validate_attendees,
)
from calendar_mcp.auth import get_credentials
from calendar_mcp.calendar_client import CalendarClient
from calendar_mcp.security import log_tool_call
from calendar_mcp.tools import ALL_TOOL_DEFINITIONS

logger = logging.getLogger("calendar-mcp.server")

# These are set by __main__.py before the server starts
config: dict = {}
client_secrets_path: str = ""

app = Server("calendar-mcp-secure")

# Cache authenticated Calendar clients per account
_clients: dict[str, CalendarClient] = {}


def _get_client(account: str) -> CalendarClient:
    """Get or create an authenticated CalendarClient for the given account."""
    if account not in _clients:
        # Validate that the account is in the config
        configured_emails = {a["email"] for a in config.get("accounts", [])}
        if account not in configured_emails:
            raise ValueError(
                f"Account '{account}' is not configured. "
                f"Configured accounts: {sorted(configured_emails)}"
            )

        enabled_tools = get_enabled_tools(config)
        scopes = get_required_scopes(enabled_tools)
        credentials = get_credentials(account, client_secrets_path or None, scopes)
        _clients[account] = CalendarClient(credentials)

    return _clients[account]


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Return only the tools enabled in the current configuration."""
    enabled = get_enabled_tools(config)
    return [
        tool_def for tool_name, tool_def in ALL_TOOL_DEFINITIONS.items() if tool_name in enabled
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a tool invocation, with access control and audit logging."""
    enabled = get_enabled_tools(config)

    if name not in enabled:
        current_preset = config.get("tool_access", {}).get("preset", "read-only")
        raise ValueError(
            f"Tool '{name}' is not enabled. "
            f"Current preset: '{current_preset}'. "
            f"Change the preset or add it to 'overrides' in your config."
        )

    log_tool_call(name, arguments.get("account", "unknown"), list(arguments.keys()))

    handler = TOOL_HANDLERS.get(name)
    if not handler:
        raise ValueError(f"No handler registered for tool: {name}")

    try:
        return await handler(arguments)
    except HttpError as e:
        # Calendar API error — return status and reason without leaking internals
        logger.exception("Calendar API error in %s", name)
        raise ValueError(f"Calendar API error ({e.resp.status}): {e.reason}") from None
    except GoogleAuthError:
        # Auth error — evict cached client so next call re-authenticates
        _clients.pop(arguments.get("account", ""), None)
        logger.exception("Authentication error in %s", name)
        raise ValueError(
            f"Authentication failed for account '{arguments.get('account', 'unknown')}'. "
            f"Try re-running: python -m calendar_mcp auth --account {arguments.get('account', '')}"
        ) from None
    except ValueError:
        # Our own validation errors (e.g. attendee rejection) — pass through as-is
        raise  # noqa: TRY201 — intentionally preserves chain for our own errors
    except Exception:
        # Catch-all — log full trace to stderr, return safe message to AI
        logger.exception("Unexpected error in %s", name)
        raise ValueError(f"An unexpected error occurred while executing {name}") from None


# -- Tool handlers --


async def handle_list_calendars(arguments: dict) -> list[TextContent]:
    client = _get_client(arguments["account"])
    calendars = client.list_calendars()
    return [TextContent(type="text", text=json.dumps(calendars, indent=2))]


async def handle_get_events(arguments: dict) -> list[TextContent]:
    client = _get_client(arguments["account"])
    max_results = arguments.get("max_results", 50)
    max_results = max(1, min(100, max_results))
    # Default time_min to now for deterministic behavior
    time_min = arguments.get("time_min") or datetime.now(UTC).isoformat()
    events = client.get_events(
        calendar_id=arguments.get("calendar_id", "primary"),
        time_min=time_min,
        time_max=arguments["time_max"],
        max_results=max_results,
        query=arguments.get("query"),
    )
    return [TextContent(type="text", text=json.dumps(events, indent=2))]


async def handle_get_event(arguments: dict) -> list[TextContent]:
    client = _get_client(arguments["account"])
    event = client.get_event(
        event_id=arguments["event_id"],
        calendar_id=arguments.get("calendar_id", "primary"),
    )
    return [TextContent(type="text", text=json.dumps(event, indent=2))]


async def handle_get_freebusy(arguments: dict) -> list[TextContent]:
    client = _get_client(arguments["account"])
    result = client.get_freebusy(
        calendars=arguments["calendars"],
        time_min=arguments["time_min"],
        time_max=arguments["time_max"],
    )
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_create_event(arguments: dict) -> list[TextContent]:
    client = _get_client(arguments["account"])
    attendee_settings = get_attendee_settings(config)

    # Validate attendees against security settings
    validated_attendees: list[str] = []
    if arguments.get("attendees"):
        validated_attendees = validate_attendees(arguments["attendees"], attendee_settings)

    # Notification setting from config, NOT from caller
    send_updates = "all" if attendee_settings["send_notifications"] else "none"

    result = client.create_event(
        summary=arguments["summary"],
        start_time=arguments["start_time"],
        end_time=arguments["end_time"],
        calendar_id=arguments.get("calendar_id", "primary"),
        description=arguments.get("description"),
        location=arguments.get("location"),
        timezone=arguments.get("timezone", "UTC"),
        # Empty list → None so we skip the attendees field entirely
        attendees=validated_attendees or None,
        send_updates=send_updates,
    )
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_delete_event(arguments: dict) -> list[TextContent]:
    client = _get_client(arguments["account"])
    result = client.delete_event(
        event_id=arguments["event_id"],
        calendar_id=arguments.get("calendar_id", "primary"),
    )
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


TOOL_HANDLERS = {
    "calendar_list_calendars": handle_list_calendars,
    "calendar_get_events": handle_get_events,
    "calendar_get_event": handle_get_event,
    "calendar_get_freebusy": handle_get_freebusy,
    "calendar_create_event": handle_create_event,
    "calendar_delete_event": handle_delete_event,
}


async def main() -> None:
    """Run the MCP server over stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())
