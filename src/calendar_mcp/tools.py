"""MCP tool definitions and input schemas."""

from mcp.types import Tool

ALL_TOOL_DEFINITIONS: dict[str, Tool] = {
    "calendar_list_calendars": Tool(
        name="calendar_list_calendars",
        description=(
            "List all calendars accessible by the user, including shared calendars. "
            "Returns calendar ID, name, and access level."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "account": {
                    "type": "string",
                    "description": "Email address of the Google account",
                },
            },
            "required": ["account"],
            "additionalProperties": False,
        },
    ),
    "calendar_get_events": Tool(
        name="calendar_get_events",
        description=(
            "Retrieve calendar events within a time range. "
            "Event descriptions are wrapped in XML-style tags to clearly "
            "separate data from instructions. Returns event title, time, "
            "location, and description."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "account": {
                    "type": "string",
                    "description": "Email address of the Google account",
                },
                "calendar_id": {
                    "type": "string",
                    "description": (
                        "Calendar ID (use 'primary' for the main calendar, "
                        "or get IDs from calendar_list_calendars)"
                    ),
                    "default": "primary",
                },
                "time_min": {
                    "type": "string",
                    "description": (
                        "Start of time range in ISO 8601 format "
                        "(e.g., '2026-03-06T00:00:00Z'). Defaults to now."
                    ),
                },
                "time_max": {
                    "type": "string",
                    "description": (
                        "End of time range in ISO 8601 format. Required to limit results."
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum events to return (1-100)",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 100,
                },
                "query": {
                    "type": "string",
                    "description": "Optional text search query to filter events",
                },
            },
            "required": ["account", "time_max"],
            "additionalProperties": False,
        },
    ),
    "calendar_get_event": Tool(
        name="calendar_get_event",
        description=(
            "Retrieve a single calendar event by its ID, including full "
            "description, attendees, and conference details. Content is "
            "wrapped in XML-style tags."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "account": {
                    "type": "string",
                    "description": "Email address of the Google account",
                },
                "calendar_id": {
                    "type": "string",
                    "description": "Calendar ID (default: primary)",
                    "default": "primary",
                },
                "event_id": {
                    "type": "string",
                    "description": "The calendar event ID",
                },
            },
            "required": ["account", "event_id"],
            "additionalProperties": False,
        },
    ),
    "calendar_get_freebusy": Tool(
        name="calendar_get_freebusy",
        description=(
            "Check free/busy availability for one or more calendars. "
            "Returns time slots marked as busy without exposing event details. "
            "Useful for finding meeting times."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "account": {
                    "type": "string",
                    "description": "Email address of the Google account",
                },
                "calendars": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Calendar IDs to check (use email addresses for people's primary calendars)"
                    ),
                },
                "time_min": {
                    "type": "string",
                    "description": "Start of time range (ISO 8601)",
                },
                "time_max": {
                    "type": "string",
                    "description": "End of time range (ISO 8601)",
                },
            },
            "required": ["account", "calendars", "time_min", "time_max"],
            "additionalProperties": False,
        },
    ),
    "calendar_create_event": Tool(
        name="calendar_create_event",
        description=(
            "Create a new calendar event. SECURITY NOTE: This tool cannot "
            "add external attendees or send notifications. Events are created "
            "silently on your calendar only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "account": {
                    "type": "string",
                    "description": "Email address of the Google account",
                },
                "calendar_id": {
                    "type": "string",
                    "description": "Calendar ID (default: primary)",
                    "default": "primary",
                },
                "summary": {
                    "type": "string",
                    "description": "Event title",
                },
                "start_time": {
                    "type": "string",
                    "description": "Start time in ISO 8601 format",
                },
                "end_time": {
                    "type": "string",
                    "description": "End time in ISO 8601 format",
                },
                "description": {
                    "type": "string",
                    "description": "Event description/notes (optional)",
                },
                "location": {
                    "type": "string",
                    "description": "Event location (optional)",
                },
                "timezone": {
                    "type": "string",
                    "description": (
                        "IANA timezone (e.g., 'America/New_York', 'Europe/London'). "
                        "Defaults to UTC."
                    ),
                    "default": "UTC",
                },
                "attendees": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Email addresses of attendees (optional). "
                        "Only allowed if attendee domain whitelist is configured. "
                        "External domains are always blocked."
                    ),
                },
            },
            "required": ["account", "summary", "start_time", "end_time"],
            "additionalProperties": False,
        },
    ),
    "calendar_delete_event": Tool(
        name="calendar_delete_event",
        description=(
            "Delete a calendar event by its ID. Does not send cancellation notifications."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "account": {
                    "type": "string",
                    "description": "Email address of the Google account",
                },
                "calendar_id": {
                    "type": "string",
                    "description": "Calendar ID (default: primary)",
                    "default": "primary",
                },
                "event_id": {
                    "type": "string",
                    "description": "The event ID to delete",
                },
            },
            "required": ["account", "event_id"],
            "additionalProperties": False,
        },
    ),
}
