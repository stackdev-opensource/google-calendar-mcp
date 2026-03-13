"""Content sanitization, prompt injection defense, and audit logging."""

import copy
import logging

logger = logging.getLogger("calendar-mcp.audit")


def log_tool_call(tool_name: str, user_id: str, arg_keys: list[str]) -> None:
    """Log a tool invocation for audit purposes. Never logs full content."""
    logger.info("TOOL=%s USER=%s ARGS=%s", tool_name, user_id, arg_keys)


def sanitize_event_content(event_data: dict) -> dict:
    """Wrap untrusted event content in XML-style delimiters.

    Returns a deep copy — does not mutate the input or share nested objects.
    """
    result = copy.deepcopy(event_data)
    if "summary" in result:
        result["summary"] = f"<event_title>{result['summary']}</event_title>"
    if "description" in result:
        result["description"] = (
            f"<event_description>\n{result['description']}\n</event_description>"
        )
    if "location" in result:
        result["location"] = f"<event_location>{result['location']}</event_location>"
    if "organizer" in result:
        result["organizer"] = f"<event_organizer>{result['organizer']}</event_organizer>"
    return result


def sanitize_calendar_content(calendar_data: dict) -> dict:
    """Wrap untrusted calendar metadata in XML-style delimiters.

    Shared calendar names and descriptions are attacker-controlled.
    Returns a deep copy — does not mutate the input.
    """
    result = copy.deepcopy(calendar_data)
    if result.get("summary"):
        result["summary"] = f"<calendar_name>{result['summary']}</calendar_name>"
    if result.get("description"):
        result["description"] = (
            f"<calendar_description>{result['description']}</calendar_description>"
        )
    return result
