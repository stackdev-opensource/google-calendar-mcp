"""Content sanitization, prompt injection defense, and audit logging."""

import logging

logger = logging.getLogger("calendar-mcp.audit")


def log_tool_call(tool_name: str, user_id: str, arg_keys: list[str]) -> None:
    """Log a tool invocation for audit purposes. Never logs full content."""
    logger.info("TOOL=%s USER=%s ARGS=%s", tool_name, user_id, arg_keys)


def sanitize_event_content(event_data: dict) -> dict:
    """Wrap untrusted content in XML-style delimiters.

    Returns a new dict — does not mutate the input. This prevents
    double-wrapping if the same parsed dict is ever reused.
    """
    result = dict(event_data)
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
