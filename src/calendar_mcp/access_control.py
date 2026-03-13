"""Tiered tool access system, attendee security, and OAuth scope resolution."""

from enum import StrEnum


class ToolPreset(StrEnum):
    READ_ONLY = "read-only"
    STANDARD = "standard"
    FULL = "full"


CALENDAR_TOOL_TIERS: dict[ToolPreset, dict[str, bool]] = {
    ToolPreset.READ_ONLY: {
        "calendar_list_calendars": True,
        "calendar_get_events": True,
        "calendar_get_event": True,
        "calendar_get_freebusy": True,
        "calendar_create_event": False,
        "calendar_delete_event": False,
    },
    ToolPreset.STANDARD: {
        "calendar_list_calendars": True,
        "calendar_get_events": True,
        "calendar_get_event": True,
        "calendar_get_freebusy": True,
        "calendar_create_event": True,
        "calendar_delete_event": False,
    },
    ToolPreset.FULL: {
        "calendar_list_calendars": True,
        "calendar_get_events": True,
        "calendar_get_event": True,
        "calendar_get_freebusy": True,
        "calendar_create_event": True,
        "calendar_delete_event": True,
    },
}

# Maps tools to the additional OAuth scopes they require beyond calendar.readonly
TOOL_SCOPE_REQUIREMENTS: dict[str, str] = {
    "calendar_create_event": "https://www.googleapis.com/auth/calendar.events",
    "calendar_delete_event": "https://www.googleapis.com/auth/calendar.events",
}

SCOPE_READONLY = "https://www.googleapis.com/auth/calendar.readonly"


def get_enabled_tools(config: dict) -> set[str]:
    """Resolve the final set of enabled tools from preset + overrides.

    Defaults to read-only if no preset is specified.
    """
    tool_access = config.get("tool_access", {})
    preset_name = tool_access.get("preset", "read-only")

    try:
        preset = ToolPreset(preset_name)
    except ValueError:
        valid = [p.value for p in ToolPreset]
        raise ValueError(f"Invalid preset '{preset_name}'. Valid options: {valid}") from None

    enabled = {
        tool_name for tool_name, is_enabled in CALENDAR_TOOL_TIERS[preset].items() if is_enabled
    }

    all_known_tools = set(CALENDAR_TOOL_TIERS[ToolPreset.FULL].keys())
    overrides = tool_access.get("overrides", {})
    for tool_name, should_enable in overrides.items():
        if tool_name not in all_known_tools:
            raise ValueError(
                f"Unknown tool '{tool_name}' in overrides. Valid tools: {sorted(all_known_tools)}"
            )
        if should_enable:
            enabled.add(tool_name)
        else:
            enabled.discard(tool_name)

    return enabled


def get_required_scopes(enabled_tools: set[str]) -> list[str]:
    """Determine the minimum OAuth scopes required for the enabled tools."""
    scopes = [SCOPE_READONLY]

    for tool_name, required_scope in TOOL_SCOPE_REQUIREMENTS.items():
        if tool_name in enabled_tools and required_scope not in scopes:
            scopes.append(required_scope)

    return scopes


def get_attendee_settings(config: dict) -> dict:
    """Get the attendee restriction settings from config.

    Returns settings that control whether attendees are allowed
    and which domains are permitted.
    """
    security = config.get("security", {})

    return {
        "allow_attendees": security.get("allow_attendees", False),
        "allowed_domains": security.get("allowed_attendee_domains", []),
        "send_notifications": security.get("send_notifications", False),
    }


def validate_attendees(attendees: list[str] | None, settings: dict) -> list[str]:
    """Validate attendee list against security settings.

    If attendees aren't allowed at all, raises an error.
    If they are allowed, validates all are from permitted domains.
    """
    if not attendees:
        return []

    if not settings["allow_attendees"]:
        raise ValueError(
            "Adding attendees is disabled in the current configuration. "
            "To enable it, set 'security.allow_attendees' to true in your config file."
        )

    allowed_domains = [d.lower() for d in settings["allowed_domains"]]

    if not allowed_domains:
        raise ValueError(
            "Attendees are enabled but no allowed domains are configured. "
            "Add domains to 'security.allowed_attendee_domains' in your config file."
        )

    validated = []
    rejected = []

    for email in attendees:
        domain = email.split("@")[-1].lower()
        if domain in allowed_domains:
            validated.append(email)
        else:
            rejected.append(email)

    if rejected:
        raise ValueError(
            f"The following attendees are outside allowed domains and were blocked: {rejected}. "
            f"Allowed domains: {allowed_domains}"
        )

    return validated
