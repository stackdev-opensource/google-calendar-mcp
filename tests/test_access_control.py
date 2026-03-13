"""Tests for tiered access control, attendee validation, and scope resolution."""

import pytest

from calendar_mcp.access_control import (
    get_attendee_settings,
    get_enabled_tools,
    get_required_scopes,
    validate_attendees,
)


class TestGetEnabledTools:
    def test_default_is_read_only(self):
        config = {"tool_access": {}}
        enabled = get_enabled_tools(config)
        assert "calendar_list_calendars" in enabled
        assert "calendar_get_events" in enabled
        assert "calendar_get_event" in enabled
        assert "calendar_get_freebusy" in enabled
        assert "calendar_create_event" not in enabled
        assert "calendar_delete_event" not in enabled

    def test_standard_preset(self, standard_config):
        enabled = get_enabled_tools(standard_config)
        assert "calendar_create_event" in enabled
        assert "calendar_delete_event" not in enabled

    def test_full_preset(self, full_config):
        enabled = get_enabled_tools(full_config)
        assert "calendar_create_event" in enabled
        assert "calendar_delete_event" in enabled

    def test_override_enables_tool(self, read_only_config):
        read_only_config["tool_access"]["overrides"]["calendar_create_event"] = True
        enabled = get_enabled_tools(read_only_config)
        assert "calendar_create_event" in enabled

    def test_override_disables_tool(self, full_config):
        full_config["tool_access"]["overrides"]["calendar_delete_event"] = False
        enabled = get_enabled_tools(full_config)
        assert "calendar_delete_event" not in enabled

    def test_invalid_preset_raises(self):
        config = {"tool_access": {"preset": "invalid"}}
        with pytest.raises(ValueError, match="Invalid preset"):
            get_enabled_tools(config)

    def test_unknown_tool_in_overrides_raises(self, read_only_config):
        read_only_config["tool_access"]["overrides"]["nonexistent_tool"] = True
        with pytest.raises(ValueError, match="Unknown tool"):
            get_enabled_tools(read_only_config)

    def test_empty_config_defaults_to_read_only(self):
        enabled = get_enabled_tools({})
        assert len(enabled) == 4
        assert "calendar_create_event" not in enabled


class TestGetRequiredScopes:
    def test_read_only_scope(self):
        tools = {"calendar_list_calendars", "calendar_get_events"}
        scopes = get_required_scopes(tools)
        assert scopes == ["https://www.googleapis.com/auth/calendar.readonly"]

    def test_write_adds_events_scope(self):
        tools = {"calendar_list_calendars", "calendar_create_event"}
        scopes = get_required_scopes(tools)
        assert "https://www.googleapis.com/auth/calendar.readonly" in scopes
        assert "https://www.googleapis.com/auth/calendar.events" in scopes

    def test_delete_adds_events_scope(self):
        tools = {"calendar_list_calendars", "calendar_delete_event"}
        scopes = get_required_scopes(tools)
        assert "https://www.googleapis.com/auth/calendar.events" in scopes

    def test_no_duplicate_scopes(self):
        tools = {"calendar_create_event", "calendar_delete_event"}
        scopes = get_required_scopes(tools)
        assert scopes.count("https://www.googleapis.com/auth/calendar.events") == 1


class TestGetAttendeeSettings:
    def test_defaults_all_off(self):
        settings = get_attendee_settings({})
        assert settings["allow_attendees"] is False
        assert settings["allowed_domains"] == []
        assert settings["send_notifications"] is False

    def test_reads_from_security_section(self, attendee_config):
        settings = get_attendee_settings(attendee_config)
        assert settings["allow_attendees"] is True
        assert "example.com" in settings["allowed_domains"]
        assert settings["send_notifications"] is False


class TestValidateAttendees:
    def test_empty_attendees_returns_empty(self):
        settings = {"allow_attendees": False, "allowed_domains": [], "send_notifications": False}
        assert validate_attendees([], settings) == []
        assert validate_attendees(None, settings) == []

    def test_attendees_disabled_raises(self):
        settings = {"allow_attendees": False, "allowed_domains": [], "send_notifications": False}
        with pytest.raises(ValueError, match="disabled"):
            validate_attendees(["user@example.com"], settings)

    def test_no_domains_configured_raises(self):
        settings = {"allow_attendees": True, "allowed_domains": [], "send_notifications": False}
        with pytest.raises(ValueError, match="no allowed domains"):
            validate_attendees(["user@example.com"], settings)

    def test_valid_internal_attendees(self):
        settings = {
            "allow_attendees": True,
            "allowed_domains": ["example.com"],
            "send_notifications": False,
        }
        result = validate_attendees(["alice@example.com", "bob@example.com"], settings)
        assert result == ["alice@example.com", "bob@example.com"]

    def test_external_attendees_rejected(self):
        settings = {
            "allow_attendees": True,
            "allowed_domains": ["example.com"],
            "send_notifications": False,
        }
        with pytest.raises(ValueError, match="outside allowed domains"):
            validate_attendees(["attacker@evil.com"], settings)

    def test_mixed_attendees_rejected(self):
        settings = {
            "allow_attendees": True,
            "allowed_domains": ["example.com"],
            "send_notifications": False,
        }
        with pytest.raises(ValueError, match="attacker@evil.com"):
            validate_attendees(["alice@example.com", "attacker@evil.com"], settings)

    def test_case_insensitive_domain(self):
        settings = {
            "allow_attendees": True,
            "allowed_domains": ["Example.COM"],
            "send_notifications": False,
        }
        result = validate_attendees(["user@example.com"], settings)
        assert result == ["user@example.com"]
