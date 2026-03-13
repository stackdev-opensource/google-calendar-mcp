"""Tests for the MCP server tool dispatch and access control."""

from calendar_mcp.access_control import get_enabled_tools
from calendar_mcp.server import TOOL_HANDLERS
from calendar_mcp.tools import ALL_TOOL_DEFINITIONS


class TestToolDefinitions:
    def test_all_tools_have_definitions(self):
        """Every tool referenced in tiers has a definition."""
        from calendar_mcp.access_control import CALENDAR_TOOL_TIERS, ToolPreset

        all_tools = set(CALENDAR_TOOL_TIERS[ToolPreset.FULL].keys())
        defined_tools = set(ALL_TOOL_DEFINITIONS.keys())
        assert all_tools == defined_tools

    def test_all_schemas_have_additional_properties_false(self):
        """Every tool schema rejects unknown properties."""
        for name, tool in ALL_TOOL_DEFINITIONS.items():
            schema = tool.inputSchema
            assert schema.get("additionalProperties") is False, (
                f"Tool '{name}' is missing additionalProperties: false"
            )

    def test_all_schemas_require_account(self):
        """Every tool requires the account parameter."""
        for name, tool in ALL_TOOL_DEFINITIONS.items():
            schema = tool.inputSchema
            assert "account" in schema.get("required", []), (
                f"Tool '{name}' does not require 'account'"
            )

    def test_read_only_tools_listed(self, read_only_config):
        """Read-only preset exposes exactly 4 tools."""
        enabled = get_enabled_tools(read_only_config)
        assert len(enabled) == 4
        assert enabled == {
            "calendar_list_calendars",
            "calendar_get_events",
            "calendar_get_event",
            "calendar_get_freebusy",
        }

    def test_standard_tools_listed(self, standard_config):
        """Standard preset exposes 5 tools."""
        enabled = get_enabled_tools(standard_config)
        assert len(enabled) == 5
        assert "calendar_create_event" in enabled

    def test_full_tools_listed(self, full_config):
        """Full preset exposes all 6 tools."""
        enabled = get_enabled_tools(full_config)
        assert len(enabled) == 6

    def test_handlers_match_definitions(self):
        """Every tool definition has a corresponding handler."""
        assert set(TOOL_HANDLERS.keys()) == set(ALL_TOOL_DEFINITIONS.keys())
