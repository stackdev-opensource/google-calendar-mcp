"""Shared fixtures for calendar-mcp tests."""

import pytest


@pytest.fixture()
def read_only_config():
    """Config with read-only preset (default, safest)."""
    return {
        "accounts": [{"email": "test@example.com"}],
        "tool_access": {"preset": "read-only", "overrides": {}},
    }


@pytest.fixture()
def standard_config():
    """Config with standard preset (adds event creation)."""
    return {
        "accounts": [{"email": "test@example.com"}],
        "tool_access": {"preset": "standard", "overrides": {}},
    }


@pytest.fixture()
def full_config():
    """Config with full preset (adds event deletion)."""
    return {
        "accounts": [{"email": "test@example.com"}],
        "tool_access": {"preset": "full", "overrides": {}},
    }


@pytest.fixture()
def attendee_config():
    """Config with attendee domain whitelist enabled."""
    return {
        "accounts": [{"email": "test@example.com"}],
        "tool_access": {"preset": "standard", "overrides": {}},
        "security": {
            "allow_attendees": True,
            "allowed_attendee_domains": ["example.com", "trusted.org"],
            "send_notifications": False,
        },
    }
