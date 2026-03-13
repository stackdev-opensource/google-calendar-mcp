"""Tests for OAuth authentication and credential resolution."""

import pytest

from calendar_mcp.auth import (
    _env_key,
    _token_path,
    _validate_email_for_path,
)


class TestValidateEmailForPath:
    def test_normal_email_passes(self):
        _validate_email_for_path("user@example.com")

    def test_rejects_slash(self):
        with pytest.raises(ValueError, match="Invalid email"):
            _validate_email_for_path("../../etc/passwd")

    def test_rejects_backslash(self):
        with pytest.raises(ValueError, match="Invalid email"):
            _validate_email_for_path("user\\@example.com")

    def test_rejects_dotdot(self):
        with pytest.raises(ValueError, match="Invalid email"):
            _validate_email_for_path("user@..com")

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="Invalid email"):
            _validate_email_for_path("user@example\0.com")


class TestEnvKey:
    def test_converts_email_to_env_key(self):
        assert _env_key("user@example.com") == "USER_EXAMPLE_COM"

    def test_handles_plus(self):
        assert _env_key("user+tag@example.com") == "USER_TAG_EXAMPLE_COM"


class TestTokenPath:
    def test_returns_expected_path(self):
        path = _token_path("test@example.com")
        assert str(path).endswith("accounts/test@example.com/token.json")
        assert "calendar-mcp" in str(path)
