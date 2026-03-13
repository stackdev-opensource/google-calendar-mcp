"""OAuth authentication with multi-tier credential storage.

Resolution order:
1. Environment variables (CALENDAR_REFRESH_TOKEN + CALENDAR_CLIENT_ID + CALENDAR_CLIENT_SECRET)
2. Token file (~/.config/calendar-mcp/accounts/<email>/token.json)
3. Browser-based OAuth flow (only via `auth` subcommand)
"""

import json
import logging
import os
import stat
import sys
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

logger = logging.getLogger("calendar-mcp.auth")

CONFIG_DIR = Path(os.environ.get("CALENDAR_MCP_CONFIG_DIR", "~/.config/calendar-mcp")).expanduser()


def _validate_email_for_path(email: str) -> None:
    """Reject email values that could escape the accounts directory."""
    if "/" in email or "\\" in email or ".." in email or "\0" in email:
        raise ValueError(f"Invalid email for path operations: {email!r}")


def _token_path(email: str) -> Path:
    """Return the token file path for an account."""
    _validate_email_for_path(email)
    return CONFIG_DIR / "accounts" / email / "token.json"


def _save_token(email: str, creds: Credentials) -> None:
    """Save credentials to a JSON file with restrictive permissions.

    Uses os.open with O_CREAT to set 600 permissions atomically,
    avoiding a window where the file is world-readable.
    """
    path = _token_path(email)
    os.makedirs(path.parent, mode=0o700, exist_ok=True)
    # Enforce 700 even if directory already existed with lax permissions
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, creds.to_json().encode())
    finally:
        os.close(fd)
    logger.info("Token saved to %s", path)


def _load_token_from_file(email: str, scopes: list[str]) -> Credentials | None:
    """Load credentials from the token file if it exists."""
    path = _token_path(email)
    if not path.is_file():
        return None

    try:
        data = json.loads(path.read_text())
        return Credentials.from_authorized_user_info(data, scopes)
    except (json.JSONDecodeError, ValueError, KeyError):
        logger.warning("Invalid token file at %s, ignoring", path)
        return None


def _env_key(email: str) -> str:
    """Convert email to an env var suffix: user@example.com -> USER_EXAMPLE_COM."""
    return email.replace("@", "_").replace(".", "_").replace("+", "_").upper()


def _load_token_from_env(email: str, scopes: list[str]) -> Credentials | None:
    """Build credentials from environment variables.

    - client_id/client_secret are shared (one OAuth app for all accounts)
    - refresh_token is per-account: checks CALENDAR_REFRESH_TOKEN_<SUFFIX> first,
      then falls back to generic CALENDAR_REFRESH_TOKEN for single-account setups
    """
    client_id = os.environ.get("CALENDAR_CLIENT_ID")
    client_secret = os.environ.get("CALENDAR_CLIENT_SECRET")
    if not client_id or not client_secret:
        return None

    suffix = _env_key(email)
    refresh_token = os.environ.get(f"CALENDAR_REFRESH_TOKEN_{suffix}") or os.environ.get(
        "CALENDAR_REFRESH_TOKEN"
    )
    if not refresh_token:
        return None

    return Credentials(
        token=None,
        refresh_token=refresh_token,
        client_id=client_id,
        client_secret=client_secret,
        token_uri="https://oauth2.googleapis.com/token",  # noqa: S106
        scopes=scopes,
    )


def _refresh_if_needed(creds: Credentials, email: str | None = None) -> Credentials:
    """Refresh credentials if expired. Optionally save to file."""
    if creds.valid:
        return creds

    if creds.refresh_token:
        logger.info("Refreshing token%s", f" for {email}" if email else "")
        creds.refresh(Request())
        if email:
            _save_token(email, creds)
        return creds

    raise ValueError("Token is invalid and cannot be refreshed")


def get_credentials(
    email: str,
    client_secrets_path: str | None,
    scopes: list[str],
) -> Credentials:
    """Get valid OAuth credentials for an account.

    Resolution:
    1. Environment variables (CALENDAR_REFRESH_TOKEN + client ID/secret)
    2. Token file (~/.config/calendar-mcp/accounts/<email>/token.json)
    3. Raises ValueError — user must run `auth` subcommand first
    """
    # Tier 1: Environment variables (per-account, then generic fallback)
    creds = _load_token_from_env(email, scopes)
    if creds:
        return _refresh_if_needed(creds)

    # Tier 2: Token file
    creds = _load_token_from_file(email, scopes)
    if creds:
        try:
            return _refresh_if_needed(creds, email)
        except ValueError:
            logger.warning("Stored token for %s is invalid, re-authentication needed", email)

    # Tier 3: No valid credentials — cannot open browser during serve
    raise ValueError(
        f"No valid credentials for '{email}'. "
        f"Run: python -m calendar_mcp auth --account {email}"
        + (f" --client-secrets {client_secrets_path}" if client_secrets_path else "")
    )


def run_oauth_flow(
    email: str,
    client_secrets_path: str | None,
    scopes: list[str],
    *,
    show_credentials: bool = False,
) -> Credentials:
    """Run the interactive browser OAuth flow and save the token.

    Called by the `auth` subcommand only.
    """
    secrets_path = client_secrets_path or os.environ.get("CALENDAR_CLIENT_SECRETS")
    if not secrets_path:
        raise ValueError(
            "Client secrets required. "
            "Provide --client-secrets or set CALENDAR_CLIENT_SECRETS env var."
        )

    if not os.path.isfile(secrets_path):
        raise FileNotFoundError(f"Client secrets file not found: {secrets_path}")

    logger.info("Starting OAuth flow for %s", email)
    flow = InstalledAppFlow.from_client_secrets_file(secrets_path, scopes)
    creds = flow.run_local_server(port=4101)
    _save_token(email, creds)

    print(f"Authenticated {email} successfully.", file=sys.stderr)
    print(f"Token saved to {_token_path(email)}", file=sys.stderr)

    if show_credentials:
        suffix = _env_key(email)
        print(
            "\nTo use environment variables instead (for Docker/CI/MCP client config):",
            file=sys.stderr,
        )
        print(f"  CALENDAR_CLIENT_ID={creds.client_id}", file=sys.stderr)
        print(f"  CALENDAR_CLIENT_SECRET={creds.client_secret}", file=sys.stderr)
        print(f"  CALENDAR_REFRESH_TOKEN_{suffix}={creds.refresh_token}", file=sys.stderr)
        print("\n  (CALENDAR_REFRESH_TOKEN also works for single-account setups)", file=sys.stderr)
    else:
        print(
            "\nTo get env vars for Docker/CI, re-run with --show-credentials",
            file=sys.stderr,
        )

    return creds
