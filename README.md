# Google Calendar MCP Server (Secure)

[![PyPI](https://img.shields.io/pypi/v/calendar-mcp-secure)](https://pypi.org/project/calendar-mcp-secure/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A secure [MCP](https://modelcontextprotocol.io/) server that gives AI assistants like Claude access to Google Calendar. Security-first design — hardened against prompt injection via malicious calendar invites, credential theft, and unauthorized data exfiltration.

**Why this one?** Unlike other Calendar MCP servers, this one ships with tiered access control, attendee domain whitelisting, prompt injection defense, notification suppression, and audit logging. Read more in [Security](#security).

## Quick Start

### 1. Install

```bash
pip install calendar-mcp-secure
```

Requires Python 3.11+.

### 2. Set up Google Cloud

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project and enable the **Google Calendar API** (APIs & Services > Library)
3. Create **OAuth 2.0 credentials** (APIs & Services > Credentials > Create Credentials > OAuth client ID > Desktop app)
4. Download the JSON file as `client_secret.json`
5. Add your email as a **test user** in the OAuth consent screen

### 3. Authenticate

```bash
python -m calendar_mcp auth \
  --account you@example.com \
  --client-secrets client_secret.json
```

This opens a browser for Google consent, saves the token locally, and prints environment variables you can use instead.

### 4. Run

```bash
python -m calendar_mcp serve --account you@example.com
```

## MCP Client Integration

### Claude Desktop

Add to your config file:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "calendar": {
      "command": "python",
      "args": ["-m", "calendar_mcp", "serve", "--account", "you@example.com"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add calendar -- python -m calendar_mcp serve --account you@example.com
```

### Environment Variables (Docker / CI / any client)

Instead of file-based tokens, pass credentials via environment variables:

```json
{
  "mcpServers": {
    "calendar": {
      "command": "python",
      "args": ["-m", "calendar_mcp", "serve", "--account", "you@example.com"],
      "env": {
        "CALENDAR_CLIENT_ID": "xxxxx.apps.googleusercontent.com",
        "CALENDAR_CLIENT_SECRET": "GOCSPX-xxxxx",
        "CALENDAR_REFRESH_TOKEN": "1//xxxxx"
      }
    }
  }
}
```

The `auth` subcommand prints these values after authenticating.

### Multi-Account

```bash
python -m calendar_mcp serve \
  --account work@company.com \
  --account personal@gmail.com
```

For multi-account env vars, use per-account refresh tokens:

```
CALENDAR_REFRESH_TOKEN_WORK_COMPANY_COM=1//xxxxx
CALENDAR_REFRESH_TOKEN_PERSONAL_GMAIL_COM=1//yyyyy
```

The suffix is the email with `@`, `.`, `+` replaced by `_`, uppercased (e.g. `work@company.com` → `WORK_COMPANY_COM`). Falls back to `CALENDAR_REFRESH_TOKEN` for single-account setups.

Or use a config file:

```bash
python -m calendar_mcp serve --accounts-file accounts.json
```

See [config/example.accounts.json](config/example.accounts.json) for the file format.

## Available Tools

### Read-Only (default)

| Tool | Description |
|------|-------------|
| `calendar_list_calendars` | List all calendars (including shared calendars) |
| `calendar_get_events` | Retrieve events within a time range with optional text search |
| `calendar_get_event` | Get full details of a single event by ID |
| `calendar_get_freebusy` | Check free/busy availability without exposing event details |

### Standard (includes all read-only tools, plus:)

| Tool | Description | Scope |
|------|-------------|-------|
| `calendar_create_event` | Create an event (attendees restricted to whitelisted domains) | `calendar.events` |

### Full (includes all standard tools, plus:)

| Tool | Description | Scope |
|------|-------------|-------|
| `calendar_delete_event` | Delete an event (no cancellation notifications sent) | `calendar.events` |

## Tool Access Configuration

By default, the server runs in `read-only` mode — the safest option.

### Presets

| Preset | What the AI can do |
|--------|-------------------|
| `read-only` | List calendars, read events, check free/busy |
| `standard` | All of the above + create events |
| `full` | All of the above + delete events |

### Examples

```bash
# Standard preset (enables event creation)
python -m calendar_mcp serve --account you@example.com --preset standard

# Read-only but enable just event creation
python -m calendar_mcp serve --account you@example.com --enable-tool calendar_create_event

# Full but disable event deletion
python -m calendar_mcp serve --account you@example.com --preset full --disable-tool calendar_delete_event
```

When authenticating, match the preset so the correct OAuth scopes are requested:

```bash
python -m calendar_mcp auth --account you@example.com --preset standard --client-secrets client_secret.json
```

### Config File

```json
{
  "accounts": [{"email": "you@example.com"}],
  "tool_access": {
    "preset": "standard",
    "overrides": {
      "calendar_delete_event": false
    }
  },
  "security": {
    "allow_attendees": true,
    "allowed_domains": ["yourcompany.com"],
    "send_notifications": false
  }
}
```

### Attendee Security

By default, event creation does **not** allow attendees. To enable attendees:

1. Set `allow_attendees: true` in your config
2. Specify `allowed_domains` — only email addresses matching these domains are accepted
3. External domains are always blocked, preventing data exfiltration via calendar invites

Notifications are controlled server-side via `send_notifications` (default: `false`). The AI caller cannot override this setting.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CALENDAR_CLIENT_ID` | Google OAuth client ID (shared across all accounts) |
| `CALENDAR_CLIENT_SECRET` | Google OAuth client secret (shared across all accounts) |
| `CALENDAR_REFRESH_TOKEN` | OAuth refresh token (single-account setups) |
| `CALENDAR_REFRESH_TOKEN_<SUFFIX>` | Per-account refresh token (e.g. `CALENDAR_REFRESH_TOKEN_YOU_EXAMPLE_COM`) |
| `CALENDAR_CLIENT_SECRETS` | Path to `client_secret.json` (alternative to `--client-secrets`) |
| `CALENDAR_MCP_CONFIG_DIR` | Override config directory (default: `~/.config/calendar-mcp`) |

## Security

### Design Principles

1. **Read-only by default** — write operations must be explicitly enabled via preset or overrides
2. **Attendee domain whitelist** — event creation cannot add external attendees; domains must be explicitly allowed
3. **Notification suppression** — `sendUpdates='none'` enforced server-side; the AI cannot trigger email notifications
4. **No conference links** — created events never include auto-generated Meet/Zoom links
5. **Minimal OAuth scopes** — only `calendar.readonly` by default; `calendar.events` added dynamically when write tools are enabled
6. **Prompt injection defense** — all untrusted content (event titles, descriptions, attendee names/emails, calendar names) wrapped in XML-style delimiters
7. **Restrictive file permissions** — token files stored with `600` permissions (owner read/write only)
8. **Path traversal protection** — email addresses validated before constructing file paths
9. **Error isolation** — internal errors logged to stderr; only safe messages returned to the AI
10. **Audit logging** — every tool call logged with timestamp, tool name, and argument keys (never values)

### Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## Development

```bash
git clone https://github.com/stackdev-opensource/google-calendar-mcp.git
cd google-calendar-mcp
uv venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev]"
ruff check src/
pytest
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
