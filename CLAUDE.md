# Google Calendar MCP Server — Project Instructions

## Project Overview

Secure MCP server providing Google Calendar access to AI assistants. Security is the top priority.

## Architecture

- `src/calendar_mcp/` — main package
  - `server.py` — MCP server setup and tool dispatch
  - `tools.py` — tool definitions and input schemas
  - `auth.py` — OAuth authentication (env vars, file-based tokens)
  - `calendar_client.py` — Calendar API wrapper
  - `security.py` — content sanitization, audit logging
  - `access_control.py` — tiered tool access, attendee validation, scope resolution
  - `__main__.py` — CLI entry point
- `config/` — example configuration files
- `PROJECT.md` — full specification and design document

## Key Conventions

- Python 3.11+, use modern syntax
- Ruff for linting (`ruff check src/`)
- All tools must be registered in the tiered access system
- Event content returned to the AI must be wrapped in XML delimiters (`<event_title>`, `<event_description>`, `<event_location>`, `<event_organizer>`)
- OAuth tokens stored as file-based tokens (`~/.config/calendar-mcp/`) with 600 permissions, or via environment variables
- Permitted OAuth scopes: `calendar.readonly`, `calendar.events` — never use `https://www.googleapis.com/auth/calendar`

## Security Rules (Non-Negotiable)

- NEVER allow external attendees by default — domain whitelist required
- Notifications MUST default to `sendUpdates='none'`
- Token files MUST use restrictive permissions (600) — never world-readable
- NEVER add OAuth scopes beyond calendar.readonly and calendar.events
- ALL untrusted content must be sanitized before returning to the AI
- ALL tool invocations must be audit-logged
- NO conferenceData on created events — prevents auto-generated Meet links

## Testing

- Tests live in `tests/`
- Run with `pytest`

## Git

- Do not commit `accounts.json`, `client_secret*.json`, or any credential files
