# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-13

### Added
- 6 MCP tools: `calendar_list_calendars`, `calendar_get_events`, `calendar_get_event`, `calendar_get_freebusy`, `calendar_create_event`, `calendar_delete_event`
- Tiered access control with 3 presets (read-only, standard, full) and per-tool overrides
- Content sanitization with XML delimiters for prompt injection defense
- Attendee domain whitelist to prevent data exfiltration via calendar invites
- Notification suppression (`sendUpdates='none'`) enforced server-side
- Multi-account support with env var and file-based credential storage
- Dynamic OAuth scope resolution based on enabled tools
- Defense-in-depth access checks in both `list_tools()` and `call_tool()`
- Audit logging of tool invocations (argument keys only, never values)
- CLI with `auth` and `serve` subcommands
- 51 tests covering security, access control, auth, and server modules
