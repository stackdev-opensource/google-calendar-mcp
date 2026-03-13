# Contributing to google-calendar-mcp

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/google-calendar-mcp.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Install in development mode: `uv pip install -e ".[dev]"`

## Development Guidelines

### Code Style

- We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting
- Target Python 3.11+
- Line length limit: 100 characters
- Run `ruff check src/` before submitting

### Security First

This project handles sensitive calendar data. All contributions must:

- **Never** introduce OAuth scopes beyond `calendar.readonly` and `calendar.events`
- **Never** allow the AI caller to control notification settings — `sendUpdates` is server-side only
- **Never** allow attendees from domains not in the whitelist
- **Never** include `conferenceData` in created events
- **Never** write credentials with world-readable permissions — token files must use `600` permissions
- **Always** wrap untrusted content (event titles, descriptions, attendee names/emails, calendar names) in XML-style delimiters
- **Always** log tool invocations for audit purposes
- **Never** log full event content — only argument keys and metadata

### Commit Messages

- Use [conventional commits](https://www.conventionalcommits.org/) (enforced by pre-commit hook)
- Format: `feat: add freebusy support`, `fix: handle expired OAuth tokens`, `chore: update deps`
- Reference issues when applicable: `fix: handle expired OAuth tokens (#42)`

### Pull Requests

1. Keep PRs focused — one feature or fix per PR
2. Update documentation if your change affects user-facing behavior
3. Add tests for new functionality
4. Ensure all existing tests pass
5. Fill out the PR template

## Reporting Bugs

- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml)
- Include steps to reproduce, expected behavior, and actual behavior
- **Never** include OAuth tokens, client secrets, or calendar content in bug reports

## Security Vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. Instead, see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Questions?

Open a [discussion](https://github.com/stackdev-opensource/google-calendar-mcp/discussions) for questions that aren't bug reports or feature requests.
