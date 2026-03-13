# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) feature on this repository.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix or mitigation**: depends on severity; critical issues targeted within 2 weeks

## Security Model

This project handles sensitive calendar data. Key security properties:

1. **Read-only by default** — write operations must be explicitly enabled
2. **Attendee domain whitelist** — event creation cannot add external attendees; only explicitly allowed domains are permitted
3. **Notification suppression** — `sendUpdates='none'` enforced server-side; the AI cannot trigger email notifications
4. **No conference links** — created events never include auto-generated Meet/Zoom links
5. **Restrictive file permissions** — token files stored with `600` permissions; environment variables supported for containerized deployments
6. **Prompt injection defense** — untrusted calendar content wrapped in XML delimiters
7. **Minimal OAuth scopes** — only `calendar.readonly` and `calendar.events`; never `https://www.googleapis.com/auth/calendar` (full access)
8. **Error isolation** — internal errors logged to stderr; only safe messages returned to the AI
9. **Audit logging** — all tool invocations are logged

If you believe any of these properties can be bypassed, that constitutes a security vulnerability.
