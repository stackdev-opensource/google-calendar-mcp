"""Entry point for running the server: python -m calendar_mcp"""

import argparse
import asyncio
import json
import logging
import sys


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments shared between auth and serve subcommands."""
    parser.add_argument(
        "--account",
        action="append",
        dest="accounts",
        metavar="EMAIL",
        help="Google account email (can be repeated for multiple accounts)",
    )
    parser.add_argument(
        "--accounts-file",
        metavar="PATH",
        help="Path to accounts.json config file (alternative to --account)",
    )
    parser.add_argument(
        "--client-secrets",
        metavar="PATH",
        help="Path to Google OAuth client secrets JSON (or set CALENDAR_CLIENT_SECRETS)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )


def _resolve_config(args: argparse.Namespace) -> dict:
    """Build a unified config dict from CLI args and/or accounts file."""
    config: dict = {"accounts": [], "tool_access": {"overrides": {}}}

    # Load from file if provided
    if args.accounts_file:
        try:
            with open(args.accounts_file) as f:
                file_config = json.load(f)
        except FileNotFoundError:
            print(f"Error: accounts file not found: {args.accounts_file}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON in {args.accounts_file}: {e}", file=sys.stderr)
            sys.exit(1)
        config["accounts"] = file_config.get("accounts", [])
        for i, account in enumerate(config["accounts"]):
            if not isinstance(account, dict) or "email" not in account:
                print(
                    f"Error: accounts[{i}] in {args.accounts_file} must have an 'email' field",
                    file=sys.stderr,
                )
                sys.exit(1)
        config["tool_access"] = file_config.get("tool_access", {"overrides": {}})
        if "overrides" not in config["tool_access"]:
            config["tool_access"]["overrides"] = {}
        # Carry over security settings from file
        if "security" in file_config:
            config["security"] = file_config["security"]

    # Add accounts from --account flags
    if args.accounts:
        existing_emails = {a["email"] for a in config["accounts"]}
        for email in args.accounts:
            if email not in existing_emails:
                config["accounts"].append({"email": email})

    if not config["accounts"]:
        print(
            "Error: provide at least one account via --account or --accounts-file",
            file=sys.stderr,
        )
        sys.exit(1)

    return config


def cmd_auth(args: argparse.Namespace) -> None:
    """Handle the `auth` subcommand — run OAuth flow for each account."""
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    config = _resolve_config(args)

    # Apply preset and tool overrides so scope resolution picks up the right tools
    if args.preset:
        config["tool_access"]["preset"] = args.preset
    if args.enable_tools:
        for tool in args.enable_tools:
            config["tool_access"]["overrides"][tool] = True
    if args.disable_tools:
        for tool in args.disable_tools:
            config["tool_access"]["overrides"][tool] = False

    from calendar_mcp.access_control import get_enabled_tools, get_required_scopes
    from calendar_mcp.auth import run_oauth_flow

    enabled_tools = get_enabled_tools(config)
    scopes = get_required_scopes(enabled_tools)

    for account in config["accounts"]:
        email = account["email"]
        print(f"\nAuthenticating {email}...", file=sys.stderr)
        run_oauth_flow(email, args.client_secrets, scopes, show_credentials=args.show_credentials)

    print("\nAll accounts authenticated. You can now run:", file=sys.stderr)
    account_flags = " ".join(f"--account {a['email']}" for a in config["accounts"])
    print(f"  python -m calendar_mcp serve {account_flags}", file=sys.stderr)


def cmd_serve(args: argparse.Namespace) -> None:
    """Handle the `serve` subcommand — run the MCP server."""
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    config = _resolve_config(args)

    # Apply CLI preset/tool overrides
    if args.preset:
        config["tool_access"]["preset"] = args.preset
    if args.enable_tools:
        for tool in args.enable_tools:
            config["tool_access"]["overrides"][tool] = True
    if args.disable_tools:
        for tool in args.disable_tools:
            config["tool_access"]["overrides"][tool] = False

    # Wire config into the server module
    import calendar_mcp.server as server_module

    server_module.config = config
    server_module.client_secrets_path = args.client_secrets or ""

    logger = logging.getLogger("calendar-mcp")

    from calendar_mcp.access_control import get_enabled_tools

    enabled = get_enabled_tools(config)
    preset = config["tool_access"].get("preset", "read-only")
    logger.info(
        "Starting calendar-mcp with preset='%s', enabled tools: %s", preset, sorted(enabled)
    )

    asyncio.run(server_module.main())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Secure Google Calendar MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # -- auth subcommand --
    auth_parser = subparsers.add_parser(
        "auth",
        help="Authenticate Google accounts (one-time OAuth flow)",
        description="Run the browser-based OAuth flow for one or more Google accounts.",
    )
    _add_common_args(auth_parser)
    auth_parser.add_argument(
        "--preset",
        choices=["read-only", "standard", "full"],
        default=None,
        help="Tool access preset — determines which OAuth scopes to request (default: read-only)",
    )
    auth_parser.add_argument(
        "--enable-tool",
        action="append",
        dest="enable_tools",
        metavar="TOOL_NAME",
        help="Enable a specific tool for scope resolution (can be repeated)",
    )
    auth_parser.add_argument(
        "--disable-tool",
        action="append",
        dest="disable_tools",
        metavar="TOOL_NAME",
        help="Disable a specific tool for scope resolution (can be repeated)",
    )
    auth_parser.add_argument(
        "--show-credentials",
        action="store_true",
        default=False,
        help="Print OAuth credentials (client ID, secret, refresh token) after authenticating",
    )

    # -- serve subcommand --
    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the MCP server",
        description="Start the Calendar MCP server over stdio.",
    )
    _add_common_args(serve_parser)
    serve_parser.add_argument(
        "--preset",
        choices=["read-only", "standard", "full"],
        default=None,
        help="Tool access preset (default: read-only)",
    )
    serve_parser.add_argument(
        "--enable-tool",
        action="append",
        dest="enable_tools",
        metavar="TOOL_NAME",
        help="Enable a specific tool (can be repeated)",
    )
    serve_parser.add_argument(
        "--disable-tool",
        action="append",
        dest="disable_tools",
        metavar="TOOL_NAME",
        help="Disable a specific tool (can be repeated)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "auth":
        cmd_auth(args)
    elif args.command == "serve":
        cmd_serve(args)


if __name__ == "__main__":
    main()
