"""Command line entry point: GUI by default, plus a few scriptable commands."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, core
from .i18n import _


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="auth-switch", description=_("Switch between Proxmox VE accounts."))
    parser.add_argument("--version", action="version", version=f"auth-switch {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("gui", help=_("open the window (default)"))
    commands.add_parser("list", help=_("print the accounts as JSON"))
    switch = commands.add_parser("switch", help=_("activate an account"))
    switch.add_argument("token_id")
    switch.add_argument("--hostname")
    run = commands.add_parser("exec", help=_("run a command with the active account in its environment"))
    run.add_argument("--hostname")
    run.add_argument("program", nargs=argparse.REMAINDER)
    check = commands.add_parser("leak-check", help=_("check files or a git working copy for private data"))
    check.add_argument("paths", nargs="*")
    check.add_argument("--repository", help=_("check what the next push of this working copy would publish"))
    commands.add_parser("mcp", help=_("run the MCP server on stdio"))
    args = parser.parse_args(argv)

    try:
        if args.command == "mcp":
            from . import mcp

            return mcp.main()
        if args.command == "exec":
            program = args.program[1:] if args.program[:1] == ["--"] else args.program
            if not program:
                parser.error(_("exec needs a command, for example: auth-switch exec -- terraform plan"))
            # The secret only reaches the child's environment; it is never printed.
            os.execvpe(program[0], program, {**os.environ, **core.environment(args.hostname)})
        if args.command == "leak-check":
            return _leak_check(args)
        if args.command in ("list", "switch"):
            result = core.describe_accounts() if args.command == "list" else core.switch_account(args.token_id, args.hostname)
            print(json.dumps(result, indent=2))
            return 0
    except (core.AuthError, OSError) as error:
        print(_("auth-switch: {error}").format(error=error), file=sys.stderr)
        return 2 if args.command == "leak-check" else 1

    from . import gui

    return gui.main()


def _leak_check(args) -> int:
    from . import leaks

    context = leaks.gather()
    found = leaks.scan_paths(args.paths, context)
    if args.repository or not args.paths:
        found += leaks.scan_repository(args.repository or ".", context)
    result = leaks.report(found)
    for finding in result["findings"]:
        print(f"{finding['severity']:8} {finding['where']}: {finding['detail']}\n         {finding['excerpt']}")
    print(_("No private data found.") if result["clean"] else _("{count} finding(s).").format(count=len(result["findings"])))
    return 0 if result["clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
