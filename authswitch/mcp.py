"""Minimal MCP server (stdio transport) for Proxmox VE accounts.

Implements just the parts of the Model Context Protocol that a tool-only
server needs, so no third-party SDK is required.
"""

from __future__ import annotations

import json
import sys
import threading

from . import __version__, core, leaks, update
from .i18n import _

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
HOSTNAME = {"type": "string", "description": _("Server as host or host:port, only needed if several are set up")}

TOOLS = [
    {
        "name": "list_proxmox_accounts",
        "description": _(
            "List the Proxmox VE accounts (API tokens) Auth-Switch manages, per server, including which one is "
            "active, whether the token still works and the Proxmox VE version. Secrets are never returned."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "switch_proxmox_account",
        "description": _(
            "Make another API token the active account of a Proxmox VE server. The Proxmox tools of this server "
            "and 'auth-switch exec' then act with its permissions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "token_id": {"type": "string", "description": _("Token ID such as root@pam!automation, or a user")},
                "hostname": HOSTNAME,
            },
            "required": ["token_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "proxmox_api_get",
        "description": _(
            "Read from the Proxmox VE API as the active account. The path is relative to /api2/json, for example "
            "/cluster/resources?type=vm, /nodes, /nodes/NODE/qemu, /nodes/NODE/lxc/VMID/status/current, "
            "/nodes/NODE/storage or /cluster/tasks. Endpoints that issue tickets or credentials are blocked."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": _("API path below /api2/json, starting with /")},
                "params": {"type": "object", "description": _("Query parameters")},
                "hostname": HOSTNAME,
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "proxmox_api_write",
        "description": _(
            "Change something through the Proxmox VE API as the active account, for example start or stop a "
            "guest (POST /nodes/NODE/qemu/VMID/status/start), create a snapshot "
            "(POST /nodes/NODE/qemu/VMID/snapshot) or change a configuration (PUT /nodes/NODE/qemu/VMID/config). "
            "The path is relative to /api2/json; parameters are sent as form fields. Many calls return a task ID "
            "(UPID) whose progress can be read at /nodes/NODE/tasks/UPID/status. DELETE removes data permanently."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["POST", "PUT", "DELETE"]},
                "path": {"type": "string", "description": _("API path below /api2/json, starting with /")},
                "params": {"type": "object", "description": _("Parameters of the call")},
                "hostname": HOSTNAME,
            },
            "required": ["method", "path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
    {
        "name": "check_for_leaks",
        "description": _(
            "Check content for private data before it is published: secrets of the Proxmox VE accounts, other "
            "access tokens and private keys, addresses of the user's Proxmox servers, the real git e-mail "
            "address, paths in the home directory, the computer name and internal network addresses. Call it "
            "before committing, pushing, creating a release, opening an issue or pull request, or putting text "
            "into a README. Pass 'repository' to check what the next push would publish, 'paths' for files or "
            "folders, or 'text' for a draft. Findings of severity 'secret' must be removed; discuss 'private' "
            "and 'review' findings with the user instead of publishing them."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": _("Text to check, for example a draft README or message")},
                "paths": {"type": "array", "items": {"type": "string"}, "description": _("Files or folders to check")},
                "repository": {
                    "type": "string",
                    "description": _("Git working copy; checks staged changes and commits not yet on the upstream"),
                },
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
]

# Larger results are cut so one call cannot flood the conversation.
MAX_RESULT_CHARS = 60000


def instructions() -> str:
    """Guidance the client shows the model for the whole session."""
    text = _(
        "Before publishing anything on the user's behalf (commit, push, release, issue, pull request, README), "
        "run check_for_leaks on it and resolve the findings with the user."
    )
    rules = core.load_settings().get("restricted")
    terms = ", ".join(str(term) for term in (rules or {}).get("terms") or []) if isinstance(rules, dict) else ""
    if terms:
        text += "\n" + _(
            "Do not mention {terms} in anything you publish, and add no Co-Authored-By or 'Generated with' lines "
            "naming them."
        ).format(terms=terms)
        if rules.get("repository"):
            text += " " + _("Such notes belong only in the repository {repository}.").format(repository=rules["repository"])
    return "\n".join([text, *notices()])


def notices() -> list[str]:
    """Things the user should hear about: a newer release, or this server being outdated."""
    found = []
    installed = update.outdated_process()
    if installed:
        message = _("Auth-Switch was updated to {version}; restart the client so this MCP server runs the new version.")
        found.append(message.format(version=installed))
    latest = update.cached() if core.load_settings().get("check_updates") else None
    if latest:
        found.append(_("Auth-Switch {version} is available: {url}").format(**latest))
    return found


def _refuse_secrets(*values: object) -> None:
    """Stop a call that would carry a secret or private key to a server."""
    text = "\n".join(json.dumps(value, ensure_ascii=False) for value in values if value is not None)
    secrets = [f for f in leaks.scan_text(text, "request") if f.severity == leaks.SECRET]
    if secrets:
        raise core.AuthError(_("Not sent: the request contains a secret ({detail})").format(detail=secrets[0].detail))


def _call_tool(name: str, arguments: dict) -> object:
    text = {key: value for key, value in arguments.items() if isinstance(value, str)}
    params = arguments.get("params") if isinstance(arguments.get("params"), dict) else None
    host = text.get("hostname")
    if name == "list_proxmox_accounts":
        result: dict = {"accounts": core.describe_accounts()}
        if notices():
            result["notices"] = notices()
        return result
    if name == "switch_proxmox_account":
        if not text.get("token_id"):
            raise core.AuthError(_("'token_id' is required"))
        return core.switch_account(text["token_id"], host)
    if name == "proxmox_api_get":
        return core.api("GET", text.get("path", ""), params, host)
    if name == "proxmox_api_write":
        method = text.get("method", "").upper()
        if method not in ("POST", "PUT", "DELETE"):
            raise core.AuthError(_("Unsupported method: {method}").format(method=method))
        _refuse_secrets(text.get("path"), params)
        return core.api(method, text.get("path", ""), params, host)
    if name == "check_for_leaks":
        context, found = leaks.gather(), []
        if isinstance(arguments.get("text"), str):
            found += leaks.scan_text(arguments["text"], "text", context)
        if isinstance(arguments.get("paths"), list):
            found += leaks.scan_paths([str(path) for path in arguments["paths"]], context)
        if isinstance(arguments.get("repository"), str):
            found += leaks.scan_repository(arguments["repository"], context)
        return leaks.report(found)
    raise core.AuthError(_("Unknown tool: {name}").format(name=name))


def handle(message: dict) -> dict | None:
    """Handle one JSON-RPC message; returns the response or None for notifications."""
    method, params = message.get("method"), message.get("params") or {}
    if "id" not in message:
        return None

    def reply(result=None, error=None) -> dict:
        response = {"jsonrpc": "2.0", "id": message["id"]}
        response.update({"error": error} if error else {"result": result})
        return response

    if method == "initialize":
        requested = params.get("protocolVersion")
        return reply(
            {
                "protocolVersion": requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": core.APP, "version": __version__},
                "instructions": instructions(),
            }
        )
    if method == "ping":
        return reply({})
    if method == "tools/list":
        return reply({"tools": TOOLS})
    if method == "tools/call":
        try:
            result = _call_tool(params.get("name", ""), params.get("arguments") or {})
        except core.AuthError as error:
            return reply({"content": [{"type": "text", "text": str(error)}], "isError": True})
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if len(text) > MAX_RESULT_CHARS:
            text = text[:MAX_RESULT_CHARS] + "\n" + _("[Result cut off; narrow the request.]")
        return reply({"content": [{"type": "text", "text": text}]})
    return reply(error={"code": -32601, "message": _("Method not found: {method}").format(method=method)})


def main() -> int:
    # Refreshes the cached answer in the background; the result shows up as a notice.
    threading.Thread(target=update.check, daemon=True).start()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": _("Parse error")}}
        else:
            response = handle(message) if isinstance(message, dict) else None
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
