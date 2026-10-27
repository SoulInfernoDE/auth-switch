"""Proxmox VE accounts: storage, certificate pinning, API access and switching.

An account is an API token (``user@realm!name``) on a Proxmox VE server. Its
secret lives in the system keyring only; a small file lists the accounts, the
active one per server and, for servers without a trusted certificate, the
fingerprint the user confirmed.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .i18n import _

APP = "auth-switch"
DEFAULT_PORT = 8006
TOKEN_ID = re.compile(r"[\w.+-]+@[\w.-]+![A-Za-z][\w.-]*")
API_METHODS = ("GET", "POST", "PUT", "DELETE")
# Endpoints that hand out tickets or new credentials stay closed, so no secret can end up in a result.
_CREDENTIAL_PATH = re.compile(
    r"^/access/(?:ticket|password|tfa)|/(?:termproxy|vncproxy|spiceproxy|vncwebsocket|mtunnel)\b"
)
# Creating a token returns its secret; reading or changing a token's settings does not.
_TOKEN_PATH = re.compile(r"^/access/users/[^/]+/token(?:/|$)")


class AuthError(RuntimeError):
    """Raised for anything the user has to be told about."""


@dataclass(frozen=True)
class Account:
    host: str
    token_id: str
    active: bool

    @property
    def user(self) -> str:
        return self.token_id.split("!", 1)[0]


@dataclass
class Profile:
    """Result of checking an account against its server; ``valid`` is ``None`` if the server did not answer."""

    valid: bool | None
    version: str = ""
    detail: str = ""


# --- files ------------------------------------------------------------------


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / APP


def accounts_file() -> Path:
    return config_dir() / "accounts.json"


def _write_private(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _load() -> dict[str, dict]:
    """Return ``{host: {"tokens": [...], "active": id, "fingerprint": hex}}``; never contains a secret."""
    try:
        stored = json.loads(accounts_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    hosts = {}
    for host, entry in stored.items() if isinstance(stored, dict) else ():
        tokens = entry.get("tokens") if isinstance(entry, dict) else None
        if isinstance(tokens, list) and tokens:
            hosts[host] = {
                "tokens": [str(token) for token in tokens],
                "active": str(entry.get("active") or ""),
                "fingerprint": str(entry.get("fingerprint") or ""),
                "repository": str(entry.get("repository") or ""),
            }
    return hosts


def list_accounts() -> list[Account]:
    return [Account(host, token, token == entry["active"]) for host, entry in _load().items() for token in entry["tokens"]]


def load_settings() -> dict:
    settings = {"sounds": True, "check_updates": True, "leak_allow": [], "restricted": {}}
    try:
        stored = json.loads((config_dir() / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return settings
    if isinstance(stored, dict):
        settings.update(stored)
    return settings


def save_settings(settings: dict) -> None:
    _write_private(config_dir() / "config.json", settings)


# --- input ------------------------------------------------------------------


def normalize_host(text: str) -> str:
    """Turn a pasted address such as ``https://PVE.lan:8006/#v1`` into ``pve.lan:8006``."""
    host = text.strip().lower().split("://", 1)[-1].split("/", 1)[0].split("#", 1)[0]
    if not host:
        return ""
    if host.startswith("["):
        return host if "]:" in host else f"{host}:{DEFAULT_PORT}"
    return host if ":" in host else f"{host}:{DEFAULT_PORT}"


def split_host(host: str) -> tuple[str, int]:
    name, _sep, port = host.rpartition(":")
    return name.strip("[]"), int(port)


def web_interface(host: str) -> str:
    return f"https://{host}/"


# --- keyring ----------------------------------------------------------------


def _keyring():
    try:
        import gi

        gi.require_version("Secret", "1")
        from gi.repository import Secret
    except (ImportError, ValueError):
        raise AuthError(
            _("No system keyring is available (libsecret is missing), so the secret cannot be stored safely.")
        ) from None
    attributes = {"host": Secret.SchemaAttributeType.STRING, "token": Secret.SchemaAttributeType.STRING}
    return Secret, Secret.Schema.new("dev.authswitch.Token", Secret.SchemaFlags.NONE, attributes)


def _keyring_call(action):
    from gi.repository import GLib

    try:
        return action()
    except GLib.Error as error:
        raise AuthError(_("The system keyring refused the request: {detail}").format(detail=error.message)) from None


def store_secret(host: str, token_id: str, secret: str) -> None:
    keyring, schema = _keyring()
    attributes = {"host": host, "token": token_id}
    label = f"Auth-Switch: {token_id} @ {host}"
    stored = _keyring_call(
        lambda: keyring.password_store_sync(schema, attributes, keyring.COLLECTION_DEFAULT, label, secret, None)
    )
    if not stored:
        raise AuthError(_("The secret could not be stored in the system keyring."))


def lookup_secret(host: str, token_id: str) -> str:
    keyring, schema = _keyring()
    return _keyring_call(lambda: keyring.password_lookup_sync(schema, {"host": host, "token": token_id}, None)) or ""


def clear_secret(host: str, token_id: str) -> None:
    keyring, schema = _keyring()
    _keyring_call(lambda: keyring.password_clear_sync(schema, {"host": host, "token": token_id}, None))


# --- TLS --------------------------------------------------------------------


def _format_fingerprint(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def certificate_trusted(host: str) -> bool:
    """Whether the system already trusts the server's certificate (e.g. one from Let's Encrypt)."""
    name, port = split_host(host)
    try:
        with socket.create_connection((name, port), timeout=8) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=name):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except OSError as error:
        raise AuthError(_("{host} cannot be reached: {detail}").format(host=host, detail=error)) from None


def server_fingerprint(host: str) -> str:
    """SHA-256 fingerprint of the certificate the server presents right now."""
    name, port = split_host(host)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((name, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=name) as tls:
                return _format_fingerprint(tls.getpeercert(binary_form=True))
    except OSError as error:
        raise AuthError(_("{host} cannot be reached: {detail}").format(host=host, detail=error)) from None


def pinned_fingerprint(host: str) -> str:
    return _load().get(host, {}).get("fingerprint", "")


class _Connection(http.client.HTTPSConnection):
    """HTTPS that checks a pinned fingerprint before a single byte of the request is sent."""

    def __init__(self, host: str, fingerprint: str):
        name, port = split_host(host)
        context = ssl.create_default_context()
        if fingerprint:
            # The pin replaces the CA check; it is verified in connect().
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        super().__init__(name, port, context=context, timeout=30)
        self.fingerprint = fingerprint

    def connect(self) -> None:
        super().connect()
        if self.fingerprint and _format_fingerprint(self.sock.getpeercert(binary_form=True)) != self.fingerprint:
            self.close()
            raise AuthError(
                _(
                    "The certificate of {host} is not the one you confirmed. Nothing was sent. If the server got a "
                    "new certificate, add the account again to confirm it."
                ).format(host=f"{self.host}:{self.port}")
            )


# --- API --------------------------------------------------------------------


def _encode(params: dict | None) -> str:
    def value(item: object) -> str:
        if isinstance(item, bool):
            return "1" if item else "0"
        if isinstance(item, (dict, list)):
            return json.dumps(item)
        return str(item)

    return urllib.parse.urlencode({key: value(item) for key, item in (params or {}).items() if item is not None})


def _check_path(path: str, method: str = "GET") -> None:
    segments = path.split("?", 1)[0].split("/")
    if not path.startswith("/") or path.startswith("//") or ".." in segments or any(c.isspace() for c in path):
        raise AuthError(_("The path must start with a single / and stay below /api2/json."))
    if _CREDENTIAL_PATH.search(path) or (method == "POST" and _TOKEN_PATH.search(path)):
        raise AuthError(_("Endpoints that issue tickets or credentials are not available here."))


def request(
    host: str,
    token_id: str,
    secret: str,
    method: str,
    path: str,
    params: dict | None = None,
    fingerprint: str | None = None,
) -> object:
    """Call ``/api2/json`` + ``path`` with an API token; returns the ``data`` member of the answer."""
    method = method.upper()
    if method not in API_METHODS:
        raise AuthError(_("Unsupported method: {method}").format(method=method))
    _check_path(path, method)
    query, body, target = _encode(params), None, "/api2/json" + path
    if method in ("POST", "PUT"):
        body, query = query.encode(), ""
    if query:
        target += ("&" if "?" in target else "?") + query
    headers = {
        "Authorization": f"PVEAPIToken={token_id}={secret}",
        "Accept": "application/json",
        "User-Agent": f"{APP}/{__version__}",
    }
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    connection = _Connection(host, pinned_fingerprint(host) if fingerprint is None else fingerprint)
    try:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        text = response.read().decode("utf-8", "replace")
    except ssl.SSLCertVerificationError:
        message = _("The certificate of {host} is not trusted; add the account again to confirm it.")
        raise AuthError(message.format(host=host)) from None
    except (OSError, http.client.HTTPException) as error:
        raise AuthError(_("{host} cannot be reached: {detail}").format(host=host, detail=error)) from None
    finally:
        connection.close()
    if response.status != 200:
        raise AuthError(f"HTTP {response.status} {response.reason}: {text[:300].strip()}".rstrip(": "))
    try:
        return json.loads(text).get("data")
    except (ValueError, AttributeError):
        return text


def validate(host: str, token_id: str, secret: str, fingerprint: str | None = None) -> Profile:
    try:
        data = request(host, token_id, secret, "GET", "/version", fingerprint=fingerprint)
    except AuthError as error:
        message = str(error)
        return Profile(valid=False if message.startswith("HTTP 401") else None, detail=message)
    version = data.get("version", "") if isinstance(data, dict) else ""
    return Profile(valid=True, version=str(version))


def fetch_profile(account: Account) -> Profile:
    try:
        secret = lookup_secret(account.host, account.token_id)
    except AuthError as error:
        return Profile(valid=None, detail=str(error))
    if not secret:
        return Profile(valid=False)
    return validate(account.host, account.token_id, secret)


# --- actions ----------------------------------------------------------------


def add_account(host: str, token_id: str, secret: str, fingerprint: str = "") -> Account:
    """Check the token against the server, file the secret in the keyring and activate the account."""
    host, token_id, secret = normalize_host(host), token_id.strip(), secret.strip()
    if not TOKEN_ID.fullmatch(token_id):
        raise AuthError(_("The token ID must look like user@realm!name, for example root@pam!auth-switch."))
    profile = validate(host, token_id, secret, fingerprint)
    if profile.valid is False:
        raise AuthError(_("{host} rejected the token.").format(host=host))
    if not profile.valid:
        raise AuthError(profile.detail or _("{host} did not answer like a Proxmox VE server.").format(host=host))
    store_secret(host, token_id, secret)
    hosts = _load()
    entry = hosts.setdefault(host, {"tokens": [], "active": "", "fingerprint": "", "repository": ""})
    if token_id not in entry["tokens"]:
        entry["tokens"].append(token_id)
    entry["active"], entry["fingerprint"] = token_id, fingerprint
    _write_private(accounts_file(), hosts)
    return Account(host, token_id, True)


def _on_host(account: Account, host: str | None) -> bool:
    return not host or account.host in (host, normalize_host(host))


def find_account(token_or_user: str, host: str | None = None) -> Account:
    """Resolve a token ID, or a user that has exactly one token, to a known account."""
    wanted = token_or_user.strip().lower()
    candidates = [account for account in list_accounts() if _on_host(account, host)]
    matches = [a for a in candidates if a.token_id.lower() == wanted] or [
        a for a in candidates if a.user.lower() == wanted
    ]
    if not matches:
        known = ", ".join(f"{a.token_id} @ {a.host}" for a in list_accounts()) or _("none")
        raise AuthError(_("No account '{user}'. Known accounts: {known}").format(user=token_or_user, known=known))
    if len(matches) > 1:
        raise AuthError(_("'{user}' is ambiguous; pass the full token ID and a hostname.").format(user=token_or_user))
    return matches[0]


def switch_account(token_or_user: str, host: str | None = None) -> dict:
    account = find_account(token_or_user, host)
    hosts = _load()
    hosts[account.host]["active"] = account.token_id
    _write_private(accounts_file(), hosts)
    return {"host": account.host, "token_id": account.token_id}


def remove_account(account: Account) -> None:
    clear_secret(account.host, account.token_id)
    hosts = _load()
    entry = hosts.get(account.host)
    if not entry:
        return
    entry["tokens"] = [token for token in entry["tokens"] if token != account.token_id]
    if not entry["tokens"]:
        del hosts[account.host]
    elif entry["active"] == account.token_id:
        entry["active"] = entry["tokens"][0]
    _write_private(accounts_file(), hosts)


def active_account(host: str | None = None) -> Account:
    active = [account for account in list_accounts() if account.active and _on_host(account, host)]
    if not active:
        raise AuthError(_("No Proxmox VE account is set up for this server."))
    if len(active) > 1:
        raise AuthError(_("Several Proxmox VE servers are known; pass a hostname."))
    return active[0]


def _active_secret(account: Account) -> str:
    secret = lookup_secret(account.host, account.token_id)
    if not secret:
        message = _("No secret for {token} in the system keyring; add the account again.")
        raise AuthError(message.format(token=account.token_id))
    return secret


def api(method: str, path: str, params: dict | None = None, host: str | None = None) -> object:
    """Call the API of a server as its active account."""
    account = active_account(host)
    return request(account.host, account.token_id, _active_secret(account), method, path, params)


# --- token permissions ------------------------------------------------------

def permission_roles() -> list[tuple[str, str, str]]:
    """Built-in Proxmox VE roles offered as switches: (role, title, what it allows)."""
    return [
        ("PVEAuditor", _("Read everything"), _("See guests, nodes, storage and settings without changing them")),
        ("PVEVMUser", _("Use guests"), _("Start, stop, open the console and back up virtual machines and containers")),
        ("PVEVMAdmin", _("Manage guests"), _("Create, configure, migrate and delete virtual machines and containers")),
        ("PVEDatastoreAdmin", _("Manage storage"), _("Add storage, upload images and manage backups")),
        ("PVEPoolAdmin", _("Manage pools"), _("Create resource pools and assign guests to them")),
        ("PVEUserAdmin", _("Manage accounts"), _("Create, change and delete users, groups and their API tokens")),
        ("PVESDNAdmin", _("Manage networks"), _("Configure software-defined networks (SDN)")),
        ("PVESysAdmin", _("Administer nodes"), _("Node settings, network, updates and services")),
        ("Administrator", _("Full access"), _("Everything, including changing permissions")),
    ]


def _token_path(token_id: str) -> str:
    user, name = token_id.split("!", 1)
    return f"/access/users/{urllib.parse.quote(user, safe='@')}/token/{urllib.parse.quote(name)}"


def token_permissions(host: str, token_id: str, manager: Account) -> dict:
    """Roles the token holds on "/" and whether it is privilege-separated, as seen by ``manager``."""
    secret = _active_secret(manager)
    info = request(host, manager.token_id, secret, "GET", _token_path(token_id))
    acl = request(host, manager.token_id, secret, "GET", "/access/acl")
    roles = {
        entry.get("roleid")
        for entry in acl or []
        if entry.get("type") == "token" and entry.get("ugid") == token_id and entry.get("path") == "/"
    }
    return {"privsep": bool(int((info or {}).get("privsep", 1))), "roles": roles}


def set_token_roles(host: str, token_id: str, add: set[str], remove: set[str], manager: Account) -> None:
    """Grant and revoke roles on "/" for the token, using ``manager``'s rights to do so."""
    secret = _active_secret(manager)
    for roles, delete in ((add, False), (remove, True)):
        if roles:
            params = {"path": "/", "roles": ",".join(sorted(roles)), "tokens": token_id, "propagate": True}
            if delete:
                params["delete"] = True
            request(host, manager.token_id, secret, "PUT", "/access/acl", params)


# --- access to single resources ---------------------------------------------

NO_ACCESS = "NoAccess"


def managers_for(host: str, token_id: str) -> list[Account]:
    """Accounts of ``host`` that may change rights, best first: another account than the token, active first."""
    candidates = [account for account in list_accounts() if account.host == host]
    return sorted(candidates, key=lambda a: (a.token_id == token_id, not a.active))


def list_resources(host: str, manager: Account) -> list[dict]:
    """Guests, storages and nodes of the cluster with the ACL path that controls access to them."""
    data = request(host, manager.token_id, _active_secret(manager), "GET", "/cluster/resources") or []
    found: dict[str, dict] = {}
    for item in data:
        kind = item.get("type")
        if kind in ("qemu", "lxc") and item.get("vmid") is not None:
            path, label = f"/vms/{item['vmid']}", f"{item['vmid']} · {item.get('name') or ''}".rstrip(" ·")
        elif kind == "storage" and item.get("storage"):
            path, label = f"/storage/{item['storage']}", str(item["storage"])
        elif kind == "node" and item.get("node"):
            path, label = f"/nodes/{item['node']}", str(item["node"])
        else:
            continue
        # Storages are listed once per node but share one ACL path.
        found.setdefault(path, {"path": path, "kind": kind, "label": label, "node": item.get("node", "")})
    order = {"qemu": 0, "lxc": 0, "storage": 1, "node": 2}
    return sorted(found.values(), key=lambda r: (order[r["kind"]], r["path"]))


def denied_paths(host: str, token_id: str, manager: Account) -> set[str]:
    acl = request(host, manager.token_id, _active_secret(manager), "GET", "/access/acl") or []
    return {
        entry.get("path")
        for entry in acl
        if entry.get("type") == "token" and entry.get("ugid") == token_id and entry.get("roleid") == NO_ACCESS
    }


def set_denied(host: str, token_id: str, path: str, denied: bool, manager: Account) -> None:
    """Deny the token access to ``path`` with the NoAccess role, which overrides rights inherited from above."""
    params = {"path": path, "roles": NO_ACCESS, "tokens": token_id, "propagate": True}
    if not denied:
        params["delete"] = True
    request(host, manager.token_id, _active_secret(manager), "PUT", "/access/acl", params)


# --- subscription and package repositories ---------------------------------

ENTERPRISE, NO_SUBSCRIPTION, NEEDS_SETUP = "enterprise", "no-subscription", "needs-setup"


def stored_repository(host: str) -> str:
    return _load().get(host, {}).get("repository", "")


def _store_repository(host: str, state: str) -> None:
    hosts = _load()
    if host in hosts:
        hosts[host]["repository"] = state
        _write_private(accounts_file(), hosts)


def _enterprise_entries(state: dict) -> list[tuple[str, int, dict]]:
    """Enabled repositories that point at the paid enterprise mirror, as (file, index, entry)."""
    found = []
    for file in state.get("files") or []:
        for index, entry in enumerate(file.get("repositories") or []):
            if entry.get("Enabled") and any("enterprise.proxmox.com" in uri for uri in entry.get("URIs") or []):
                found.append((file.get("path", ""), index, entry))
    return found


def _standard(state: dict, handle: str) -> dict:
    return next((repo for repo in state.get("standard-repos") or [] if repo.get("handle") == handle), {})


def inspect_server(host: str, manager: Account) -> dict:
    """Subscription and repository state of every node, read with ``manager``'s rights."""
    secret = _active_secret(manager)
    nodes = {}
    for node in request(host, manager.token_id, secret, "GET", "/nodes") or []:
        name = node.get("node")
        if not name or node.get("status") not in (None, "online"):
            continue
        subscription = request(host, manager.token_id, secret, "GET", f"/nodes/{name}/subscription") or {}
        repositories = request(host, manager.token_id, secret, "GET", f"/nodes/{name}/apt/repositories") or {}
        nodes[name] = {
            "subscribed": subscription.get("status") == "active",
            "enterprise_enabled": bool(_enterprise_entries(repositories)),
            "no_subscription_enabled": _standard(repositories, "no-subscription").get("status") == 1,
        }
    if not nodes:
        raise AuthError(_("No node of {host} could be read.").format(host=host))
    if all(node["subscribed"] for node in nodes.values()):
        state = ENTERPRISE
    elif all(node["subscribed"] or (node["no_subscription_enabled"] and not node["enterprise_enabled"]) for node in nodes.values()):
        state = NO_SUBSCRIPTION
    else:
        state = NEEDS_SETUP
    _store_repository(host, state)
    return {"state": state, "nodes": nodes}


def use_no_subscription_repository(host: str, manager: Account) -> list[str]:
    """On every node without a subscription: enable the no-subscription repositories, disable the enterprise ones.

    Goes through the API (``/nodes/NODE/apt/repositories``), so it works for the
    old ``.list`` and the new ``.sources`` format alike and covers Ceph.
    """
    secret = _active_secret(manager)
    changed = []
    for name, node in inspect_server(host, manager)["nodes"].items():
        if node["subscribed"]:
            continue
        path = f"/nodes/{name}/apt/repositories"
        state = request(host, manager.token_id, secret, "GET", path) or {}
        enterprise = _enterprise_entries(state)
        wanted = {"no-subscription"}
        if any("/ceph" in uri for _file, _index, entry in enterprise for uri in entry.get("URIs") or []):
            wanted |= {r["handle"] for r in state.get("standard-repos") or [] if str(r.get("handle", "")).startswith("ceph-") and r["handle"].endswith("-no-subscription")}
        for handle in sorted(wanted):
            if _standard(state, handle).get("status") != 1:
                request(host, manager.token_id, secret, "PUT", path, {"handle": handle})
                changed.append(f"{name}: + {handle}")
        for file, index, entry in enterprise:
            request(host, manager.token_id, secret, "POST", path, {"path": file, "index": index, "enabled": False})
            changed.append(f"{name}: - {' '.join(entry.get('Components') or [])} ({file})")
    inspect_server(host, manager)
    return changed


# Hides the "No valid subscription" notice and keeps it hidden after updates of
# proxmox-widget-toolkit through an APT hook. Runs as root on the node.
NOTICE_FIX_SCRIPT = r"""set -e
cat > /usr/local/sbin/pve-subscription-notice-hook <<'HOOK'
#!/bin/sh
# Installed by Auth-Switch: hides the "No valid subscription" notice of the web interface.
# Remove this file and /etc/apt/apt.conf.d/99-pve-subscription-notice to undo it.
f=/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js
[ -f "$f" ] || exit 0
grep -q "No valid sub" "$f" || exit 0
# Only the check in checked_command is changed, so the action behind the notice still runs.
grep -Ezq "!res \|\|\s*res\s*\.data\.status\.toLowerCase\(\) !== 'active'" "$f" || exit 0
cp "$f" "$f.auth-switch.orig"
sed -Ezi "s/(!res \|\|\s*)res\s*\.data\.status\.toLowerCase\(\) !== 'active'/\1false/" "$f"
systemctl restart pveproxy.service || true
exit 0
HOOK
chmod 0755 /usr/local/sbin/pve-subscription-notice-hook
echo 'DPkg::Post-Invoke { "/usr/local/sbin/pve-subscription-notice-hook || true"; };' > /etc/apt/apt.conf.d/99-pve-subscription-notice
/usr/local/sbin/pve-subscription-notice-hook
echo "auth-switch: subscription notice removed on $(hostname)"
"""


def notice_fix_command() -> str:
    """One line to paste into a root shell of the node."""
    import base64

    encoded = base64.b64encode(NOTICE_FIX_SCRIPT.encode()).decode()
    return f"echo {encoded} | base64 -d | sh"


def node_shell_url(host: str, node: str) -> str:
    return f"https://{host}/?console=shell&xtermjs=1&vmid=0&vmname=&node={urllib.parse.quote(node)}&cmd="


def remove_notice_via_ssh(host: str) -> str:
    """Run the fix as root over SSH with the user's own keys; never asks for or stores a password."""
    if not shutil.which("ssh"):
        raise AuthError(_("ssh is not installed."))
    name = split_host(host)[0]
    try:
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", f"root@{name}", "sh", "-s"],
            input=NOTICE_FIX_SCRIPT, capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise AuthError(_("SSH to {host} timed out.").format(host=name)) from None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [""]
        raise AuthError(_("SSH as root@{host} failed: {detail}").format(host=name, detail=detail[0]))
    return proc.stdout.strip()


def describe_accounts(check: bool = True) -> list[dict]:
    """Plain-data view of all accounts; never includes a secret."""
    described = []
    for account in list_accounts():
        entry = {
            "host": account.host,
            "token_id": account.token_id,
            "active": account.active,
            "pinned_certificate": bool(pinned_fingerprint(account.host)),
            "repository": stored_repository(account.host),
        }
        if check:
            profile = fetch_profile(account)
            entry.update(token_valid=profile.valid, version=profile.version)
        described.append(entry)
    return described


def environment(host: str | None = None) -> dict[str, str]:
    """Variables that hand the active account to common Proxmox tools (Terraform providers, Ansible)."""
    account = active_account(host)
    secret = _active_secret(account)
    name, port = split_host(account.host)
    return {
        "PROXMOX_VE_ENDPOINT": f"https://{account.host}/",
        "PROXMOX_VE_API_TOKEN": f"{account.token_id}={secret}",
        "PM_API_URL": f"https://{account.host}/api2/json",
        "PM_API_TOKEN_ID": account.token_id,
        "PM_API_TOKEN_SECRET": secret,
        "PROXMOX_HOST": name,
        "PROXMOX_PORT": str(port),
        "PROXMOX_USER": account.user,
        "PROXMOX_TOKEN_ID": account.token_id.split("!", 1)[1],
        "PROXMOX_TOKEN_SECRET": secret,
    }


def get_git_email() -> str:
    try:
        return subprocess.run(
            ["git", "config", "--global", "--get", "user.email"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# --- MCP clients ------------------------------------------------------------

MCP_NAME = APP


def mcp_command() -> list[str]:
    script = shutil.which("auth-switch-mcp")
    return [script] if script else [sys.executable, "-m", "authswitch.mcp"]


def mcp_client_config() -> str:
    """The ``mcpServers`` entry most MCP clients accept in their configuration file."""
    command = mcp_command()
    entry = {"type": "stdio", "command": command[0], "args": command[1:]}
    return json.dumps({"mcpServers": {MCP_NAME: entry}}, indent=2)
