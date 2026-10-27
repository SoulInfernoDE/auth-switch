"""SSH access as root for the user's own terminal, switched on and off per server.

The key pair is made for one server only. Its private key is kept in the
system keyring; while access is on, a copy sits in ``~/.ssh/auth-switch/`` and
an entry in an included SSH config makes ``ssh <alias>`` work. Switching off
deletes that copy and the entry, so ssh can no longer use the key, while the
keyring keeps it and the server still trusts it – switching on again needs
nothing else. Removing it completely also takes it off the server.

The server's host key is read through the root console over the HTTPS
connection the user already confirmed, so it is trusted without a blind
"yes". The MCP server has no tool for any of this.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import core, rootshell
from .i18n import _

MARKER = "auth-switch"


def _ssh_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".ssh"


def _own_dir() -> Path:
    return _ssh_dir() / "auth-switch"


def _key_file(host: str) -> Path:
    return _own_dir() / re.sub(r"[^\w.-]", "_", host)


def _include_file() -> Path:
    return _own_dir() / "config"


def _keyring():
    secret, _schema = core._keyring()
    attributes = {"host": secret.SchemaAttributeType.STRING}
    return secret, secret.Schema.new("dev.authswitch.SshKey", secret.SchemaFlags.NONE, attributes)


def _store_key(host: str, private: str) -> None:
    secret, schema = _keyring()
    label = f"Auth-Switch SSH: root @ {host}"
    if not core._keyring_call(lambda: secret.password_store_sync(schema, {"host": host}, secret.COLLECTION_DEFAULT, label, private, None)):
        raise core.AuthError(_("The secret could not be stored in the system keyring."))


def _lookup_key(host: str) -> str:
    secret, schema = _keyring()
    return core._keyring_call(lambda: secret.password_lookup_sync(schema, {"host": host}, None)) or ""


def _clear_key(host: str) -> None:
    secret, schema = _keyring()
    core._keyring_call(lambda: secret.password_clear_sync(schema, {"host": host}, None))


def _state(host: str) -> dict:
    return core._load().get(host, {}).get("ssh") or {}


def _store_state(host: str, state: dict | None) -> None:
    hosts = core._load()
    if host in hosts:
        if state is None:
            hosts[host].pop("ssh", None)
        else:
            hosts[host]["ssh"] = state
        core._write_private(core.accounts_file(), hosts)


def status(host: str) -> dict:
    """``{"set_up": bool, "enabled": bool, "alias": str}`` for the window."""
    state = _state(host)
    return {
        "set_up": bool(state.get("public")),
        "enabled": bool(state.get("enabled")) and _key_file(host).exists(),
        "alias": state.get("alias", ""),
    }


def _generate(host: str) -> tuple[str, str]:
    """A new ed25519 key pair without passphrase; the files only exist inside a private temporary folder."""
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder, "key")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{MARKER}@{host}", "-f", str(path)],
            check=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30,
        )
        return path.read_text(), Path(folder, "key.pub").read_text().strip()


def install_script(public: str) -> str:
    """Root script: trust the public key and print the server's host keys."""
    return (
        "set -e\n"
        "install -d -m 700 /root/.ssh\n"
        "touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys\n"
        f"grep -qxF '{public}' /root/.ssh/authorized_keys || echo '{public}' >> /root/.ssh/authorized_keys\n"
        "for key in /etc/ssh/ssh_host_*_key.pub; do echo \"HOSTKEY $(cut -d' ' -f1,2 \"$key\")\"; done\n"
    )


def _remember_host_keys(name: str, output: str) -> None:
    keys = re.findall(r"HOSTKEY (ssh-[\w-]+|ecdsa-[\w-]+) ([A-Za-z0-9+/=]+)", output)
    if not keys:
        raise core.AuthError(_("The server did not report its SSH host key."))
    known = _ssh_dir() / "known_hosts"
    _ssh_dir().mkdir(mode=0o700, exist_ok=True)
    subprocess.run(["ssh-keygen", "-R", name, "-f", str(known)], capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    with open(known, "a", encoding="utf-8") as handle:
        for kind, key in keys:
            handle.write(f"{name} {kind} {key}\n")
    known.chmod(0o600)


def _write_include() -> None:
    """The included config lists every server with access switched on; ~/.ssh/config gets one Include line."""
    entries = []
    for host, entry in core._load().items():
        state = entry.get("ssh") or {}
        if state.get("enabled") and _key_file(host).exists():
            entries.append(
                f"Host {state['alias']}\n    HostName {core.split_host(host)[0]}\n    User root\n"
                f"    IdentityFile {_key_file(host)}\n    IdentitiesOnly yes\n"
            )
    _own_dir().mkdir(mode=0o700, parents=True, exist_ok=True)
    _include_file().write_text("# Written by Auth-Switch; changes are overwritten.\n" + "\n".join(entries))
    _include_file().chmod(0o600)
    config = _ssh_dir() / "config"
    line = f"Include {_include_file()}"
    current = config.read_text() if config.exists() else ""
    if line not in current:
        # Include only applies everywhere when it comes before the first Host block.
        config.write_text(line + "\n\n" + current)
        config.chmod(0o600)


def set_up(host: str, node: str, alias: str, password: str, code: str = "") -> None:
    """Create the key, trust it on the server through the root console and switch access on."""
    if not shutil.which("ssh-keygen"):
        raise core.AuthError(_("ssh is not installed."))
    private, public = _generate(host)
    session = rootshell.sign_in(host, "root@pam", password, code)
    try:
        exit_status, output = rootshell.run_script(host, node, session, install_script(public), timeout=120)
    finally:
        session.clear()
    if exit_status != 0:
        raise core.AuthError(_("The fix failed on {node}: {detail}").format(node=node, detail=output.strip()[-200:]))
    _remember_host_keys(core.split_host(host)[0], output)
    _store_key(host, private)
    _store_state(host, {"public": public, "alias": alias, "enabled": False})
    enable(host)


def enable(host: str) -> None:
    private = _lookup_key(host)
    if not private:
        raise core.AuthError(_("The SSH key is no longer in the system keyring; set up access again."))
    _own_dir().mkdir(mode=0o700, parents=True, exist_ok=True)
    path = _key_file(host)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(private)
    _store_state(host, {**_state(host), "enabled": True})
    _write_include()


def disable(host: str) -> None:
    _key_file(host).unlink(missing_ok=True)
    if _state(host):
        _store_state(host, {**_state(host), "enabled": False})
    _write_include()


def remove(host: str) -> None:
    """Take the key off the server (over SSH with the key itself), then forget it here."""
    state = _state(host)
    public = state.get("public", "")
    if public:
        if not _key_file(host).exists():
            enable(host)
        key_body = public.split()[1]
        script = f"sed -i '\\#{key_body}#d' /root/.ssh/authorized_keys\n"
        try:
            subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-i", str(_key_file(host)), "-o", "IdentitiesOnly=yes",
                 f"root@{core.split_host(host)[0]}", "sh", "-s"],
                input=script, capture_output=True, text=True, timeout=60, check=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            detail = getattr(error, "stderr", "") or str(error)
            raise core.AuthError(_("The key could not be removed from the server: {detail}").format(detail=detail.strip()[-200:])) from None
    disable(host)
    _clear_key(host)
    _store_state(host, None)
