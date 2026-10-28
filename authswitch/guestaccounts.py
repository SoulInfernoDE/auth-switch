"""User accounts inside guests: list them, change a password, rename one without leaving the old name behind.

Virtual machines are reached through the QEMU guest agent, containers through
``pct exec`` over the SSH access of "SSH for my terminal". Passwords never
appear on a command line inside the guest: VMs use the agent's own
set-user-password call, containers get the password on standard input.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import time

from . import core
from .i18n import _

WINDOWS, LINUX = "windows", "linux"
# Windows allows at most 20 characters; the same set is safe for Linux and for embedding in scripts.
NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,19}")


class Guest:
    """One VM or container of a server, as the active account sees it."""

    def __init__(self, host: str, node: str, kind: str, vmid: int, manager: core.Account):
        self.host, self.node, self.kind, self.vmid, self.manager = host, node, kind, int(vmid), manager
        self.base = f"/nodes/{node}/{kind}/{vmid}"

    def _api(self, method: str, path: str, params: dict | None = None):
        secret = core._active_secret(self.manager)
        return core.request(self.host, self.manager.token_id, secret, method, self.base + path, params)

    # --- running commands ---------------------------------------------------

    def run(self, command: list[str], stdin: str | None = None, timeout: float = 300) -> tuple[int, str]:
        if self.kind == "lxc":
            return self._run_in_container(command, stdin, timeout)
        params = {"command": command}
        if stdin is not None:
            params["input-data"] = stdin
        try:
            pid = self._api("POST", "/agent/exec", params)["pid"]
        except core.AuthError as error:
            raise core.AuthError(_("The guest agent does not answer; is the VM running with the agent installed?") + f"\n\n{error}") from None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                status = self._api("GET", "/agent/exec-status", {"pid": pid})
            except core.AuthError as error:
                # A busy guest sometimes answers the status call late; that is no reason to give up.
                if "timeout" not in str(error):
                    raise
                time.sleep(2)
                continue
            if status.get("exited"):
                return int(status.get("exitcode", 1)), status.get("out-data", "") + status.get("err-data", "")
            time.sleep(1)
        raise core.AuthError(_("The command in the guest did not finish in time."))

    def _run_in_container(self, command: list[str], stdin: str | None, timeout: float) -> tuple[int, str]:
        from . import sshaccess

        if not sshaccess.status(self.host)["enabled"]:
            raise core.AuthError(_("Containers are reached over SSH; switch on \"SSH for my terminal\" for this server first."))
        ssh = core.ssh_command(self.host) + ["pct", "exec", str(self.vmid), "--", *command]
        try:
            proc = subprocess.run(ssh, input=stdin, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise core.AuthError(_("The command in the guest did not finish in time.")) from None
        return proc.returncode, proc.stdout + proc.stderr

    def system(self) -> str:
        if self.kind == "lxc":
            return LINUX
        try:
            info = self._api("GET", "/agent/get-osinfo").get("result", {})
        except core.AuthError as error:
            raise core.AuthError(_("The guest agent does not answer; is the VM running with the agent installed?") + f"\n\n{error}") from None
        return WINDOWS if info.get("id") == "mswindows" else LINUX

    # --- accounts -----------------------------------------------------------

    def users(self) -> list[dict]:
        """Accounts people sign in with: enabled local Windows users, or root and regular Linux users."""
        if self.system() == WINDOWS:
            script = (
                "Get-LocalUser | Where-Object Enabled | Select-Object Name,FullName,"
                "@{n='Sid';e={$_.SID.Value}} | ConvertTo-Json -Compress"
            )
            status, output = self.run(["powershell.exe", "-NoProfile", "-Command", script])
            data = json.loads(output or "[]") if status == 0 else []
            users = [data] if isinstance(data, dict) else data
            return [{"name": u["Name"], "fullname": u.get("FullName") or ""} for u in users]
        status, output = self.run(["getent", "passwd"])
        users = []
        for line in output.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            uid, shell = int(parts[2]) if parts[2].isdigit() else -1, parts[6]
            if (uid == 0 or 1000 <= uid < 65534) and not shell.endswith(("nologin", "false")):
                users.append({"name": parts[0], "fullname": parts[4].split(",")[0]})
        return users

    def set_password(self, user: str, password: str) -> None:
        if not NAME.fullmatch(user):
            raise core.AuthError(_("This user name cannot be handled here."))
        if self.kind == "qemu":
            self._api("POST", "/agent/set-user-password", {"username": user, "password": password})
            return
        status, output = self.run(["chpasswd"], stdin=f"{user}:{password}\n", timeout=60)
        if status != 0:
            raise core.AuthError(_("The password could not be changed: {detail}").format(detail=output.strip()[-200:]))

    def rename(self, old: str, new: str, preview: bool) -> str:
        """Rename ``old`` to ``new``; with ``preview`` only report what would change and where the name remains."""
        for name in (old, new):
            if not NAME.fullmatch(name):
                raise core.AuthError(_("Names may contain letters, digits, dot, dash and underscore, at most 20 characters."))
        if self.system() == WINDOWS:
            script = windows_rename_script(old, new, preview)
            encoded = base64.b64encode(script.encode("utf-16-le")).decode()
            status, output = self.run(["powershell.exe", "-NoProfile", "-EncodedCommand", encoded], timeout=600)
        else:
            status, output = self.run(["sh", "-s"], stdin=linux_rename_script(old, new, preview), timeout=600)
        report = describe(output)
        if status != 0:
            raise core.AuthError(report or output.strip()[-600:] or _("The rename failed."))
        return report


def describe(output: str) -> str:
    """Turn the tagged lines of the guest scripts into translated text."""
    texts = {
        "ACCOUNT": _("Account: {0} → {1}"),
        "DISPLAY": _("Display name: {0} → {1}"),
        "PROFILE": _("Profile folder: {0} → {1}"),
        "GROUP": _("Group: {0} → {1}"),
        "HIVE": _("Paths in {0}: {1}"),
        "SYSTEM": _("Paths elsewhere in the system registry: {0}"),
        "FILE": _("Entry in {0}"),
        "CRON": _("Scheduled jobs (crontab) move along"),
        "MAIL": _("Mailbox moves along"),
        "UNCHANGED": _("Left unchanged because the check failed: {0}"),
        "LEFTCOUNT": _("Places still naming the old name: {0}"),
        "LEFT": "  {0}",
    }
    errors = {
        "exists": _("An account named {0} already exists."),
        "signedin": _("{0} is signed in. Sign the account out first, then rename it."),
        "folder": _("The folder {0} already exists."),
        "missing": _("There is no account {0}."),
    }
    lines = []
    for raw in output.splitlines():
        parts = raw.rstrip("\r").split("\t")
        if parts[0] == "ERROR" and len(parts) >= 3:
            lines.append(errors.get(parts[1], parts[1]).format(*parts[2:]))
        elif parts[0] in texts:
            lines.append(texts[parts[0]].format(*parts[1:]))
    return "\n".join(lines)


def windows_rename_script(old: str, new: str, preview: bool) -> str:
    """PowerShell: account, display name, profile folder and its path inside the user's registry hives."""
    return r"""$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
$old = '__OLD__'; $new = '__NEW__'; $preview = __PREVIEW__
$user = Get-LocalUser -Name $old
if (Get-LocalUser -Name $new -ErrorAction SilentlyContinue) { "ERROR`texists`t$new"; exit 3 }
$sid = $user.SID.Value
$key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
$profile = if (Test-Path $key) { (Get-ItemProperty $key).ProfileImagePath } else { $null }
$newProfile = if ($profile) { Join-Path (Split-Path $profile) $new } else { $null }
$sessions = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User }) -contains $old
if ($sessions -and -not $preview) { "ERROR`tsignedin`t$old"; exit 3 }
if ($newProfile -and (Test-Path $newProfile)) { "ERROR`tfolder`t$newProfile"; exit 3 }

function Replace-InHive($root, $from, $to, $apply, $recurse = $true) {
    $count = 0
    $items = @(Get-Item $root)
    if ($recurse) { $items += @(Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue) }
    foreach ($item in $items) {
        foreach ($name in $item.GetValueNames()) {
            $kind = $item.GetValueKind($name)
            if ($kind -notin 'String', 'ExpandString', 'MultiString') { continue }
            $value = $item.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
            $text = if ($kind -eq 'MultiString') { $value -join "`n" } else { [string]$value }
            if ($text -notlike "*$from*") { continue }
            $count++
            if ($apply) {
                $replaced = [regex]::Replace($text, [regex]::Escape($from), $to.Replace('$', '$$'), 'IgnoreCase')
                $writable = (Get-Item $item.PSPath).OpenSubKey('', $true)
                if ($kind -eq 'MultiString') { $writable.SetValue($name, [string[]]($replaced -split "`n"), $kind) }
                else { $writable.SetValue($name, $replaced, $kind) }
                $writable.Close()
            }
        }
    }
    return $count
}

$report = @()
$report += "ACCOUNT`t$old`t$new"
if ($user.FullName) { $report += "DISPLAY`t$($user.FullName)`t$new" }
if ($profile) {
    $report += "PROFILE`t$profile`t$newProfile"
    $hives = @(@('NTUSER.DAT', 'AS_RENAME_USER'), @('AppData\Local\Microsoft\Windows\UsrClass.dat', 'AS_RENAME_CLASSES'))
    foreach ($hive in $hives) {
        $file = Join-Path $profile $hive[0]
        if (-not (Test-Path $file) -or $sessions) { continue }
        reg.exe load "HKU\$($hive[1])" $file | Out-Null
        try { $n = Replace-InHive "Registry::HKEY_USERS\$($hive[1])" $profile $newProfile (-not $preview) }
        finally { [gc]::Collect(); Start-Sleep -Milliseconds 300; reg.exe unload "HKU\$($hive[1])" | Out-Null }
        $report += "HIVE`t$($hive[0])`t$n"
    }
}
function Find-SystemKeys($text) {
    # Through cmd, so access-denied notes of protected keys stay out of the report.
    @(cmd.exe /c "reg query HKLM\SOFTWARE /f `"$text`" /s /d 2>nul" | Select-String -SimpleMatch 'HKEY_' | ForEach-Object { $_.Line.Trim() })
}
$systemKeys = if ($profile) { Find-SystemKeys $profile } else { @() }
$report += "SYSTEM`t$($systemKeys.Count)"
if (-not $preview) {
    if ($profile) {
        Rename-Item -LiteralPath $profile -NewName $new
        foreach ($systemKey in $systemKeys) { $null = Replace-InHive "Registry::$systemKey" $profile $newProfile $true $false }
        Set-ItemProperty $key -Name ProfileImagePath -Value $newProfile
    }
    Rename-LocalUser -Name $old -NewName $new
    if ($user.FullName) { Set-LocalUser -Name $new -FullName $new }
}
$left = @()
if ($profile -and -not $preview) { $left += @(Find-SystemKeys $profile | Select-Object -First 10) }
if (-not $preview) { $report += "LEFTCOUNT`t$($left.Count)" }
$report += @($left | ForEach-Object { "LEFT`t$_" })
$report -join "`n"
""".replace("__OLD__", old).replace("__NEW__", new).replace("__PREVIEW__", "$true" if preview else "$false")


def linux_rename_script(old: str, new: str, preview: bool) -> str:
    """sh: account, primary group, home, display name, crontab, mail, subordinate ids and sudo rules."""
    return r"""set -e
old='__OLD__'; new='__NEW__'; preview=__PREVIEW__
getent passwd "$old" >/dev/null || { printf 'ERROR\tmissing\t%s\n' "$old"; exit 3; }
if getent passwd "$new" >/dev/null; then printf 'ERROR\texists\t%s\n' "$new"; exit 3; fi
home=$(getent passwd "$old" | cut -d: -f6)
newhome=$(dirname "$home")/$new
printf 'ACCOUNT\t%s\t%s\n' "$old" "$new"
[ "$home" = "$(dirname "$home")/$old" ] && printf 'PROFILE\t%s\t%s\n' "$home" "$newhome" || newhome=$home
getent group "$old" >/dev/null && printf 'GROUP\t%s\t%s\n' "$old" "$new"
files=$(grep -rlw -- "$old" /etc/sudoers /etc/sudoers.d /etc/subuid /etc/subgid 2>/dev/null || true)
for f in $files; do printf 'FILE\t%s\n' "$f"; done
[ -e "/var/spool/cron/crontabs/$old" ] && printf 'CRON\n'
[ -e "/var/mail/$old" ] && printf 'MAIL\n'
if [ "$preview" = 0 ]; then
    if pgrep -u "$old" >/dev/null 2>&1; then printf 'ERROR\tsignedin\t%s\n' "$old"; exit 3; fi
    if [ "$newhome" != "$home" ]; then usermod -l "$new" -d "$newhome" -m -c "$new" "$old"
    else usermod -l "$new" -c "$new" "$old"; fi
    getent group "$old" >/dev/null && groupmod -n "$new" "$old"
    for f in /etc/subuid /etc/subgid; do [ -f "$f" ] && sed -i "s/^$old:/$new:/" "$f"; done
    for f in /etc/sudoers $(ls /etc/sudoers.d/* 2>/dev/null); do
        if grep -qw -- "$old" "$f" 2>/dev/null; then cp -p "$f" "$f.as-tmp"; sed -i "s/\b$old\b/$new/g" "$f.as-tmp"
            if visudo -cf "$f.as-tmp" >/dev/null 2>&1; then mv "$f.as-tmp" "$f"; else rm -f "$f.as-tmp"; printf 'UNCHANGED\t%s\n' "$f"; fi
        fi
    done
    [ -e "/var/spool/cron/crontabs/$old" ] && mv "/var/spool/cron/crontabs/$old" "/var/spool/cron/crontabs/$new"
    [ -e "/var/mail/$old" ] && mv "/var/mail/$old" "/var/mail/$new"
fi
left=$(grep -rlIw -- "$old" /etc 2>/dev/null | grep -v '\.as-tmp$' | head -n 10 || true)
[ "$preview" = 0 ] && printf 'LEFTCOUNT\t%s\n' "$(printf '%s' "$left" | grep -c . || true)"
printf '%s\n' "$left" | while read -r line; do [ -n "$line" ] && printf 'LEFT\t%s\n' "$line"; done
exit 0
""".replace("__OLD__", old).replace("__NEW__", new).replace("__PREVIEW__", "1" if preview else "0")
