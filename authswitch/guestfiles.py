"""Copy files into a guest and out of it.

Containers stream the file through ``pct exec`` over the SSH access of "SSH for my
terminal". VMs go through the QEMU guest agent: Proxmox VE accepts at most 60 KiB per
agent write, so an upload is written in parts that a command in the guest joins at the
end; a download reads the file in parts as base64 through a command in the guest.
Uploaded files get the owner of the folder they land in.
"""

from __future__ import annotations

import base64
import secrets
import shlex
import subprocess
import time
from pathlib import Path
from typing import Callable

from . import core
from .guestaccounts import WINDOWS, Guest
from .i18n import _

# Raw bytes per agent write; as base64 they stay below the 61440 characters Proxmox VE allows.
WRITE_CHUNK = 45 * 1024
# Raw bytes per read command; the agent returns up to 16 MiB of output.
READ_CHUNK = 3 * 1024 * 1024
STREAM_CHUNK = 1024 * 1024

Progress = Callable[[int, int], None]


def default_folder(guest: Guest) -> str:
    """Downloads of the first account people sign in with, or its home folder."""
    if guest.kind == "qemu" and guest.system() == WINDOWS:
        users = guest.users()
        return f"C:\\Users\\{users[0]['name']}\\Downloads" if users else "C:\\Users\\Public"
    status, output = guest.run(retries=2, command=["sh", "-c", (
        "home=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $6; exit}'); "
        "home=${home:-/root}; if [ -d \"$home/Downloads\" ]; then echo \"$home/Downloads\"; else echo \"$home\"; fi"
    )])
    return output.strip().splitlines()[-1] if status == 0 and output.strip() else "/tmp"


def join(guest: Guest, folder: str, name: str) -> str:
    if guest.kind == "qemu" and guest.system() == WINDOWS:
        return folder.rstrip("\\/") + "\\" + name
    return folder.rstrip("/") + "/" + name


def upload(guest: Guest, local: Path, folder: str, progress: Progress) -> str:
    """Copy a local file into a folder of the guest; returns its path there."""
    target = join(guest, folder, local.name)
    total = local.stat().st_size
    if guest.kind == "lxc":
        _stream_into_container(guest, local, target, total, progress)
    else:
        _upload_to_vm(guest, local, folder, target, total, progress)
    return target


def download(guest: Guest, remote: str, local: Path, progress: Progress) -> None:
    """Copy a file of the guest to a local path."""
    if guest.kind == "lxc":
        _stream_out_of_container(guest, remote, local, progress)
    else:
        _download_from_vm(guest, remote, local, progress)


# --- containers -------------------------------------------------------------

def _container_command(guest: Guest, command: list[str]) -> list[str]:
    from . import sshaccess

    if not sshaccess.status(guest.host)["enabled"]:
        raise core.AuthError(_("Containers are reached over SSH; switch on \"SSH for my terminal\" for this server first."))
    # The remote shell reads the command line once more, so every word is quoted.
    return core.ssh_command(guest.host) + [shlex.join(["pct", "exec", str(guest.vmid), "--", *command])]


def _stream_into_container(guest: Guest, local: Path, target: str, total: int, progress: Progress) -> None:
    script = 'test -d "$(dirname "$1")" || exit 3; cat > "$1" && chown --reference="$(dirname "$1")" "$1"'
    proc = subprocess.Popen(_container_command(guest, ["sh", "-c", script, "sh", target]),
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    done = 0
    try:
        with local.open("rb") as source:
            while chunk := source.read(STREAM_CHUNK):
                proc.stdin.write(chunk)
                done += len(chunk)
                progress(done, total)
        proc.stdin.close()
    except BrokenPipeError:
        pass
    error = proc.stderr.read().decode(errors="replace")
    if proc.wait() != 0:
        raise core.AuthError(_("The file could not be written in the guest: {detail}").format(
            detail=error.strip()[-300:] or _("the folder does not exist")))


def _stream_out_of_container(guest: Guest, remote: str, local: Path, progress: Progress) -> None:
    status, output = guest.run(["stat", "-c", "%s", remote])
    if status != 0 or not output.strip().isdigit():
        raise core.AuthError(_("There is no file {path} in the guest.").format(path=remote))
    total = int(output.strip())
    proc = subprocess.Popen(_container_command(guest, ["cat", remote]), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    done = 0
    with local.open("wb") as target:
        while chunk := proc.stdout.read(STREAM_CHUNK):
            target.write(chunk)
            done += len(chunk)
            progress(done, total)
    if proc.wait() != 0:
        raise core.AuthError(_("The file could not be read in the guest: {detail}").format(
            detail=proc.stderr.read().decode(errors="replace").strip()[-300:]))


# --- virtual machines -------------------------------------------------------
# Every command and write below may run twice without harm, so a guest that answers late
# (shortly after booting, for example) only costs a retry.
RETRIES = 3


def _execute(guest: Guest, command: list[str], timeout: float = 600) -> tuple[int, str, str]:
    return guest.execute(command, timeout=timeout, retries=RETRIES)


def _powershell(guest: Guest, script: str, timeout: float = 600) -> tuple[int, str, str]:
    encoded = base64.b64encode(("$ProgressPreference = 'SilentlyContinue'\n" + script).encode("utf-16-le")).decode()
    return _execute(guest, ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout)


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _write_part(guest: Guest, path: str, chunk: bytes) -> None:
    params = {"file": path, "content": base64.b64encode(chunk).decode(), "encode": 0}
    for attempt in range(RETRIES + 1):
        try:
            guest._api("POST", "/agent/file-write", params)
            return
        except core.AuthError as error:
            if "timeout" not in str(error) or attempt == RETRIES:
                raise
            time.sleep(5)


def _upload_to_vm(guest: Guest, local: Path, folder: str, target: str, total: int, progress: Progress) -> None:
    windows = guest.system() == WINDOWS
    if windows:
        status, _out, _err = _powershell(guest, f"if (-not (Test-Path -LiteralPath {_ps_quote(folder)} -PathType Container)) {{ exit 3 }}")
    else:
        status, _out, _err = _execute(guest, ["test", "-d", folder])
    if status != 0:
        raise core.AuthError(_("The folder {path} does not exist in the guest.").format(path=folder))
    name = "auth-switch-" + secrets.token_hex(6)
    prefix = ("C:\\Windows\\Temp\\" if windows else "/tmp/") + name
    count = done = 0
    with local.open("rb") as source:
        while chunk := source.read(WRITE_CHUNK):
            _write_part(guest, f"{prefix}.{count:06d}", chunk)
            count += 1
            done += len(chunk)
            progress(done, total)
    # Joined into a temporary file next to the target and moved over it at the end; when the
    # parts are gone already, an earlier run of this command has finished the job.
    if windows:
        status, _out, error = _powershell(guest, (
            "$ErrorActionPreference = 'Stop'\n"
            f"$target = {_ps_quote(target)}; $total = {total}\n"
            f"$parts = @(Get-ChildItem -LiteralPath 'C:\\Windows\\Temp' -Filter {_ps_quote(name + '.*')} | Sort-Object Name)\n"
            "if ($parts.Count -eq 0) {\n"
            "    if ($total -eq 0) { [IO.File]::WriteAllBytes($target, @()) }\n"
            "    elseif (-not ((Test-Path -LiteralPath $target) -and (Get-Item -LiteralPath $target).Length -eq $total)) { exit 4 }\n"
            "    exit 0\n"
            "}\n"
            "$joined = $target + '.part'\n"
            "$out = [IO.File]::Create($joined)\n"
            "try { foreach ($part in $parts) { $bytes = [IO.File]::ReadAllBytes($part.FullName); $out.Write($bytes, 0, $bytes.Length) } }\n"
            "finally { $out.Close() }\n"
            "Move-Item -LiteralPath $joined -Destination $target -Force\n"
            "$parts | Remove-Item -Force\n"
        ))
    else:
        script = (
            'set -e; prefix=$1; target=$2; total=$3\n'
            'if [ -e "$prefix.000000" ]; then\n'
            '    cat "$prefix".* > "$target.part"; mv -f "$target.part" "$target"; rm -f "$prefix".*\n'
            'elif [ "$total" = 0 ]; then : > "$target"\n'
            'elif [ "$(stat -c %s "$target" 2>/dev/null)" != "$total" ]; then exit 4\n'
            'fi\n'
            'chown --reference="$(dirname "$target")" "$target"\n'
        )
        status, _out, error = _execute(guest, ["sh", "-c", script, "sh", prefix, target, str(total)])
    if status != 0:
        raise core.AuthError(_("The file could not be written in the guest: {detail}").format(
            detail=error.strip()[-300:] or _("the parts were lost on the way")))


def _download_from_vm(guest: Guest, remote: str, local: Path, progress: Progress) -> None:
    windows = guest.system() == WINDOWS
    if windows:
        status, out, _err = _powershell(guest, f"(Get-Item -LiteralPath {_ps_quote(remote)} -ErrorAction Stop).Length")
    else:
        status, out, _err = _execute(guest, ["stat", "-c", "%s", remote])
    if status != 0 or not out.strip().isdigit():
        raise core.AuthError(_("There is no file {path} in the guest.").format(path=remote))
    total = int(out.strip())
    done = 0
    with local.open("wb") as target:
        while done < total:
            if windows:
                status, out, error = _powershell(guest, (
                    f"$file = [IO.File]::OpenRead({_ps_quote(remote)})\n"
                    f"try {{ [void]$file.Seek({done}, 'Begin'); $buffer = New-Object byte[] {READ_CHUNK}\n"
                    "$read = $file.Read($buffer, 0, $buffer.Length); [Convert]::ToBase64String($buffer, 0, $read) }\n"
                    "finally { $file.Close() }\n"
                ))
            else:
                status, out, error = _execute(guest, ["sh", "-c", (
                    'dd if="$1" bs=65536 skip=$3 count=$2 iflag=skip_bytes,count_bytes 2>/dev/null | base64 -w0'
                ), "sh", remote, str(READ_CHUNK), str(done)])
            if status != 0:
                raise core.AuthError(_("The file could not be read in the guest: {detail}").format(detail=error.strip()[-300:]))
            chunk = base64.b64decode("".join(out.split()))
            if not chunk:
                break
            target.write(chunk)
            done += len(chunk)
            progress(done, total)
