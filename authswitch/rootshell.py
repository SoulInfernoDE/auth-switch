"""Run a script in the root console of a node, signed in once with the root password.

This is the console the web interface opens under Node → Shell: a ticket from
``/access/ticket``, a terminal from ``termproxy`` and its websocket. It goes over
the HTTPS connection whose certificate the user confirmed, so no SSH host key is
involved. The password and the ticket only live in memory for this one call and
are never stored. These endpoints are blocked for the MCP server and the API
helpers; only this module uses them, and only on the user's explicit request.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import struct
import time
import urllib.parse

from . import core
from .i18n import _

_EXIT = re.compile(rb"AUTH-SWITCH-EXIT:(\d+)")


class TwoFactorRequired(core.AuthError):
    """The account uses two-factor authentication; call again with the one-time code."""


class ConsoleClosed(core.AuthError):
    """The console went away before the script reported its exit status."""


def _post(host: str, path: str, params: dict, cookie: str = "", csrf: str = "") -> object:
    connection = core._Connection(host, core.pinned_fingerprint(host))
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if cookie:
        headers["Cookie"] = f"PVEAuthCookie={urllib.parse.quote(cookie, safe='')}"
    if csrf:
        headers["CSRFPreventionToken"] = csrf
    try:
        connection.request("POST", "/api2/json" + path, body=urllib.parse.urlencode(params).encode(), headers=headers)
        response = connection.getresponse()
        text = response.read().decode("utf-8", "replace")
    except OSError as error:
        raise core.AuthError(_("{host} cannot be reached: {detail}").format(host=host, detail=error)) from None
    finally:
        connection.close()
    if response.status == 401:
        raise core.AuthError(_("The server rejected the user name or password."))
    if response.status != 200:
        raise core.AuthError(f"HTTP {response.status} {response.reason}: {text[:200].strip()}".rstrip(": "))
    return json.loads(text).get("data")


def sign_in(host: str, user: str, password: str, code: str = "") -> dict:
    """Return the ticket and CSRF token of a short web session."""
    data = _post(host, "/access/ticket", {"username": user, "password": password}) or {}
    if data.get("NeedTFA"):
        if not code:
            raise TwoFactorRequired(_("This account uses two-factor authentication; enter the one-time code."))
        data = _post(host, "/access/ticket", {"username": user, "tfa-challenge": data["ticket"], "password": f"totp:{code}"}) or {}
    if not data.get("ticket") or not data.get("CSRFPreventionToken"):
        raise core.AuthError(_("The server did not issue a session."))
    return {"ticket": data["ticket"], "csrf": data["CSRFPreventionToken"], "user": data.get("username", user)}


# --- a minimal websocket client (RFC 6455) -----------------------------------


def _frame(payload: bytes, opcode: int = 0x2) -> bytes:
    """A masked client frame, as the protocol requires for data sent by clients."""
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", 0x80 | opcode, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, length)
    return header + mask + bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))


def _read_exact(sock, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConsoleClosed(_("The console closed the connection."))
        data += chunk
    return data


def _read_frame(sock) -> tuple[int, bytes]:
    first, second = _read_exact(sock, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _read_exact(sock, 8))[0]
    mask = _read_exact(sock, 4) if second & 0x80 else b""
    payload = _read_exact(sock, length)
    if mask:
        payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    return first & 0x0F, payload


def _open_websocket(host: str, path: str, cookie: str):
    connection = core._Connection(host, core.pinned_fingerprint(host))
    connection.connect()
    sock = connection.sock
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    name, port = core.split_host(host)
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {name}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n"
        f"Cookie: PVEAuthCookie={urllib.parse.quote(cookie, safe='')}\r\n\r\n"
    )
    sock.sendall(request.encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += _read_exact(sock, 1)
    if not head.startswith(b"HTTP/1.1 101"):
        sock.close()
        raise core.AuthError(_("The console could not be opened: {detail}").format(detail=head.split(b"\r\n", 1)[0].decode()))
    return sock


def run_script(host: str, node: str, session: dict, script: str, timeout: float = 600) -> tuple[int, str]:
    """Run ``script`` in the node's root console; returns its exit status and output."""
    proxy = _post(host, f"/nodes/{node}/termproxy", {}, session["ticket"], session["csrf"]) or {}
    query = urllib.parse.urlencode({"port": proxy["port"], "vncticket": proxy["ticket"]})
    sock = _open_websocket(host, f"/api2/json/nodes/{node}/vncwebsocket?{query}", session["ticket"])
    sock.settimeout(30)
    try:
        sock.sendall(_frame(f"{proxy['user']}:{proxy['ticket']}\n".encode()))
        if not _read_frame(sock)[1].startswith(b"OK"):
            raise core.AuthError(_("The console refused the session."))
        # Terminal size first, then one line that unpacks and runs the script and prints its exit status.
        sock.sendall(_frame(b"1:200:50:"))
        encoded = base64.b64encode(script.encode()).decode()
        line = f"echo {encoded} | base64 -d | sh; echo AUTH-SWITCH-EXIT:$?\n".encode()
        sock.sendall(_frame(b"0:%d:%s" % (len(line), line)))
        output, deadline = b"", time.monotonic() + timeout
        while time.monotonic() < deadline:
            opcode, payload = _read_frame(sock)
            if opcode == 0x8:
                raise ConsoleClosed(_("The console closed the connection."))
            if opcode == 0x9:
                sock.sendall(_frame(payload, 0xA))
                continue
            output += payload
            match = _EXIT.search(output)
            if match:
                sock.sendall(_frame(b"0:5:exit\n"))
                text = output[: match.start()].decode("utf-8", "replace")
                return int(match.group(1)), text
        raise core.AuthError(_("The console did not finish in time."))
    finally:
        sock.close()


def local_node(host: str, token_account: core.Account) -> str:
    """Name of the node behind ``host``, whose web interface the user sees."""
    status = core.request(host, token_account.token_id, core._active_secret(token_account), "GET", "/cluster/status") or []
    return next((e["name"] for e in status if e.get("type") == "node" and e.get("local")), "")


def remove_notice(host: str, node: str, user: str, password: str, code: str = "") -> str:
    """Sign in, run the notice fix in the root console and forget the session again."""
    session = sign_in(host, user, password, code)
    try:
        status, output = run_script(host, node, session, core.NOTICE_FIX_SCRIPT, timeout=300)
    except ConsoleClosed:
        # Older hooks restart pveproxy at once, which also ends this console; the served file tells the truth.
        for _attempt in range(6):
            time.sleep(3)
            try:
                if core.notice_status(host) == core.NOTICE_REMOVED:
                    return ""
            except core.AuthError:
                continue
        raise
    finally:
        session.clear()
    if status != 0:
        tail = [line for line in output.splitlines() if line.strip()][-1:] or [""]
        raise core.AuthError(_("The fix failed on {node}: {detail}").format(node=node, detail=tail[0]))
    return output
