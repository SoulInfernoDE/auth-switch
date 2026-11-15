"""Find Proxmox VE servers in the local networks, and check a typed address.

Each address of the directly attached private networks is asked for the start
page on port 8006, which Proxmox VE titles "<node> - Proxmox Virtual
Environment". No account and no secret is involved, so certificates are not
checked here; adding an account still goes through the normal certificate check.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor

from . import core

MAX_ADDRESSES = 1024
_TITLE = re.compile(rb"<title>\s*(.*?)\s*-\s*Proxmox Virtual Environment\s*</title>", re.IGNORECASE | re.DOTALL)
# DSM titles its sign-in page "<name> - Synology DiskStation" (or RackStation, VirtualDSM, …).
_DSM_TITLE = re.compile(rb"<title>\s*(.*?)\s*-\s*Synology[^<]*</title>", re.IGNORECASE | re.DOTALL)
# Container and VM bridges of this machine rarely host a Proxmox VE server.
_SKIPPED_INTERFACES = ("lo", "docker", "veth", "br-", "podman", "cni", "flannel", "tun", "wg")


def local_networks() -> list[ipaddress.IPv4Network]:
    """Private IPv4 networks of this machine's interfaces; larger ones are narrowed to the own /24."""
    try:
        interfaces = json.loads(
            subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=5).stdout or "[]"
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        interfaces = []
    networks: list[ipaddress.IPv4Network] = []
    for interface in interfaces:
        if str(interface.get("ifname", "")).startswith(_SKIPPED_INTERFACES):
            continue
        for address in interface.get("addr_info") or []:
            try:
                own = ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}")
            except (KeyError, ValueError):
                continue
            if not own.ip.is_private or own.ip.is_loopback or own.ip.is_link_local:
                continue
            network = own.network if own.network.prefixlen >= 24 else ipaddress.ip_interface(f"{own.ip}/24").network
            if network not in networks:
                networks.append(network)
    return networks


def probe(address: str, port: int = core.DEFAULT_PORT, timeout: float = 0.8, kind: str = core.PROXMOX) -> str | None:
    """The node or NAS name if ``address`` serves the web interface of ``kind``, else ``None``."""
    state, name = _ask(address, port, timeout)
    return name if state == FOUND[kind] else None


PROXMOX, SYNOLOGY_FOUND, OTHER, DOWN = "proxmox", "synology", "other", "down"
FOUND = {core.PROXMOX: PROXMOX, core.SYNOLOGY: SYNOLOGY_FOUND}
PORTS = {core.PROXMOX: core.DEFAULT_PORT, core.SYNOLOGY: 5001}


def _fetch(address: str, port: int, path: str, timeout: float, until: bytes | None = None) -> bytes | None:
    """GET ``path`` over HTTPS without checking the certificate; the raw answer, or None without one."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        ipaddress.ip_address(address)
        server_name = None
    except ValueError:
        # A reverse proxy picks the site by the name sent when the connection is set up (SNI).
        server_name = address
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as tls:
                tls.settimeout(timeout * 3)
                host = address if port == 443 else f"{address}:{port}"
                tls.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {core.APP}\r\n\r\n".encode())
                page = b""
                while len(page) < 65536 and not (until and until in page.lower()):
                    chunk = tls.recv(8192)
                    if not chunk:
                        break
                    page += chunk
    except (OSError, ValueError):
        return None
    return page


# Asked without signing in; only DSM answers it with its sign-in API.
_DSM_API = "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth"
_ANY_TITLE = re.compile(rb"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)


def _ask(address: str, port: int, timeout: float) -> tuple[str, str | None]:
    """Fetch the start page: Proxmox VE with its node name, Synology DSM with its name, another web server, or no answer."""
    page = _fetch(address, port, "/", timeout, until=b"</title>")
    if page is None:
        return DOWN, None
    match = _TITLE.search(page)
    if match:
        return PROXMOX, match.group(1).decode("utf-8", "replace")
    page = page.replace(b"&nbsp;", b" ")
    match = _DSM_TITLE.search(page)
    if match:
        return SYNOLOGY_FOUND, match.group(1).decode("utf-8", "replace")
    if not page.startswith(b"HTTP/"):
        return DOWN, None
    # The title of the DSM sign-in page can be changed (Control Panel → Login Portal); the API cannot.
    answer = _fetch(address, port, _DSM_API, timeout) or b""
    if b'"SYNO.API.Auth"' in answer and b'"success":true' in answer.replace(b" ", b""):
        title = _ANY_TITLE.search(page)
        name = title.group(1).decode("utf-8", "replace").strip() if title else ""
        return SYNOLOGY_FOUND, name or address
    return OTHER, None


def check(text: str, timeout: float = 2.0, kind: str = core.PROXMOX) -> dict:
    """Whether a typed address serves Proxmox VE, as ``{"host", "state", "name", "tried"}``.

    An address without a port is asked on port 8006 first and then on 443, where a server behind a
    reverse proxy answers; ``host`` is the address that answered.
    """
    host = core.normalize_host(text, PORTS[kind])
    if not host:
        return {"host": "", "state": DOWN, "name": None, "tried": []}
    candidates = [host]
    if not core.has_port(text) and "://" not in text:
        candidates.append(f"{core.split_host(host)[0]}:443")
    first = None
    for candidate in candidates:
        address, port = core.split_host(candidate)
        state, name = _ask(address, port, timeout)
        if state == FOUND[kind]:
            return {"host": candidate, "state": state, "name": name, "tried": [port]}
        if state in (OTHER, PROXMOX, SYNOLOGY_FOUND) and first is None:
            first = {"host": candidate, "state": OTHER, "name": None, "tried": [port]}
    tried = [core.split_host(candidate)[1] for candidate in candidates]
    return first or {"host": host, "state": DOWN, "name": None, "tried": tried}


def discover(networks: list[ipaddress.IPv4Network] | None = None, timeout: float = 0.8, kind: str = core.PROXMOX) -> list[dict]:
    """Servers of ``kind`` in ``networks`` (default: the local ones) as ``{"host", "address", "name"}``."""
    addresses = []
    for network in networks if networks is not None else local_networks():
        addresses += [str(host) for host in network.hosts()]
    addresses = addresses[:MAX_ADDRESSES]
    with ThreadPoolExecutor(max_workers=128) as pool:
        names = list(pool.map(lambda address: probe(address, PORTS[kind], timeout, kind), addresses))
    found = [
        {"host": f"{address}:{PORTS[kind]}", "address": address, "name": name}
        for address, name in zip(addresses, names)
        if name is not None
    ]
    return sorted(found, key=lambda server: ipaddress.ip_address(server["address"]))
