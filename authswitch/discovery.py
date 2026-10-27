"""Find Proxmox VE servers in the local networks.

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


def probe(address: str, port: int = core.DEFAULT_PORT, timeout: float = 0.8) -> str | None:
    """The node name if ``address`` serves the Proxmox VE web interface, else ``None``."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            with context.wrap_socket(sock) as tls:
                tls.settimeout(timeout * 3)
                tls.sendall(f"GET / HTTP/1.0\r\nHost: {address}\r\nUser-Agent: {core.APP}\r\n\r\n".encode())
                page = b""
                while len(page) < 65536 and b"</title>" not in page.lower():
                    chunk = tls.recv(8192)
                    if not chunk:
                        break
                    page += chunk
    except (OSError, ValueError):
        return None
    match = _TITLE.search(page)
    return match.group(1).decode("utf-8", "replace") if match else None


def discover(networks: list[ipaddress.IPv4Network] | None = None, timeout: float = 0.8) -> list[dict]:
    """Proxmox VE servers in ``networks`` (default: the local ones) as ``{"host", "address", "name"}``."""
    addresses = []
    for network in networks if networks is not None else local_networks():
        addresses += [str(host) for host in network.hosts()]
    addresses = addresses[:MAX_ADDRESSES]
    with ThreadPoolExecutor(max_workers=128) as pool:
        names = list(pool.map(lambda address: probe(address, timeout=timeout), addresses))
    found = [
        {"host": f"{address}:{core.DEFAULT_PORT}", "address": address, "name": name}
        for address, name in zip(addresses, names)
        if name is not None
    ]
    return sorted(found, key=lambda server: ipaddress.ip_address(server["address"]))
