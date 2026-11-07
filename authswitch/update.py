"""Look for newer releases and notice when a running process is outdated."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__, core

RELEASES_API = "https://api.github.com/repos/SoulInfernoDE/auth-switch/releases/latest"
# Cheap: an unchanged answer comes back as "304 Not Modified", which GitHub does not count.
CHECK_INTERVAL = 30 * 60


def _cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(base) / core.APP / "update.json"


def _numbers(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _fetch_latest(previous: dict) -> dict:
    """The latest release; with the ETag of the previous answer GitHub only says whether it changed."""
    # Deliberately unauthenticated: an update check must not carry any account.
    headers = {"User-Agent": f"{core.APP}/{__version__}"}
    if previous.get("etag") and previous.get("version"):
        headers["If-None-Match"] = previous["etag"]
    request = urllib.request.Request(RELEASES_API, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            release = json.load(response)
            etag = response.headers.get("ETag", "")
    except urllib.error.HTTPError as error:
        if error.code == 304:
            return {key: previous[key] for key in ("version", "url", "etag") if key in previous}
        raise
    return {"version": str(release["tag_name"]).lstrip("v"), "url": str(release["html_url"]), "etag": etag}


def cached() -> dict | None:
    """The newer release found by the last check, without touching the network."""
    try:
        latest = json.loads(_cache_file().read_text(encoding="utf-8"))
        newer = _numbers(latest["version"]) > _numbers(__version__)
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return {"version": latest["version"], "url": latest["url"]} if newer else None


def check(force: bool = False) -> dict | None:
    """Return ``{"version", "url"}`` if a newer release exists; asks GitHub at most every 30 minutes."""
    if not core.load_settings().get("check_updates"):
        return None
    path = _cache_file()
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
        fresh = time.time() - previous["checked"] < CHECK_INTERVAL
    except (OSError, ValueError, KeyError, TypeError):
        previous, fresh = {}, False
    if force or not fresh:
        try:
            latest = _fetch_latest(previous if isinstance(previous, dict) else {})
        except (OSError, ValueError, KeyError):
            return cached()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({**latest, "checked": time.time()}), encoding="utf-8")
    return cached()


_checking = threading.Lock()
_started = 0.0


def check_in_background() -> None:
    """Refresh the cached answer without waiting for it, at most one check at a time and one a minute."""
    global _started
    if time.time() - _started < 60:
        return
    _started = time.time()

    def run():
        if _checking.acquire(blocking=False):
            try:
                check()
            finally:
                _checking.release()

    threading.Thread(target=run, daemon=True).start()


def installed_version() -> str:
    """Version of the files on disk, which differs from ours after an upgrade while we keep running."""
    try:
        source = (Path(__file__).parent / "__init__.py").read_text(encoding="utf-8")
    except OSError:
        return __version__
    match = re.search(r'^__version__ = "([^"]+)"', source, re.MULTILINE)
    return match.group(1) if match else __version__


def outdated_process() -> str | None:
    """The installed version if this process still runs an older one."""
    installed = installed_version()
    return installed if _numbers(installed) > _numbers(__version__) else None
