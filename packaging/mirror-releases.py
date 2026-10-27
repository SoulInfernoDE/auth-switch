#!/usr/bin/python3
"""Copy the GitHub releases, with notes and assets, to a Forgejo mirror.

A Forgejo pull mirror follows branches and tags but not releases. This script
first asks the mirror to sync, waits until it has every release tag and then
creates the releases that are missing. The Forgejo token is read from the
system keyring through Git-Switch, so the account must have been added there.

Usage: mirror-releases.py <github owner/repo> <forgejo host> <forgejo owner/repo>
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# The Forgejo account is the one Git-Switch manages; its token is read from the keyring through it.
from gitswitch import forge  # noqa: E402


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def download(source: str, tag: str, name: str, directory: str) -> None:
    """Fetch one asset; GitHub may need a moment before a just-published asset can be downloaded."""
    for attempt in range(5):
        try:
            gh("release", "download", tag, "--repo", source, "--dir", directory, "--pattern", name)
            return
        except subprocess.CalledProcessError as error:
            if attempt == 4:
                sys.exit(f"cannot download {name} of {tag}: {error.stderr.strip()}")
            time.sleep(5)


def wait_for_tags(host: str, target: str, tags: list[str], timeout: int = 180) -> None:
    """Sync the mirror until it has all ``tags``; a release without its tag would point at the wrong commit."""
    forge.api("POST", f"/repos/{target}/mirror-sync", host=host)
    deadline = time.monotonic() + timeout
    while True:
        mirrored = {tag["name"] for tag in forge.api("GET", f"/repos/{target}/tags?limit=100", host=host)}
        missing = [tag for tag in tags if tag not in mirrored]
        if not missing:
            return
        if time.monotonic() > deadline:
            sys.exit(f"mirror still lacks the tags {', '.join(missing)}")
        time.sleep(5)


def main() -> int:
    source, host, target = sys.argv[1:4]
    listed = json.loads(gh("release", "list", "--repo", source, "--limit", "100", "--json", "tagName"))
    tags = [entry["tagName"] for entry in reversed(listed)]
    wait_for_tags(host, target, tags)
    present = {release["tag_name"]: release for release in forge.api("GET", f"/repos/{target}/releases?limit=100", host=host)}

    for tag in tags:
        release = json.loads(gh("release", "view", tag, "--repo", source, "--json", "name,body,isPrerelease,assets"))
        mirrored = present.get(tag)
        if mirrored is None:
            body = {"tag_name": tag, "name": release["name"], "body": release["body"], "prerelease": release["isPrerelease"]}
            mirrored = forge.api("POST", f"/repos/{target}/releases", body, host)
        have = {asset["name"] for asset in mirrored.get("assets") or []}
        missing = [asset["name"] for asset in release["assets"] if asset["name"] not in have]
        with tempfile.TemporaryDirectory() as directory:
            for name in missing:
                download(source, tag, name, directory)
                forge.upload_release_asset(target, tag, str(Path(directory, name)), host)
        if missing or tag not in present:
            print(f"{tag}: release {'created' if tag not in present else 'kept'}, {len(missing)} asset(s) copied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
