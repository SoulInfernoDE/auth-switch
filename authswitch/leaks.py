"""Find private data in content that is about to be published.

Unlike a generic secret scanner this knows what is private on this machine:
the secrets of the Proxmox VE accounts, the servers they belong to, the real
git e-mail address, the home directory and the machine name.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from . import core
from .i18n import _

SECRET, PRIVATE, REVIEW = "secret", "private", "review"
MAX_FILE_BYTES = 1_000_000

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,})"
    rf"|PVEAPIToken=\S+|[\w.+-]+@[\w.-]+![\w.-]+\s*[=:]\s*{_UUID}"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_INTERNAL_HOST = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:local|lan|internal|intranet|home\.arpa)\b", re.IGNORECASE)
_ATTRIBUTION = re.compile(r"^\W*(?:co-authored-by|generated (?:with|by)|signed-off-by)\b", re.IGNORECASE)
_PLACEHOLDER_MAIL = re.compile(r"noreply|@(?:[\w-]+\.)*example\.(?:com|org|net)$|\.(?:invalid|test|example)$", re.IGNORECASE)


@dataclass
class Finding:
    kind: str
    severity: str
    where: str
    excerpt: str
    detail: str


@dataclass
class Context:
    """What counts as private here; gathered once per scan."""

    tokens: dict[str, str] = field(default_factory=dict)
    hosts: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    home: str = ""
    machine: str = ""
    allow: list[str] = field(default_factory=list)
    # Terms and file names the user keeps out of published content, except in one repository ("host/owner/name").
    restricted_terms: re.Pattern | None = None
    restricted_files: set[str] = field(default_factory=set)
    restricted_repository: str = ""
    restricted_label: str = ""
    # Phrases in which a term is fine, e.g. the name of a product the code integrates with.
    restricted_phrases: list[str] = field(default_factory=list)

    @property
    def restricting(self) -> bool:
        return self.restricted_terms is not None or bool(self.restricted_files)


def repository_id(location: str) -> str:
    """``host/owner/name`` for a remote URL (HTTPS or SSH) or such a spec, in lower case."""
    text = location.strip().lower()
    text = text.split("://", 1)[-1]
    text = text.split("@", 1)[-1] if "@" in text.split("/", 1)[0] else text
    text = text.replace(":", "/", 1) if ":" in text.split("/", 1)[0] and not location.startswith(("http", "ssh")) else text
    text = text.rstrip("/")
    return text[:-4] if text.endswith(".git") else text


def restricted_allowed(host: str, repository: str, context: "Context | None" = None) -> bool:
    """Whether content for ``repository`` on ``host`` may contain the restricted terms."""
    context = context or gather()
    if not context.restricting:
        return True
    return bool(context.restricted_repository) and repository_id(f"{host}/{repository}") == context.restricted_repository


def _restricted_settings(context: "Context", settings: dict) -> None:
    rules = settings.get("restricted") if isinstance(settings.get("restricted"), dict) else {}
    terms = [str(term) for term in rules.get("terms") or [] if str(term).strip()]
    if terms:
        context.restricted_terms = re.compile(r"\b(?:" + "|".join(map(re.escape, terms)) + r")\b", re.IGNORECASE)
    context.restricted_files = {str(name) for name in rules.get("files") or [] if str(name).strip()}
    context.restricted_phrases = [str(phrase).lower() for phrase in rules.get("allow") or [] if str(phrase).strip()]
    if rules.get("repository"):
        context.restricted_repository = repository_id(str(rules["repository"]))
        context.restricted_label = str(rules["repository"])


def gather() -> Context:
    context = Context(home=str(Path.home()), machine=socket.gethostname())
    settings = core.load_settings()
    context.allow = [str(entry) for entry in settings.get("leak_allow") or []]
    _restricted_settings(context, settings)
    for account in core.list_accounts():
        try:
            secret = core.lookup_secret(account.host, account.token_id)
        except core.AuthError:
            secret = ""
        if secret:
            context.tokens[secret] = f"{account.token_id} @ {account.host}"
        context.hosts.add(core.split_host(account.host)[0].lower())
    email = core.get_git_email()
    if email and not _PLACEHOLDER_MAIL.search(email):
        context.emails.add(email.lower())
    return context


def _mask(line: str, secret: str) -> str:
    return line.replace(secret, secret[:4] + "…")


def scan_line(line: str, where: str, context: Context) -> list[Finding]:
    found: list[Finding] = []
    shown = line.strip()

    def add(kind: str, severity: str, match: str, detail: str) -> None:
        if any(entry and entry in match for entry in context.allow):
            return
        found.append(Finding(kind, severity, where, shown[:200], detail))

    for token, label in context.tokens.items():
        if token in line:
            shown = _mask(shown, token)
            add("live-token", SECRET, token, _("The token currently stored for {account}.").format(account=label))
    for match in _TOKEN.finditer(line):
        if match.group(0) not in context.tokens:
            shown = _mask(shown, match.group(0))
            add("token", SECRET, match.group(0), _("Looks like an access token."))
    if _PRIVATE_KEY.search(line):
        add("private-key", SECRET, line, _("A private key."))
    lowered = line.lower()
    for host in context.hosts:
        if host in lowered:
            add("private-server", PRIVATE, host, _("Address of your Proxmox VE server {host}.").format(host=host))
    for match in _EMAIL.finditer(line):
        address = match.group(0)
        if address.lower() in context.emails:
            add("own-email", PRIVATE, address, _("Your real git e-mail address."))
        elif not _PLACEHOLDER_MAIL.search(address) and not address.lower().startswith("git@"):
            add("email", REVIEW, address, _("An e-mail address; check that it is meant to be public."))
    if context.home and context.home in line:
        add("home-path", PRIVATE, context.home, _("A path inside your home directory; it reveals your user name."))
    if len(context.machine) >= 4 and re.search(rf"\b{re.escape(context.machine)}\b", line):
        add("machine-name", REVIEW, context.machine, _("The name of this computer."))
    for match in _IPV4.finditer(line):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.is_private and not address.is_loopback and not address.is_unspecified:
            add("private-address", REVIEW, match.group(0), _("An address from a private network."))
    for match in _INTERNAL_HOST.finditer(line):
        add("internal-host", REVIEW, match.group(0), _("A host name from an internal network."))
    if context.restricted_terms is not None:
        term = context.restricted_terms.search(line)
        if term and _ATTRIBUTION.search(line):
            add("restricted-attribution", PRIVATE, term.group(0), _restricted_detail(context, _("An attribution line naming {term}."), term.group(0)))
        elif term and not any(phrase in line.lower() for phrase in context.restricted_phrases):
            add("restricted-term", PRIVATE, term.group(0), _restricted_detail(context, _("A mention of {term}."), term.group(0)))
    return found


def _restricted_detail(context: Context, what: str, term: str = "") -> str:
    text = what.format(term=term)
    if context.restricted_repository:
        place = context.restricted_label or context.restricted_repository
        return text + " " + _("This belongs only in {repository}.").format(repository=place)
    return text + " " + _("This is not meant to be published.")


def _restricted_file(path: str, context: Context) -> list[Finding]:
    hits = context.restricted_files.intersection(Path(path).parts)
    if not hits:
        return []
    return [Finding("restricted-file", PRIVATE, path, path, _restricted_detail(context, _("A file on your restricted list ({term})."), sorted(hits)[0]))]


def scan_text(text: str, where: str = "text", context: Context | None = None) -> list[Finding]:
    context = context or gather()
    return [
        finding
        for number, line in enumerate(text.splitlines(), 1)
        for finding in scan_line(line, f"{where}:{number}", context)
    ]


def scan_paths(paths: list[str], context: Context | None = None) -> list[Finding]:
    context = context or gather()
    found: list[Finding] = []
    for given in paths:
        root = Path(given).expanduser()
        if not root.exists():
            raise core.AuthError(_("{path} does not exist.").format(path=root))
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)
        for path in files:
            found += _restricted_file(str(path), context)
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
            if b"\0" not in data:
                found += scan_text(data.decode("utf-8", "replace"), str(path), context)
    return found


def _git(repository: str, *args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", "-C", repository, *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise core.AuthError(str(error)) from None


def _scan_diff(diff: str, context: Context) -> list[Finding]:
    found: list[Finding] = []
    path, number = "", 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
            found += _restricted_file(path, context) if path else []
        elif line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            number = int(match.group(1)) if match else 0
        elif line.startswith("+") and path:
            found += scan_line(line[1:], f"{path}:{number}", context)
            number += 1
    return found


def _push_target(root: str) -> str:
    """``host/owner/name`` the next push goes to."""
    upstream = _git(root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    remote = upstream.stdout.split("/", 1)[0] if upstream.returncode == 0 else "origin"
    url = _git(root, "remote", "get-url", "--push", remote)
    return repository_id(url.stdout) if url.returncode == 0 else ""


def scan_repository(repository: str, context: Context | None = None) -> list[Finding]:
    """Scan what the next push would publish: staged changes and commits the upstream lacks."""
    context = context or gather()
    top = _git(repository, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        raise core.AuthError(_("{path} is not a git repository.").format(path=repository))
    root = top.stdout.strip()
    if context.restricted_repository and _push_target(root) == context.restricted_repository:
        context = replace(context, restricted_terms=None, restricted_files=set())
    found = _scan_diff(_git(root, "diff", "--cached", "-U0").stdout, context)
    if _git(root, "rev-parse", "--abbrev-ref", "@{upstream}").returncode == 0:
        commits = "@{upstream}..HEAD"
        found += _scan_diff(_git(root, "log", "-p", "-U0", "--format=", commits).stdout, context)
    else:
        # Nothing has been published yet, so everything tracked is new to the outside.
        commits = "HEAD"
        tracked = [str(Path(root, name)) for name in _git(root, "ls-files").stdout.splitlines()]
        found += scan_paths([path for path in tracked if Path(path).is_file()], context)
    for entry in _git(root, "log", "--format=%h%x09%an <%ae>%x09%cn <%ce>%x09%s", commits).stdout.splitlines():
        commit, author, committer, subject = (entry.split("\t") + ["", "", ""])[:4]
        found += scan_line(f"{author} / {committer}", f"commit {commit} (author)", context)
        found += scan_line(subject, f"commit {commit} (message)", context)
    return found


def report(findings: list[Finding]) -> dict:
    """Plain data for the command line and the MCP server; identical findings are merged."""
    unique: dict[tuple, Finding] = {}
    for finding in findings:
        unique.setdefault((finding.kind, finding.where, finding.excerpt), finding)
    ordered = sorted(unique.values(), key=lambda f: (SECRET, PRIVATE, REVIEW).index(f.severity))
    counts = {level: sum(1 for f in ordered if f.severity == level) for level in (SECRET, PRIVATE, REVIEW)}
    return {"clean": not ordered, "counts": counts, "findings": [asdict(finding) for finding in ordered]}
