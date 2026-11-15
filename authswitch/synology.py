"""Synology DSM accounts: sign in to the DSM Web API and call it as the active account.

DSM has no API tokens, so an account is a DSM user and its password, kept in the system
keyring like a Proxmox VE secret. With two-factor sign-in, the first sign-in takes a code
and registers Auth-Switch as a trusted device; the device token DSM returns is kept in the
keyring too, so later sign-ins need no code. Sessions live in memory only and are opened
again when DSM ends them. Like Proxmox VE requests, every call goes over HTTPS to the
server's pinned or trusted certificate.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import threading
import urllib.parse

from . import __version__, core
from .i18n import _

KIND = "synology"
DEFAULT_PORT = 5001
DEVICE_NAME = "Auth-Switch"
AUTH_VERSION = 6
# Parts of the API that hand out sessions, passwords or second factors are not available as tools.
BLOCKED_APIS = re.compile(r"^SYNO\.(API\.Auth|API\.OTP|Core\.OTP|Core\.User\.PasswordConfirm|Core\.User\.PasswordExpiry)(\.|$)")
# Methods that only read; anything else counts as a change.
READ_METHOD = re.compile(r"^(get|list|query|info|getinfo|status|load|search|check|count|read)", re.IGNORECASE)
# DSM answers these when a session has ended; the call is repeated with a new session.
SESSION_ERRORS = {105, 106, 107, 119}

_sessions: dict[tuple[str, str], str] = {}
_lock = threading.Lock()


class OtpRequired(core.AuthError):
    """DSM asks for the code of the second factor."""


def _messages() -> dict[int, str]:
    return {
        400: _("DSM rejected the user name or the password."),
        401: _("The DSM account is disabled."),
        402: _("The DSM account may not sign in here."),
        403: _("DSM asks for the code of the second sign-in step."),
        404: _("The code of the second sign-in step is wrong or was used already."),
        406: _("DSM requires two-factor sign-in for this account; set it up in DSM first."),
        407: _("DSM has blocked the address of this computer after too many failed sign-ins."),
        408: _("The password of the DSM account has expired."),
        409: _("The password of the DSM account has expired."),
        410: _("DSM wants a new password for this account; sign in once in the web interface."),
        102: _("DSM does not offer this API."),
        103: _("DSM does not offer this method."),
        104: _("DSM does not offer this API version."),
        105: _("The DSM account has no permission for this."),
        119: _("The DSM session has ended."),
    }


def _error(code: int, api: str) -> core.AuthError:
    text = _messages().get(code) or _("DSM answered with error {code}.").format(code=code)
    if api == "SYNO.API.Auth" and code == 403:
        return OtpRequired(text)
    return core.AuthError(text)


def _post(host: str, fields: dict, fingerprint: str | None = None) -> dict:
    """POST to ``/webapi/entry.cgi`` and return the answer of DSM as a dict."""
    body = urllib.parse.urlencode({key: value for key, value in fields.items() if value not in (None, "")}).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": f"{core.APP}/{__version__}",
    }
    connection = core._Connection(host, core.pinned_fingerprint(host) if fingerprint is None else fingerprint)
    try:
        connection.request("POST", "/webapi/entry.cgi", body=body, headers=headers)
        response = connection.getresponse()
        text = response.read().decode("utf-8", "replace")
    except ssl.SSLCertVerificationError:
        message = _("The certificate of {host} is not trusted; add the account again to confirm it.")
        raise core.AuthError(message.format(host=host)) from None
    except (OSError, http.client.HTTPException) as error:
        raise core.AuthError(_("{host} cannot be reached: {detail}").format(host=host, detail=error)) from None
    finally:
        connection.close()
    if response.status != 200:
        raise core.AuthError(f"HTTP {response.status} {response.reason}")
    try:
        answer = json.loads(text)
    except ValueError:
        raise core.AuthError(_("{host} did not answer like a Synology DSM server.").format(host=host)) from None
    if not isinstance(answer, dict) or "success" not in answer:
        raise core.AuthError(_("{host} did not answer like a Synology DSM server.").format(host=host))
    return answer


def login(host: str, user: str, password: str, otp: str = "", device: str = "", fingerprint: str | None = None) -> dict:
    """Open a session; returns ``{"sid", "device"}``, where ``device`` is a new device token after a code."""
    fields = {
        "api": "SYNO.API.Auth", "version": AUTH_VERSION, "method": "login", "account": user, "passwd": password,
        "session": core.APP, "format": "sid",
    }
    if otp:
        fields.update(otp_code=otp, enable_device_token="yes", device_name=DEVICE_NAME)
    elif device:
        fields.update(device_id=device, device_name=DEVICE_NAME)
    answer = _post(host, fields, fingerprint)
    if not answer["success"]:
        raise _error(int((answer.get("error") or {}).get("code") or 0), "SYNO.API.Auth")
    data = answer.get("data") or {}
    return {"sid": str(data.get("sid") or ""), "device": str(data.get("did") or data.get("device_id") or "")}


def logout(host: str, sid: str, fingerprint: str | None = None) -> None:
    try:
        _post(host, {"api": "SYNO.API.Auth", "version": AUTH_VERSION, "method": "logout", "session": core.APP, "_sid": sid}, fingerprint)
    except core.AuthError:
        pass


def device_key(user: str) -> str:
    """Keyring entry of the device token that spares the code of the second factor."""
    return f"{user}#device"


def _info(host: str, sid: str, fingerprint: str | None = None) -> dict:
    answer = _post(host, {"api": "SYNO.DSM.Info", "version": 2, "method": "getinfo", "_sid": sid}, fingerprint)
    return (answer.get("data") or {}) if answer["success"] else {}


def validate(host: str, user: str, password: str, otp: str = "", fingerprint: str | None = None) -> tuple[core.Profile, str]:
    """Sign in once and read the model and version; returns the profile and a new device token, if any."""
    try:
        device = core.lookup_secret(host, device_key(user)) if not otp else ""
    except core.AuthError:
        device = ""
    try:
        session = login(host, user, password, otp, device, fingerprint)
    except OtpRequired:
        raise
    except core.AuthError as error:
        rejected = str(error) in (_messages()[400], _messages()[401], _messages()[402])
        return core.Profile(valid=False if rejected else None, detail=str(error)), ""
    try:
        info = _info(host, session["sid"], fingerprint)
    finally:
        logout(host, session["sid"], fingerprint)
    version = str(info.get("version_string") or "").removeprefix("DSM ").strip()
    model = str(info.get("model") or "")
    return core.Profile(valid=True, version=version, detail=model), session["device"]


def add_account(host: str, user: str, password: str, otp: str = "", fingerprint: str = "") -> core.Account:
    """Check the DSM account, keep its password (and device token) in the keyring and activate it."""
    host, user = core.normalize_host(host, DEFAULT_PORT), user.strip()
    if not user or any(c.isspace() for c in user):
        raise core.AuthError(_("Enter the user name of the DSM account."))
    profile, device = validate(host, user, password, otp.strip(), fingerprint)
    if profile.valid is False:
        raise core.AuthError(profile.detail or _("{host} rejected the account.").format(host=host))
    if not profile.valid:
        raise core.AuthError(profile.detail or _("{host} did not answer like a Synology DSM server.").format(host=host))
    core.store_secret(host, user, password)
    if device:
        core.store_secret(host, device_key(user), device)
    return core.remember_account(host, user, fingerprint, KIND)


def fetch_profile(account: core.Account) -> core.Profile:
    try:
        password = core.lookup_secret(account.host, account.token_id)
    except core.AuthError as error:
        return core.Profile(valid=None, detail=str(error))
    if not password:
        return core.Profile(valid=False)
    try:
        return validate(account.host, account.token_id, password)[0]
    except OtpRequired as error:
        # The device token is gone (e.g. removed in DSM); signing in needs a code again.
        return core.Profile(valid=False, detail=str(error))


def call(account: core.Account, api: str, method: str, version: int, params: dict | None = None) -> object:
    """Call one method of the DSM Web API as ``account``; returns the ``data`` of the answer."""
    if not re.fullmatch(r"SYNO\.[A-Za-z0-9_.]+", api or ""):
        raise core.AuthError(_("The API name must look like SYNO.Core.System."))
    if BLOCKED_APIS.match(api):
        raise core.AuthError(_("APIs that hand out sessions, passwords or second factors are not available here."))
    if not re.fullmatch(r"[A-Za-z0-9_]+", method or ""):
        raise core.AuthError(_("Unsupported method: {method}").format(method=method))
    fields = {key: value if isinstance(value, str) else json.dumps(value) for key, value in (params or {}).items()}
    for reserved in ("api", "method", "version", "_sid", "SynoToken"):
        fields.pop(reserved, None)
    fields.update(api=api, method=method, version=int(version))
    for attempt in range(2):
        sid = _session(account, fresh=attempt > 0)
        answer = _post(account.host, {**fields, "_sid": sid})
        if answer["success"]:
            return answer.get("data")
        code = int((answer.get("error") or {}).get("code") or 0)
        if code not in SESSION_ERRORS or attempt:
            raise _error(code, api)
    raise core.AuthError(_("The DSM session has ended."))


def _session(account: core.Account, fresh: bool = False) -> str:
    key = (account.host, account.token_id)
    with _lock:
        if fresh:
            _sessions.pop(key, None)
        if key not in _sessions:
            password = core._active_secret(account)
            try:
                device = core.lookup_secret(account.host, device_key(account.token_id))
            except core.AuthError:
                device = ""
            try:
                _sessions[key] = login(account.host, account.token_id, password, device=device)["sid"]
            except OtpRequired:
                raise core.AuthError(_(
                    "DSM asks for a code of the second sign-in step for {user}; add the account again in Auth-Switch."
                ).format(user=account.token_id)) from None
        return _sessions[key]


def forget(account: core.Account) -> None:
    """Remove the account's device token from the keyring and drop its session."""
    with _lock:
        sid = _sessions.pop((account.host, account.token_id), None)
    if sid:
        logout(account.host, sid)
    core.clear_secret(account.host, device_key(account.token_id))


def is_read(method: str) -> bool:
    return bool(READ_METHOD.match(method or ""))
