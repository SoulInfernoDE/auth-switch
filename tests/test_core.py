import gettext
import http.server
import json
import os
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from authswitch import core, leaks, mcp, update

TOKEN = "root@pam!automation"
SECRET = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"


class AccountTest(unittest.TestCase):
    """Accounts with the keyring and the server replaced by fakes."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.keyring = {}
        patches = [
            mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.dir.name, "XDG_CACHE_HOME": self.dir.name}),
            mock.patch.object(core, "store_secret", lambda host, token, secret: self.keyring.__setitem__((host, token), secret)),
            mock.patch.object(core, "lookup_secret", lambda host, token: self.keyring.get((host, token), "")),
            mock.patch.object(core, "clear_secret", lambda host, token: self.keyring.pop((host, token), None)),
            mock.patch.object(core, "validate", return_value=core.Profile(valid=True, version="8.2.4")),
            mock.patch.object(leaks, "gather", return_value=leaks.Context()),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.account = core.add_account("https://PVE.example.com/#v1", TOKEN, f" {SECRET} ")

    def test_add_account(self):
        self.assertEqual(self.account, core.Account("pve.example.com:8006", TOKEN, True))
        self.assertEqual(core.list_accounts(), [self.account])
        self.assertEqual(self.keyring, {("pve.example.com:8006", TOKEN): SECRET})

    def test_bad_token_id_is_refused(self):
        for token_id in ("root@pam", "root!x", "root@pam!", "root@pam!1x"):
            with self.assertRaises(core.AuthError, msg=token_id):
                core.add_account("pve.example.com", token_id, SECRET)

    def test_rejected_token_is_not_stored(self):
        with mock.patch.object(core, "validate", return_value=core.Profile(valid=False)):
            with self.assertRaises(core.AuthError):
                core.add_account("pve.example.com", "ops@pve!ci", "bad")
        self.assertNotIn("bad", self.keyring.values())

    def test_secret_is_not_written_to_disk(self):
        for path in Path(self.dir.name).rglob("*"):
            if path.is_file():
                self.assertNotIn(SECRET, path.read_text())
        self.assertEqual(core.accounts_file().stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SECRET, json.dumps(core.describe_accounts(check=False)))

    def test_switch_and_remove(self):
        core.add_account("pve.example.com", "ops@pve!ci", "1" * 36)
        self.assertEqual([a.token_id for a in core.list_accounts() if a.active], ["ops@pve!ci"])
        self.assertEqual(core.switch_account("root@pam")["token_id"], TOKEN)
        self.assertEqual([a.token_id for a in core.list_accounts() if a.active], [TOKEN])
        core.remove_account(core.find_account(TOKEN))
        self.assertEqual([(a.token_id, a.active) for a in core.list_accounts()], [("ops@pve!ci", True)])
        core.remove_account(core.find_account("ops@pve!ci"))
        self.assertEqual(core.list_accounts(), [])
        self.assertEqual(self.keyring, {})

    def test_api_uses_the_active_account(self):
        with mock.patch.object(core, "request", return_value=[{"node": "pve"}]) as request:
            self.assertEqual(core.api("GET", "/nodes"), [{"node": "pve"}])
        request.assert_called_once_with("pve.example.com:8006", TOKEN, SECRET, "GET", "/nodes", None)

    def test_environment_for_tools(self):
        env = core.environment()
        self.assertEqual(env["PROXMOX_VE_API_TOKEN"], f"{TOKEN}={SECRET}")
        self.assertEqual(env["PM_API_URL"], "https://pve.example.com:8006/api2/json")
        self.assertEqual((env["PROXMOX_USER"], env["PROXMOX_TOKEN_ID"]), ("root@pam", "automation"))

    def test_token_permissions(self):
        core.add_account("pve.example.com", "ops@pve!ci", "1" * 36)
        manager = core.find_account(TOKEN)
        acl = [
            {"type": "token", "ugid": "ops@pve!ci", "path": "/", "roleid": "PVEVMUser"},
            {"type": "token", "ugid": "ops@pve!ci", "path": "/vms/100", "roleid": "PVEVMAdmin"},
            {"type": "user", "ugid": "ops@pve", "path": "/", "roleid": "PVEAuditor"},
        ]
        with mock.patch.object(core, "request", side_effect=[{"privsep": 1}, acl]) as request:
            self.assertEqual(core.token_permissions(manager.host, "ops@pve!ci", manager), {"privsep": True, "roles": {"PVEVMUser"}})
        self.assertEqual(request.call_args_list[0].args[4], "/access/users/ops@pve/token/ci")
        with mock.patch.object(core, "request") as request:
            core.set_token_roles(manager.host, "ops@pve!ci", {"PVEUserAdmin"}, {"PVEVMUser"}, manager)
        grant, revoke = (call.args[5] for call in request.call_args_list)
        self.assertEqual(grant, {"path": "/", "roles": "PVEUserAdmin", "tokens": "ops@pve!ci", "propagate": True})
        self.assertEqual(revoke["roles"], "PVEVMUser")
        self.assertTrue(revoke["delete"])
        self.assertTrue(all(call.args[1] == TOKEN for call in request.call_args_list))

    def test_mcp_tools(self):
        names = [tool["name"] for tool in mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]]
        self.assertEqual(
            names,
            ["list_proxmox_accounts", "switch_proxmox_account", "proxmox_api_get", "proxmox_api_write", "check_for_leaks"],
        )
        with mock.patch.object(core, "request", return_value={"ok": 1}) as request:
            call = {"name": "proxmox_api_write", "arguments": {"method": "POST", "path": "/nodes/pve/qemu/100/status/start"}}
            result = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": call})["result"]
            self.assertFalse(result.get("isError"))
            call = {"name": "proxmox_api_write", "arguments": {"method": "GET", "path": "/nodes"}}
            result = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call})["result"]
            self.assertTrue(result["isError"])
        request.assert_called_once()

    def test_mcp_write_refuses_secrets(self):
        context = leaks.Context(tokens={SECRET: "root"})
        with mock.patch.object(leaks, "gather", return_value=context), mock.patch.object(core, "request") as request:
            call = {"name": "proxmox_api_write", "arguments": {"method": "PUT", "path": "/x", "params": {"notes": SECRET}}}
            result = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": call})["result"]
        self.assertTrue(result["isError"])
        request.assert_not_called()


class InputTest(unittest.TestCase):
    def test_normalize_host(self):
        self.assertEqual(core.normalize_host(" https://PVE.lan:8006/#v1:0 "), "pve.lan:8006")
        self.assertEqual(core.normalize_host("10.0.0.5"), "10.0.0.5:8006")
        self.assertEqual(core.normalize_host("[fd00::5]"), "[fd00::5]:8006")
        self.assertEqual(core.split_host("[fd00::5]:8006"), ("fd00::5", 8006))
        self.assertEqual(core.normalize_host("  "), "")

    def test_paths_cannot_leave_the_api_or_fetch_credentials(self):
        for method, path in (
            ("GET", "nodes"),
            ("GET", "//evil.example/x"),
            ("GET", "/../../x"),
            ("GET", "/nodes /x"),
            ("POST", "/access/ticket"),
            ("POST", "/access/users/root@pam/token/new"),
            ("POST", "/access/users/root@pam/token"),
            ("POST", "/nodes/pve/qemu/100/vncproxy"),
            ("POST", "/nodes/pve/termproxy"),
            ("PATCH", "/nodes"),
        ):
            with self.assertRaises(core.AuthError, msg=path):
                core.request("127.0.0.1:1", TOKEN, SECRET, method, path)

    def test_token_settings_may_be_read(self):
        with mock.patch.object(core, "_Connection") as connection:
            connection.return_value.getresponse.return_value = mock.Mock(status=200, read=lambda: b'{"data": {"privsep": 1}}')
            self.assertEqual(core.request("h:1", TOKEN, SECRET, "GET", "/access/users/root@pam/token/x"), {"privsep": 1})

    def test_form_encoding(self):
        self.assertEqual(core._encode({"onboot": True, "memory": 2048, "skip": None}), "onboot=1&memory=2048")


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        _Handler.seen.append(self.headers.get("Authorization"))
        body = json.dumps({"data": {"version": "8.2.4"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@unittest.skipUnless(subprocess.run(["which", "openssl"], capture_output=True).returncode == 0, "needs openssl")
class PinningTest(unittest.TestCase):
    """A real HTTPS server with a self-signed certificate, as Proxmox VE ships it."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        key, cert = Path(cls.dir.name, "key.pem"), Path(cls.dir.name, "cert.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
             "-keyout", key, "-out", cert],
            check=True, capture_output=True,
        )
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.host = f"127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.dir.cleanup()

    def setUp(self):
        _Handler.seen.clear()

    def test_untrusted_certificate_is_detected(self):
        self.assertFalse(core.certificate_trusted(self.host))
        with self.assertRaises(core.AuthError):
            core.request(self.host, TOKEN, SECRET, "GET", "/version", fingerprint="")
        self.assertEqual(_Handler.seen, [])

    def test_matching_pin_lets_the_request_through(self):
        pin = core.server_fingerprint(self.host)
        self.assertEqual(core.request(self.host, TOKEN, SECRET, "GET", "/version", fingerprint=pin), {"version": "8.2.4"})
        self.assertEqual(_Handler.seen, [f"PVEAPIToken={TOKEN}={SECRET}"])

    def test_wrong_pin_sends_nothing(self):
        with self.assertRaises(core.AuthError):
            core.request(self.host, TOKEN, SECRET, "GET", "/version", fingerprint="00:" * 31 + "00")
        self.assertEqual(_Handler.seen, [])


class LeakTest(unittest.TestCase):
    def setUp(self):
        self.context = leaks.Context(
            tokens={SECRET: f"{TOKEN} @ pve.example.com:8006"},
            hosts={"pve.example.com"},
            emails={"dana@real-mail.example.net"},
            home="/home/dana",
            machine="danas-laptop",
        )

    def kinds(self, text):
        return [finding.kind for finding in leaks.scan_text(text, "t", self.context)]

    def test_finds_what_is_private_here(self):
        self.assertEqual(self.kinds("see https://pve.example.com:8006/"), ["private-server"])
        self.assertEqual(self.kinds(f"secret {SECRET}"), ["live-token"])
        self.assertEqual(self.kinds("PVEAPIToken=ops@pve!ci=11111111-2222-3333-4444-555555555555"), ["token"])
        self.assertEqual(self.kinds("-----BEGIN OPENSSH PRIVATE KEY-----"), ["private-key"])
        self.assertEqual(self.kinds("Dana <dana@real-mail.example.net>"), ["own-email"])
        self.assertEqual(self.kinds("see /home/dana/projects"), ["home-path"])
        self.assertEqual(self.kinds("http://192.168.1.20:8006 and pve.local"), ["private-address", "internal-host"])

    def test_leaves_public_things_alone(self):
        for text in ("https://github.com/dana/x", "root@pam!automation", "commit 25cd9b7f51af22f3669200591f28d7438997f603"):
            self.assertEqual(self.kinds(text), [], text)

    def test_secrets_are_masked(self):
        finding = leaks.scan_text(f"x {SECRET}", "t", self.context)[0]
        self.assertNotIn(SECRET, finding.excerpt)

    def test_restricted_terms(self):
        rules = {"terms": ["Acme"], "files": ["ACME.md"], "repository": "git.example.com/dana/notes"}
        leaks._restricted_settings(self.context, {"restricted": rules})
        self.assertEqual(self.kinds("Co-Authored-By: Acme Bot <b@acme.invalid>"), ["restricted-attribution"])
        self.assertEqual(self.kinds("asked acme"), ["restricted-term"])
        self.assertTrue(leaks.restricted_allowed("git.example.com", "dana/notes", self.context))


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": self.dir.name, "XDG_CONFIG_HOME": self.dir.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_newer_release_is_reported_and_cached(self):
        newer = {"version": "99.0.0", "url": "https://example.com/r"}
        with mock.patch.object(update, "_fetch_latest", return_value=newer) as fetch:
            self.assertEqual(update.check(), newer)
            self.assertEqual(update.check(), newer)
        fetch.assert_called_once()
        self.assertTrue(any("99.0.0" in notice for notice in mcp.notices()))

    def test_switch_turns_the_check_off(self):
        core.save_settings({"check_updates": False})
        with mock.patch.object(update, "_fetch_latest") as fetch:
            self.assertIsNone(update.check())
        fetch.assert_not_called()


class CatalogTest(unittest.TestCase):
    LOCALE_DIR = Path(core.__file__).parent / "locale"

    def test_german_catalog_is_complete(self):
        german = gettext.translation("auth-switch", self.LOCALE_DIR, languages=["de"])
        self.assertEqual(german.gettext("Switch"), "Wechseln")
        template = (self.LOCALE_DIR / "auth-switch.pot").read_text(encoding="utf-8")
        catalog = (self.LOCALE_DIR / "de" / "LC_MESSAGES" / "auth-switch.po").read_text(encoding="utf-8")
        self.assertEqual(template.count("\nmsgid "), catalog.count("\nmsgid "))
        self.assertNotIn('msgstr ""\n\n', catalog.split("\n\n", 1)[1] + "\n")


if __name__ == "__main__":
    unittest.main()
