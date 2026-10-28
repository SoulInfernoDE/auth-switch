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

from authswitch import core, discovery, guestaccounts, leaks, mcp, rootshell, sshaccess, update

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

    def test_resources_and_denied_access(self):
        manager = core.find_account(TOKEN)
        resources = [
            {"type": "qemu", "vmid": 101, "name": "web", "node": "pve"},
            {"type": "lxc", "vmid": 200, "name": "dns", "node": "pve"},
            {"type": "storage", "storage": "local", "node": "pve"},
            {"type": "storage", "storage": "local", "node": "pve2"},
            {"type": "node", "node": "pve"},
            {"type": "sdn", "sdn": "localnetwork"},
        ]
        with mock.patch.object(core, "request", return_value=resources):
            listed = core.list_resources(manager.host, manager)
        self.assertEqual([r["path"] for r in listed], ["/vms/101", "/vms/200", "/storage/local", "/nodes/pve"])
        self.assertEqual(listed[0]["label"], "101 · web")
        acl = [
            {"type": "token", "ugid": "ops@pve!ci", "path": "/vms/101", "roleid": "NoAccess"},
            {"type": "token", "ugid": "ops@pve!ci", "path": "/", "roleid": "PVEVMAdmin"},
            {"type": "token", "ugid": "other@pve!x", "path": "/vms/200", "roleid": "NoAccess"},
        ]
        with mock.patch.object(core, "request", return_value=acl):
            self.assertEqual(core.denied_paths(manager.host, "ops@pve!ci", manager), {"/vms/101"})
        with mock.patch.object(core, "request") as request:
            core.set_denied(manager.host, "ops@pve!ci", "/vms/101", True, manager)
            core.set_denied(manager.host, "ops@pve!ci", "/vms/101", False, manager)
        deny, allow = (call.args[5] for call in request.call_args_list)
        self.assertEqual(deny, {"path": "/vms/101", "roles": "NoAccess", "tokens": "ops@pve!ci", "propagate": True})
        self.assertTrue(allow["delete"])
        self.assertEqual(core.managers_for(manager.host, TOKEN), [manager])

    def test_subscription_and_repositories(self):
        manager = core.find_account(TOKEN)
        enterprise_on = {
            "files": [
                {"path": "/etc/apt/sources.list.d/pve-enterprise.sources", "repositories": [
                    {"Enabled": 1, "URIs": ["https://enterprise.proxmox.com/debian/pve"], "Components": ["pve-enterprise"]}]},
                {"path": "/etc/apt/sources.list.d/ceph.sources", "repositories": [
                    {"Enabled": 1, "URIs": ["https://enterprise.proxmox.com/debian/ceph-squid"], "Components": ["enterprise"]}]},
            ],
            "standard-repos": [
                {"handle": "enterprise", "status": 1}, {"handle": "no-subscription"},
                {"handle": "ceph-squid-enterprise", "status": 1}, {"handle": "ceph-squid-no-subscription"},
            ],
        }
        switched = {"files": [], "standard-repos": [{"handle": "no-subscription", "status": 1}]}
        calls = []

        def fake(host, token, secret, method, path, params=None, fingerprint=None):
            calls.append((method, path, params))
            if path == "/nodes":
                return [{"node": "pve", "status": "online"}]
            if path.endswith("/subscription"):
                return {"status": "notfound"}
            if path.endswith("/apt/repositories") and method == "GET":
                return switched if any(c[0] == "POST" for c in calls) else enterprise_on

        with mock.patch.object(core, "request", side_effect=fake):
            self.assertEqual(core.inspect_server(manager.host, manager)["state"], core.NEEDS_SETUP)
            self.assertEqual(core.stored_repository(manager.host), core.NEEDS_SETUP)
            changes = core.use_no_subscription_repository(manager.host, manager)
        writes = [(m, p["handle"] if "handle" in p else (p["path"], p["index"], p["enabled"])) for m, _path, p in calls if m != "GET"]
        self.assertEqual(writes, [
            ("PUT", "ceph-squid-no-subscription"),
            ("PUT", "no-subscription"),
            ("POST", ("/etc/apt/sources.list.d/pve-enterprise.sources", 0, False)),
            ("POST", ("/etc/apt/sources.list.d/ceph.sources", 0, False)),
        ])
        self.assertEqual(len(changes), 4)
        self.assertEqual(core.stored_repository(manager.host), core.NO_SUBSCRIPTION)

    def test_notice_fix_command_is_self_contained(self):
        import base64

        encoded = core.notice_fix_command().split()[1]
        self.assertEqual(base64.b64decode(encoded).decode(), core.NOTICE_FIX_SCRIPT)
        self.assertIn("99-pve-subscription-notice", core.NOTICE_FIX_SCRIPT)
        self.assertIn(r"/\1false/", core.NOTICE_FIX_SCRIPT)
        self.assertIn(r"(void\(\{ \/\/)+(Ext\.Msg\.show)/\2/g", core.NOTICE_FIX_SCRIPT)
        self.assertIn("systemd-run --quiet --on-active=3", core.NOTICE_FIX_SCRIPT)

    def test_web_language(self):
        manager = core.find_account(TOKEN)
        with mock.patch.object(core, "request", return_value={"language": "de", "keyboard": "de"}):
            self.assertEqual(core.get_web_language(manager.host, manager), "de")
        with mock.patch.object(core, "request") as request:
            core.set_web_language(manager.host, "fr", manager)
            core.set_web_language(manager.host, "", manager)
        self.assertEqual([c.args[3:6] for c in request.call_args_list], [
            ("PUT", "/cluster/options", {"language": "fr"}),
            ("PUT", "/cluster/options", {"delete": "language"}),
        ])
        self.assertIn("de", [code for code, _name in core.WEB_LANGUAGES])

    def test_node_updates(self):
        manager = core.find_account(TOKEN)
        upid = "UPID:pve:0000:0000:0000:aptupdate::root@pam!automation:"
        answers = {
            ("GET", "/cluster/status"): [{"type": "cluster"}, {"type": "node", "name": "pve", "local": 1}],
            ("GET", "/nodes"): [{"node": "pve", "status": "online"}, {"node": "pve2", "status": "offline"}],
            ("POST", "/nodes/pve/apt/update"): upid,
            ("GET", "/nodes/pve/status"): {"pveversion": "pve-manager/8.2.4/faa83925c9641325"},
            ("GET", "/nodes/pve/apt/update"): [{"Package": "pve-manager"}, {"Package": "libc6"}],
            ("GET", "/nodes/pve/apt/versions"): [],
        }

        def fake(host, token, secret, method, path, params=None, fingerprint=None):
            if "/tasks/" in path:
                return {"status": "stopped", "exitstatus": "OK"}
            return answers[(method, path)]

        with mock.patch.object(core, "request", side_effect=fake):
            nodes = core.node_updates(manager.host, manager, refresh=True)
        self.assertEqual(nodes, [{"node": "pve", "version": "8.2.4", "updates": 2, "packages": ["libc6", "pve-manager"], "local": True, "reboot": False}])
        self.assertEqual(core.major_upgrade_guide("8.2.4"), "https://pve.proxmox.com/wiki/Upgrade_from_8_to_9")
        self.assertIn("console=upgrade", core.upgrade_console_url(manager.host, "pve"))

    def test_reboot(self):
        manager = core.find_account(TOKEN)
        answers = {
            "/nodes/pve/qemu": [{"vmid": 101, "name": "web", "status": "running"}, {"vmid": 102, "status": "stopped"}],
            "/nodes/pve/lxc": [{"vmid": 200, "name": "dns", "status": "running"}],
            "/nodes/pve/qemu/101/config": {"onboot": 1},
            "/nodes/pve/lxc/200/config": {},
        }
        with mock.patch.object(core, "request", side_effect=lambda h, t, s, m, path, *a, **k: answers[path]):
            self.assertEqual(core.running_guests(manager.host, "pve", manager), [
                {"vmid": 101, "name": "web", "kind": "qemu", "onboot": True},
                {"vmid": 200, "name": "dns", "kind": "lxc", "onboot": False},
            ])
        with mock.patch.object(core, "request") as request:
            core.reboot_node(manager.host, "pve", manager)
        self.assertEqual(request.call_args.args[3:6], ("POST", "/nodes/pve/status", {"command": "reboot"}))
        states = [None, core.AuthError("down"), core.AuthError("down"), {"version": "9"}]

        def answer(*_args, **_kwargs):
            state = states.pop(0)
            if isinstance(state, Exception):
                raise state
            return state

        with mock.patch.object(core, "request", side_effect=answer), mock.patch("time.sleep"):
            self.assertTrue(core.wait_until_back(manager.host, manager))

    def test_pending_reboot_from_installed_kernels(self):
        status = {"current-kernel": {"release": "7.0.14-24-pve"}}
        versions = [
            {"Package": "proxmox-kernel-7.0.14-26-pve-signed", "CurrentState": "Installed"},
            {"Package": "proxmox-kernel-7.0.14-24-pve-signed", "CurrentState": "Installed"},
            {"Package": "proxmox-kernel-7.0", "CurrentState": "Installed"},
            {"Package": "proxmox-kernel-helper", "CurrentState": "Installed"},
        ]
        self.assertTrue(core.newer_kernel_installed(status, versions))
        self.assertFalse(core.newer_kernel_installed({"current-kernel": {"release": "7.0.14-26-pve"}}, versions))
        self.assertFalse(core.newer_kernel_installed({}, versions))
        old = [{"Package": "pve-kernel-6.8.12-4-pve", "CurrentState": "Installed"}]
        self.assertTrue(core.newer_kernel_installed({"current-kernel": {"release": "6.8.12-1-pve"}}, old))

    def test_upgrade_over_ssh_reports_a_needed_reboot(self):
        output = "Reading package lists...\npve-manager/8.4.1/2a5fa54a8503f96d (running kernel: 6.8.12-9-pve)\nAUTH-SWITCH-REBOOT\n"
        with mock.patch.object(core, "run_as_root", return_value=output) as run:
            self.assertEqual(core.upgrade_via_ssh("pve.example.com:8006"), {"reboot": True, "version": "pve-manager/8.4.1/2a5fa54a8503f96d (running kernel: 6.8.12-9-pve)"})
        self.assertIn("dist-upgrade", run.call_args.args[1])

    def test_local_blocks_are_enforced_for_the_mcp_server(self):
        account = core.find_account(TOKEN)
        core.set_access(account.host, TOKEN, "/vms/101", True, account, privsep=False, server_denied=set())
        core.set_access(account.host, TOKEN, "/storage/backup", True, account, privsep=False, server_denied=set())
        self.assertEqual(core.local_blocks(account.host, TOKEN), {"/vms/101", "/storage/backup"})
        resources = [{"vmid": 100, "type": "qemu"}, {"vmid": 101, "type": "qemu"}, {"storage": "backup", "type": "storage"}]
        with mock.patch.object(core, "request", return_value=resources) as request:
            self.assertEqual(core.api("GET", "/cluster/resources"), [{"vmid": 100, "type": "qemu"}])
            for path, params in (
                ("/nodes/pve/qemu/101/status/start", None),
                ("/nodes/pve/lxc/101/config", None),
                ("/nodes/pve/vzdump", {"vmid": "100,101"}),
                ("/nodes/pve/storage/backup/content", None),
                ("/nodes/pve/qemu/100/clone", {"newid": 101}),
            ):
                with self.assertRaises(core.AuthError, msg=path):
                    core.api("POST", path, params)
            core.api("POST", "/nodes/pve/qemu/100/status/start")
        self.assertEqual(request.call_count, 2)
        core.set_access(account.host, TOKEN, "/vms/101", False, account, privsep=False, server_denied=set())
        self.assertEqual(core.local_blocks(account.host, TOKEN), {"/storage/backup"})

    def test_server_blocks_are_adopted(self):
        account = core.find_account(TOKEN)
        core.adopt_server_blocks(account.host, TOKEN, {"/vms/100"})
        self.assertEqual(core.local_blocks(account.host, TOKEN), {"/vms/100"})
        with mock.patch.object(core, "request") as request:
            core.set_access(account.host, TOKEN, "/vms/100", False, account, privsep=False, server_denied={"/vms/100"})
        self.assertTrue(request.call_args.args[5]["delete"])
        self.assertEqual(core.local_blocks(account.host, TOKEN), set())

    def test_a_token_can_lift_its_own_block(self):
        account = core.find_account(TOKEN)
        calls = []

        def fake(host, token, secret, method, path, params=None, fingerprint=None):
            calls.append((method, path, dict(params or {})))
            privsep = [c[2]["privsep"] for c in calls if "privsep" in c[2]]
            if path == "/access/acl" and params.get("delete") and (not privsep or privsep[-1]):
                raise core.AuthError("HTTP 403 Permission check failed (/vms/101, Permissions.Modify|VM.Allocate)")

        with mock.patch.object(core, "request", side_effect=fake):
            core.set_access(account.host, TOKEN, "/vms/101", False, account, privsep=True, server_denied={"/vms/101"})
        steps = [(m, p, c.get("privsep", c.get("delete"))) for m, p, c in calls]
        self.assertEqual(steps, [
            ("PUT", "/access/acl", True),
            ("PUT", "/access/users/root@pam/token/automation", False),
            ("PUT", "/access/acl", True),
            ("PUT", "/access/users/root@pam/token/automation", True),
        ])

    def test_enforce_on_server_checks_the_role_first(self):
        account = core.find_account(TOKEN)
        with mock.patch.object(core, "request", return_value=[]) as request:
            with self.assertRaises(core.AuthError):
                core.enable_server_blocking(account.host, TOKEN, account)
        self.assertFalse(any("privsep" in (c.args[5] or {}) for c in request.call_args_list if len(c.args) > 5))

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

    def test_token_without_rights_is_recognised(self):
        answers = {"/version": {"version": "8.2.4"}, "/access/permissions": {}}
        with mock.patch.object(core, "request", side_effect=lambda h, t, s, m, path, *a, **k: answers[path]):
            profile = core.validate("pve.example.com:8006", TOKEN, SECRET)
        self.assertEqual((profile.valid, profile.has_rights), (True, False))
        answers["/access/permissions"] = {"/": {"Sys.Audit": 1}}
        with mock.patch.object(core, "request", side_effect=lambda h, t, s, m, path, *a, **k: answers[path]):
            self.assertTrue(core.validate("pve.example.com:8006", TOKEN, SECRET).has_rights)

    def test_form_encoding(self):
        self.assertEqual(core._encode({"onboot": True, "memory": 2048, "skip": None}), "onboot=1&memory=2048")
        # e.g. the "command" of /agent/exec, which the API expects as a repeated field
        self.assertEqual(
            core._encode({"command": ["cmd.exe", "/c", "ver"], "input-data": "x"}),
            "command=cmd.exe&command=%2Fc&command=ver&input-data=x",
        )


class NoticeTest(unittest.TestCase):
    PAGE = '<script type="text/javascript" src="/proxmoxlib.js?ver=v5.2.10-t1"></script>'
    SHOWN = "!res ||\n    res.data.status.toLowerCase() !== 'active'\n) {\n    Ext.Msg.show({\n title: gettext('No valid sub"

    def status(self, source):
        with mock.patch.object(core, "_public_get", side_effect=lambda host, path: self.PAGE if path == "/" else source):
            return core.notice_status("pve.example.com:8006")

    def test_notice_states(self):
        self.assertEqual(self.status(self.SHOWN), core.NOTICE_SHOWN)
        self.assertEqual(self.status(self.SHOWN.replace("Ext.Msg.show", "void({ //void({ //Ext.Msg.show")), core.NOTICE_BROKEN)
        self.assertEqual(self.status(self.SHOWN.replace("res.data.status.toLowerCase() !== 'active'", "false")), core.NOTICE_REMOVED)
        self.assertEqual(self.status("nothing"), core.NOTICE_UNKNOWN)


class _FakeSocket:
    """Plays the server side of the console websocket."""

    def __init__(self, replies):
        self.inbox = b"".join(self.frame(reply) for reply in replies)
        self.sent = []

    @staticmethod
    def frame(payload):
        return bytes([0x82, len(payload)]) + payload if len(payload) < 126 else bytes([0x82, 126]) + len(payload).to_bytes(2, "big") + payload

    def recv(self, count):
        chunk, self.inbox = self.inbox[:count], self.inbox[count:]
        return chunk

    def sendall(self, data):
        opcode, payload = rootshell._read_frame(_FakeSocket.reader(data))
        self.sent.append(payload)

    @staticmethod
    def reader(data):
        class Reader:
            buffer = data

            def recv(self, count):
                chunk, Reader.buffer = Reader.buffer[:count], Reader.buffer[count:]
                return chunk

        return Reader()

    def settimeout(self, _value):
        pass

    def close(self):
        pass


class RootShellTest(unittest.TestCase):
    def test_two_factor_needs_a_code(self):
        answers = [{"NeedTFA": 1, "ticket": "PVE:partial"}, {"ticket": "PVE:full", "CSRFPreventionToken": "csrf", "username": "root@pam"}]
        with mock.patch.object(rootshell, "_post", side_effect=lambda *a, **k: answers.pop(0)) as post:
            with self.assertRaises(rootshell.TwoFactorRequired):
                rootshell.sign_in("h:8006", "root@pam", "pw")
        answers[:0] = [{"NeedTFA": 1, "ticket": "PVE:partial"}]
        with mock.patch.object(rootshell, "_post", side_effect=lambda *a, **k: answers.pop(0)) as post:
            session = rootshell.sign_in("h:8006", "root@pam", "pw", "123456")
        self.assertEqual(session["ticket"], "PVE:full")
        self.assertEqual(post.call_args.args[2], {"username": "root@pam", "tfa-challenge": "PVE:partial", "password": "totp:123456"})

    def test_script_runs_in_the_console(self):
        sock = _FakeSocket([b"OK", b"echo ...base64 -d | sh; echo AUTH-SWITCH-EXIT:$?\r\n", b"auth-switch: subscription notice removed on pve\r\nAUTH-SWITCH-EXIT:0\r\n"])
        proxy = {"port": 5900, "ticket": "PVEVNC:abc", "user": "root@pam"}
        with mock.patch.object(rootshell, "_post", return_value=proxy), mock.patch.object(rootshell, "_open_websocket", return_value=sock) as ws:
            status, output = rootshell.run_script("h:8006", "pve", {"ticket": "T", "csrf": "C"}, "echo hi\n")
        self.assertEqual(status, 0)
        self.assertIn("notice removed on pve", output)
        self.assertIn("vncticket=PVEVNC%3Aabc", ws.call_args.args[1])
        self.assertEqual(sock.sent[0], b"root@pam:PVEVNC:abc\n")
        line = sock.sent[2].split(b":", 2)[2]
        encoded = line.split()[1]
        import base64
        self.assertEqual(base64.b64decode(encoded), b"echo hi\n")
        self.assertEqual(sock.sent[-1], b"0:5:exit\n")

    def test_closed_console_counts_as_done_when_the_notice_is_gone(self):
        session = {"ticket": "T", "csrf": "C"}
        with mock.patch.object(rootshell, "sign_in", return_value=session), \
                mock.patch.object(rootshell, "run_script", side_effect=rootshell.ConsoleClosed("closed")), \
                mock.patch.object(rootshell.time, "sleep"), \
                mock.patch.object(core, "notice_status", side_effect=[core.NOTICE_BROKEN, core.NOTICE_REMOVED]):
            self.assertEqual(rootshell.remove_notice("h:8006", "pve", "root@pam", "pw"), "")
        self.assertEqual(session, {})
        with mock.patch.object(rootshell, "sign_in", return_value={}), \
                mock.patch.object(rootshell, "run_script", side_effect=rootshell.ConsoleClosed("closed")), \
                mock.patch.object(rootshell.time, "sleep"), \
                mock.patch.object(core, "notice_status", return_value=core.NOTICE_SHOWN):
            with self.assertRaises(rootshell.ConsoleClosed):
                rootshell.remove_notice("h:8006", "pve", "root@pam", "pw")

    def test_frames_are_masked_and_readable(self):
        frame = rootshell._frame(b"x" * 300)
        self.assertTrue(frame[1] & 0x80)
        self.assertEqual(rootshell._read_frame(_FakeSocket.reader(frame)), (0x2, b"x" * 300))


class SshAccessTest(unittest.TestCase):
    """Runs against a temporary home folder; the real ~/.ssh is never touched."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.home = Path(self.dir.name)
        (self.home / ".ssh").mkdir(mode=0o700)
        (self.home / ".ssh" / "config").write_text("Host other\n    HostName other.example.com\n")
        self.keys, self.secrets = {}, {}
        patches = [
            mock.patch.dict(os.environ, {"HOME": self.dir.name, "XDG_CONFIG_HOME": self.dir.name}),
            mock.patch.object(core, "store_secret", lambda h, t, s: self.secrets.__setitem__((h, t), s)),
            mock.patch.object(core, "lookup_secret", lambda h, t: self.secrets.get((h, t), "")),
            mock.patch.object(core, "validate", return_value=core.Profile(valid=True)),
            mock.patch.object(sshaccess, "_store_key", lambda h, k: self.keys.__setitem__(h, k)),
            mock.patch.object(sshaccess, "_lookup_key", lambda h: self.keys.get(h, "")),
            mock.patch.object(sshaccess, "_clear_key", lambda h: self.keys.pop(h, None)),
            mock.patch.object(rootshell, "sign_in", return_value={"ticket": "T", "csrf": "C"}),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.host = core.add_account("pve.example.com", TOKEN, SECRET).host

    def test_set_up_switch_and_remove(self):
        output = "HOSTKEY ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleHostKey\nHOSTKEY ssh-rsa AAAAB3NzaC1yc2EAAAADAQABExample\n"
        with mock.patch.object(rootshell, "run_script", return_value=(0, output)) as run:
            sshaccess.set_up(self.host, "pve", "pve", "pw")
        script = run.call_args.args[3]
        public = sshaccess._state(self.host)["public"]
        self.assertIn(public, script)
        self.assertTrue(public.startswith("ssh-ed25519 ") and public.endswith("auth-switch@pve.example.com:8006"))
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", self.keys[self.host])
        key_file = sshaccess._key_file(self.host)
        self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)
        config = (self.home / ".ssh" / "config").read_text()
        self.assertTrue(config.startswith(f"Include {sshaccess._include_file()}"))
        self.assertIn("Host other", config)
        include = sshaccess._include_file().read_text()
        self.assertIn("Host pve\n    HostName pve.example.com\n    User root", include)
        known = (self.home / ".ssh" / "known_hosts").read_text()
        self.assertIn("pve.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleHostKey", known)
        self.assertEqual(sshaccess.status(self.host), {"set_up": True, "enabled": True, "alias": "pve"})

        sshaccess.disable(self.host)
        self.assertFalse(key_file.exists())
        self.assertNotIn("Host pve", sshaccess._include_file().read_text())
        self.assertIn(self.host, self.keys)
        sshaccess.enable(self.host)
        self.assertTrue(key_file.exists())
        self.assertEqual((self.home / ".ssh" / "config").read_text().count("Include"), 1)

        with mock.patch.object(sshaccess.subprocess, "run") as ssh:
            sshaccess.remove(self.host)
        self.assertIn(public.split()[1], ssh.call_args.kwargs["input"])
        self.assertFalse(key_file.exists())
        self.assertNotIn(self.host, self.keys)
        self.assertEqual(sshaccess.status(self.host), {"set_up": False, "enabled": False, "alias": ""})

    def test_app_uses_the_key_while_access_is_on(self):
        output = "HOSTKEY ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleHostKey\n"
        plain = core.ssh_command(self.host)
        self.assertNotIn("-i", plain)
        with mock.patch.object(rootshell, "run_script", return_value=(0, output)):
            sshaccess.set_up(self.host, "pve", "pve", "pw")
        command = core.ssh_command(self.host)
        self.assertEqual(command[-1], "root@pve.example.com")
        self.assertIn(str(sshaccess._key_file(self.host)), command)
        self.assertIn("IdentitiesOnly=yes", command)
        with mock.patch.object(core.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="done", stderr="")) as run:
            core.run_as_root(self.host, "echo hi\n", 60)
        self.assertIn(str(sshaccess._key_file(self.host)), run.call_args.args[0])
        sshaccess.disable(self.host)
        self.assertNotIn("-i", core.ssh_command(self.host))

    def test_failed_install_leaves_nothing_behind(self):
        with mock.patch.object(rootshell, "run_script", return_value=(1, "permission denied")):
            with self.assertRaises(core.AuthError):
                sshaccess.set_up(self.host, "pve", "pve", "pw")
        self.assertEqual(self.keys, {})
        self.assertFalse(sshaccess._own_dir().exists())


class ClaudeIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        patches = [
            mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": self.dir.name, "XDG_CONFIG_HOME": self.dir.name}),
            mock.patch.object(core, "claude_cli", return_value=None),
            mock.patch.object(core, "mcp_command", return_value=["/usr/bin/auth-switch-mcp"]),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_nothing_installed(self):
        self.assertEqual(core.claude_targets(), [])

    def test_register_in_code_and_desktop(self):
        (self.root / ".claude.json").write_text(json.dumps({"numStartups": 3, "mcpServers": {"other": {"command": "x"}}}))
        (self.root / ".claude.json").chmod(0o600)
        (self.root / "Claude").mkdir()
        desktop = self.root / "Claude" / "claude_desktop_config.json"
        desktop.write_text(json.dumps({"preferences": {"a": 1}, "mcpServers": {"blender": {"command": "b"}}}))
        self.assertEqual(core.claude_targets(), ["code", "desktop"])
        self.assertFalse(core.claude_registered())
        core.claude_register()
        code = json.loads((self.root / ".claude.json").read_text())
        self.assertEqual(code["numStartups"], 3)
        self.assertEqual(code["mcpServers"]["auth-switch"]["command"], "/usr/bin/auth-switch-mcp")
        self.assertIn("other", code["mcpServers"])
        self.assertEqual((self.root / ".claude.json").stat().st_mode & 0o777, 0o600)
        settings = json.loads(desktop.read_text())
        self.assertEqual(settings["mcpServers"]["auth-switch"], {"command": "/usr/bin/auth-switch-mcp", "args": []})
        self.assertEqual(settings["preferences"], {"a": 1})
        self.assertTrue(core.claude_registered())
        core.claude_unregister()
        self.assertNotIn("auth-switch", json.loads(desktop.read_text())["mcpServers"])
        self.assertNotIn("auth-switch", json.loads((self.root / ".claude.json").read_text())["mcpServers"])
        self.assertFalse(core.claude_registered())

    def test_integration_lines_are_exempt_from_restricted_terms(self):
        context = leaks.Context()
        rules = {"terms": ["Acme"], "allow": ["Acme Tools", ".acme.json"]}
        leaks._restricted_settings(context, {"restricted": rules})
        self.assertEqual(leaks.scan_text('title=_("Acme Tools integration")', "t", context), [])
        self.assertEqual(leaks.scan_text("Path.home() / '.acme.json'", "t", context), [])
        attribution = leaks.scan_text("Co-Authored-By: Acme Tools <x@y.invalid>", "t", context)
        self.assertEqual([f.kind for f in attribution], ["restricted-attribution"])
        self.assertEqual([f.kind for f in leaks.scan_text("asked acme about it", "t", context)], ["restricted-term"])


class GuestAccountTest(unittest.TestCase):
    def setUp(self):
        # Compare against the English source texts whatever the locale of the machine running the tests.
        patcher = mock.patch.object(guestaccounts, "_", lambda text: text)
        patcher.start()
        self.addCleanup(patcher.stop)

    def guest(self, kind="qemu"):
        return guestaccounts.Guest("pve.example.com:8006", "pve", kind, 100, core.Account("pve.example.com:8006", TOKEN, True))

    def test_windows_users(self):
        guest = self.guest()
        answer = json.dumps([{"Name": "dana", "FullName": "Dana", "Sid": "S-1"}, {"Name": "ops", "FullName": None, "Sid": "S-2"}])
        with mock.patch.object(guest, "system", return_value=guestaccounts.WINDOWS), mock.patch.object(guest, "run", return_value=(0, answer)):
            self.assertEqual(guest.users(), [{"name": "dana", "fullname": "Dana"}, {"name": "ops", "fullname": ""}])

    def test_linux_users(self):
        guest = self.guest()
        passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\ndana:x:1000:1000:Dana D,,,:/home/dana:/bin/bash\nsvc:x:1001:1001::/srv:/bin/false\n"
        with mock.patch.object(guest, "system", return_value=guestaccounts.LINUX), mock.patch.object(guest, "run", return_value=(0, passwd)):
            self.assertEqual([u["name"] for u in guest.users()], ["root", "dana"])

    def test_password_never_on_a_command_line(self):
        guest = self.guest("qemu")
        with mock.patch.object(guest, "_api") as api:
            guest.set_password("dana", "s3cret pass")
        api.assert_called_once_with("POST", "/agent/set-user-password", {"username": "dana", "password": "s3cret pass"})
        container = self.guest("lxc")
        with mock.patch.object(container, "run", return_value=(0, "")) as run:
            container.set_password("dana", "s3cret pass")
        self.assertEqual(run.call_args.args[0], ["chpasswd"])
        self.assertEqual(run.call_args.kwargs["stdin"], "dana:s3cret pass\n")
        with self.assertRaises(core.AuthError):
            guest.set_password("dana; rm -rf /", "x")

    def test_rename_checks_names_and_builds_scripts(self):
        guest = self.guest()
        for bad in ("", "1abc", "with space", "a" * 21, "x'y"):
            with self.assertRaises(core.AuthError, msg=bad):
                guest.rename("dana", bad, preview=True)
        script = guestaccounts.windows_rename_script("dana", "erin", preview=True)
        self.assertIn("$old = 'dana'; $new = 'erin'; $preview = $true", script)
        self.assertIn("ProfileImagePath", script)
        linux = guestaccounts.linux_rename_script("dana", "erin", preview=False)
        self.assertIn("old='dana'; new='erin'; preview=0", linux)
        self.assertEqual(subprocess.run(["sh", "-n"], input=linux, text=True).returncode, 0)
        with mock.patch.object(guest, "system", return_value=guestaccounts.LINUX), mock.patch.object(guest, "run", return_value=(0, "ACCOUNT\tdana\terin\nnoise\n")) as run:
            self.assertEqual(guest.rename("dana", "erin", preview=True), "Account: dana → erin")
        self.assertEqual(run.call_args.args[0], ["sh", "-s"])

    def test_report_is_translated_from_tags(self):
        text = guestaccounts.describe("ACCOUNT\tdana\terin\r\nHIVE\tNTUSER.DAT\t74\nLEFTCOUNT\t1\nLEFT\tHKLM\\X\n")
        self.assertEqual(text.splitlines(), ["Account: dana → erin", "Paths in NTUSER.DAT: 74", "Places still naming the old name: 1", "  HKLM\\X"])
        self.assertEqual(guestaccounts.describe("ERROR\tsignedin\tdana\n"), "dana is signed in. Sign the account out first, then rename it.")

    def test_containers_need_ssh(self):
        container = self.guest("lxc")
        with mock.patch.object(sshaccess, "status", return_value={"enabled": False}):
            with self.assertRaises(core.AuthError):
                container.run(["true"])


class DiscoveryTest(unittest.TestCase):
    def test_local_networks(self):
        interfaces = [
            {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]},
            {"ifname": "wlan0", "addr_info": [{"local": "192.168.178.22", "prefixlen": 24}]},
            {"ifname": "eth1", "addr_info": [{"local": "10.20.30.40", "prefixlen": 16}]},
            {"ifname": "docker0", "addr_info": [{"local": "172.17.0.1", "prefixlen": 16}]},
            {"ifname": "eth2", "addr_info": [{"local": "81.2.69.5", "prefixlen": 24}]},
        ]
        with mock.patch.object(discovery.subprocess, "run", return_value=mock.Mock(stdout=json.dumps(interfaces))):
            networks = [str(n) for n in discovery.local_networks()]
        self.assertEqual(networks, ["192.168.178.0/24", "10.20.30.0/24"])

    def test_discover_keeps_only_proxmox(self):
        import ipaddress

        names = {"192.168.1.10": "pve", "192.168.1.11": "pve2"}
        with mock.patch.object(discovery, "probe", side_effect=lambda address, timeout: names.get(address)):
            found = discovery.discover([ipaddress.ip_network("192.168.1.0/28")])
        self.assertEqual(found, [
            {"host": "192.168.1.10:8006", "address": "192.168.1.10", "name": "pve"},
            {"host": "192.168.1.11:8006", "address": "192.168.1.11", "name": "pve2"},
        ])


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        _Handler.seen.append(self.headers.get("Authorization"))
        body = json.dumps({"data": {"version": "8.2.4"}}).encode()
        if self.path == "/":
            body = b"<html><head><title>pve-lab - Proxmox Virtual Environment</title></head></html>"
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

    def test_probe_recognises_the_web_interface(self):
        address, port = self.host.split(":")
        self.assertEqual(discovery.probe(address, int(port)), "pve-lab")
        self.assertIsNone(discovery.probe("127.0.0.1", 1))
        self.assertEqual(_Handler.seen, [None])

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
