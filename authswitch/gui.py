"""GTK 4 / libadwaita window for switching Proxmox VE accounts."""

from __future__ import annotations

import shutil
import sys
import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from . import __version__, core, discovery, sound, update  # noqa: E402
from .i18n import _  # noqa: E402

APP_ID = ICON_NAME = "dev.authswitch.AuthSwitch"


def run_async(func, callback) -> None:
    """Run ``func`` in a thread and deliver ``(result, error)`` on the main loop."""

    def worker():
        try:
            result, error = func(), None
        except Exception as exc:  # shown to the user by the callback
            result, error = None, exc
        GLib.idle_add(lambda: callback(result, error) and False)

    threading.Thread(target=worker, daemon=True).start()


class Window(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application):
        super().__init__(application=app, title="Auth-Switch", default_width=460, default_height=760)
        self.settings = core.load_settings()
        self.profiles: dict[core.Account, core.Profile] = {}
        self.host_groups: list[Adw.PreferencesGroup] = []
        self.generation = 0
        self.reload_source = 0
        self.update_url = ""

        header = Adw.HeaderBar()
        add_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text=_("Add account"))
        add_button.connect("clicked", lambda *_args: self.ask_account())
        header.pack_start(add_button)
        refresh_button = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Refresh"))
        refresh_button.connect("clicked", lambda *_args: self.reload(recheck=True))
        about_button = Gtk.Button(icon_name="help-about-symbolic", tooltip_text=_("About"))
        about_button.connect("clicked", lambda *_args: self.show_about())
        header.pack_end(about_button)
        header.pack_end(refresh_button)

        self.page = Adw.PreferencesPage()
        logo = Adw.PreferencesGroup()
        logo.add(Gtk.Image(icon_name=ICON_NAME, pixel_size=128, halign=Gtk.Align.CENTER))
        self.page.add(logo)
        self.status = Adw.StatusPage(icon_name=ICON_NAME)
        self.stack = Gtk.Stack()
        self.stack.add_named(self.page, "accounts")
        self.stack.add_named(self.status, "status")
        self.toasts = Adw.ToastOverlay(child=self.stack)

        self.update_banner = Adw.Banner(button_label=_("Show"))
        self.update_banner.connect("button-clicked", lambda *_args: self.open_uri(self.update_url))
        view = Adw.ToolbarView(content=self.toasts)
        view.add_top_bar(header)
        view.add_top_bar(self.update_banner)
        self.set_content(view)

        self.build_options()
        for name, handler, parameter in (
            ("web", lambda _a, p: self.open_uri(core.web_interface(p.unpack())), "s"),
            ("again", lambda _a, p: self.ask_account(*p.unpack()), "(ss)"),
            ("permissions", lambda _a, p: self.edit_permissions(*p.unpack()), "(ss)"),
            ("repository", lambda _a, p: self.check_subscription(*p.unpack()), "(ss)"),
            ("maintenance", lambda _a, p: self.open_maintenance(*p.unpack()), "(ss)"),
            ("remove", self.on_remove_action, "(ss)"),
        ):
            action = Gio.SimpleAction.new(name, GLib.VariantType.new(parameter))
            action.connect("activate", handler)
            self.add_action(action)

        # Follow changes made elsewhere, e.g. by the MCP server or the command line.
        self.monitor = Gio.File.new_for_path(str(core.accounts_file())).monitor_file(
            Gio.FileMonitorFlags.WATCH_MOVES, None
        )
        self.monitor.connect("changed", self.on_accounts_changed)
        self.reload()
        self.look_for_update()

    # --- helpers -----------------------------------------------------------

    def toast(self, text: str, sound_name: str | None = None) -> None:
        self.toasts.add_toast(Adw.Toast(title=text, use_markup=False))
        if sound_name and self.settings["sounds"]:
            sound.play(sound_name)

    def explain(self, heading: str, text: str) -> None:
        """Error that needs more room than a toast."""
        dialog = Adw.MessageDialog(transient_for=self, heading=heading, body=text)
        dialog.add_response("close", _("Close"))
        dialog.present()
        if self.settings["sounds"]:
            sound.play("error")

    def copy(self, text: str) -> None:
        self.get_clipboard().set(text)
        self.toast(_("Copied to clipboard"))

    def open_uri(self, uri: str) -> None:
        if uri:
            Gio.AppInfo.launch_default_for_uri(uri, None)

    def show_about(self) -> None:
        Adw.AboutWindow(
            transient_for=self,
            application_name="Auth-Switch",
            application_icon=ICON_NAME,
            version=__version__,
            comments=_("Switch between Proxmox VE accounts"),
            website="https://github.com/SoulInfernoDE/auth-switch",
            issue_url="https://github.com/SoulInfernoDE/auth-switch/issues",
            license_type=Gtk.License.MIT_X11,
        ).present()

    def on_accounts_changed(self, *_args) -> None:
        if self.reload_source:
            GLib.source_remove(self.reload_source)
        self.reload_source = GLib.timeout_add(300, self.on_reload_timeout)

    def on_reload_timeout(self) -> bool:
        self.reload_source = 0
        self.reload()
        return GLib.SOURCE_REMOVE

    # --- account list ------------------------------------------------------

    def reload(self, recheck: bool = False) -> None:
        self.generation += 1
        if recheck:
            self.profiles.clear()
        for group in self.host_groups:
            self.page.remove(group)
        self.host_groups.clear()

        accounts = core.list_accounts()
        if not accounts:
            self.status.set_title(_("No accounts yet"))
            self.status.set_description(_("Add an API token of your Proxmox VE server to get started."))
            button = Gtk.Button(label=_("Add account"), halign=Gtk.Align.CENTER)
            button.add_css_class("pill")
            button.add_css_class("suggested-action")
            button.connect("clicked", lambda *_args: self.ask_account())
            self.status.set_child(button)
            self.stack.set_visible_child_name("status")
            return
        self.stack.set_visible_child_name("accounts")

        groups: dict[str, Adw.PreferencesGroup] = {}
        for account in accounts:
            if account.host not in groups:
                groups[account.host] = self.build_host_group(account.host)
                self.host_groups.append(groups[account.host])
            groups[account.host].add(self.build_row(account))
        # Keep the options group below the accounts.
        self.page.remove(self.options)
        for group in self.host_groups:
            self.page.add(group)
        self.page.add(self.options)

    def build_host_group(self, host: str) -> Adw.PreferencesGroup:
        pinned = core.pinned_fingerprint(host)
        parts = [_("Certificate confirmed by you") if pinned else _("Certificate trusted by the system")]
        repository = {
            core.ENTERPRISE: _("Enterprise Repository"),
            core.NO_SUBSCRIPTION: _("No-Subscription Repository"),
            core.NEEDS_SETUP: _("No subscription – repository not set up"),
        }.get(core.stored_repository(host))
        if repository:
            parts.insert(0, repository)
        group = Adw.PreferencesGroup(title=host, description=" · ".join(parts))
        button = Gtk.Button(icon_name="web-browser-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Open web interface"))
        button.add_css_class("flat")
        button.connect("clicked", lambda *_args: self.open_uri(core.web_interface(host)))
        group.set_header_suffix(button)
        return group

    def build_row(self, account: core.Account) -> Adw.ActionRow:
        row = Adw.ActionRow(title=account.token_id, use_markup=False)
        avatar = Adw.Avatar(size=40, text=account.user.split("@", 1)[0], show_initials=True)
        row.add_prefix(avatar)

        if account.active:
            check = Gtk.Image(icon_name="object-select-symbolic")
            check.add_css_class("accent")
            row.add_suffix(check)
        else:
            button = Gtk.Button(label=_("Switch"), valign=Gtk.Align.CENTER)
            button.connect("clicked", lambda *_args: self.on_row_button(account))
            row.add_suffix(button)
            row.set_activatable_widget(button)
            row.button = button

        target = GLib.Variant("(ss)", (account.host, account.token_id))
        menu = Gio.Menu()
        for label, action, value in (
            (_("Permissions…"), "win.permissions", target),
            (_("Subscription and repository…"), "win.repository", target),
            (_("Updates and language…"), "win.maintenance", target),
            (_("Open web interface"), "win.web", GLib.Variant("s", account.host)),
            (_("Enter secret again"), "win.again", target),
            (_("Remove"), "win.remove", target),
        ):
            item = Gio.MenuItem.new(label, None)
            item.set_action_and_target_value(action, value)
            menu.append_item(item)
        access = Gtk.MenuButton(
            icon_name="changes-prevent-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Access to guests and storage")
        )
        access.add_css_class("flat")
        access.set_popover(self.build_access_popover(account))
        row.add_suffix(access)
        more = Gtk.MenuButton(icon_name="view-more-symbolic", menu_model=menu, valign=Gtk.Align.CENTER)
        more.add_css_class("flat")
        row.add_suffix(more)

        generation = self.generation

        def show(profile, error=None):
            if generation != self.generation:
                return
            if error or profile is None:
                profile = core.Profile(valid=None)
            self.profiles[account] = profile
            self.show_profile(row, account, profile)

        if account in self.profiles:
            show(self.profiles[account])
        else:
            row.set_subtitle(_("Checking token…"))
            run_async(lambda: core.fetch_profile(account), show)
        return row

    def show_profile(self, row, account: core.Account, profile: core.Profile) -> None:
        if profile.valid is False:
            row.set_subtitle(_("Token invalid – enter the secret again"))
            if not account.active:
                row.button.set_label(_("Enter again"))
            return
        if profile.valid is None:
            row.set_subtitle(_("Server not reachable"))
            return
        parts = [_("Proxmox VE {version}").format(version=profile.version)] if profile.version else []
        if account.active:
            parts.append(_("Active"))
        row.set_subtitle(" · ".join(parts))

    # --- actions -----------------------------------------------------------

    def on_row_button(self, account: core.Account) -> None:
        profile = self.profiles.get(account)
        if profile is not None and profile.valid is False:
            self.ask_account(account.host, account.token_id)
        else:
            self.switch(account)

    def switch(self, account: core.Account) -> None:
        def done(_result, error):
            if error:
                self.explain(_("Switching failed"), str(error))
                return
            self.toast(_("Switched to {token}").format(token=account.token_id), "switch")
            self.reload()

        run_async(lambda: core.switch_account(account.token_id, account.host), done)

    def on_remove_action(self, _action, parameter) -> None:
        host, token_id = parameter.unpack()
        account = next((a for a in core.list_accounts() if (a.host, a.token_id) == (host, token_id)), None)
        if account is None:
            return
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("Remove {token}?").format(token=token_id),
            body=_(
                "The secret is deleted from the system keyring. The token itself stays valid on {host}; revoke it "
                "in the web interface if you no longer need it."
            ).format(host=host),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("remove", _("Remove"))
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)

        def done(_result, error):
            if error:
                self.explain(_("Removing failed"), str(error))
            else:
                self.toast(_("Removed {token}").format(token=token_id), "signout")
            self.reload(recheck=True)

        def on_response(_dialog, response):
            if response == "remove":
                run_async(lambda: core.remove_account(account), done)

        dialog.connect("response", on_response)
        dialog.present()

    # --- permissions ------------------------------------------------------

    def build_access_popover(self, account: core.Account) -> Gtk.Popover:
        """Drop-down with one switch per guest, storage and node; off means the token is denied access."""
        managers = core.managers_for(account.host, account.token_id)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)
        heading = Gtk.Label(label=_("Access for {token}").format(token=account.token_id), xalign=0)
        heading.add_css_class("heading")
        hint = Gtk.Label(label=_("Switched off means no access, even if broader rights would allow it."), xalign=0, wrap=True, max_width_chars=40)
        hint.add_css_class("dim-label")
        status = Gtk.Label(xalign=0, wrap=True, max_width_chars=40)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        scrolled = Gtk.ScrolledWindow(child=rows, hscrollbar_policy=Gtk.PolicyType.NEVER, propagate_natural_height=True, max_content_height=420, min_content_width=340)
        chooser = Gtk.DropDown(model=Gtk.StringList.new([a.token_id for a in managers]), tooltip_text=_("Change with"))
        chooser.set_visible(len(managers) > 1)
        for widget in (heading, hint, status, scrolled, chooser):
            box.append(widget)
        popover = Gtk.Popover(child=box)
        icons = {"qemu": "computer-symbolic", "lxc": "package-x-generic-symbolic", "storage": "drive-harddisk-symbolic", "node": "network-server-symbolic"}
        kinds = {"qemu": _("Virtual machine"), "lxc": _("Container"), "storage": _("Storage"), "node": _("Node")}

        def manager() -> core.Account:
            return managers[chooser.get_selected()]

        def toggled(switch, _pspec, path):
            if getattr(switch, "busy", False):
                return
            denied = not switch.get_active()
            switch.set_sensitive(False)

            def done(_result, error):
                switch.set_sensitive(True)
                if error:
                    switch.busy = True
                    switch.set_active(denied)
                    switch.busy = False
                    self.explain(_("Access could not be changed"), str(error))
                else:
                    text = _("Access to {path} denied") if denied else _("Access to {path} allowed")
                    self.toast(text.format(path=path), "signout" if denied else "switch")

            run_async(lambda: core.set_denied(account.host, account.token_id, path, denied, manager()), done)

        def loaded(result, error):
            while (child := rows.get_first_child()) is not None:
                rows.remove(child)
            if error:
                status.set_label(str(error))
                return
            resources, denied, privsep = result
            status.set_label("" if privsep else _("This token has no privilege separation, so denying access has no effect."))
            for resource in resources:
                row = Adw.ActionRow(title=resource["label"], subtitle=kinds[resource["kind"]], use_markup=False)
                row.add_prefix(Gtk.Image(icon_name=icons[resource["kind"]]))
                switch = Gtk.Switch(active=resource["path"] not in denied, valign=Gtk.Align.CENTER, tooltip_text=resource["path"])
                switch.connect("notify::active", toggled, resource["path"])
                row.add_suffix(switch)
                row.set_activatable_widget(switch)
                rows.append(row)
            if not resources:
                status.set_label(_("No guests, storages or nodes are visible to the selected account."))

        def load(*_args):
            status.set_label(_("Loading…"))
            chosen = manager()

            def fetch():
                return (
                    core.list_resources(account.host, chosen),
                    core.denied_paths(account.host, account.token_id, chosen),
                    core.token_permissions(account.host, account.token_id, chosen)["privsep"],
                )

            run_async(fetch, loaded)

        popover.connect("show", load)
        chooser.connect("notify::selected", load)
        return popover

    def edit_permissions(self, host: str, token_id: str) -> None:
        """Switches for the token's roles; another account of the server may be needed to change them."""
        # A token rarely may change its own rights, so prefer another account of the server.
        managers = core.managers_for(host, token_id)

        def loaded(result, error, manager):
            if error:
                others = [a for a in managers if a != manager]
                text = str(error)
                if others:
                    text += "\n\n" + _("Try again with another account of this server.")
                self.explain(_("Permissions could not be read"), text)
                return
            self.show_permissions(host, token_id, managers, manager, result)

        manager = managers[0]
        run_async(lambda: core.token_permissions(host, token_id, manager), lambda r, e: loaded(r, e, manager))

    def show_permissions(self, host, token_id, managers, manager, current) -> None:
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(440, -1)
        switches = {}
        for role, title, subtitle in core.permission_roles():
            row = Adw.SwitchRow(title=title, subtitle=subtitle, active=role in current["roles"])
            row.set_tooltip_text(role)
            rows.append(row)
            switches[role] = row
        chooser = Adw.ComboRow(
            title=_("Change with"), model=Gtk.StringList.new([a.token_id for a in managers]), selected=managers.index(manager)
        )
        rows.append(chooser)
        scrolled = Gtk.ScrolledWindow(child=rows, min_content_height=420, hscrollbar_policy=Gtk.PolicyType.NEVER)

        body = _(
            "Roles for {token} on the whole server (path /). Rights on other paths stay as they are. Changing them "
            "needs an account with the right to modify permissions, such as a token of root@pam."
        ).format(token=token_id)
        if not current["privsep"]:
            body += "\n\n" + _(
                "This token has no privilege separation, so it holds all rights of its user and these roles have no "
                "effect. Turn on privilege separation in the web interface to limit it."
            )
        dialog = Adw.MessageDialog(
            transient_for=self, heading=_("Permissions"), body=body, extra_child=scrolled
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("apply", _("Apply"))
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)

        def applied(_result, error):
            if error:
                self.explain(_("Permissions could not be changed"), str(error))
            else:
                self.toast(_("Permissions of {token} changed").format(token=token_id), "success")

        def on_response(_dialog, response):
            if response != "apply":
                return
            wanted = {role for role, row in switches.items() if row.get_active()}
            add, remove = wanted - current["roles"], current["roles"] - wanted
            changer = managers[chooser.get_selected()]
            run_async(lambda: core.set_token_roles(host, token_id, add, remove, changer), applied)

        dialog.connect("response", on_response)
        dialog.present()

    # --- adding an account -------------------------------------------------

    def ask_account(self, host: str = "", token_id: str = "") -> None:
        """Dialog for adding an account: server, token ID and secret."""
        server = Adw.EntryRow(title=_("Server address, e.g. pve.example.com"), text=host)
        token = Adw.EntryRow(title=_("API token ID, e.g. root@pam!auth-switch"), text=token_id)
        secret = Adw.PasswordEntryRow(title=_("Secret"))
        web = Gtk.Button(icon_name="web-browser-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Open web interface"))
        web.add_css_class("flat")
        server.add_suffix(web)
        found_model = Gtk.StringList()
        found = Adw.ComboRow(title=_("Servers in your network"), model=found_model)
        search = Gtk.Button(icon_name="system-search-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Search again"))
        search.add_css_class("flat")
        spinner = Gtk.Spinner()
        found.add_suffix(spinner)
        found.add_suffix(search)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(420, -1)
        for row in (found, server, token, secret):
            rows.append(row)
        servers: list[dict] = []
        known = {account.host for account in core.list_accounts()}

        def discovered(result, error):
            spinner.stop()
            search.set_sensitive(True)
            servers[:] = result or []
            names = [s["name"] for s in servers]
            # The address follows in the field below; it only goes into the list to tell equal names apart.
            labels = [s["name"] if names.count(s["name"]) == 1 else f"{s['name']} ({s['address']})" for s in servers]
            found_model.splice(0, found_model.get_n_items(), [
                label + (" " + _("(already added)") if s["host"] in known else "") for label, s in zip(labels, servers)
            ])
            if error or not servers:
                found.set_subtitle(_("No Proxmox VE server found in your local networks"))
                return
            found.set_subtitle(_("{count} found").format(count=len(servers)))
            if not server.get_text().strip():
                fresh = [s for s in servers if s["host"] not in known] or servers
                found.set_selected(servers.index(fresh[0]))
                server.set_text(fresh[0]["host"])

        def search_network(*_args):
            spinner.start()
            search.set_sensitive(False)
            found.set_subtitle(_("Searching your local networks…"))
            run_async(discovery.discover, discovered)

        def picked(*_args):
            index = found.get_selected()
            if 0 <= index < len(servers):
                server.set_text(servers[index]["host"])

        found.connect("notify::selected", picked)
        search.connect("clicked", search_network)
        search_network()

        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("Add account"),
            body=_(
                "Create an API token in the web interface under Datacenter → Permissions → API Tokens and copy its "
                "ID and secret. The secret is kept in the system keyring only."
            ),
            extra_child=rows,
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("add", _("Add"))
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("add")

        def update(*_args):
            ready = bool(core.normalize_host(server.get_text())) and bool(core.TOKEN_ID.fullmatch(token.get_text().strip()))
            dialog.set_response_enabled("add", ready and bool(secret.get_text().strip()))

        def on_response(_dialog, response):
            if response == "add":
                self.add_account(core.normalize_host(server.get_text()), token.get_text().strip(), secret.get_text())

        web.connect("clicked", lambda *_args: self.open_uri(core.web_interface(core.normalize_host(server.get_text()))))
        for row in (server, token, secret):
            row.connect("changed", update)
        update()
        dialog.connect("response", on_response)
        dialog.present()

    def add_account(self, host: str, token_id: str, secret: str) -> None:
        """Check the certificate first; a server without a trusted one needs the user's confirmation."""

        def added(account, error):
            if error:
                self.explain(_("Adding failed"), str(error))
                return
            self.toast(_("Added {token}").format(token=account.token_id), "success")
            self.reload(recheck=True)
            self.check_subscription(account.host, account.token_id, quiet=True)

        def add(fingerprint: str = ""):
            run_async(lambda: core.add_account(host, token_id, secret, fingerprint), added)

        def checked(result, error):
            if error:
                self.explain(_("Adding failed"), str(error))
            elif result is True:
                add()
            else:
                self.confirm_certificate(host, result, add)

        def check():
            if core.certificate_trusted(host):
                return True
            return core.server_fingerprint(host)

        run_async(check, checked)

    def confirm_certificate(self, host: str, fingerprint: str, accept) -> None:
        previous = core.pinned_fingerprint(host)
        body = _(
            "The certificate of {host} is not signed by an authority your system trusts, which is normal for "
            "Proxmox VE. Compare this SHA-256 fingerprint with the one shown under Node → System → Certificates, "
            "or by 'pvenode cert info' on the server. Only continue if they match."
        ).format(host=host)
        if previous and previous != fingerprint:
            body = _("Warning: this is not the certificate you confirmed before.") + "\n\n" + body
        label = Gtk.Label(label=fingerprint, wrap=True, selectable=True, max_width_chars=48)
        label.add_css_class("monospace")
        dialog = Adw.MessageDialog(
            transient_for=self, heading=_("Check the server certificate"), body=body, extra_child=label
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("trust", _("Fingerprint matches"))
        dialog.set_response_appearance("trust", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dialog, response):
            if response == "trust":
                accept(fingerprint)

        dialog.connect("response", on_response)
        dialog.present()

    # --- subscription and repository ------------------------------------

    def check_subscription(self, host: str, token_id: str, quiet: bool = False) -> None:
        """Read subscription and repositories; offer to switch to the no-subscription repository if needed."""
        managers = core.managers_for(host, token_id)

        def inspected(result, error):
            if error:
                if not quiet:
                    self.explain(_("Subscription could not be checked"), str(error) + "\n\n" + _(
                        "Reading needs the right Sys.Audit on the nodes, changing it Sys.Modify, for example with a "
                        "token of root@pam."
                    ))
                return
            self.reload()
            if result["state"] == core.NEEDS_SETUP:
                self.offer_repository_setup(host, managers[0], result)
            elif result["state"] == core.NO_SUBSCRIPTION:
                self.offer_notice_fix(host, list(result["nodes"]))
            elif not quiet:
                self.toast(_("{host} has an active subscription and uses the enterprise repository").format(host=host))

        run_async(lambda: core.inspect_server(host, managers[0]), inspected)

    def offer_repository_setup(self, host: str, manager: core.Account, result: dict) -> None:
        nodes = ", ".join(name for name, node in result["nodes"].items() if not node["subscribed"])
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("No valid subscription"),
            body=_(
                "{nodes} on {host} have no active subscription, but the enterprise repository is still in use or "
                "the no-subscription repository is missing, so updates fail. Auth-Switch can enable the "
                "no-subscription repository, also for Ceph, and disable the enterprise repositories through the "
                "Proxmox VE API. This is done with {token}."
            ).format(nodes=nodes, host=host, token=manager.token_id),
        )
        dialog.add_response("cancel", _("Not now"))
        dialog.add_response("setup", _("Set up"))
        dialog.set_response_appearance("setup", Adw.ResponseAppearance.SUGGESTED)

        def done(changes, error):
            if error:
                self.explain(_("Repositories could not be changed"), str(error))
                return
            self.toast(_("{host} now uses the no-subscription repository").format(host=host), "success")
            self.reload()
            self.offer_notice_fix(host, list(result["nodes"]))

        def on_response(_dialog, response):
            if response == "setup":
                run_async(lambda: core.use_no_subscription_repository(host, manager), done)

        dialog.connect("response", on_response)
        dialog.present()

    def offer_notice_fix(self, host: str, nodes: list[str]) -> None:
        """The notice can only be removed with root on the node; the API offers no way to do it."""
        node = nodes[0] if nodes else ""
        text = _(
            "The web interface of {host} shows \"No valid subscription\" at every login. Auth-Switch can hide it "
            "and install an APT hook that hides it again after updates. This needs root on the node: either over "
            "SSH as root with your existing keys – nothing is typed or stored here – or by pasting a command into "
            "the node shell."
        ).format(host=host)
        if len(nodes) > 1:
            text += "\n\n" + _("Only the node you connect to is changed; repeat it on {nodes} if you use their web interface.").format(
                nodes=", ".join(nodes[1:])
            )
        dialog = Adw.MessageDialog(transient_for=self, heading=_("Remove the subscription notice?"), body=text)
        dialog.add_response("cancel", _("Not now"))
        dialog.add_response("copy", _("Copy command"))
        if shutil.which("ssh"):
            dialog.add_response("ssh", _("Run over SSH"))
            dialog.set_response_appearance("ssh", Adw.ResponseAppearance.SUGGESTED)

        def done(output, error):
            if error:
                self.explain(
                    _("SSH did not work"),
                    str(error) + "\n\n" + _("Use \"Copy command\" and paste it into the node shell instead."),
                )
            else:
                self.toast(_("Subscription notice removed on {host}").format(host=host), "success")

        def on_response(_dialog, response):
            if response == "ssh":
                run_async(lambda: core.remove_notice_via_ssh(host), done)
            elif response == "copy":
                self.copy(core.notice_fix_command())
                self.open_uri(core.node_shell_url(host, node))

        dialog.connect("response", on_response)
        dialog.present()

    # --- updates and language -----------------------------------------------

    def open_maintenance(self, host: str, token_id: str) -> None:
        manager = core.managers_for(host, token_id)[0]

        def loaded(result, error):
            if error:
                self.explain(_("Server could not be read"), str(error) + "\n\n" + _(
                    "This needs Sys.Audit, and Sys.Modify for changes, for example with a token of root@pam."
                ))
                return
            self.show_maintenance(host, manager, *result)

        run_async(lambda: (core.get_web_language(host, manager), core.node_updates(host, manager)), loaded)

    def show_maintenance(self, host: str, manager: core.Account, language: str, nodes: list[dict]) -> None:
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(440, -1)

        codes = [""] + [code for code, _name in core.WEB_LANGUAGES]
        names = [_("Browser default")] + [name for _code, name in core.WEB_LANGUAGES]
        chooser = Adw.ComboRow(
            title=_("Language of the web interface"),
            subtitle=_("Default for everyone who has not chosen a language at login"),
            model=Gtk.StringList.new(names),
            selected=codes.index(language) if language in codes else 0,
        )
        rows.append(chooser)

        def language_set(_result, error):
            if error:
                self.explain(_("Language could not be changed"), str(error))
            else:
                self.toast(_("Language of the web interface: {language}").format(language=names[chooser.get_selected()]))

        chooser.connect(
            "notify::selected",
            lambda *_a: run_async(lambda: core.set_web_language(host, codes[chooser.get_selected()], manager), language_set),
        )

        node_rows = []
        for node in nodes:
            row = Adw.ActionRow(title=node["node"], use_markup=False)
            button = Gtk.Button(label=_("Upgrade"), valign=Gtk.Align.CENTER)
            button.connect("clicked", lambda _b, n=node: self.confirm_upgrade(host, manager, n))
            row.add_suffix(button)
            rows.append(row)
            node_rows.append((row, button))

        def show_nodes(current):
            for (row, button), node in zip(node_rows, current):
                count = node["updates"]
                state = _("up to date") if not count else _("{count} updates available").format(count=count)
                row.set_subtitle(_("Proxmox VE {version}").format(version=node["version"]) + " · " + state)
                row.set_tooltip_text(", ".join(node["packages"][:30]))
                button.set_sensitive(bool(count))

        show_nodes(nodes)
        refresh = Adw.ActionRow(title=_("Check for updates"), subtitle=_("Runs apt update on every node"))
        refresh_button = Gtk.Button(icon_name="view-refresh-symbolic", valign=Gtk.Align.CENTER)
        refresh_button.add_css_class("flat")
        refresh.add_suffix(refresh_button)
        rows.append(refresh)

        def refreshed(result, error):
            refresh_button.set_sensitive(True)
            if error:
                self.explain(_("Updates could not be checked"), str(error))
            elif result:
                show_nodes(result)

        def run_refresh(*_args):
            refresh_button.set_sensitive(False)
            run_async(lambda: core.node_updates(host, manager, refresh=True), refreshed)

        refresh_button.connect("clicked", run_refresh)

        guide = core.major_upgrade_guide(nodes[0]["version"]) if nodes else ""
        body = _(
            "Upgrade installs all pending updates of a node, the same as the Upgrade button of the web interface. It "
            "stays within the installed major version; moving to the next one needs the official upgrade guide."
        )
        dialog = Adw.MessageDialog(transient_for=self, heading=_("Updates and language"), body=body, extra_child=rows)
        dialog.add_response("close", _("Close"))
        if guide:
            dialog.add_response("guide", _("Major upgrade guide"))

        def on_response(_dialog, response):
            if response == "guide":
                self.open_uri(guide)

        dialog.connect("response", on_response)
        dialog.present()

    def confirm_upgrade(self, host: str, manager: core.Account, node: dict) -> None:
        body = _(
            "Installs {count} updates on {node} with apt dist-upgrade. Running guests keep running; a new kernel only "
            "takes effect after a reboot. The upgrade console of the web interface shows every step, SSH runs it "
            "unattended as root with your existing keys."
        ).format(count=node["updates"], node=node["node"])
        dialog = Adw.MessageDialog(transient_for=self, heading=_("Upgrade {node}?").format(node=node["node"]), body=body)
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("console", _("Open upgrade console"))
        if node["local"] and shutil.which("ssh"):
            dialog.add_response("ssh", _("Upgrade over SSH"))
            dialog.set_response_appearance("ssh", Adw.ResponseAppearance.SUGGESTED)

        def done(result, error):
            if error:
                self.explain(_("Upgrade failed"), str(error) + "\n\n" + _("Use the upgrade console instead."))
                return
            text = _("{node} is up to date").format(node=node["node"])
            if result["reboot"]:
                self.explain(_("Reboot recommended"), _("{node} has a new kernel; it takes effect after a reboot.").format(node=node["node"]))
            self.toast(text, "success")

        def on_response(_dialog, response):
            if response == "console":
                self.open_uri(core.upgrade_console_url(host, node["node"]))
            elif response == "ssh":
                self.toast(_("Upgrading {node}… this can take a few minutes").format(node=node["node"]))
                run_async(lambda: core.upgrade_via_ssh(host), done)

        dialog.connect("response", on_response)
        dialog.present()

    # --- options -----------------------------------------------------------

    def build_options(self) -> None:
        self.options = Adw.PreferencesGroup(title=_("Options"))

        mcp_row = Adw.ActionRow(
            title=_("MCP server"),
            subtitle=_("Lets AI assistants with MCP support use your Proxmox VE accounts; copy the entry for their configuration"),
        )
        button = Gtk.Button(label=_("Copy entry"), valign=Gtk.Align.CENTER)
        button.connect("clicked", lambda *_args: self.copy(core.mcp_client_config()))
        mcp_row.add_suffix(button)
        self.options.add(mcp_row)

        sound_row = Adw.SwitchRow(title=_("Sound effects"), active=bool(self.settings["sounds"]))
        sound_row.connect("notify::active", self.on_sounds_toggled)
        self.options.add(sound_row)

        update_row = Adw.SwitchRow(
            title=_("Check for updates on start"),
            subtitle=_("Asks GitHub for the latest release, without any account"),
            active=bool(self.settings["check_updates"]),
        )
        update_row.connect("notify::active", self.on_updates_toggled)
        self.options.add(update_row)
        self.page.add(self.options)

    def look_for_update(self) -> None:
        def done(latest, _error):
            self.update_banner.set_revealed(bool(latest))
            if latest:
                self.update_banner.set_title(_("Auth-Switch {version} is available").format(version=latest["version"]))
                self.update_url = latest["url"]

        run_async(update.check, done)

    def on_updates_toggled(self, row, _pspec) -> None:
        self.settings["check_updates"] = row.get_active()
        core.save_settings(self.settings)
        self.look_for_update()

    def on_sounds_toggled(self, row, _pspec) -> None:
        self.settings["sounds"] = row.get_active()
        core.save_settings(self.settings)
        if row.get_active():
            sound.play("switch")


def _on_startup(_app) -> None:
    # The bundled copy makes the logo available even if no icon theme has it.
    icons = Path(__file__).resolve().parent / "icons"
    Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(icons))
    Gtk.Window.set_default_icon_name(ICON_NAME)


def main() -> int:
    app = Adw.Application(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
    app.connect("startup", _on_startup)
    app.connect("activate", lambda app: (app.get_active_window() or Window(app)).present())
    return app.run(sys.argv[:1])
