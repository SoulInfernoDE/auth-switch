"""GTK 4 / libadwaita window for switching Proxmox VE accounts."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from . import __version__, core, sound, update  # noqa: E402
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
        description = _("Certificate confirmed by you") if pinned else _("Certificate trusted by the system")
        group = Adw.PreferencesGroup(title=host, description=description)
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
            (_("Open web interface"), "win.web", GLib.Variant("s", account.host)),
            (_("Enter secret again"), "win.again", target),
            (_("Remove"), "win.remove", target),
        ):
            item = Gio.MenuItem.new(label, None)
            item.set_action_and_target_value(action, value)
            menu.append_item(item)
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

    def edit_permissions(self, host: str, token_id: str) -> None:
        """Switches for the token's roles; another account of the server may be needed to change them."""
        managers = [a for a in core.list_accounts() if a.host == host]
        # A token rarely may change its own rights, so prefer another account of the server.
        managers.sort(key=lambda a: (a.token_id == token_id, not a.active))

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
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(420, -1)
        for row in (server, token, secret):
            rows.append(row)

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
