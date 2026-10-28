"""GTK 4 / libadwaita window for switching Proxmox VE accounts."""

from __future__ import annotations

import re
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from . import __version__, core, discovery, guestaccounts, guestfiles, rootshell, sound, sshaccess, update  # noqa: E402
from .i18n import _  # noqa: E402

APP_ID = ICON_NAME = "dev.authswitch.AuthSwitch"


def PRIVILEGE_HINT() -> str:  # noqa: N802 - looked up when shown, after the language is set
    return _(
        "The token lacks the right for this. A token with privilege separation only has the rights granted to the "
        "token itself. For a management token of root@pam, open Datacenter → Permissions → API Tokens in the web "
        "interface, edit the token and untick \"Privilege Separation\"; otherwise grant it a role with "
        "\"Permissions…\" from another account."
    )


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
            ("repository", lambda _a, p: self.open_subscription(*p.unpack()), "(ss)"),
            ("maintenance", lambda _a, p: self.open_maintenance(*p.unpack()), "(ss)"),
            ("ssh", lambda _a, p: self.open_ssh(*p.unpack()), "(ss)"),
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
        if "HTTP 403" in text:
            text += "\n\n" + PRIVILEGE_HINT()
        dialog = Adw.MessageDialog(transient_for=self, heading=heading, body=text)
        dialog.add_response("close", _("Close"))
        dialog.present()
        if self.settings["sounds"]:
            sound.play("error")

    def busy(self, text: str):
        """Show a spinner while something loads; returns the function that hides it again."""
        box = Gtk.Box(spacing=10)
        spinner = Gtk.Spinner(spinning=True)
        box.append(spinner)
        box.append(Gtk.Label(label=text))
        toast = Adw.Toast(custom_title=box, timeout=0)
        self.toasts.add_toast(toast)
        return toast.dismiss

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
            (_("Subscription and repository…"), "win.repository", target),
            (_("Updates and language…"), "win.maintenance", target),
            (_("SSH for my terminal…"), "win.ssh", target),
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
        self.keep_open(access.get_popover(), access)
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
        repository = {
            core.ENTERPRISE: _("Enterprise Repository"),
            core.NO_SUBSCRIPTION: _("No-Subscription Repository"),
            core.NEEDS_SETUP: _("No subscription – repository not set up"),
        }.get(core.stored_repository(account.host))
        if repository:
            parts.append(repository)
        if profile.has_rights is False:
            parts.append(_("No rights – check privilege separation"))
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
        scrolled = Gtk.ScrolledWindow(child=rows, hscrollbar_policy=Gtk.PolicyType.NEVER, propagate_natural_height=True, max_content_height=420, min_content_width=440)
        chooser = Gtk.DropDown(model=Gtk.StringList.new([a.token_id for a in managers]), tooltip_text=_("Change with"))
        chooser.set_visible(len(managers) > 1)
        for widget in (heading, hint, status, scrolled, chooser):
            box.append(widget)
        popover = Gtk.Popover(child=box)
        icons = {"qemu": "computer-symbolic", "lxc": "package-x-generic-symbolic", "storage": "drive-harddisk-symbolic", "node": "network-server-symbolic"}
        kinds = {"qemu": _("Virtual machine"), "lxc": _("Container"), "storage": _("Storage"), "node": _("Node")}

        state = {"privsep": True, "server": set()}
        enforce = Gtk.Button(label=_("Enforce on the server"), visible=False, halign=Gtk.Align.START)
        enforce.set_tooltip_text(_("Grants the token Administrator on / and turns on privilege separation"))
        box.insert_child_after(enforce, status)

        def manager() -> core.Account:
            return managers[chooser.get_selected()]

        def enforced(_result, error):
            enforce.set_sensitive(True)
            if error:
                self.explain(_("Blocks could not be enforced on the server"), str(error))
            else:
                self.toast(_("Blocks of {token} now apply to every access").format(token=account.token_id), "success")
            load()

        def enforce_on_server(*_args):
            enforce.set_sensitive(False)
            run_async(lambda: core.enable_server_blocking(account.host, account.token_id, manager()), enforced)

        enforce.connect("clicked", enforce_on_server)

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

            run_async(
                lambda: core.set_access(account.host, account.token_id, path, denied, manager(), state["privsep"], state["server"]),
                done,
            )

        def loaded(result, error):
            while (child := rows.get_first_child()) is not None:
                rows.remove(child)
            if error:
                status.set_label(str(error))
                return
            resources, server_denied, privsep = result
            state.update(privsep=privsep, server=server_denied)
            core.adopt_server_blocks(account.host, account.token_id, server_denied)
            denied = core.local_blocks(account.host, account.token_id)
            status.set_label(
                "" if privsep else _(
                    "Without privilege separation the server does not enforce these blocks; only the MCP server of "
                    "Auth-Switch keeps to them."
                )
            )
            enforce.set_visible(not privsep)
            states = {"running": _("running"), "stopped": _("off"), "paused": _("paused")}
            for resource in resources:
                # For guests the icon already tells VM from container; the state matters more.
                subtitle = states.get(resource["status"], resource["status"]) if resource.get("status") else kinds[resource["kind"]]
                row = Adw.ActionRow(title=resource["label"], subtitle=subtitle, use_markup=False)
                row.add_prefix(Gtk.Image(icon_name=icons[resource["kind"]]))
                if resource["kind"] in ("qemu", "lxc"):
                    # The list stays open while these dialogs are shown; it closes on a click beside it.
                    for icon, tip, handler in (
                        ("system-shutdown-symbolic", _("Start, shut down …"), self.open_guest_power),
                        ("document-send-symbolic", _("Transfer files…"), self.open_guest_files),
                        ("system-users-symbolic", _("User accounts…"), self.open_guest_accounts),
                    ):
                        button = Gtk.Button(icon_name=icon, valign=Gtk.Align.CENTER, tooltip_text=tip)
                        button.add_css_class("flat")
                        button.connect("clicked", lambda _b, r=resource, h=handler: h(account.host, r, manager(), load))
                        row.add_suffix(button)
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

    def keep_open(self, popover: Gtk.Popover, button: Gtk.MenuButton) -> None:
        """Keep a drop-down open while dialogs started from it are shown; a click beside it closes it."""
        popover.set_autohide(False)
        if not hasattr(self, "sticky"):
            self.sticky = []
            click = Gtk.GestureClick(button=0, propagation_phase=Gtk.PropagationPhase.CAPTURE)
            click.connect("pressed", self.close_sticky)
            self.add_controller(click)
        self.sticky.append((popover, button))
        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", lambda _c, key, _code, _state: key == Gdk.KEY_Escape and (popover.popdown() or True))
        popover.add_controller(keys)

    def close_sticky(self, _gesture, _count, x, y) -> None:
        # Clicks inside a drop-down reach its own surface, never the window: anything here is beside it.
        picked = self.pick(x, y, Gtk.PickFlags.DEFAULT)
        for popover, button in self.sticky:
            if popover.get_visible() and not (picked and picked.is_ancestor(button) or picked is button):
                popover.popdown()

    # --- user accounts inside a guest ------------------------------------------

    # --- power and files of a guest --------------------------------------------

    def open_guest_power(self, host: str, resource: dict, manager: core.Account, refresh=None) -> None:
        vmid = resource["path"].rsplit("/", 1)[1]
        guest = guestaccounts.Guest(host, resource["node"], resource["kind"], vmid, manager)
        label = resource["label"]
        done_loading = self.busy(_("Reading the state of {guest}…").format(guest=label))

        def loaded(state, error):
            done_loading()
            if error:
                self.explain(_("The state could not be read"), str(error))
                return
            running = state == "running"
            dialog = Adw.MessageDialog(
                transient_for=self, heading=label,
                body=(_("Running. Shutting down and restarting ask the system in the guest; stopping switches it off "
                        "at once like a power cut, unsaved work is lost.") if running else _("Switched off.")),
            )
            dialog.add_response("close", _("Close"))
            if running:
                dialog.add_response("stop", _("Stop"))
                dialog.add_response("reboot", _("Restart"))
                dialog.add_response("shutdown", _("Shut down"))
                dialog.set_response_appearance("stop", Adw.ResponseAppearance.DESTRUCTIVE)
                dialog.set_response_appearance("shutdown", Adw.ResponseAppearance.SUGGESTED)
            else:
                dialog.add_response("start", _("Start"))
                dialog.set_response_appearance("start", Adw.ResponseAppearance.SUGGESTED)
            dialog.connect("response", lambda _d, action: action in guestaccounts.POWER_ACTIONS and self.power_guest(guest, label, action, refresh))
            dialog.present()

        run_async(guest.status, loaded)

    def power_guest(self, guest, label: str, action: str, refresh=None) -> None:
        busy = {
            "start": _("Starting {guest}…"), "shutdown": _("Shutting down {guest}…"),
            "reboot": _("Restarting {guest}…"), "stop": _("Stopping {guest}…"),
        }
        done_text = {
            "start": _("{guest} is running"), "shutdown": _("{guest} is shut down"),
            "reboot": _("{guest} has restarted"), "stop": _("{guest} is stopped"),
        }
        done_loading = self.busy(busy[action].format(guest=label))

        def done(_result, error):
            done_loading()
            if error:
                self.explain(_("{guest} did not react as expected").format(guest=label), str(error))
            else:
                self.toast(done_text[action].format(guest=label), "success")
            if refresh:
                refresh()

        run_async(lambda: guest.power(action), done)

    def open_guest_files(self, host: str, resource: dict, manager: core.Account, refresh=None) -> None:
        vmid = resource["path"].rsplit("/", 1)[1]
        guest = guestaccounts.Guest(host, resource["node"], resource["kind"], vmid, manager)
        label = resource["label"]
        if resource.get("status") not in ("running", ""):
            self.explain(_("Files cannot be transferred"), _("{guest} is switched off; start it first.").format(guest=label))
            return
        dialog = Adw.MessageDialog(
            transient_for=self, heading=_("Transfer files – {guest}").format(guest=label),
            body=_("Copies files into the guest or out of it. Virtual machines need the QEMU guest agent, containers "
                   "\"SSH for my terminal\". Large files take a while on virtual machines."),
        )
        dialog.add_response("close", _("Close"))
        dialog.add_response("download", _("Copy from the guest…"))
        dialog.add_response("upload", _("Copy into the guest…"))
        dialog.set_response_appearance("upload", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dialog, response):
            if response == "upload":
                Gtk.FileDialog(title=_("Files to copy into {guest}").format(guest=label)).open_multiple(self, None, chosen)
            elif response == "download":
                ask_path(_("File in the guest"), _("Copy from the guest"), fetch, file=True)

        def chosen(file_dialog, result):
            try:
                files = file_dialog.open_multiple_finish(result)
            except GLib.Error:
                return
            paths = [Path(files.get_item(i).get_path()) for i in range(files.get_n_items())]
            ask_path(_("Folder in the guest"), _("Copy here"), lambda folder: self.transfer(
                guest, label, [(path, folder) for path in paths], upload=True), file=False)

        def ask_path(title: str, action: str, then, file: bool) -> None:
            entry = Adw.EntryRow(title=title)
            rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            rows.add_css_class("boxed-list")
            rows.set_size_request(420, -1)
            rows.append(entry)
            ask = Adw.MessageDialog(transient_for=self, heading=label, extra_child=rows)
            ask.add_response("cancel", _("Cancel"))
            ask.add_response("ok", action)
            ask.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
            entry.connect("changed", lambda *_a: ask.set_response_enabled("ok", bool(entry.get_text().strip())))
            ask.set_response_enabled("ok", False)
            ask.connect("response", lambda _d, r: r == "ok" and then(entry.get_text().strip()))
            ask.present()
            # The folder people usually want, filled in once it is known (asking the guest takes a moment)
            def suggestion():
                folder = guestfiles.default_folder(guest)
                return guestfiles.join(guest, folder, "") if file else folder

            run_async(suggestion, lambda text, error: not error and not entry.get_text() and entry.set_text(text))

        def fetch(remote: str) -> None:
            name = remote.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            save = Gtk.FileDialog(title=_("Save as"), initial_name=name)

            def saved(file_dialog, result):
                try:
                    target = file_dialog.save_finish(result)
                except GLib.Error:
                    return
                self.transfer(guest, label, [(remote, Path(target.get_path()))], upload=False)

            save.save(self, None, saved)

        dialog.connect("response", on_response)
        dialog.present()

    def transfer(self, guest, label: str, jobs: list, upload: bool) -> None:
        """Copy one file after the other and show the progress in a toast."""
        box = Gtk.Box(spacing=10)
        box.append(Gtk.Spinner(spinning=True))
        text = Gtk.Label()
        box.append(text)
        toast = Adw.Toast(custom_title=box, timeout=0)
        self.toasts.add_toast(toast)

        def show(name: str, done: int, total: int) -> None:
            percent = 100 if not total else done * 100 // total
            GLib.idle_add(lambda: text.set_label(_("Copying {name} … {percent} %").format(name=name, percent=percent)) and False)

        def work():
            for source, target in jobs:
                name = source.name if upload else source.replace("\\", "/").rsplit("/", 1)[-1]
                show(name, 0, 1)
                if upload:
                    guestfiles.upload(guest, source, target, lambda done, total, n=name: show(n, done, total))
                else:
                    guestfiles.download(guest, source, target, lambda done, total, n=name: show(n, done, total))
            return len(jobs)

        def done(count, error):
            toast.dismiss()
            if error:
                self.explain(_("The transfer stopped"), str(error))
            elif upload:
                self.toast(_("{count} file(s) copied into {guest}").format(count=count, guest=label), "success")
            else:
                self.toast(_("{count} file(s) copied from {guest}").format(count=count, guest=label), "success")

        run_async(work, done)

    def open_guest_accounts(self, host: str, resource: dict, manager: core.Account, refresh=None) -> None:
        vmid = resource["path"].rsplit("/", 1)[1]
        guest = guestaccounts.Guest(host, resource["node"], resource["kind"], vmid, manager)
        done_loading = self.busy(_("Reading the accounts of {guest}…").format(guest=resource["label"]))

        def fetch():
            users = guest.users()
            try:
                computer = guest.computer_name()
            except core.AuthError:
                computer = None
            return users, computer

        def loaded(result, error):
            done_loading()
            if error:
                self.explain(_("Accounts could not be read"), str(error))
            elif not result[0]:
                self.explain(_("Accounts could not be read"), _("No account to sign in with was found."))
            else:
                self.show_guest_accounts(guest, resource["label"], *result)

        run_async(fetch, loaded)

    def show_guest_accounts(self, guest, label: str, users: list[dict], computer: dict | None = None) -> None:
        names = [u["name"] for u in users]
        chooser = Adw.ComboRow(title=_("Account"), model=Gtk.StringList.new(names))
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(400, -1)
        rows.append(chooser)
        dialog = Adw.MessageDialog(
            transient_for=self, heading=_("User accounts in {guest}").format(guest=label),
            body=_("Changes an account inside the guest directly; the VM must be running."), extra_child=rows,
        )
        if computer:
            rows.append(self.computer_name_row(guest, label, computer, dialog))
        dialog.add_response("close", _("Close"))
        dialog.add_response("rename", _("Rename…"))
        dialog.add_response("password", _("Change password…"))
        dialog.set_response_appearance("password", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dialog, response):
            user = names[chooser.get_selected()]
            if response == "password":
                self.ask_guest_password(guest, user)
            elif response == "rename":
                self.ask_guest_rename(guest, user)

        dialog.connect("response", on_response)
        dialog.present()

    def computer_name_row(self, guest, label: str, computer: dict, parent) -> Gtk.Widget:
        """The guest's computer name, with a button to give it the VM name when the two differ."""
        windows = computer["system"] == guestaccounts.WINDOWS

        def same(a: str, b: str) -> bool:
            # Windows does not tell upper and lower case apart in computer names.
            return a.lower() == b.lower() if windows else a == b

        current, pending, target = computer["current"], computer["pending"], computer["target"]
        row = Adw.ActionRow(title=_("Computer name"), subtitle=current, use_markup=False)
        if not target:
            row.set_subtitle(current + "\n" + _("The VM name {name} is no valid computer name.").format(name=computer["vm"]))
            return row
        if same(current, target):
            row.add_suffix(Gtk.Image(icon_name="object-select-symbolic", tooltip_text=_("Matches the VM name")))
            return row
        if same(pending, target):
            row.set_subtitle(_("{current} → {new} after a restart").format(current=current, new=pending))
            action = Gtk.Button(label=_("Restart…"), valign=Gtk.Align.CENTER)
        else:
            action = Gtk.Button(label=_("Use VM name…"), valign=Gtk.Align.CENTER, tooltip_text=target)
        action.connect("clicked", lambda _b: (parent.close(), self.ask_computer_name(guest, label, computer)))
        row.add_suffix(action)
        return row

    def ask_computer_name(self, guest, label: str, computer: dict) -> None:
        target = computer["target"]
        windows = computer["system"] == guestaccounts.WINDOWS
        renamed = computer["pending"].lower() == target.lower() if windows else computer["pending"] == target
        lines = []
        if windows:
            lines.append(_("Windows uses the new name after a restart. A restart signs out everyone who is signed in."))
            if len(target) > guestaccounts.NETBIOS_LENGTH:
                lines.append(_("Older Windows network services only see the first {count} characters: {short}").format(
                    count=guestaccounts.NETBIOS_LENGTH, short=target[:guestaccounts.NETBIOS_LENGTH].upper()))
        else:
            lines.append(_("Sets the host name and the matching line in /etc/hosts; no restart is needed."))
        if renamed:
            heading = _("Restart {guest}?").format(guest=label)
        else:
            heading = _("Rename the computer {current} to {new}?").format(current=computer["current"], new=target)
        dialog = Adw.MessageDialog(transient_for=self, heading=heading, body="\n\n".join(lines))
        dialog.add_response("cancel", _("Cancel"))
        if windows and not renamed:
            dialog.add_response("rename", _("Rename only"))
        if windows:
            dialog.add_response("restart", _("Restart now") if renamed else _("Rename and restart"))
            dialog.set_response_appearance("restart", Adw.ResponseAppearance.SUGGESTED)
        else:
            dialog.add_response("rename", _("Rename"))
            dialog.set_response_appearance("rename", Adw.ResponseAppearance.SUGGESTED)

        def apply(restart: bool):
            later = False if renamed else guest.set_computer_name(target)
            if restart:
                guest.restart()
            return later and not restart

        def on_response(_dialog, response):
            if response not in ("rename", "restart"):
                return
            done_loading = self.busy(_("Changing the computer name of {guest}…").format(guest=label))

            def done(later, error):
                done_loading()
                if error:
                    self.explain(_("The computer name could not be changed"), str(error))
                elif later:
                    self.toast(_("{guest} is called {name} after the next restart").format(guest=label, name=target), "success")
                elif response == "restart":
                    self.toast(_("{guest} restarts as {name}").format(guest=label, name=target), "success")
                else:
                    self.toast(_("The computer name is now {name}").format(name=target), "success")

            run_async(lambda: apply(response == "restart"), done)

        dialog.connect("response", on_response)
        dialog.present()

    def ask_guest_password(self, guest, user: str) -> None:
        first = Adw.PasswordEntryRow(title=_("New password"))
        second = Adw.PasswordEntryRow(title=_("Repeat the new password"))
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(400, -1)
        rows.append(first)
        rows.append(second)
        dialog = Adw.MessageDialog(
            transient_for=self, heading=_("New password for {user}").format(user=user),
            body=_("Takes effect at the next sign-in. Auth-Switch does not store it."), extra_child=rows,
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("apply", _("Change password"))
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)

        def update(*_args):
            dialog.set_response_enabled("apply", bool(first.get_text()) and first.get_text() == second.get_text())

        for row in (first, second):
            row.connect("changed", update)
        update()

        def done(_result, error):
            if error:
                self.explain(_("The password could not be changed"), str(error))
            else:
                self.toast(_("Password of {user} changed").format(user=user), "success")

        def on_response(_dialog, response):
            password = first.get_text()
            first.set_text("")
            second.set_text("")
            if response == "apply":
                run_async(lambda: guest.set_password(user, password), done)

        dialog.connect("response", on_response)
        dialog.present()

    def ask_guest_rename(self, guest, user: str) -> None:
        name = Adw.EntryRow(title=_("New account name"))
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(400, -1)
        rows.append(name)
        dialog = Adw.MessageDialog(
            transient_for=self, heading=_("Rename {user}").format(user=user),
            body=_(
                "Renames the account, its display name and its profile folder, and replaces the old profile path in "
                "the registry or configuration. The account must be signed out. You see a preview first."
            ),
            extra_child=rows,
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("preview", _("Preview"))
        dialog.set_response_appearance("preview", Adw.ResponseAppearance.SUGGESTED)
        name.connect("changed", lambda *_a: dialog.set_response_enabled(
            "preview", bool(guestaccounts.NAME.fullmatch(name.get_text().strip())) and name.get_text().strip() != user))
        dialog.set_response_enabled("preview", False)

        def on_response(_dialog, response):
            if response == "preview":
                self.preview_guest_rename(guest, user, name.get_text().strip())

        dialog.connect("response", on_response)
        dialog.present()

    def preview_guest_rename(self, guest, old: str, new: str) -> None:
        done_loading = self.busy(_("Looking for every place that names {user}…").format(user=old))

        def previewed(report, error):
            done_loading()
            if error:
                self.explain(_("The rename is not possible"), str(error))
                return
            dialog = Adw.MessageDialog(
                transient_for=self, heading=_("Rename {old} to {new}?").format(old=old, new=new),
                body=_("This would change:") + "\n\n" + report,
            )
            dialog.add_response("cancel", _("Cancel"))
            dialog.add_response("rename", _("Rename"))
            dialog.set_response_appearance("rename", Adw.ResponseAppearance.DESTRUCTIVE)

            def renamed(result, rename_error):
                done_renaming()
                if rename_error:
                    self.explain(_("The rename failed"), str(rename_error))
                else:
                    self.explain(_("{old} is now {new}").format(old=old, new=new), result + "\n\n" + _(
                        "Sign in with the new name from now on, also in Remmina."
                    ))

            def on_response(_dialog, response):
                nonlocal done_renaming
                if response == "rename":
                    done_renaming = self.busy(_("Renaming {user}…").format(user=old))
                    run_async(lambda: guest.rename(old, new, preview=False), renamed)

            done_renaming = lambda: None  # noqa: E731 - replaced once the rename starts
            dialog.connect("response", on_response)
            dialog.present()

        run_async(lambda: guest.rename(old, new, preview=True), previewed)

    def edit_permissions(self, host: str, token_id: str) -> None:
        """Switches for the token's roles; another account of the server may be needed to change them."""
        # A token rarely may change its own rights, so prefer another account of the server.
        managers = core.managers_for(host, token_id)

        done_loading = self.busy(_("Reading permissions…"))

        def loaded(result, error, manager):
            done_loading()
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
            run_async(lambda: core.fetch_profile(account), lambda profile, _e: self.after_add(account, profile))

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

    def after_add(self, account: core.Account, profile) -> None:
        """A token without any right cannot be checked further, so say why before anything else fails."""
        if profile is not None and profile.has_rights is False:
            self.explain(
                _("{token} has no rights yet").format(token=account.token_id),
                _("It can sign in, but may not read or change anything.") + "\n\n" + PRIVILEGE_HINT(),
            )
            return
        self.open_subscription(account.host, account.token_id, only_if_needed=True)

    def open_subscription(self, host: str, token_id: str, only_if_needed: bool = False) -> None:
        """Checklist of subscription, repositories and notice, each with the one action it may need."""
        manager = core.managers_for(host, token_id)[0]

        def notice():
            try:
                return core.notice_status(host)
            except core.AuthError:
                return core.NOTICE_UNKNOWN

        def gather():
            # The checks are independent, so they run side by side.
            with ThreadPoolExecutor(max_workers=4) as pool:
                jobs = [pool.submit(job) for job in (
                    lambda: core.inspect_server(host, manager), notice,
                    lambda: core.ssh_ready(host), lambda: rootshell.local_node(host, manager),
                )]
                return tuple(job.result() for job in jobs)

        done_loading = self.busy(_("Checking subscription and repositories…"))

        def loaded(result, error):
            done_loading()
            if error:
                if not only_if_needed:
                    self.explain(_("Subscription could not be checked"), str(error))
                return
            server, notice, ssh, node = result
            self.reload()
            done = server["state"] == core.ENTERPRISE or (
                server["state"] == core.NO_SUBSCRIPTION and notice in (core.NOTICE_REMOVED, core.NOTICE_UNKNOWN)
            )
            if only_if_needed and done:
                return
            self.show_subscription(host, manager, server, notice, ssh, node)

        run_async(gather, loaded)

    def show_subscription(self, host, manager, server, notice, ssh, node) -> None:
        unsubscribed = [name for name, entry in server["nodes"].items() if not entry["subscribed"]]
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(440, -1)

        def status_row(title):
            row = Adw.ActionRow(title=title, use_markup=False)
            icon = Gtk.Image()
            row.add_prefix(icon)
            rows.append(row)
            return row, icon

        def mark(row, icon, ok, text):
            icon.set_from_icon_name("emblem-ok-symbolic" if ok else "dialog-warning-symbolic")
            row.set_subtitle(text)

        subscription_row, subscription_icon = status_row(_("Subscription"))
        mark(
            subscription_row, subscription_icon, True,
            _("Active on every node") if not unsubscribed else _("None on {nodes} – that is fine for home and test use").format(nodes=", ".join(unsubscribed)),
        )

        repository_row, repository_icon = status_row(_("Package repositories"))
        repository_button = Gtk.Button(label=_("Switch over"), valign=Gtk.Align.CENTER, visible=False)
        repository_row.add_suffix(repository_button)

        notice_row, notice_icon = status_row(_("\"No valid subscription\" notice"))
        notice_row.set_visible(bool(unsubscribed))
        notice_button = Gtk.Button(valign=Gtk.Align.CENTER, visible=False)
        notice_row.add_suffix(notice_button)

        def show_repository(state):
            needs = state == core.NEEDS_SETUP
            texts = {
                core.ENTERPRISE: _("Enterprise repository"),
                core.NO_SUBSCRIPTION: _("No-subscription repository – updates work"),
                core.NEEDS_SETUP: _("Enterprise repository without subscription – updates fail"),
            }
            mark(repository_row, repository_icon, not needs, texts.get(state, ""))
            repository_button.set_visible(needs)

        def show_notice(state):
            texts = {
                core.NOTICE_REMOVED: _("Hidden; the actions behind it keep working"),
                core.NOTICE_SHOWN: _("Shown at every login"),
                core.NOTICE_BROKEN: _("Hidden by another recipe that also stops actions such as adding a repository"),
                core.NOTICE_UNKNOWN: _("Could not be determined"),
            }
            mark(notice_row, notice_icon, state in (core.NOTICE_REMOVED, core.NOTICE_UNKNOWN), texts[state])
            notice_button.set_label(_("Repair…") if state == core.NOTICE_BROKEN else _("Remove…"))
            notice_button.set_visible(state in (core.NOTICE_SHOWN, core.NOTICE_BROKEN))

        show_repository(server["state"])
        show_notice(notice)

        def repository_done(result, error):
            repository_button.set_sensitive(True)
            if error:
                self.explain(_("Repositories could not be changed"), str(error))
                return
            show_repository(core.stored_repository(host))
            self.toast(_("{host} now uses the no-subscription repository").format(host=host), "success")
            self.reload()

        def switch_repository(*_args):
            repository_button.set_sensitive(False)
            run_async(lambda: core.use_no_subscription_repository(host, manager), repository_done)

        repository_button.connect("clicked", switch_repository)

        poll = {"source": 0, "until": 0.0}

        def check_notice():
            def checked(state, error):
                if not error:
                    show_notice(state)
                    if state == core.NOTICE_REMOVED:
                        poll["until"] = 0
                        self.toast(_("Subscription notice removed on {host}").format(host=host), "success")

            run_async(lambda: core.notice_status(host), checked)
            if GLib.get_monotonic_time() / 1e6 < poll["until"]:
                return GLib.SOURCE_CONTINUE
            poll["source"] = 0
            return GLib.SOURCE_REMOVE

        def watch_notice(seconds: int) -> None:
            """Keep reading the state for a while, e.g. while the user pastes the command into the shell."""
            poll["until"] = GLib.get_monotonic_time() / 1e6 + seconds
            if not poll["source"]:
                poll["source"] = GLib.timeout_add_seconds(4, check_notice)

        notice_button.connect("clicked", lambda *_a: self.ask_notice_fix(host, node, ssh, watch_notice))

        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("Subscription and repository"),
            body=_("{host}: what is set up, and what Auth-Switch can do for you.").format(host=host),
            extra_child=rows,
        )
        dialog.add_response("close", _("Close"))

        def closed(*_args):
            poll["until"] = 0

        dialog.connect("response", closed)
        dialog.present()

    def ask_notice_fix(self, host: str, node: str, ssh: bool, watch) -> None:
        """Three ways to run the fix as root; the script is shown before anything runs."""
        password = Adw.PasswordEntryRow(title=_("Password of root@pam (not stored)"))
        code = Adw.EntryRow(title=_("One-time code (two-factor authentication)"), visible=False)
        script = Gtk.Label(label=core.NOTICE_FIX_SCRIPT.strip(), selectable=True, xalign=0, wrap=False)
        script.add_css_class("monospace")
        script.add_css_class("caption")
        shown = Gtk.ScrolledWindow(child=script, min_content_height=160, max_content_height=220)
        expander = Gtk.Expander(label=_("Show what runs as root"), child=shown)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(440, -1)
        rows.append(password)
        rows.append(code)
        box.append(rows)
        box.append(expander)

        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("Hide the notice on {node}").format(node=node or host),
            body=_(
                "This changes a file of the web interface and installs an APT hook that keeps the change after "
                "updates, so it has to run as root. Easiest: enter the root password – Auth-Switch signs in once, "
                "runs the script in the node's own root console over the connection you already trust, and forgets "
                "the password right away."
            ),
            extra_child=box,
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("manual", _("Do it myself"))
        if ssh:
            dialog.add_response("ssh", _("Over SSH"))
        dialog.add_response("password", _("Run with password"))
        dialog.set_response_appearance("password", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_response_enabled("password", False)
        password.connect("changed", lambda *_a: dialog.set_response_enabled("password", bool(password.get_text())))
        dialog.set_close_response("cancel")

        def finished(_result, error):
            if isinstance(error, rootshell.TwoFactorRequired):
                code.set_visible(True)
                dialog.present()
                return
            if error:
                self.explain(_("The notice could not be removed"), str(error))
                return
            watch(20)

        def on_response(_dialog, response):
            secret, otp = password.get_text(), code.get_text().strip()
            password.set_text("")
            if response == "password":
                dialog.set_visible(False)
                self.toast(_("Signing in as root@pam and running the script…"))
                run_async(lambda: rootshell.remove_notice(host, node, "root@pam", secret, otp), finished)
            elif response == "ssh":
                run_async(lambda: core.remove_notice_via_ssh(host), finished)
            elif response == "manual":
                self.copy(core.notice_fix_command())
                self.open_uri(core.web_interface(host))
                self.explain(
                    _("Paste the command in the node shell"),
                    _(
                        "The command is in the clipboard and the web interface is opening. Sign in there, select "
                        "{node} and open Shell, then paste the command and press Enter. This window notices by "
                        "itself when the notice is gone."
                    ).format(node=node or _("the node")),
                )
                watch(300)

        dialog.connect("response", on_response)
        dialog.present()

    # --- SSH for the user's own terminal --------------------------------------

    def ssh_warning(self) -> Gtk.Label:
        label = Gtk.Label(
            label=_(
                "While it is on, any program running as you – including an AI assistant with shell access – can log "
                "in as root without asking. The MCP server of Auth-Switch does not use it and knows nothing about it."
            ),
            wrap=True, xalign=0, max_width_chars=52,
        )
        label.add_css_class("warning")
        return label

    def open_ssh(self, host: str, token_id: str) -> None:
        state = sshaccess.status(host)
        if state["set_up"]:
            self.show_ssh_switch(host, state)
            return
        manager = core.managers_for(host, token_id)[0]
        done_loading = self.busy(_("Reading the server…"))

        def loaded(node, _error):
            done_loading()
            self.ask_ssh_setup(host, node or "")

        run_async(lambda: rootshell.local_node(host, manager), loaded)

    def ask_ssh_setup(self, host: str, node: str) -> None:
        alias = Adw.EntryRow(title=_("Name for ssh, e.g. ssh {name}").format(name=node or "pve"), text=node or "pve")
        password = Adw.PasswordEntryRow(title=_("Password of root@pam (not stored)"))
        code = Adw.EntryRow(title=_("One-time code (two-factor authentication)"), visible=False)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(440, -1)
        for row in (alias, password, code):
            rows.append(row)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(self.ssh_warning())
        box.append(rows)
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("SSH for my terminal"),
            body=_(
                "Auth-Switch creates a key only for {host}, lets root on the server trust it and takes the server's "
                "host key over the connection you already confirmed. Afterwards \"ssh NAME\" logs you in as root. "
                "The key stays in the system keyring; switching off removes it from ssh, switching on brings it back."
            ).format(host=host),
            extra_child=box,
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("setup", _("Set up"))
        dialog.set_response_appearance("setup", Adw.ResponseAppearance.SUGGESTED)

        def update(*_args):
            ok = bool(re.fullmatch(r"[\w.-]+", alias.get_text().strip())) and bool(password.get_text())
            dialog.set_response_enabled("setup", ok)

        for row in (alias, password):
            row.connect("changed", update)
        update()

        def finished(_result, error):
            if isinstance(error, rootshell.TwoFactorRequired):
                code.set_visible(True)
                dialog.present()
                return
            if error:
                self.explain(_("SSH could not be set up"), str(error))
                return
            self.toast(_("SSH ready: ssh {alias}").format(alias=alias.get_text().strip()), "success")

        def on_response(_dialog, response):
            secret, otp = password.get_text(), code.get_text().strip()
            password.set_text("")
            if response == "setup":
                dialog.set_visible(False)
                name = alias.get_text().strip()
                run_async(lambda: sshaccess.set_up(host, node, name, secret, otp), finished)

        dialog.connect("response", on_response)
        dialog.present()

    def show_ssh_switch(self, host: str, state: dict) -> None:
        switch = Adw.SwitchRow(title=_("SSH access as root"), subtitle=f"ssh {state['alias']}", active=state["enabled"])
        copy = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Copy command"))
        copy.add_css_class("flat")
        copy.connect("clicked", lambda *_a: self.copy(f"ssh {state['alias']}"))
        switch.add_suffix(copy)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        rows.set_size_request(440, -1)
        rows.append(switch)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        warning = self.ssh_warning()
        warning.set_visible(state["enabled"])
        box.append(warning)
        box.append(rows)
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("SSH for my terminal"),
            body=_(
                "Off removes the key from ssh at once; it stays in the system keyring and on the server, so switching on "
                "again needs nothing else. Remove takes it off the server and out of the keyring."
            ),
            extra_child=box,
        )
        dialog.add_response("remove", _("Remove"))
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.add_response("close", _("Close"))

        def toggled(*_args):
            warning.set_visible(switch.get_active())
            try:
                (sshaccess.enable if switch.get_active() else sshaccess.disable)(host)
            except core.AuthError as error:
                self.explain(_("SSH could not be changed"), str(error))
                return
            text = _("SSH to {host} on") if switch.get_active() else _("SSH to {host} off")
            self.toast(text.format(host=host), "switch" if switch.get_active() else "signout")

        switch.connect("notify::active", toggled)

        def removed(_result, error):
            if error:
                self.explain(_("SSH could not be changed"), str(error))
            else:
                self.toast(_("SSH access to {host} removed").format(host=host), "signout")

        def on_response(_dialog, response):
            if response == "remove":
                run_async(lambda: sshaccess.remove(host), removed)

        dialog.connect("response", on_response)
        dialog.present()

    # --- updates and language -----------------------------------------------

    def open_maintenance(self, host: str, token_id: str) -> None:
        manager = core.managers_for(host, token_id)[0]

        done_loading = self.busy(_("Reading versions and updates…"))

        def loaded(result, error):
            done_loading()
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
            reboot = Gtk.Button(label=_("Reboot"), valign=Gtk.Align.CENTER, visible=False)
            reboot.add_css_class("destructive-action")
            reboot.connect("clicked", lambda _b, n=node: self.offer_reboot(host, manager, n["node"]))
            row.add_suffix(reboot)
            button = Gtk.Button(label=_("Upgrade"), valign=Gtk.Align.CENTER)
            button.connect("clicked", lambda b, n=node: self.prepare_upgrade(host, manager, n, b, reread))
            row.add_suffix(button)
            rows.append(row)
            node_rows.append((row, button, reboot))

        def show_nodes(current):
            for (row, button, reboot), node in zip(node_rows, current):
                count = node["updates"]
                state = _("up to date") if not count else _("{count} updates available").format(count=count)
                parts = [_("Proxmox VE {version}").format(version=node["version"]), state]
                if node.get("reboot"):
                    parts.append(_("reboot pending"))
                row.set_subtitle(" · ".join(parts))
                row.set_tooltip_text(", ".join(node["packages"][:30]))
                button.set_sensitive(bool(count))
                reboot.set_visible(bool(node.get("reboot")))

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

        def reread():
            run_async(lambda: core.node_updates(host, manager), lambda result, error: show_nodes(result) if result else None)

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

    def prepare_upgrade(self, host: str, manager: core.Account, node: dict, button: Gtk.Button, refresh) -> None:
        """One click: if SSH works, the upgrade simply runs; otherwise the upgrade console is offered."""
        if not node["local"]:
            self.offer_upgrade_console(host, manager, node)
            return
        button.set_sensitive(False)
        done_loading = self.busy(_("Checking SSH access…"))

        def finished(result, error):
            done_upgrading()
            button.set_sensitive(True)
            refresh()
            if error:
                self.explain(_("Upgrade failed"), str(error) + "\n\n" + _("Use the upgrade console instead."))
                return
            self.toast(_("{node} is up to date").format(node=node["node"]), "success")
            if result["reboot"]:
                self.offer_reboot(host, manager, node["node"])

        def checked(ready, _error):
            nonlocal done_upgrading
            done_loading()
            if not ready:
                button.set_sensitive(True)
                self.offer_upgrade_console(host, manager, node)
                return
            done_upgrading = self.busy(_("Upgrading {node}… this can take a few minutes").format(node=node["node"]))
            run_async(lambda: core.upgrade_via_ssh(host), finished)

        done_upgrading = lambda: None  # noqa: E731 - replaced once the upgrade starts
        run_async(lambda: core.ssh_ready(host), checked)

    def offer_reboot(self, host: str, manager: core.Account, node: str) -> None:
        """A new kernel only helps after a reboot, so ask right away and say what it means for running guests."""
        done_loading = self.busy(_("Reading running guests…"))

        def loaded(guests, error):
            done_loading()
            guests = guests or []
            lines = [_("{node} has a new kernel; it takes effect after a reboot.").format(node=node)]
            if guests:
                back = [g for g in guests if g["onboot"]]
                stay = [g for g in guests if not g["onboot"]]
                lines.append(_("Running guests are shut down first."))
                if back:
                    lines.append(_("Start again by themselves: {guests}").format(guests=", ".join(f"{g['vmid']} {g['name']}".strip() for g in back)))
                if stay:
                    lines.append(_("Stay off until you start them: {guests}").format(guests=", ".join(f"{g['vmid']} {g['name']}".strip() for g in stay)))
            elif error is None:
                lines.append(_("No guest is running."))
            lines.append(_("The web interface is unreachable for a few minutes."))
            dialog = Adw.MessageDialog(transient_for=self, heading=_("Reboot {node} now?").format(node=node), body="\n\n".join(lines))
            dialog.add_response("later", _("Later"))
            dialog.add_response("reboot", _("Reboot now"))
            dialog.set_response_appearance("reboot", Adw.ResponseAppearance.DESTRUCTIVE)

            def back_again(result, back_error):
                done_waiting()
                if result:
                    self.toast(_("{node} is back after the reboot").format(node=node), "success")
                else:
                    self.explain(_("{node} is not back yet").format(node=node), str(back_error or "") or _(
                        "It did not answer within 15 minutes. Check the console of the machine."
                    ))

            def rebooting(_result, reboot_error):
                nonlocal done_waiting
                if reboot_error:
                    self.explain(_("Reboot failed"), str(reboot_error))
                    return
                done_waiting = self.busy(_("{node} is rebooting…").format(node=node))
                run_async(lambda: core.wait_until_back(host, manager), back_again)

            done_waiting = lambda: None  # noqa: E731 - replaced once the reboot starts

            def on_response(_dialog, response):
                if response == "reboot":
                    run_async(lambda: core.reboot_node(host, node, manager), rebooting)

            dialog.connect("response", on_response)
            dialog.present()

        run_async(lambda: core.running_guests(host, node, manager), loaded)

    def offer_upgrade_console(self, host: str, manager: core.Account, node: dict) -> None:
        body = _(
            "SSH as root does not work for {node}, so the upgrade runs in the upgrade console of the web interface, "
            "which shows every step after you sign in. For upgrades with a single click, set up \"SSH for my "
            "terminal\" once."
        ).format(node=node["node"])
        dialog = Adw.MessageDialog(transient_for=self, heading=_("Upgrade {node}?").format(node=node["node"]), body=body)
        dialog.add_response("cancel", _("Cancel"))
        if node["local"]:
            dialog.add_response("ssh", _("Set up SSH…"))
        dialog.add_response("console", _("Open upgrade console"))
        dialog.set_response_appearance("console", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dialog, response):
            if response == "console":
                self.open_uri(core.upgrade_console_url(host, node["node"]))
            elif response == "ssh":
                self.open_ssh(host, manager.token_id)

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

        targets = core.claude_targets()
        if targets:
            names = {"code": _("Claude Code"), "desktop": _("Claude Desktop")}
            claude_row = Adw.SwitchRow(
                title=_("Claude Code integration"),
                subtitle=_("Registers the MCP server in {apps}").format(apps=" + ".join(names[t] for t in targets)),
                active=core.claude_registered(),
            )
            claude_row.connect("notify::active", self.on_claude_toggled)
            self.options.add(claude_row)

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

    def on_claude_toggled(self, row, _pspec) -> None:
        if getattr(row, "busy", False):
            return
        register = row.get_active()
        row.set_sensitive(False)

        def done(_result, error):
            row.set_sensitive(True)
            if error:
                row.busy = True
                row.set_active(not register)
                row.busy = False
                self.explain(_("Claude Code integration could not be changed"), str(error))
            elif register:
                self.toast(_("MCP server registered; restart Claude Code to load it"), "success")
            else:
                self.toast(_("MCP server removed from Claude Code"))

        run_async(core.claude_register if register else core.claude_unregister, done)

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
