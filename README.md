<p align="center">
  <img src="authswitch/icons/hicolor/scalable/apps/dev.authswitch.AuthSwitch.svg" width="128" alt="Auth-Switch logo">
</p>

<h1 align="center">Auth-Switch</h1>

<p align="center">
  Switch between Proxmox VE accounts with one click.<br>
  <b>English</b> · <a href="README.de.md">Deutsch</a>
</p>

<p align="center">
  <img src="docs/screenshot.png" width="480" alt="Auth-Switch window">
</p>

A small GTK app that keeps Proxmox VE API tokens safe and switches the active
account per server – in the window, on the command line, for other tools such
as Terraform or Ansible, and for AI assistants through the bundled MCP server.
Auth-Switch is based on [Git-Switch](https://github.com/SoulInfernoDE/gitswitch).

## Features

- Accounts are API tokens (`user@realm!name`); several per server, one active
- Shows per account whether the token still works and the Proxmox VE version
- Servers with a self-signed certificate – the Proxmox VE default – are pinned
  to the fingerprint you confirmed once
- Adjust what a token may do with switches – read, use or manage guests, manage
  storage, accounts, networks or nodes (Proxmox VE roles)
- Deny a token access to single guests, storages or nodes from a drop-down in
  its entry
- Runs other tools with the active account: `auth-switch exec -- terraform plan`
- MCP server with read and write access to the Proxmox VE API
- Leak check: finds token secrets, server addresses, your real e-mail address
  and similar private data before they are published
- Looks for a newer version on start
- Soft sound effects, English and German interface

## Install

Requires Python ≥ 3.10, GTK 4, libadwaita ≥ 1.4, libsecret and a running
keyring (GNOME Keyring, KWallet or similar).

**Debian / Ubuntu / Linux Mint** – download the `.deb` from the
[releases page](../../releases) and install it:

```bash
sudo apt install ./auth-switch_0.3.0_all.deb
```

**Other distributions** – install PyGObject, GTK 4, libadwaita and libsecret
from your package manager, then:

```bash
pipx install --system-site-packages auth_switch-0.3.0-py3-none-any.whl
```

## Adding an account

1. In the Proxmox VE web interface open **Datacenter → Permissions → API
   Tokens** and add a token. Give it only the permissions it needs; with
   *Privilege Separation* enabled, grant them to the token itself.
2. In Auth-Switch press **+**, enter the server address, the token ID
   (`user@realm!name`) and the secret.
3. If the server's certificate is not trusted by your system, Auth-Switch
   shows its SHA-256 fingerprint. Compare it with **Node → System →
   Certificates** or `pvenode cert info` on the server and confirm only if it
   matches.

## Permissions

**Permissions…** in the menu of an account shows switches for the built-in
Proxmox VE roles, for example *Use guests* (PVEVMUser), *Manage guests*
(PVEVMAdmin) or *Manage accounts* (PVEUserAdmin), and grants or revokes them for
the token on the whole server (path `/`). Rights on other paths stay as they
are. Changing permissions needs an account that may modify them, usually a
token of `root@pam`; the dialog uses another account of the same server for
that and lets you pick it. A token without privilege separation always has all
rights of its user, so the dialog points this out.

### Access to single guests

The lock button in an account's entry opens a drop-down with every virtual
machine, container, storage and node of the cluster. Switching one off denies
the token access to it with the *NoAccess* role, which overrides broader
rights such as a role on `/`; switching it on again removes that entry. Like
the roles, this is changed with another account of the server, selectable at
the bottom of the drop-down.

## How secrets are protected

- A secret is stored in the system keyring only – never in a file, a command
  line or a log. Without a keyring the account is not added.
- It is sent only to its own server, only over HTTPS. For a pinned server the
  certificate is checked against the confirmed fingerprint before anything is
  sent; a changed certificate stops the request.
- Redirects are not followed, and API endpoints that issue tickets or new
  credentials are blocked.
- The window, the command line and the MCP server never show a secret.
  `auth-switch exec` hands it only to the environment of the program it
  starts.

## Usage

```bash
auth-switch                        # open the window
auth-switch list                   # accounts as JSON
auth-switch switch root@pam!ops    # switch from the shell
auth-switch exec -- terraform plan # run a tool with the active account
auth-switch leak-check             # check what the next push would publish
```

`auth-switch exec` sets the variables of the common tools:
`PROXMOX_VE_ENDPOINT` and `PROXMOX_VE_API_TOKEN` (Terraform provider bpg),
`PM_API_URL`, `PM_API_TOKEN_ID` and `PM_API_TOKEN_SECRET` (Terraform provider
Telmate) and `PROXMOX_HOST`, `PROXMOX_PORT`, `PROXMOX_USER`,
`PROXMOX_TOKEN_ID` and `PROXMOX_TOKEN_SECRET` (Ansible). Those tools verify the
certificate themselves, so for them a certificate your system trusts is
recommended.

## MCP server

Press **Copy entry** in the window and add it to the configuration of your MCP
client, or register `auth-switch-mcp` as a stdio server. Tools:

| Tool | Purpose |
| --- | --- |
| `list_proxmox_accounts` | Accounts per server, the active one, token validity, version |
| `switch_proxmox_account` | Activate another token |
| `proxmox_api_get` | Read from the API: nodes, guests, storage, tasks … |
| `proxmox_api_write` | Change things: start/stop guests, snapshots, configuration … |
| `check_for_leaks` | Check text, files or the next push for private data |

Reading and writing are separate tools so that reading can be allowed
permanently while changes still ask for confirmation. Calls run with the
permissions of the active token, so a token with limited rights limits what the
assistant can do.

## Leak check

| Severity | What is found |
| --- | --- |
| `secret` | The secrets of your tokens, other access tokens, private keys |
| `private` | Addresses of your Proxmox VE servers, your real git e-mail address, paths in your home directory |
| `review` | Other e-mail addresses, the computer name, private network addresses, internal host names |

`auth-switch leak-check` exits with status 1 if it finds something, so it works
as a git `pre-push` hook. Entries under `leak_allow` in
`~/.config/auth-switch/config.json` are ignored. Terms you want to keep out of
published content can be listed there as well and allowed in exactly one
repository:

```json
"restricted": {
  "terms": ["Example Tool"],
  "files": ["EXAMPLE.md"],
  "repository": "git.example.com/you/notes"
}
```

The check reads text only; it cannot see what a screenshot shows.

## Updates

On start the window and the MCP server ask GitHub for the latest release, at
most every 12 hours and without using any account. Turn it off with **Check
for updates on start**. Nothing is installed automatically.

## Development

Program texts live in gettext catalogs under `authswitch/locale/`; English is
the source language and the fallback.

```bash
/usr/bin/python3 -m unittest discover -s tests
packaging/update-translations.sh   # extract program texts, update and compile the catalogs
packaging/build-deb.sh
packaging/release.sh <notes file> [<forgejo host> <forgejo owner/repo>]   # build, release on GitHub, copy to the mirror
```

## License

MIT
