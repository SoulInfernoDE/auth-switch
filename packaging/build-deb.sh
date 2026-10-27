#!/bin/sh
# Build dist/auth-switch_<version>_all.deb from the source tree.
set -eu
cd "$(dirname "$0")/.."

version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' authswitch/__init__.py)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

lib="$root/usr/lib/python3/dist-packages/authswitch"
install -d "$root/DEBIAN" "$root/usr/bin" "$lib/sounds"
install -m 644 authswitch/*.py "$lib/"
install -m 644 authswitch/sounds/*.wav "$lib/sounds/"
for catalog in authswitch/locale/*/LC_MESSAGES/auth-switch.mo; do
    install -Dm 644 "$catalog" "$root/usr/lib/python3/dist-packages/$catalog"
done
icon=icons/hicolor/scalable/apps/dev.authswitch.AuthSwitch.svg
install -Dm 644 "authswitch/$icon" "$lib/$icon"
install -Dm 644 "authswitch/$icon" "$root/usr/share/$icon"
install -Dm 644 data/dev.authswitch.AuthSwitch.desktop "$root/usr/share/applications/dev.authswitch.AuthSwitch.desktop"
install -Dm 644 LICENSE "$root/usr/share/doc/auth-switch/copyright"

for entry in "auth-switch:authswitch.__main__" "auth-switch-mcp:authswitch.mcp"; do
    printf '#!/usr/bin/python3\nimport sys\nfrom %s import main\nsys.exit(main())\n' "${entry#*:}" > "$root/usr/bin/${entry%%:*}"
    chmod 755 "$root/usr/bin/${entry%%:*}"
done

cat > "$root/DEBIAN/control" <<CONTROL
Package: auth-switch
Version: $version
Architecture: all
Maintainer: auth-switch contributors
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1 (>= 1.4), gir1.2-secret-1
Recommends: git, pipewire-bin | pulseaudio-utils | alsa-utils
Section: admin
Priority: optional
Description: GUI and MCP server for switching Proxmox VE accounts
 A small GTK window that keeps Proxmox VE API tokens in the system keyring
 and switches the active account per server. Servers with self-signed
 certificates are pinned to the fingerprint the user confirmed. Ships an
 MCP server for AI assistants and runs other tools with the active account.
CONTROL

mkdir -p dist
dpkg-deb --build --root-owner-group "$root" "dist/auth-switch_${version}_all.deb"
