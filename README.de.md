<p align="center">
  <img src="authswitch/icons/hicolor/scalable/apps/dev.authswitch.AuthSwitch.svg" width="128" alt="Auth-Switch-Logo">
</p>

<h1 align="center">Auth-Switch</h1>

<p align="center">
  Mit einem Klick zwischen Proxmox-VE-Konten wechseln.<br>
  <a href="README.md">English</a> · <b>Deutsch</b>
</p>

<p align="center">
  <img src="docs/screenshot.de.png" width="480" alt="Auth-Switch-Fenster">
</p>

Eine kleine GTK-App, die API-Tokens für Proxmox VE sicher verwahrt und das
aktive Konto pro Server wechselt – im Fenster, auf der Kommandozeile, für
andere Werkzeuge wie Terraform oder Ansible und für KI-Assistenten über den
mitgelieferten MCP-Server. Auth-Switch basiert auf
[Git-Switch](https://github.com/SoulInfernoDE/gitswitch).

## Funktionen

- Konten sind API-Tokens (`benutzer@realm!name`); mehrere pro Server, eines aktiv
- Zeigt pro Konto, ob das Token noch funktioniert, und die Proxmox-VE-Version
- Server mit selbstsigniertem Zertifikat – bei Proxmox VE der Standard – werden
  auf den Fingerabdruck festgelegt, den du einmal bestätigt hast
- Per Schalter festlegen, was ein Token darf – Gäste lesen, benutzen oder
  verwalten, Speicher, Konten, Netzwerke oder Knoten verwalten (Proxmox-VE-Rollen)
- Einem Token den Zugriff auf einzelne Gäste, Speicher oder Knoten über ein
  Dropdown im Eintrag verweigern
- Startet andere Werkzeuge mit dem aktiven Konto: `auth-switch exec -- terraform plan`
- MCP-Server mit Lese- und Schreibzugriff auf die Proxmox-VE-API
- Leak-Prüfung: findet Token-Geheimnisse, Serveradressen, deine echte
  E-Mail-Adresse und ähnliche private Daten, bevor sie veröffentlicht werden
- Sucht beim Start nach einer neueren Version
- Dezente Soundeffekte, Oberfläche auf Englisch und Deutsch

## Installation

Benötigt Python ≥ 3.10, GTK 4, libadwaita ≥ 1.4, libsecret und einen laufenden
Schlüsselbund (GNOME Keyring, KWallet o. Ä.).

**Debian / Ubuntu / Linux Mint** – das `.deb` von der
[Release-Seite](../../releases) herunterladen und installieren:

```bash
sudo apt install ./auth-switch_0.3.0_all.deb
```

**Andere Distributionen** – PyGObject, GTK 4, libadwaita und libsecret über den
Paketmanager installieren, dann:

```bash
pipx install --system-site-packages auth_switch-0.3.0-py3-none-any.whl
```

## Konto hinzufügen

1. In der Proxmox-VE-Weboberfläche **Rechenzentrum → Berechtigungen →
   API-Token** öffnen und ein Token anlegen. Gib ihm nur die nötigen
   Berechtigungen; bei aktivierter *Privilegientrennung* müssen sie dem Token
   selbst erteilt werden.
2. In Auth-Switch **+** drücken, Serveradresse, Token-ID (`benutzer@realm!name`)
   und Geheimnis eingeben.
3. Vertraut dein System dem Zertifikat des Servers nicht, zeigt Auth-Switch
   dessen SHA-256-Fingerabdruck. Vergleiche ihn mit **Knoten → System →
   Zertifikate** oder `pvenode cert info` auf dem Server und bestätige nur,
   wenn er übereinstimmt.

## Berechtigungen

**Berechtigungen …** im Menü eines Kontos zeigt Schalter für die eingebauten
Proxmox-VE-Rollen, zum Beispiel *Gäste benutzen* (PVEVMUser), *Gäste verwalten*
(PVEVMAdmin) oder *Konten verwalten* (PVEUserAdmin), und erteilt oder entzieht
sie dem Token für den ganzen Server (Pfad `/`). Rechte auf anderen Pfaden
bleiben unverändert. Zum Ändern braucht es ein Konto, das Berechtigungen ändern
darf, meist ein Token von `root@pam`; der Dialog nimmt dafür ein anderes Konto
desselben Servers und lässt dich eines auswählen. Ein Token ohne
Privilegientrennung hat immer alle Rechte seines Benutzers; darauf weist der
Dialog hin.

### Zugriff auf einzelne Gäste

Der Schloss-Knopf im Eintrag eines Kontos öffnet ein Dropdown mit allen
virtuellen Maschinen, Containern, Speichern und Knoten des Clusters.
Ausschalten verweigert dem Token den Zugriff darauf mit der Rolle *NoAccess*,
die weiter gefasste Rechte wie eine Rolle auf `/` übersteuert; Einschalten
entfernt diesen Eintrag wieder. Wie bei den Rollen geschieht das mit einem
anderen Konto des Servers, auswählbar unten im Dropdown.

## So werden Geheimnisse geschützt

- Ein Geheimnis liegt ausschließlich im System-Schlüsselbund – nie in einer
  Datei, einer Kommandozeile oder einem Log. Ohne Schlüsselbund wird das Konto
  nicht angelegt.
- Es wird nur an den eigenen Server gesendet, nur über HTTPS. Bei einem
  festgelegten Server wird das Zertifikat vor dem Senden mit dem bestätigten
  Fingerabdruck verglichen; ein geändertes Zertifikat stoppt die Anfrage.
- Weiterleitungen werden nicht verfolgt, und API-Endpunkte, die Tickets oder
  neue Zugangsdaten ausstellen, sind gesperrt.
- Fenster, Kommandozeile und MCP-Server zeigen nie ein Geheimnis.
  `auth-switch exec` gibt es nur an die Umgebung des gestarteten Programms
  weiter.

## Benutzung

```bash
auth-switch                        # Fenster öffnen
auth-switch list                   # Konten als JSON
auth-switch switch root@pam!ops    # Wechsel aus der Shell
auth-switch exec -- terraform plan # Werkzeug mit dem aktiven Konto starten
auth-switch leak-check             # prüfen, was der nächste Push veröffentlichen würde
```

`auth-switch exec` setzt die Variablen der gängigen Werkzeuge:
`PROXMOX_VE_ENDPOINT` und `PROXMOX_VE_API_TOKEN` (Terraform-Provider bpg),
`PM_API_URL`, `PM_API_TOKEN_ID` und `PM_API_TOKEN_SECRET` (Terraform-Provider
Telmate) sowie `PROXMOX_HOST`, `PROXMOX_PORT`, `PROXMOX_USER`,
`PROXMOX_TOKEN_ID` und `PROXMOX_TOKEN_SECRET` (Ansible). Diese Werkzeuge prüfen
das Zertifikat selbst; für sie empfiehlt sich daher ein Zertifikat, dem dein
System vertraut.

## MCP-Server

Im Fenster **Eintrag kopieren** drücken und in die Konfiguration deines
MCP-Clients einfügen oder `auth-switch-mcp` als stdio-Server registrieren.
Tools:

| Tool | Zweck |
| --- | --- |
| `list_proxmox_accounts` | Konten pro Server, das aktive, Token-Gültigkeit, Version |
| `switch_proxmox_account` | Ein anderes Token aktivieren |
| `proxmox_api_get` | Aus der API lesen: Knoten, Gäste, Speicher, Tasks … |
| `proxmox_api_write` | Etwas ändern: Gäste starten/stoppen, Snapshots, Konfiguration … |
| `check_for_leaks` | Text, Dateien oder den nächsten Push auf private Daten prüfen |

Lesen und Schreiben sind getrennte Tools, damit sich Lesen dauerhaft erlauben
lässt, während Änderungen weiterhin nachfragen. Aufrufe laufen mit den
Berechtigungen des aktiven Tokens; ein Token mit wenigen Rechten begrenzt also,
was der Assistent tun kann.

## Leak-Prüfung

| Stufe | Was gefunden wird |
| --- | --- |
| `secret` | Die Geheimnisse deiner Tokens, andere Zugriffstokens, private Schlüssel |
| `private` | Adressen deiner Proxmox-VE-Server, deine echte Git-E-Mail-Adresse, Pfade in deinem Home-Verzeichnis |
| `review` | Andere E-Mail-Adressen, der Rechnername, private Netzwerkadressen, interne Hostnamen |

`auth-switch leak-check` endet bei Funden mit Status 1 und eignet sich damit
als git-`pre-push`-Hook. Einträge unter `leak_allow` in
`~/.config/auth-switch/config.json` werden ignoriert. Begriffe, die nicht in
veröffentlichten Inhalten stehen sollen, lassen sich dort ebenfalls eintragen
und in genau einem Repository erlauben:

```json
"restricted": {
  "terms": ["Example Tool"],
  "files": ["EXAMPLE.md"],
  "repository": "git.example.com/you/notes"
}
```

Die Prüfung liest nur Text; was ein Screenshot zeigt, kann sie nicht erkennen.

## Updates

Beim Start fragen Fenster und MCP-Server GitHub nach dem neuesten Release,
höchstens alle 12 Stunden und ohne ein Konto zu verwenden. Abschalten lässt es
sich mit **Beim Start nach Updates suchen**. Installiert wird nichts
automatisch.

## Entwicklung

Programmtexte liegen als gettext-Kataloge unter `authswitch/locale/`; Englisch
ist Ausgangssprache und Fallback.

```bash
/usr/bin/python3 -m unittest discover -s tests
packaging/update-translations.sh   # Programmtexte extrahieren, Kataloge aktualisieren und kompilieren
packaging/build-deb.sh
packaging/release.sh <notes file> [<forgejo host> <forgejo owner/repo>]   # bauen, auf GitHub veröffentlichen, auf den Spiegel kopieren
```

## Lizenz

MIT
