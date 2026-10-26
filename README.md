# Strata — v0.6

[![Release](https://img.shields.io/github/v/release/SolidGeeks/strata)](https://github.com/SolidGeeks/strata/releases) [![License AGPL-3.0](https://raw.githubusercontent.com/SolidGeeks/.github/main/assets/badges/license-agpl.svg)](LICENSE) [![Signed releases](https://raw.githubusercontent.com/SolidGeeks/.github/main/assets/badges/signed-releases.svg)](#2-quick-start-with-docker) [![Tests](https://github.com/SolidGeeks/strata/actions/workflows/ci.yml/badge.svg)](https://github.com/SolidGeeks/strata/actions/workflows/ci.yml)

Strata is a self-hosted 3D map of your information systems (IS): zones, VLANs, low-poly assets, inbound and outbound flows, port exposure (Internet, inter-VLAN, intra-VLAN), vulnerabilities and incident contacts. Website and documentation: **https://solidgeeks.github.io/strata/**

*Formerly IS Map 3D.*

**Website and documentation:** the `docs/` folder holds the GitHub Pages site, with the scroll-driven presentation film. To publish it: *Settings › Pages › Build and deployment › Deploy from a branch*, branch `main`, folder `/docs`. The film's source code is in `media/reel/`.

## Roadmap

Strata is on its way to **1.0.0**: from then on, the API, the export format, the `.env` settings, the Docker image and `scripts/users.mjs` only break in a new major version.

| Milestone | What it brings |
|---|---|
| [0.7.0](https://github.com/SolidGeeks/strata/milestone/1) | Hardening and tests: limit failed sign-ins, a security review, a browser test of the interface |
| [0.8.0](https://github.com/SolidGeeks/strata/milestone/2) | A modern three.js, or a documented decision to stay on 0.128 |
| [0.9.0](https://github.com/SolidGeeks/strata/milestone/3) | The last breaking changes: IS Map compatibility, pre-releases, an API reference |
| [1.0.0](https://github.com/SolidGeeks/strata/milestone/4) | Release candidates (`1.0.0-rc.N`), then 1.0.0 |

Follow it on the [milestones page](https://github.com/SolidGeeks/strata/milestones). Ideas for after 1.0 are discussed, and voted on, in [Discussions](https://github.com/orgs/SolidGeeks/discussions/categories/ideas). Want to help? Start with a [good first issue](https://github.com/SolidGeeks/strata/issues?q=is%3Aopen+label%3A%22good+first+issue%22).

## Next: attack paths and blast radius

- **Attack paths** (*Analysis*): which critical assets an attacker could reach from the Internet, every path to each one along the allowed flows, most likely first, and **where to cut** (the assets to harden and the equipment whose rules to tighten, that every path to a critical asset goes through). Hover a path to pick it out on the model, in 3D or in 2D.
- **Blast radius**: pick an asset (in the panel, or *Blast radius* on its sheet) and see everything an attacker holding it could reach, the most likely way to each asset, and the business services hit.
- A step counts for the highest of: the vulnerabilities of the asset taken over (as for the risk score), 50% on a remote administration port (SSH, RDP, SMB, WinRM, VNC, Telnet, RPC), 10% on any other service; a path for the product of its steps. Both lists export as CSV.

- **Architecture file**: one document per IS (*Analysis › Architecture file*, or the IS summary), in the shape audits and security accreditation expect: cover and sign-off table, summary, scope, network diagram, zones and VLANs, applications, asset inventory, flow matrix, the rules each firewall needs, exposure, vulnerabilities and remediation order, attack paths, plans of the exposed and critical assets, incident contacts, change history and method. *Download* saves it as one HTML file, with no outside resource, that prints to A4 PDF from the browser.

## New in v0.6: business views and risk priorities

- **Three points of view** on an IS, switched at the top: **Physical** (the 3D model and the 2D diagram), **Application** (one box per application, with the assets it runs on and the flows between applications) and **Business**.
- **Business services**: record what the organisation does (online sales, payroll, production line 1) and the assets each service runs on. Strata works out the rest from the flows: what those assets call, the equipment crossed, the Internet services used. The asset sheet lists the business services an asset would hit, and through which chain of flows.
- **Risk priorities** (*Analysis*): one score per asset, 0 to 100, and the fixes in the order to follow. Each vulnerability counts for its CVSS times its likelihood of exploitation (certain on the CISA list of known exploited vulnerabilities, otherwise from its EPSS, otherwise 30%), weighed by exposure, reachability from the Internet and criticality (of the asset or of the business services it would hit). *Why?* on the asset sheet shows each factor; the list exports as CSV. Vulnerabilities take an EPSS and a KEV mark, by hand, in imported JSON, or from the Cyberwatch connector when Cyberwatch gives them. Strata does not download these feeds itself.
- **Readable flows**: every flow crossing a firewall, router, switch or gateway has its own lane there, in 3D and in 2D; *Colour by › Per flow* gives flows sharing a device different colours; hovering a flow in a sheet picks it out.
- **Architecture plan**, redrawn: one right-angle line per flow, numbered, with a table of the flows and of the **firewall rules** of the asset under the drawing; filters by direction (inbound, outbound, crossing) and kind of flow (Internet, inter-VLAN, intra-VLAN); scope limited to the asset's own flows by default.
- **Asset form**: a new asset starts on the first free IP of its VLAN range.

## Night mode (v0.5.2)

*Display › Theme*: **Auto** follows the system's light or dark setting (the default), **Day** and **Night** force one. Keyboard shortcut: **N** switches between day and night. The choice is remembered in the browser. The 3D view, the 2D diagram and the panels follow the theme; exported architecture plans (PNG/SVG) stay on a light background, for documentation.

## New name (v0.5.1)

IS Map 3D is now called **Strata**, for the layers of plates that stack zones and VLANs. Nothing changes in the data: IS Map exports and backups import as they are, scripts that still send `X-Requested-With: is-map` keep working, and the map saved in the browser is found again.

**Upgrading an existing IS Map install:**

- **Docker:** the service is now called `strata` and the data volume `strata-data`. To keep your data, add the old volume's name to `.env` (`docker volume ls`, usually `is-map_ismap-data`): `DATA_VOLUME=is-map_ismap-data`. Then run `docker compose down --remove-orphans && docker compose up -d --build`. Commands become `docker compose logs -f strata`, `docker compose exec strata …`.
- **systemd:** the new unit is `deploy/strata.service` (folders `/opt/strata`, `/var/lib/strata`, `/etc/strata.env`). You can also keep your old `is-map.service` unit and its paths: only the names change.

## New in v0.5: connectors

Four connectors, in *Collaboration › Connectors* (self-hosted version only). **None of them writes to the map directly:** each sync prepares **one proposal per IS**, which an `approver` reviews on the map (green / orange / red highlights) and then publishes or rejects, like a proposal made by hand. Until it is handled, the next sync updates the same proposal instead of piling up a new one. If the map already matches, no proposal is created.

| Connector | What it reads | What it proposes |
|---|---|---|
| **Cyberwatch** | servers and their CVEs (API v3: `/api/v3/vulnerabilities/servers`, then each server's details) | asset vulnerabilities, matched by host name, then by IP. Minimum severity and maximum count per asset can be set; CVEs ignored in Cyberwatch are left out by default. Cyberwatch "owns" the `CVE-…` entries of the assets it scans; findings entered by hand (`Config.`…) are kept. |
| **GLPI** | computers, network devices, printers, phones (REST API `apirest.php`) with their IP (network ports), OS, installed software, technician and group in charge, location | the **location** points to the IS (rules `location text = IS id`, or else the IS whose name appears in the location). Existing assets get their OS, applications and contacts (those entered by hand stay; an application entered by hand keeps its ports and takes the version from the inventory). Missing assets are created on the VLAN whose range contains their IP, or else on a *To sort (from GLPI)* plate in an *Imported* zone. |
| **phpIPAM** | sections, subnets, VLANs, addresses (API `/api/{app}/…`) | each IS's VLANs (number, name, range): a subnet already present as a VLAN of an IS goes to that IS, otherwise rules `section or location = IS id`. New VLANs arrive in the *Imported* zone. Addresses fill in asset IPs, move an asset to its subnet's VLAN, and flag IPs that differ (without changing them). Creating assets from named addresses: off by default. |
| **Palo Alto** | PAN-OS configuration of a firewall or of Panorama: an **XML file** imported in the app (*Import a configuration file*, open to `contributor`) or the **XML API** (`type=export&category=configuration`, key of a read-only admin role) | active *allow* rules become flows of the chosen IS: address objects and groups → assets by IP (a range is expanded into its assets up to a threshold, 12 by default), public addresses and FQDNs → existing Internet services (same host) or new ones, services and service groups → ports (`application-default` → the usual ports of common App-IDs), and the chosen firewall as the device crossed. An `any` source in an `untrust`/`internet`/`outside`/`wan` zone means "Internet". Inbound flows from the Internet to an administration or database port are flagged as risky. Flows of a rule that disappeared are removed (can be turned off); flows drawn by hand are never touched. What cannot be drawn (internal `any`→`any` rules, dynamic groups, negations, addresses without an asset) is listed in the proposal. |

Settings: an `admin` fills in each connector (*Settings*); *Test the connection* checks access; *Sync now* (approver) runs a sync in the background; *Sync automatically every … hours* schedules it. Credentials are stored on the server in `data/connectors.json` (mode 600), **are never sent back to the browser**, and are not in the map's JSON backups (but they are in the `backup.sh` archive: protect it). Internal certificates: paste your CA certificate in *More settings*, or tick *Accept any TLS certificate* on a trusted network.

Assets keep the link to their source record in `ext` (for example `{"glpi":"Computer/12","cyberwatch":101}`), which makes the next syncs reliable, even after a rename.

Four-eyes rule: a proposal from a Palo Alto **file** counts as the proposal of the person who imported it (they cannot approve it themselves). A live sync (data read from your tools) can be approved by the person who started it.

### Setting up the accounts in your tools

- **Cyberwatch:** *Profile › API keys › Add*, read-only key. Basic authentication (access key : secret key); the older HMAC-SHA256 *API Auth* signature is still available in the settings for older instances. The path of the server list can be changed in *More settings* if your version differs (check your instance's Swagger, `</>` button).
- **GLPI:** *Setup › General › API*: enable the REST API, create an API client (App-Token, restricted to the Strata server's IP), then a service account with a profile that can read the assets, software, locations, groups and users, and its *API token* (*Preferences › Remote access keys*).
- **phpIPAM:** *Administration › API*: create an application (id `strata`, for example), *Read* permission, security *SSL with App code token*; the application code is the token.
- **Palo Alto:** an admin role with *XML API › Export* and *Configuration* read-only, an account that uses it, then its key (`https://firewall/api/?type=keygen`); or let the connector generate the key from the user name and password.

`CONNECTORS=false` in `.env` turns the connectors off completely.

**License:** Strata is free software under the [GNU AGPL v3](LICENSE). You can use it, modify it and redistribute it; if you make a **modified** version available to users over a network, you must give them access to its source code. The *Source code* link at the bottom of the control panel points to `SOURCE_URL` (in `.env`): point it at your fork if you modify the code.

To try it without plugging in your tools: load the demo, run `node scripts/connector-sim.mjs` (with Docker: `docker compose exec -d strata node scripts/connector-sim.mjs`) (fake Cyberwatch, GLPI, phpIPAM and PAN-OS on port 8099, with data matching the Lyon IS) and use the addresses and credentials listed at the top of the script.

## New in v0.4

- **Named accounts and roles** (self-hosted version):

  | Role | Can |
  |---|---|
  | `viewer` | browse the map, the asset sheets, the plans and the history |
  | `contributor` | also prepare proposals (drafts) and submit them |
  | `approver` | also edit the map directly, approve or reject proposals, restore a version |
  | `admin` | also manage accounts |

  The first admin comes from `EDIT_USER` / `EDIT_PASS` (recreated or reset on every start, handy if you forget the password). Other accounts are managed in the app (*Collaboration › Account*) or from the command line: `node scripts/users.mjs set alice contributor` (with Docker: `docker compose exec strata node scripts/users.mjs set alice contributor`). Everyone changes their own password in *Account*. Passwords are stored hashed (scrypt) in `data/users.json`.
- **Version history and rollback:** every change is recorded (who, when, what) in `data/history.jsonl`. *Collaboration › History* lists the changes, for the open IS or the whole map. *View* shows the map as it was (read-only, yellow banner), *Restore* puts the whole map back to that version. A restore is itself a version: it can be undone.
- **Proposals to review:** a contributor clicks *Propose a change*, then edits the map as usual (2D diagram, sheets, forms). Everything goes into a draft (blue *Draft* banner); the real map does not move. *Submit for review* sends it to the approvers.
  - The approver opens the proposal from *Proposals*: the map shows with the changes applied and highlighted (green: added, orange: changed, dotted red: flow removed), with the detailed list of changes. They comment, then *Approve and publish* (the proposal becomes a version in the history) or *Reject* (the author can rework it).
  - Four-eyes rule: you cannot approve your own proposal (unless `ALLOW_SELF_APPROVAL=true`).
  - If the map changed in the meantime on the same items, the approver is warned and chooses whether to publish anyway.
  - **From a file:** *New proposal › A file* accepts a Strata (or IS Map) JSON export (the whole map, or a single IS exported with *Export this IS (JSON)* from the IS sheet). The differences with the map become the content of the proposal.
- **Internet services:** instead of a single "Internet" cloud, you describe the services allowed (ESET update servers, Ubuntu repositories, Windows Update, NTP, SaaS…) with their FQDNs/IPs and ports. They are **shared by every IS** (common catalogue, overview) or **specific to one IS** (*+ This IS* button). Flows can have a service as their source or destination: they appear next to the cloud in 3D, at the top of the 2D diagram, in architecture plans, and the firewall rules export uses their FQDNs as the destination address.

## New in v0.3

- **Synchronized 2D diagram:** in an IS, the selector at the top of the screen switches between *3D model* and *2D diagram*. The 2D diagram shows exactly the same data: one band per level, the VLAN plates in the same order, the assets in the same place, the flows with the devices they cross.
  - Dragging an asset moves it on its plate, or moves it to another VLAN if dropped on another plate. The position is saved and used by the 3D model.
  - Dragging a plate's header moves it along its level, or moves it to another zone if dropped on another level.
  - *+ Flow* tool (F key): press on the source asset and release on the destination (or on the Internet) to open the flow form, already filled in.
  - *+ Asset* tool (A key): click a plate where you want it to open the form for a new asset on that VLAN.
  - The *Auto* button of a plate arranged by hand goes back to automatic arrangement.
  - Filters (direction, exposure, severity, hidden VLANs), the asset sheet, flow details, the per-asset 2D plan and CSV exports work the same in both views. *Export SVG* saves the whole IS diagram.
  - The read-only account can browse the diagram, without moving anything.

## New in v0.2

- **A more readable model:** the pylons under the plates are hidden by default (*Layout › Standoffs*: Hidden, Thin or Full) and assets are laid out in a tight grid (*Asset spacing*: Compact or Comfortable). The height between levels is set in *Display › Level height*.
- **Arranging VLANs:** *Arrange plates* button, then drag a plate anywhere on its level (left, right, front, back; v0.4.2); the *Line up* button puts the level back in a line; or use the arrows shown in the VLAN list (in "1 VLAN per floor" mode, the arrows change the floor). The order is saved in the IS (`vlans[].pos`).
- **Flows through network devices:** each flow goes through the firewalls, routers or switches it crosses. The path is suggested automatically (edge firewall for the Internet, internal firewall or core router between VLANs) and can be corrected flow by flow in *Edit the flow › Path through the network*. Cones show the direction at each hop; hovering a wire shows "source → devices → destination", clicking it opens the flow details. New asset type: *Router / L3 core*.
- **OS and applications:** each asset lists the applications running on it (name, version, listening ports). The sheet shows the asset "open": applications, OS, hardware. An exposed port shows the application listening on it.
- **2D architecture plan:** from an asset's sheet, *2D plan* button. The plan shows the asset with its applications and OS, its direct flows, the devices crossed and every recorded path to and from the Internet, grouped by zone and by VLAN. Export as **SVG** (vector, for Confluence, Word, draw.io) or **PNG**.
- **CSV exports** from the sheet: *Flow matrix* (the asset's flow matrix, with the path and the firewalls crossed) and *Firewall rules* (one allow rule per flow and per firewall crossed, grouped by firewall; for a firewall, its own rule base). Semicolon separator and UTF-8, to open directly in Excel. Flows that cross no firewall are listed at the end.

The package contains the web app and a small Node.js server **with no runtime dependencies**:

- data is shared by all users and stored in a single JSON file;
- changes show up live for the other users;
- access is protected by named accounts with roles, and an optional shared read-only account;
- automatic backups are made at startup, every day, and before each import;
- everything works offline: three.js and the fonts are served locally, with no CDN or Google Fonts.

```
strata/
├── public/            the app (index.html, app.js, app.css)
├── server/server.js   the server (API + static files)
├── scripts/           vendor.mjs (fetches three.js and the fonts), users.mjs (accounts), backup.sh, restore.sh
├── deploy/            Caddyfile (HTTPS), strata.service (systemd)
├── tests/             API tests (npm test)
├── flake.nix, nix/    Nix package, NixOS module (services.strata) and its VM test
├── Dockerfile, docker-compose.yml, .env.example
└── package.json
```

---

## 1. Requirements

One of these two options:

- **Docker** with Docker Compose v2 (`docker compose version`), recommended;
- **Node.js 20 or later** (`node --version`);
- or **Nix** with flakes, or **NixOS** (section 5, *Nix and NixOS*).

The machine needs access to the npm registry **once**, during the build, to download three.js 0.128 and the fonts. After that, the app runs without Internet access.

Users need a recent browser with WebGL (recent Chrome, Edge, Firefox or Safari).

---

## 2. Quick start with Docker

```bash
cd strata
cp .env.example .env
nano .env                       # change EDIT_PASS
docker compose up -d --build    # builds the image here (needs the npm registry during the build)
```

On Windows (PowerShell or cmd): `copy .env.example .env`, then edit `.env` with Notepad (`notepad .env`).

Or use the prebuilt image published with each release (tag `vX.Y.Z`, see the `Release` workflow): `docker compose pull && docker compose up -d` fetches `ghcr.io/solidgeeks/strata`.

Every published image is **signed**: an attestation proves it was built by this repository's `Release` workflow, from the code of the tag. To check it before deploying (you need the [GitHub CLI](https://cli.github.com/)):

```bash
gh attestation verify oci://ghcr.io/solidgeeks/strata:0.6.0 --owner SolidGeeks
```

The command must print `Verification succeeded!`. If it fails, do not use the image, and report it (see [SECURITY.md](SECURITY.md)). Images older than 0.5.4 are not signed.

Then open http://localhost:8080 and sign in with `EDIT_USER` / `EDIT_PASS`.

The map starts empty. To explore it, click **Load demo (5 IS)**. To start from scratch, click **Delete everything**.

Useful commands:

```bash
docker compose logs -f strata    # logs
docker compose restart strata    # restart
docker compose down             # stop (the data stays in the volume)
```

By default, the port only listens on the machine itself (`127.0.0.1:8080`). To open it to your network, see section 4.

---

## 3. Configuration (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `EDIT_USER` / `EDIT_PASS` | `admin` / empty | First admin account, recreated or reset on every start. **With no `EDIT_PASS` and no account in `data/users.json`, there is no authentication at all.** |
| `VIEW_USER` / `VIEW_PASS` | `viewer` / empty | Shared read-only account, ignored while `VIEW_PASS` is empty. |
| `EDIT_PASS_FILE` / `VIEW_PASS_FILE` | — | Read the password from this file instead (Docker secrets, systemd credentials, sops-nix, agenix). The file wins over the variable; a trailing newline is ignored. If the file cannot be read, the server does not start. |
| `ALLOW_SELF_APPROVAL` | `false` | `true` lets an approver approve their own proposals. |
| `HISTORY_KEEP` | `5000` | Number of changes kept in the history. |
| `READ_ONLY` | `false` | Freezes the map for everyone. |
| `BACKUP_KEEP` | `14` | Number of automatic backups kept. |
| `BACKUP_EVERY_HOURS` | `24` | How often automatic backups are made. |
| `MAX_IMPORT_MB` | `20` | Maximum size of an imported file. |
| `PORT` / `HOST` | `8080` / `0.0.0.0` | Where the server listens. |
| `DATA_DIR` | `/data` (Docker) | Folder for the data and the backups. |
| `SITE_ADDRESS` | — | DNS name used by the HTTPS proxy (section 4). |
| `CONNECTORS` | on | `false` turns the connectors off (Cyberwatch, GLPI, phpIPAM, Palo Alto). |
| `SOURCE_URL` | `https://github.com/SolidGeeks/strata` | The app's *Source code* link (AGPL): point it at your fork if you modify the code. |
| `DATA_VOLUME` | `strata-data` | Name of the Docker data volume (to take over an IS Map install, see above). |

After changing `.env`, apply it with `docker compose up -d`.

---

## 4. Network access and HTTPS

Passwords travel with Basic Auth: **never expose the app over plain HTTP outside the machine**.

### Option A — the bundled HTTPS proxy (Caddy)

1. In `.env`, set `SITE_ADDRESS=strata.example.lan`, the name your users will type.
2. Point that name at the machine (internal DNS or hosts file).
3. Run:
   ```bash
   docker compose --profile https up -d --build
   ```
4. Open https://strata.example.lan.

The `Caddyfile` uses `tls internal`: Caddy signs the certificate with its own local authority, which suits an internal network or a VPN. To remove the browser warning, install that authority on your users' machines:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

If the name is public and reachable from the Internet on ports 80 and 443, remove the `tls internal` line and Caddy gets a Let's Encrypt certificate by itself.

### Option B — your existing reverse proxy (nginx, Traefik…)

Point the proxy at `http://127.0.0.1:8080`. Live updates use Server-Sent Events on `/api/events`: **response buffering must be turned off** on that path. nginx example:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
location /api/events {
    proxy_pass http://127.0.0.1:8080;
    proxy_buffering off;
    proxy_read_timeout 1h;
}
```

The app also works under a sub-path (for example `https://intranet/strata/`), because it only uses relative paths.

---

## 5. Install without Docker (systemd)

```bash
sudo mkdir -p /opt/strata && sudo cp -r strata/* /opt/strata/
cd /opt/strata
sudo npm run setup        # npm ci + copies three.js and the fonts into public/vendor
sudo useradd --system --home /opt/strata --shell /usr/sbin/nologin strata
sudo mkdir -p /var/lib/strata && sudo chown strata:strata /var/lib/strata
sudo cp .env.example /etc/strata.env && sudo nano /etc/strata.env && sudo chmod 600 /etc/strata.env
sudo cp deploy/strata.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now strata
journalctl -u strata -f
```

The service listens on `127.0.0.1:8080`. Put an HTTPS reverse proxy in front of it, as in option B.

For a quick test on a workstation:

```bash
npm run setup
EDIT_PASS=test npm start
```

Then open http://localhost:8080.

### Build from source

What the Dockerfile does, step by step, for packagers and other platforms:

| Step | Command | Needs |
|---|---|---|
| Install the dependencies | `npm ci` | Node.js 20 or later, npm, the npm registry (`package-lock.json` pins every package: three.js 0.128 and the Archivo and IBM Plex Mono fonts) |
| Copy them into the app | `npm run vendor` (`scripts/vendor.mjs`) | writes `public/vendor/` |
| Test | `npm test` | starts the server on `127.0.0.1` |
| Run | `node server/server.js` | Node.js only: no npm package at run time, nothing downloaded, no write outside `DATA_DIR` |

The files to ship are `package.json`, `server/`, `public/` (with `public/vendor/`) and, for the command line, `scripts/users.mjs`. `PUBLIC_DIR` and `DATA_DIR` say where the app and the data are; each release tag (`vX.Y.Z`) has a GitHub release with its source archive.

### Nix and NixOS

The repository is a flake. To try Strata (data in `./data`, listening on `127.0.0.1:8080`):

```bash
EDIT_PASS=test nix run github:SolidGeeks/strata
```

On NixOS, the module runs it as a hardened systemd service (its own `strata` user, data in `/var/lib/strata`, read-only system, no capabilities, restricted system calls):

```nix
{
  inputs.strata.url = "github:SolidGeeks/strata";

  outputs = { nixpkgs, strata, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        strata.nixosModules.default
        {
          services.strata = {
            enable = true;
            settings = {               # section 3; HOST defaults to 127.0.0.1, PORT to 8080
              EDIT_USER = "admin";
              BACKUP_KEEP = 30;
            };
            secretFiles.EDIT_PASS = "/run/secrets/strata-admin";   # kept out of the Nix store
            # environmentFile = "/run/secrets/strata.env";          # or KEY=value lines
            openFirewall = false;      # keep it behind an HTTPS reverse proxy (section 4)
          };
        }
      ];
    };
  };
}
```

Files in `secretFiles` are read by systemd as root and handed to the service as credentials: they can stay readable by root only. Accounts from the command line: `sudo -u strata env DATA_DIR=/var/lib/strata strata-users set alice contributor`.

The `Nix` workflow builds the package (which runs `npm test`) and runs a NixOS VM test of the module on every change. When `package-lock.json` changes, `npmDepsHash` in `nix/package.nix` has to follow: the build fails and prints the new value. `nix flake update` moves nixpkgs forward.

---

## 6. Backups and restore

To undo a mistake, the simplest is the history in the app (*Collaboration › History › Restore*). Backups are for losing the server.

**Automatic:** the server copies `db.json` into `/data/backups/` at startup, every `BACKUP_EVERY_HOURS` hours, before each import and before each version restore. It keeps the `BACKUP_KEEP` most recent ones.

**Manual** (Docker):

```bash
./scripts/backup.sh                                          # backups/strata-YYYYMMDD-HHMMSS.tar.gz: map, history, proposals, accounts
./scripts/restore.sh backups/strata-20261024-120000.tar.gz   # restores everything
./scripts/restore.sh export.json                             # restores the map only (db.json or Export JSON)
```

The restore script backs up what is there before replacing it. After restoring a `db.json` on its own, history lines newer than that file are ignored.

From the interface, **Export JSON** downloads the whole map and **Import JSON** loads it back (on the same instance or another one).

Remember to include the backups folder or the `strata-data` Docker volume in your usual backups.

---

## 7. Taking over a map kept in the browser only

Opened without its server (as a local file, or copied to a static web page), the app keeps the map in that browser only: the *This browser only* badge shows at the top left. To move that map to your instance:

1. In that browser, on the overview, click **Export JSON** and save the file.
2. In your instance, signed in as an editor, click **Import JSON** and pick that file.

The format is the same: IS, zones, VLANs, assets, contacts, flows and links between IS are taken over as they are. A v0.1 export imports unchanged into v0.2: flow paths are then suggested automatically.

---

## 8. Upgrading

```bash
./scripts/backup.sh
# replace the folder's files with the new version (keep your .env)
docker compose up -d --build
```

The data lives in the Docker volume and is not touched by the rebuild.

---

## 9. API (for automation)

Every route needs the same credentials as the interface, with the rights of the account's role (direct writes need `approver`). Writes require the headers `Content-Type: application/json` and `X-Requested-With: strata` (`is-map` is still accepted). A script can group several writes into a single history entry with the headers `X-Batch: <id>` and `X-Batch-Label: <URL-encoded label>`. To have a tool propose instead of write, give it a `contributor` account and use `POST /api/proposals` with `{"title", "siteId", "changes": {"si": {...}, "assets": {...}}}` (a document set to `null` = deletion).

| Method and route | What it does |
|---|---|
| `GET /api/state` | The whole map: `{si, assets, wan, services, rev, updatedAt}` |
| `GET /api/export` | The same content, as a file to download |
| `PUT /api/si/{id}` | Creates or replaces an IS (zones, VLANs, flows, contacts) |
| `DELETE /api/si/{id}` | Deletes an IS (not its assets) |
| `PUT /api/assets/{id}` | Creates or replaces an asset |
| `DELETE /api/assets/{id}` | Deletes an asset |
| `PUT /api/wan` | Replaces the links between IS: `{"links": [...]}` |
| `POST /api/import` | Replaces the whole map: `{si, assets, wan, services}` |
| `PUT /api/services` | Replaces the common catalogue of Internet services: `{"services": [...]}` |
| `GET /api/history` | Latest changes (`?before=REV&limit=N`); `GET /api/history/{rev}`: the before/after details |
| `GET /api/state?at=REV` | The map as it was right after version REV |
| `POST /api/rollback` | `{"rev": N}`: puts the map back to version N (approver) |
| `GET/POST /api/proposals`, `GET/PUT/DELETE /api/proposals/{id}` | Proposals; `POST …/{id}/submit`, `/withdraw`, `/comment`, `/approve` (`{"force": true}` on a conflict), `/reject` |
| `GET /api/users`, `PUT/DELETE /api/users/{name}` | Accounts (admin); `PUT /api/me/password`: `{"current","next"}` |
| `GET /api/connectors` | Connectors, settings (secrets masked) and latest syncs |
| `PUT /api/connectors/{id}` | A connector's settings (admin); `id`: `cyberwatch`, `glpi`, `phpipam`, `paloalto` |
| `POST /api/connectors/{id}/test` | Tests access (approver) |
| `POST /api/connectors/{id}/run` | Runs a sync (approver); `{"wait": true}` waits for the result. Palo Alto: `{"xml": "<config>…", "fileName": "…", "overrides": {"site", "firewall", "scope"}}` imports a file (contributor) |
| `GET /api/events` | SSE stream: `event: change` with the new revision, `proposals`, `connectors` |
| `GET /healthz` | Health check (no authentication) |

Example: adding an asset from a script (inventory, NetBox, scanner export…):

```bash
curl -u admin:PASSWORD -H 'Content-Type: application/json' -H 'X-Requested-With: strata' \
  -X PUT https://strata.example.lan/api/assets/srv-erp-01 \
  -d '{"site":"lyon","name":"srv-erp-01","type":"server","vlan":"v-lyo-20","ip":"10.20.0.20",
       "os":"RHEL 8","role":"ERP","crit":3,
       "vulns":[{"id":"CVE-2021-44228","title":"Log4Shell","cvss":10,"sev":"crit"}],
       "contacts":[{"name":"Application team","role":"Technical owner","phone":"+33 1 99 00 18 66","email":"apps@example.com","dispo":"Business hours"}],
       "notes":""}'
```

The simplest way to learn the exact structure is to **Export JSON** the demo.

**Flows** and **VLANs** are stored in the IS document (`si.flows`, `si.vlans`). To add some from a script: read the IS with `GET /api/state`, change it, then send it back with `PUT /api/si/{id}`.

Fields added since v0.2 (all optional):

| Field | Where | Content |
|---|---|---|
| `apps` | asset | `[{"name":"Apache Tomcat","version":"9.0.54","ports":["tcp/8080","tcp/443"]}]` |
| `via` | flow | ids of the devices crossed, in order, for example `["lyo-fw-edge","lyo-fw-int"]`. Missing: path suggested automatically. `[]`: direct flow, forced. |
| `place` | VLAN | (v0.4.2) position of the plate on its level, `[x, z]` from the level's centre. Missing on the whole level: plates lined up from left to right. |
| `pos` | VLAN | position from left to right in its zone (0, 1, 2…). Missing: sorted by VLAN number. |
| `services` | map root, and IS | Internet services: `[{"id":"svc-eset","name":"ESET update servers","category":"Antivirus / EDR","hosts":["update.eset.com"],"ports":["tcp/443"],"notes":""}]`; in a flow, the source or destination `"svc:svc-eset"` |
| `layout` | VLAN | (v0.3) positions set by hand in the 2D diagram: `{"lyo-app-erp":[3.75,0.5], …}`, in plate units from its centre (x to the right, z to the front). Missing: automatic arrangement. |
| `type: "router"` | asset | new type *Router / L3 core* |
| `ext` | asset, VLAN | (v0.5) ids in the connected tools: `{"glpi":"Computer/12","cyberwatch":101,"ipam":"57"}` |
| `src` | vulnerability, application, contact | (v0.5) `cyberwatch` or `glpi` when the entry comes from a connector (the others count as entered by hand) |
| `pan` | flow | (v0.5) Palo Alto rule(s) behind the flow: `{"rules":["in-web"],"scope":"vsys1"}` |
| `business` | IS | (v0.6) business services: `[{"id":"b-erp","name":"ERP & accounting","crit":3,"owner":"Finance director","notes":"","assets":["lyo-app-erp","lyo-db-erp"]}]`. Only the assets the service runs on: dependencies come from the flows. |
| `epss`, `kev` | vulnerability | (v0.6) EPSS, a probability from 0 to 1, and `true` when the vulnerability is on the CISA list of known exploited vulnerabilities. Used by *Risk priorities*. |

---

## 10. Security

This map describes your weak spots precisely: treat it as sensitive data.

- Keep it on an internal network or behind a VPN, over HTTPS, with a long and unique `EDIT_PASS`.
- Give the `viewer` account to people who only need to look.
- The server sends strict security headers (CSP with no external scripts, no framing, no referrer) and refuses cross-site writes.
- Published Docker images are signed (Sigstore provenance attestation): check them with `gh attestation verify` (section 2).
- These protections (authentication, roles, cross-site writes, four-eyes rule, access to the server's files) are checked by the automated tests on every code change (section 13).
- Give everyone a named account with the lowest role that is enough: every change is attributed in the history.
- Connectors: use **read-only** service accounts in Cyberwatch, GLPI, phpIPAM and PAN-OS, restricted to the Strata server's IP when the tool allows it. Their secrets are in `data/connectors.json`: protect the volume and the backup archives.

---

## 11. Troubleshooting

| Symptom | Where to look |
|---|---|
| Blank page, nothing in 3D | `public/vendor/` is missing: run `docker compose up -d --build` or `npm run setup` again, and check access to the npm registry during the build. |
| "This browser only" badge at the top left | The page cannot reach the API: it is opened as a local file, or the proxy blocks `/api/`. |
| Other users only see changes after a reload | The proxy buffers `/api/events` (see section 4, option B). |
| "You have read-only access" | You are signed in with the viewer account, or `READ_ONLY=true`. |
| Switching accounts in the browser | The browser keeps Basic Auth credentials: open a private window or close the browser. |
| Permission error on `/data` (Docker) | Keep the named volume from `docker-compose.yml`. If you mount a host folder, give it to UID 1000: `chown -R 1000:1000 ./data`. |

---

## 12. Limits of v0.6

- Storage is a single JSON file, suited to a few thousand assets. Beyond that, a real database will be needed.
- Authentication is still Basic Auth (credentials asked by the browser). For SSO (Entra ID, LDAP…), put an authenticating proxy in front and create the same account names.
- Two approvers editing the same IS directly at the same time: the last save wins (the history lets you go back). Proposals, on the other hand, detect conflicts.
- draw.io or Visio diagrams cannot be imported: only Strata JSON exports can become a proposal.
- Opened without its server, the app keeps the map in the browser only: no accounts, history, proposals or connectors.
- The path suggested for flows follows a simple rule (edge firewall, then internal firewall or core router). Check it for architectures with several firewalls in a row, and correct it flow by flow if needed.
- Exported firewall rules are a generic table, not a configuration ready to paste: your firewalls' interface and object names still have to be mapped.
- The connectors were written from the public API documentation (Cyberwatch v3, GLPI `apirest.php` 9.5/10, phpIPAM 1.4+, PAN-OS 10/11) and tested against simulators, not against your instances: run *Test the connection*, then a first sync, and review the proposal before publishing it. Fields specific to your version (Cyberwatch path, location rules) can be set without touching the code.
- Palo Alto: NAT rules, security profiles, dynamic address groups and the Panorama device-group hierarchy are not interpreted; only *allow* security rules are. A rule that is too broad (internal `any`, large range) is flagged instead of drawn.
- GLPI: one call per asset (plus one per technician and per unknown software, cached); allow a few minutes for several thousand assets. The new GLPI 11 API (`/api.php/v2`) is not supported yet.
- NetBox and NetFlow are not connected yet.
- Business dependencies follow the recorded flows: a dependency with no flow on the map (a licence server reached through a proxy, a shared storage mounted by hand) is not seen. Log and monitoring flows (syslog, SNMP traps, NetFlow) are left out on purpose.
- Attack paths follow the recorded flows only: a flow missing from the map is a path Strata does not see, and a flow recorded but blocked in practice is a path it shows. The likelihoods are a way to rank paths, not a measured probability. Paths below 0.1% or longer than 8 steps are left out of the lists (the most likely way to each asset is always given).
- The risk score uses the EPSS and KEV values recorded on each vulnerability: Strata does not fetch the FIRST and CISA feeds, so keep them up to date through the Cyberwatch connector or an import. A vulnerability is not tied to a port, so any open flow to its asset counts as a way to reach it.

## 13. Development and tests

```bash
npm test
```

The tests start a real server on a temporary data folder, create one account per role and check the API over HTTP: authentication, roles, protection against cross-site writes, the proposal cycle and the four-eyes rule, conflicts, history and rollback, import (ids, maximum size), and that the server's files cannot be read with `../`. Nothing to install: you only need Node.js 20 or later.

The `CI` workflow runs them on Node 20 and 22 on every push to `main` and every pull request. A change that touches the API must come with a test.

Contributions follow the [Solid standard](https://github.com/SolidGeeks/.github/blob/main/CONTRIBUTING.md): sign off every commit with `git commit -s` (DCO), no CLA. To report a vulnerability, see [SECURITY.md](SECURITY.md).
