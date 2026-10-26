# Changelog

All notable changes to Strata (formerly IS Map 3D). Versions follow [Semantic Versioning](https://semver.org/).

## [0.7.0] - 2026-10-26
### Added
- **Attack paths** (Analysis): the critical assets an attacker coming from the Internet could reach (criticality High, of their own or through a business service they would hit), every path to each one along the allowed flows, most likely first, and **where to cut**: the assets and the equipment that every path to a critical asset goes through. The rest of the model fades, and hovering a path picks it out, in 3D and in 2D.
  - Each step of a path is an asset taken over, with a likelihood: its vulnerabilities (CVSS times likelihood of exploitation, as for the risk score), 50% on a remote administration port (SSH, RDP, SMB, WinRM, VNC, Telnet, RPC), 10% on any other service. A path counts for the product of its steps. Flows run one way: answering a flow does not let the destination reach back.
- **Blast radius**: pick any asset as the attacker's starting point (in the panel, or *Blast radius* on the asset sheet) and see everything reachable from it, the most likely way to each asset, and the business services hit. The asset sheet gives its size.
- Both lists (attack paths, blast radius) export as CSV.
- **Architecture file**: one document per IS, from *Analysis › Architecture file* or the IS summary, in the order audits and security accreditation files follow: cover with classification, document control and sign-off table, summary (key figures, fixes first, critical assets reachable), scope (business services, links to other IS, Internet services), architecture (the 2D diagram, zones and VLANs, interconnection equipment, applications), asset inventory, flow matrix and the rules each firewall needs (with the flows between VLANs that cross no firewall), exposure, vulnerabilities and remediation order, attack paths and where to cut, plans of the internet-facing and critical assets, incident contacts, change history of the IS (self-hosted version), method and limits. Shown in the app and downloaded as a standalone HTML file that prints to A4 PDF.
- **Nix and NixOS**: the repository is a flake. `nix run github:SolidGeeks/strata` runs the server; `nixosModules.default` provides `services.strata`, a hardened systemd service (its own user, data in `/var/lib/strata`, read-only system, no capabilities, restricted system calls) with `settings`, `secretFiles`, `environmentFile` and `openFirewall`. A `Nix` workflow builds the package, which runs the tests, and runs a NixOS VM test of the module.
- **Failed sign-ins are limited** ([#13](https://github.com/SolidGeeks/strata/issues/13)): after `LOGIN_MAX_FAILS` (10) different wrong passwords for one account, or `LOGIN_MAX_FAILS_PER_ADDRESS` (20) from one client address, sign-ins are refused with `429` and `Retry-After` for `LOGIN_LOCK_MINUTES` (15). The same wrong password sent again (a tab left open with an old password) counts once, and browsers already signed in keep working from their address. `TRUST_PROXY` says which reverse proxies' `X-Forwarded-For` to believe.
- **3D view: move the view** with the middle mouse button (or the right one), left, right, up and down, instead of always turning around the same point; two fingers on a touch screen. The view stops at the edge of the model; *Reset view* centres it again. A middle click no longer selects anything, and only the left button drags plates in *Arrange* mode.
- `EDIT_PASS_FILE` and `VIEW_PASS_FILE` read the passwords from files (Docker secrets, systemd credentials, sops-nix, agenix); `NEW_PASSWORD_FILE` likewise for `scripts/users.mjs`. An unreadable file stops the server instead of starting it without a password.
- **Browser walk-through test** ([#15](https://github.com/SolidGeeks/strata/issues/15)): `npm run test:e2e` (Playwright, Chromium) signs in, loads the demo, checks that the 3D view draws a real picture and that the 2D diagram shows the demo IS, then takes a proposal from a contributor's draft to an approver who sees it highlighted and approves it. Any JavaScript error in a page fails it. It runs in CI (`e2e` job).
- Tests: `READ_ONLY=true` refuses every write, admins included ([#4](https://github.com/SolidGeeks/strata/issues/4)); the live updates stream `/api/events` sends the new revision on every change and an event on new proposals ([#8](https://github.com/SolidGeeks/strata/issues/8)).
- README: how to build from source without Docker, step by step.

### Security
- **A crafted Palo Alto configuration file could stall the server** (found by the security review, [#14](https://github.com/SolidGeeks/strata/issues/14)). The XML parser read the attributes of a tag with a regular expression that took quadratic time on a long tag without `=`: an 80 KB tag took 4 s, and a 20 MB file, which any **contributor** may import, would have blocked the server for every user for hours. Attributes are now read in one pass (20 MB in under 0.2 s), with the same result.
- **Data files were readable by every local user** on installs without Docker or the NixOS module (systemd, `npm start`): the map, its history and proposals, the accounts (password hashes) and, for an instant before a `chmod`, the connector settings with their secrets. They are now written with mode 600 and the backups folder with 700, and files left readable by older versions are tightened at start. Docker volumes and the NixOS module were not affected.
- Upgrade to 0.7.0 for both: no data migration is needed, and older data files are tightened on the first start.

### Fixed
- A request body over its limit (an import bigger than `MAX_IMPORT_MB`) gets a `413` answer with the usual JSON error, instead of a cut connection that the app could only show as a network error ([#3](https://github.com/SolidGeeks/strata/issues/3)).

### Changed
- Security review ([#14](https://github.com/SolidGeeks/strata/issues/14)), hardening: `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin` on every response; a path with a malformed percent-encoding gets `400` instead of an internal error; the current password is compared in constant time when it is changed.

## [0.6.0] - 2026-10-26
### Added
- Flows through interconnection equipment are readable: every flow that crosses a firewall, router, switch or gateway gets its own lane there, in the 3D model and in the 2D diagram, instead of all threads meeting at one point.
- Colour by › **Per flow**: each flow gets its own colour, and flows that cross the same equipment never share one (up to 10).
- Architecture plan, redrawn so each flow can be followed:
  - one line per flow, at right angles, each on its own track along the corridors between zones (and round by the left when zones are not next to each other), instead of curves merged per hop;
  - every flow is numbered; a table under the plan gives its path, port, volume, exposure and note; a badge where it arrives gives its number and port, and a number marks it on each equipment it crosses;
  - **Scope**: the asset's own flows (default), or every path from and to the Internet as before;
  - **Colour**: by exposure, or one colour per flow. The plan opens per flow when the model is coloured per flow.
  - a **Firewall rules** table under the flows: the rules this asset needs (one allow rule per flow and firewall crossed, the flows no firewall filters, the default deny), each linked to its flow number. For a firewall, its own rule base. It holds the same rules as the Firewall rules (CSV) export.
  - **Filters** in the plan bar: direction (all, inbound, outbound, and crossing for equipment) and kind of flow (Internet, inter-VLAN, intra-VLAN, several at once). The drawing, the flow table and the firewall rules follow them; the plan says which filter is on. Filters stay the same from one plan to the next.
- Hovering a flow in an asset sheet picks it out on the model and the diagram. The sheet lists the flows crossing a device in lane order, with their colour.
- Unit tests of the graph analysis (`tests/analysis.test.mjs`), run by `npm test`.
- Three points of view on an IS, Physical, Application and Business:
  - **Physical** is the 3D model and the 2D diagram, as before.
  - **Application** draws one box per application, with the assets it runs on, and arrows for the flows between applications.
  - **Business** lists the business services of the IS (new, saved on the IS: name, criticality, owner, the assets it runs on) and everything each one relies on, worked out from the flows: what its assets call, the equipment crossed, the Internet services used. "Show on the model" picks a service out in 3D or 2D.
- The asset sheet says which business services an asset would hit, and through which chain of flows. The asset form ticks the services an asset runs.
- The demo has business services on every IS.
- Asset form: a new asset gets the first free address of its VLAN range as IP, and picking another VLAN moves it to that VLAN's first free address. An IP outside the range of the VLAN picked is pointed out, with the free address to use instead. An IP typed by hand is never overwritten.
- **Risk priorities** (Analysis): one score per asset, from 0 to 100, and the remediation list in the order to follow.
  - Each vulnerability counts for its severity (CVSS) times its likelihood of exploitation: certain when it is on the CISA list of known exploited vulnerabilities (KEV), otherwise from its EPSS, otherwise 30%.
  - That is weighed by the exposure of its asset and its reachability from the Internet, and by the criticality of the asset or of the business services it would hit.
  - The asset sheet shows the score and, with "Why?", every factor.
  - The list exports as CSV.
- Vulnerabilities take an EPSS (0 to 1, or a percentage) and a "known exploited (CISA KEV)" mark, in the asset form and in imported JSON. The Cyberwatch connector reads them when Cyberwatch gives them. The demo CVEs carry approximate EPSS values and their real KEV status.
### Fixed
- Editing an IS (name, zones, contacts) dropped the Internet services recorded on that IS.
- Saving an asset from the form dropped the source of its vulnerabilities (the mark the Cyberwatch connector uses to refresh its own).

## [0.5.5] - 2026-10-25
### Security
- **Object prototype pollution through ids and account names** ([GHSA-56cq-r5jm-vpqg](https://github.com/SolidGeeks/strata/security/advisories/GHSA-56cq-r5jm-vpqg)). `__proto__` was accepted as a proposal, map document or account name, and the server looked these names up in plain objects. A contributor could change properties shared by every object of the server process by commenting on the proposal `__proto__`; an approver could hide map documents; an admin could create an admin account that no list showed, and that signed in under names such as `toString` until the next restart. `__proto__`, `constructor` and `prototype` are now refused as ids and account names, and every lookup ignores inherited properties. Upgrade to 0.5.5: no data migration is needed.
### Fixed
- Connectors: a Palo Alto configuration, or an asset of the map, named after a JavaScript built-in (`constructor`, `toString`…) made a run fail with an unexpected error. Connector ids from the URL only match the four connectors.
- `scripts/users.mjs` followed the same rule as the server: `set __proto__` reported an account that was never saved, and `role`, `disable` or `delete` on a name such as `toString` acted on an account that did not exist.

## [0.5.4] - 2026-10-25
### Added
- Signed images: every release carries a Sigstore build provenance attestation. Check one with `gh attestation verify oci://ghcr.io/solidgeeks/strata:0.5.4 --owner SolidGeeks`.
- API tests (`npm test`): authentication, roles, cross-site write protection, proposals and the four-eyes rule, conflicts, history and rollback, import limits, path traversal.
- CI workflow running them on Node 20 and 22 for every push and pull request.
### Changed
- The Release workflow runs the tests first, and publishes nothing if they fail.

## [0.5.3] - 2026-10-25
### Added
- Release workflow: every `vX.Y.Z` tag publishes the prebuilt image `ghcr.io/solidgeeks/strata` and a GitHub release, so `docker compose pull` works.
- `.env.example` lists and explains every setting (it was shipped as `venvexample`, incomplete).
- `SECURITY.md` with supported versions.
- `package-lock.json`, so `npm run setup` (`npm ci`) works.
### Changed
- Licensed AGPL-3.0-or-later, with an SPDX header in every source file.
- `.gitignore` and `.dockerignore` keep `.env` and `data/` out of the repository and of the image build context.

## [0.5.2] - 2026-10-24
### Added
- Theme switch in *Display*: Auto (follows the system), Day, Night. Keyboard shortcut **N**.
- The connector simulator ships in the Docker image.
- Published under the GNU AGPL v3, with a *Source code* link in the app (`SOURCE_URL`).
### Fixed
- `docker-compose.yml` was empty in 0.5.1.
- Code scanning alerts (CodeQL): inter-IS link values escaped in the IS sheet, text exports saved as data: URLs, PAN-OS error messages stripped of any markup.

## [0.5.1] - 2026-10-24
### Changed
- Renamed from IS Map 3D to **Strata**. Exports, backups and API scripts from IS Map keep working (`DATA_VOLUME` keeps an existing Docker volume).

## [0.5.0] - 2026-10-24
### Added
- Connectors, each run producing proposals to review: Cyberwatch (vulnerabilities), GLPI (inventory, software, contacts, locations), phpIPAM (VLANs, addresses), Palo Alto (security rules from a config file or the XML API).
- Scheduled syncs, connection tests, secrets kept server-side.

## [0.4.2] - 2026-10-23
### Added
- VLAN plates move freely on their level (left, right, front, back), in 3D and in the 2D diagram.

## [0.4.1]
### Changed
- Thinner VLAN plates.

## [0.4.0]
### Added
- Named accounts with roles (viewer, contributor, approver, admin).
- Version history with view and rollback.
- Proposals: draft changes in the editor or from a file, review on the map, approve or reject (four-eyes rule).
- Internet services (shared catalogue and per IS) as flow endpoints.

## [0.3.0]
### Added
- 2D diagram editor synchronised with the 3D model (shared positions).

## [0.2.0]
### Added
- Flows through interconnection devices, asset OS and applications, 2D architecture plans, flow matrix and firewall rules export, hideable standoffs, compact spacing, VLAN reordering.

## [0.1.0]
- First release: 3D map of IS, zones, VLANs, assets, flows, exposure, vulnerabilities and incident contacts.

[0.7.0]: https://github.com/SolidGeeks/strata/releases/tag/v0.7.0
[0.6.0]: https://github.com/SolidGeeks/strata/releases/tag/v0.6.0
[0.5.5]: https://github.com/SolidGeeks/strata/releases/tag/v0.5.5
[0.5.4]: https://github.com/SolidGeeks/strata/releases/tag/v0.5.4
[0.5.3]: https://github.com/SolidGeeks/strata/releases/tag/v0.5.3
