# Changelog

All notable changes to Strata (formerly IS Map 3D). Versions follow [Semantic Versioning](https://semver.org/).

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

[0.5.4]: https://github.com/SolidGeeks/strata/releases/tag/v0.5.4
[0.5.3]: https://github.com/SolidGeeks/strata/releases/tag/v0.5.3
