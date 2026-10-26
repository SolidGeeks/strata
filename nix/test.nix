# SPDX-License-Identifier: AGPL-3.0-or-later
# NixOS VM test of the module: the hardened service starts, the admin password comes from a file only
# root can read, the app is served with its vendored three.js, and the account command line works as
# the service user, and a connector module provided by the system runs in its own restricted process
# under the hardened service. Run with: nix build .#checks.x86_64-linux.nixos
self: pkgs:

pkgs.testers.runNixOSTest {
  name = "strata";

  nodes.machine = {
    imports = [ self.nixosModules.default ];
    services.strata = {
      enable = true;
      settings = {
        EDIT_USER = "admin";
        BACKUP_KEEP = 3;
        MODULE_REGISTRY = "off";
      };
      modules = [ ../modules/csv-inventory ];
      secretFiles.EDIT_PASS = "/etc/strata-admin-pass";
    };
    # Readable by root only, as a secret manager leaves it; with the trailing newline most tools write
    environment.etc."strata-admin-pass" = {
      text = "test-pass-1234\n";
      mode = "0400";
    };
    environment.systemPackages = [ pkgs.curl ];
  };

  testScript =
    { nodes, ... }:
    let
      users = "${nodes.machine.services.strata.package}/bin/strata-users";
    in
    ''
    import json
    state = {"si": {"lyon": {"name": "Lyon", "zones": [{"id": "z1", "name": "Main"}], "vlans": [{"id": "v20", "num": 20, "name": "Servers", "cidr": "10.20.0.0/24", "zone": "z1"}]}}, "assets": {}, "wan": []}
    csv_run = {"wait": True, "file": {"name": "inventory.csv", "text": "name,ip\napp-01,10.20.0.5\n"}, "overrides": {"site": "lyon"}}

    machine.wait_for_unit("strata.service")
    machine.wait_for_open_port(8080)

    # The health check is open; with a password set, everything else asks for it, the page included
    machine.succeed("curl -fsS http://127.0.0.1:8080/healthz")
    for path, user in [("/", ""), ("/api/state", "-u admin:wrong-pass")]:
        status = machine.succeed(f"curl -s -o /dev/null -w '%{{http_code}}' {user} http://127.0.0.1:8080{path}")
        assert status == "401", f"{path} {user or 'without a password'} got {status}"
    for path in ["/", "/vendor/three.module.js", "/vendor/three.core.js", "/vendor/OrbitControls.js", "/api/state"]:
        machine.succeed(f"curl -fsS -o /dev/null -u admin:test-pass-1234 http://127.0.0.1:8080{path}")

    # The data lives in the state directory, owned by the service user
    machine.succeed("test \"$(stat -c %U /var/lib/strata/users.json)\" = strata")

    # The account command line, run as the service user, writes accounts the server accepts
    # (it reloads the accounts file every 5 seconds)
    machine.succeed("runuser -u strata -- env DATA_DIR=/var/lib/strata NEW_PASSWORD=alice-pass-123 ${users} set alice viewer")
    machine.wait_until_succeeds("curl -fsS -o /dev/null -u alice:alice-pass-123 http://127.0.0.1:8080/api/state", timeout=30)

    # The module from services.strata.modules imports a CSV file, in its own process
    auth = "-u admin:test-pass-1234 -H 'Content-Type: application/json' -H 'X-Requested-With: strata'"
    machine.succeed(f"curl -fsS {auth} -X POST http://127.0.0.1:8080/api/import -d '{json.dumps(state)}'")
    listed = json.loads(machine.succeed(f"curl -fsS {auth} http://127.0.0.1:8080/api/connectors"))
    csv = next(c for c in listed["connectors"] if c["id"] == "csv-inventory")
    assert csv["origin"] == "provided", csv
    run = json.loads(machine.succeed(f"curl -fsS {auth} -X POST http://127.0.0.1:8080/api/connectors/csv-inventory/run -d '{json.dumps(csv_run)}'"))["run"]
    assert run["ok"] and len(run["proposals"]) == 1, run

    # Not reachable from outside: the module listens on 127.0.0.1 and leaves the firewall closed
    machine.fail("curl -fsS --max-time 3 http://$(hostname -I | cut -d' ' -f1):8080/healthz")
  '';
}
