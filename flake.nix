# SPDX-License-Identifier: AGPL-3.0-or-later
# Strata for Nix and NixOS (README, "Nix and NixOS"):
#   nix run github:SolidGeeks/strata            the server, on http://127.0.0.1:8080 with ./data
#   nixosModules.default                        services.strata, a hardened systemd service
#   nix flake check                             build, tests, and a NixOS VM test of the module
{
  description = "Strata: self-hosted 3D map of information systems";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        strata = pkgs.callPackage ./nix/package.nix { };
        default = strata;
      });

      overlays.default = final: prev: { strata = final.callPackage ./nix/package.nix { }; };

      nixosModules = rec {
        strata = import ./nix/module.nix self;
        default = strata;
      };

      checks = forAllSystems (
        pkgs:
        {
          package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          nixos = import ./nix/test.nix self pkgs;
        }
      );
    };
}
