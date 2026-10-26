# SPDX-License-Identifier: AGPL-3.0-or-later
# NixOS module: services.strata runs the server as a hardened systemd service, with its data in
# /var/lib/strata. Settings become environment variables; passwords stay out of the Nix store.
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.strata;
  inherit (lib)
    literalExpression
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  # Booleans as true/false, numbers as text
  toEnv = v: if builtins.isBool v then lib.boolToString v else toString v;
  secrets = lib.filterAttrs (_: file: file != null) cfg.secretFiles;
  modulesDir = pkgs.linkFarm "strata-modules" (
    lib.imap0 (i: m: {
      name = "${toString i}-${baseNameOf m}";
      path = m;
    }) cfg.modules
  );
  lowPort = cfg.settings.PORT < 1024;
  secretFile =
    what:
    mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/secrets/strata-admin";
      description = ''
        File holding the password of ${what}. systemd reads it as root and hands it to the service
        as a credential, so it can stay readable by root only (sops-nix, agenix). Give it as a
        string: a Nix path would be copied into the store.
      '';
    };
in
{
  options.services.strata = {
    enable = mkEnableOption "Strata, the self-hosted 3D map of information systems";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = literalExpression "strata.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The Strata package to run.";
    };

    settings = mkOption {
      type = types.submodule {
        freeformType = types.attrsOf (
          types.oneOf [
            types.bool
            types.int
            types.str
          ]
        );
        options = {
          HOST = mkOption {
            type = types.str;
            default = "127.0.0.1";
            description = ''
              Address the server listens on. Keep 127.0.0.1 behind an HTTPS reverse proxy: passwords
              travel with Basic Auth. "0.0.0.0" or "::" listens on the network.
            '';
          };
          PORT = mkOption {
            type = types.port;
            default = 8080;
            description = "Port the server listens on.";
          };
        };
      };
      default = { };
      example = literalExpression ''
        {
          EDIT_USER = "admin";
          ALLOW_SELF_APPROVAL = false;
          BACKUP_KEEP = 30;
          SOURCE_URL = "https://github.com/you/strata";
        }
      '';
      description = ''
        Environment variables of Strata, as listed in section 3 of the README and in .env.example:
        EDIT_USER, VIEW_USER, ALLOW_SELF_APPROVAL, HISTORY_KEEP, READ_ONLY, BACKUP_KEEP,
        BACKUP_EVERY_HOURS, MAX_IMPORT_MB, LOGIN_MAX_FAILS, LOGIN_MAX_FAILS_PER_ADDRESS,
        LOGIN_LOCK_MINUTES, TRUST_PROXY (set it to "loopback" behind a reverse proxy on this
        host), PUBLIC_URL, SSO_ISSUER, SSO_CLIENT_ID, SSO_NAME, SSO_ROLE_ADMIN, SSO_ROLE_APPROVER,
        SSO_ROLE_CONTRIBUTOR, SSO_ROLE_VIEWER, SSO_DEFAULT_ROLE, SSO_USER_CLAIM, SSO_GROUPS_CLAIM,
        SSO_HEADER_USER, SSO_HEADER_GROUPS, SSO_HEADER_TRUST, LOCAL_LOGIN, SESSION_HOURS, CONNECTORS, CONNECTOR_TIMEOUT_MINUTES, MODULE_REGISTRY, MODULE_UPLOAD, SOURCE_URL. The module sets DATA_DIR to
        /var/lib/strata. These values end up in the Nix store: put passwords in
        {option}`services.strata.secretFiles` or {option}`services.strata.environmentFile`.
      '';
    };

    secretFiles = {
      EDIT_PASS = secretFile "the first admin account (EDIT_USER), recreated or reset on every start";
      VIEW_PASS = secretFile "the shared read-only account (VIEW_USER)";
      SSO_CLIENT_SECRET = secretFile "the OpenID Connect client (SSO_CLIENT_ID)";
    };

    environmentFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/secrets/strata.env";
      description = ''
        File of KEY=value lines added to the environment, read by systemd as root, for settings
        that must stay out of the Nix store (EDIT_PASS=…). Give it as a string: a Nix path would be
        copied into the store.
      '';
    };

    modules = mkOption {
      type = types.listOf types.path;
      default = [ ];
      example = literalExpression "[ (strata + \"/modules/csv-inventory\") ./my-connector ]";
      description = ''
        Connector modules to provide, each a folder holding a strata-module.json (MODULES.md in
        the Strata repository). They are listed as "provided by the server" and cannot be removed
        from the web. Modules installed from the module store go to /var/lib/strata/modules; set
        {option}`services.strata.settings.MODULE_REGISTRY` to "off" to keep to these.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open {option}`services.strata.settings.PORT` in the firewall.";
    };
  };

  config = mkIf cfg.enable {
    warnings =
      lib.optional
        (
          cfg.openFirewall
          && builtins.elem cfg.settings.HOST [
            "127.0.0.1"
            "::1"
            "localhost"
          ]
        )
        "services.strata.openFirewall opens port ${toString cfg.settings.PORT}, but Strata only listens on ${cfg.settings.HOST}: set services.strata.settings.HOST, or keep the port closed behind a reverse proxy.";

    # A fixed system user rather than DynamicUser, so that the account command line
    # (sudo -u strata env DATA_DIR=/var/lib/strata strata-users …) writes the files the service reads
    users.users.strata = {
      isSystemUser = true;
      group = "strata";
      home = "/var/lib/strata";
      description = "Strata service";
    };
    users.groups.strata = { };

    # strata-users manages the accounts: sudo -u strata env DATA_DIR=/var/lib/strata strata-users list
    environment.systemPackages = [ cfg.package ];

    systemd.services.strata = {
      description = "Strata, 3D map of information systems";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      environment =
        lib.mapAttrs (_: toEnv) cfg.settings
        // lib.mapAttrs' (name: _: lib.nameValuePair "${name}_FILE" "%d/${name}") secrets
        // lib.optionalAttrs (cfg.modules != [ ]) { MODULES_DIR = "${modulesDir}"; }
        // {
          DATA_DIR = "/var/lib/strata";
          NODE_ENV = "production";
        };

      serviceConfig = {
        Type = "simple";
        ExecStart = lib.getExe cfg.package;
        User = "strata";
        Group = "strata";
        StateDirectory = "strata";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/strata";
        EnvironmentFile = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
        LoadCredential = lib.mapAttrsToList (name: file: "${name}:${file}") secrets;
        Restart = "on-failure";
        RestartSec = 3;
        UMask = "0077";

        # Hardening: the server only needs its state directory and TCP
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        # A private user namespace drops the capability a port below 1024 needs
        PrivateUsers = !lowPort;
        ProtectHostname = true;
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RemoveIPC = true;
        LockPersonality = true;
        # V8 compiles JavaScript to machine code at run time
        MemoryDenyWriteExecute = false;
        DevicePolicy = "closed";
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
        SystemCallErrorNumber = "EPERM";
        CapabilityBoundingSet = if lowPort then [ "CAP_NET_BIND_SERVICE" ] else [ "" ];
        AmbientCapabilities = lib.optional lowPort "CAP_NET_BIND_SERVICE";
      };
    };

    networking.firewall.allowedTCPPorts = lib.optional cfg.openFirewall cfg.settings.PORT;
  };
}
