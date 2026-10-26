# SPDX-License-Identifier: AGPL-3.0-or-later
# Strata built from source: npm ci from package-lock.json, then "npm run vendor" copies three.js and the
# fonts into public/vendor. Nothing is downloaded at run time: the server has no npm dependency and
# Node.js runs server/server.js. The API and analysis tests run during the build.
{
  lib,
  buildNpmPackage,
  nodejs_22,
  makeWrapper,
}:

let
  fs = lib.fileset;
  node = lib.getExe nodejs_22;
in
buildNpmPackage {
  pname = "strata";
  version = (lib.importJSON ../package.json).version;

  src = fs.toSource {
    root = ../.;
    fileset = fs.unions [
      ../package.json
      ../package-lock.json
      ../public
      ../server
      ../scripts
      ../tests
      # the example module and its store package, which the tests compare
      ../modules
      ../docs/modules
    ];
  };

  nodejs = nodejs_22;
  # Changes with package-lock.json: Nix prints the new value when it no longer matches
  # (README, "Nix and NixOS")
  npmDepsHash = "sha256-YHYqwlsVe1waoDrw+0uoXmUCL2WueH8pYUPC/qR963w=";

  npmBuildScript = "vendor";

  nativeBuildInputs = [ makeWrapper ];

  # The API tests start the server on 127.0.0.1, which the build sandbox allows
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    npm test
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/strata/scripts $out/bin
    cp -r package.json server public modules $out/share/strata/
    cp scripts/users.mjs scripts/connector-sim.mjs scripts/pack-module.mjs $out/share/strata/scripts/
    # The store is read-only: unless DATA_DIR says otherwise, the data goes to ./data where the
    # command runs, and the server listens on this machine only (nix run)
    makeWrapper ${node} $out/bin/strata \
      --add-flags $out/share/strata/server/server.js \
      --set-default PUBLIC_DIR $out/share/strata/public \
      --set-default DATA_DIR data \
      --set-default HOST 127.0.0.1 \
      --set-default NODE_ENV production
    makeWrapper ${node} $out/bin/strata-users \
      --add-flags $out/share/strata/scripts/users.mjs \
      --set-default DATA_DIR data
    makeWrapper ${node} $out/bin/strata-pack-module \
      --add-flags $out/share/strata/scripts/pack-module.mjs
    makeWrapper ${node} $out/bin/strata-connector-sim \
      --add-flags $out/share/strata/scripts/connector-sim.mjs
    runHook postInstall
  '';

  meta = {
    description = "Self-hosted 3D map of information systems: zones, VLANs, assets, flows, exposure, vulnerabilities and incident contacts";
    homepage = "https://solidgeeks.github.io/strata/";
    changelog = "https://github.com/SolidGeeks/strata/blob/main/CHANGELOG.md";
    license = lib.licenses.agpl3Plus;
    mainProgram = "strata";
    platforms = lib.platforms.unix;
  };
}
