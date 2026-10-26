# Connector modules

A connector module reads a tool you already run (an inventory, a scanner, a firewall, a CMDB, a
spreadsheet…) and turns what it finds into **proposals**: changes to the map that an approver reviews,
then accepts or rejects. A module never writes the map itself.

The four connectors that ship with Strata (Cyberwatch, GLPI, phpIPAM, Palo Alto) are modules like any
other, in [`server/connectors/builtin`](server/connectors/builtin). [`modules/csv-inventory`](modules/csv-inventory)
is a small example to start from.

## Where modules come from

| Origin | Where | Who puts it there | Removed from the web |
|---|---|---|---|
| Built-in | `server/connectors/builtin` | Strata itself | No (turn it off in its settings) |
| Provided by the server | `MODULES_DIR`, one folder per module | The administrator of the machine: a Docker volume, `services.strata.modules` on NixOS | No |
| From the store | `DATA_DIR/modules` | An administrator, in *Connectors › Module store* | Yes |

When two modules have the same `id`, the first in this order wins; the other is reported in
*Connectors* (to administrators) and left out.

## What a module is

A folder with two files at least:

```
acme-cmdb/
  strata-module.json   the manifest: who it is, what it may do, its settings
  index.mjs            the code: test() and run()
```

### The manifest, `strata-module.json`

```json
{
  "strataModule": 1,
  "id": "acme-cmdb",
  "name": "ACME CMDB",
  "version": "1.0.0",
  "description": "Servers and their owners from the ACME CMDB",
  "author": "Your name",
  "license": "AGPL-3.0-or-later",
  "homepage": "https://github.com/you/strata-acme-cmdb",
  "badge": "CMDB",
  "main": "index.mjs",
  "minStrata": "0.8.0",
  "permissions": { "map": true, "network": true },
  "live": ["url"],
  "file": {
    "label": "Import an export file",
    "accept": ".json",
    "role": "contributor",
    "fields": ["site"],
    "help": "In the CMDB: Reports › Export › JSON."
  },
  "fields": [
    { "k": "url", "label": "CMDB address", "placeholder": "https://cmdb.example.internal", "required": true },
    { "k": "token", "label": "API token", "secret": true, "required": true },
    { "k": "site", "label": "IS the servers belong to", "type": "site", "required": true },
    { "k": "withOwners", "label": "Owners → incident contacts", "type": "bool", "default": true }
  ]
}
```

| Key | Meaning |
|---|---|
| `strataModule` | The module API version: `1`. Strata refuses a module written for another version. |
| `id` | 2 to 40 lower-case letters, digits or dashes, starting with a letter. It names the module in the API (`/api/connectors/{id}`) and in the link it keeps on each asset (`ext`). |
| `name`, `description` | Shown in *Connectors* and in the store. |
| `version` | `1.2.3` (a pre-release, `1.2.3-rc.1`, sorts before its release). |
| `author`, `license`, `homepage`, `badge` | Optional. `badge`: up to 5 letters shown in the corner of its card. |
| `main` | Its code, relative to the folder. Name it `.mjs`, or ship a `package.json` with `"type": "module"`. |
| `minStrata` | Optional: the oldest Strata it works with. |
| `permissions.map` | `true` to receive the map (`ctx.state`) when it runs. Almost every connector needs it, to match what it reads to the assets. |
| `permissions.network` | `true` if it talks to a tool over the network. Shown to the administrator before installing; see [what a module can reach](#what-a-module-can-reach). |
| `live` | The settings a sync with the tool needs (default: none, always possible), or `false` for a module that only imports files. |
| `file` | Optional: the module imports files. `label` (the button), `accept` (as in `<input accept>`), `role` (`contributor`: anyone who may propose can import; default `approver`), `fields` (settings that can be changed for one import), `help`. |
| `fields` | Its settings, at most 60. |

A setting (`fields[]`):

| Key | Meaning |
|---|---|
| `k` | Its name in `cfg` (letters, digits, `_`; not a built-in JavaScript name such as `toString`). `enabled`, `everyHours`, `tlsInsecure`, `tlsCa` and `sites` are reserved: every module already has them. |
| `label`, `help`, `placeholder` | Text of the form. |
| `type` | `string` (default), `number`, `bool`, `select` and `multi` (with `options: [[value, label], …]`), `site` (an IS of the map), `asset` (an asset of the IS chosen in the `site` setting), `sites` (several IS), `rules` and `text` (several lines). |
| `default` | Its value until an administrator sets one. |
| `required` | The module is “not set up” while it is empty. |
| `secret` | A password or key: never sent back to browsers, kept in `data/connectors.json` (mode 600). |
| `advanced` | Under *More settings*. |

Every module also gets *Enabled*, *Sync automatically every … hours*, the TLS options (`cfg.tls`:
`{insecure, ca}`, to pass to `sdk.request`) and, unless it has a `site` setting, *Limit to these IS*
(Strata drops the proposals for other IS).

### The code

```js
// index.mjs
export async function test(cfg, ctx) {
  const res = await ctx.sdk.request(`${cfg.url}/api/ping`, { headers: { Authorization: `Bearer ${cfg.token}` }, tls: cfg.tls });
  await ctx.sdk.expectOk(res, 'ACME CMDB');
  return 'Connected: the CMDB answers.';
}

export async function run(cfg, ctx) {
  const { state, sdk } = ctx;
  const servers = ctx.file ? JSON.parse(ctx.file.text) : (await sdk.request(`${cfg.url}/api/servers`, { headers: { Authorization: `Bearer ${cfg.token}` }, tls: cfg.tls })).json();
  const idx = sdk.assetIndex(state, [cfg.site]);
  const assets = {};
  for (const s of servers) {
    const id = idx.find({ connector: 'acme-cmdb', ext: s.id, name: s.hostname, ips: [s.ip], site: cfg.site });
    if (!id) continue;
    const a = state.assets[id];
    const next = { ...a, os: s.os || a.os, ext: { ...(a.ext || {}), 'acme-cmdb': s.id } };
    if (JSON.stringify(next) !== JSON.stringify(a)) assets[id] = next;
  }
  return {
    proposals: Object.keys(assets).length ? [{ siteId: cfg.site, title: 'ACME CMDB: systems', description: `${servers.length} server(s) read.`, changes: { si: {}, assets } }] : [],
    summary: `${servers.length} server(s) read, ${Object.keys(assets).length} asset(s) to update.`,
  };
}
```

`test(cfg, ctx)` checks the access and returns a sentence for the person who clicked *Test the
connection*. `run(cfg, ctx)` reads and returns `{proposals, summary, report}`:

- `proposals`: one per IS at most, `{siteId, title, description, changes}`. `changes` is
  `{si: {id: document}, assets: {id: document}}` with **whole documents** (the asset as it should be,
  not a patch; `null` deletes it). A proposal stays within its IS: Strata keeps the document of that IS
  and the assets that are, or will be, in it, and leaves out anything else (other IS, the links between
  IS, the common catalogue of services). While a proposal of
  the module for that IS is still open, the next run refreshes it instead of opening another one. A
  document that only differs by its `ext` link is left out.
- `summary`: one sentence, shown in the list of runs.
- `report`: optional details; `skipped`, `warnings`, `unmatchedSample` and `noSiteSample` (lists of
  sentences) are shown under *Details*.

`ctx` holds:

| Key | Meaning |
|---|---|
| `ctx.state` | The map, `{si, assets, wan, services}`, when the manifest asks for it (`permissions.map`), `null` otherwise. A copy: changing it changes nothing. |
| `ctx.file` | `{name, text}` for a file import, `null` for a sync. |
| `ctx.sdk` | The helpers below. |
| `ctx.log(...)` | A line in the server log, prefixed with the module id. |

Throw `new ctx.sdk.ConnectorError('…')` for a problem the user can fix (wrong password, unknown IS): the
message is shown as is. Any other error is shown as *Unexpected error* and its stack goes to the log.

### The SDK, `ctx.sdk`

The same helpers the built-in modules use ([`server/connectors/sdk.js`](server/connectors/sdk.js)):

| Helper | What it does |
|---|---|
| `request(url, {method, headers, body, timeoutMs, tls, maxBytes})` | HTTP(S) with the TLS options of the settings; resolves with `{status, headers, text, body, json()}`. Network errors become a `ConnectorError` that says what to check. |
| `expectOk(res, what)` | Throws a clear `ConnectorError` on 401/403 and other errors. |
| `pool(items, n, fn)` | Runs `fn` over items, `n` at a time. |
| `assetIndex(state, siteIds).find({connector, ext, name, ips, site})` | Finds the asset an outside record describes: by the link stored last time (`ext[connector]`), then by host name, then by IP. |
| `siteFor(label, rules, state)`, `parseRules(text)` | Which IS a label (location, section) belongs to, from rules typed in a `rules` setting (`Lyon = lyon`). |
| `vlanForIp(si, ip)`, `holdingVlan(si, siteId, label)` | The VLAN whose range holds an IP; a VLAN where unplaced assets wait to be sorted. |
| `isIp`, `firstIp`, `parseRange`, `inRange`, `isPrivateRange`, `ipToInt`, `intToIp` | IPv4. |
| `parseXml`, `kids`, `kid`, `path`, `txt`, `members` | A small XML parser. |
| `norm`, `slug`, `shortName`, `hash`, `stripTags` | Text. |
| `ConnectorError` | The error to throw for a problem the user can fix. |

A module may bundle libraries in its folder (a `node_modules` inside it): it can read its whole folder.

### Asset and IS documents

Look at an export of your map (*Export*, or `GET /api/state`) for the exact shape. An asset:

```json
{ "site": "lyon", "name": "web-01", "type": "server", "vlan": "v-lyon-10", "ip": "10.10.10.11", "os": "Debian 12",
  "role": "Front end", "crit": 2, "vulns": [], "contacts": [], "apps": [], "notes": "", "ext": { "acme-cmdb": "S-1042" } }
```

`type` is one of `server dc db hypervisor firewall gateway router switch workstation printer phone ap
camera plc iot`; `crit` 1 (low) to 3 (high). Keep the outside record's id in `ext[your module id]`:
the next runs find the asset by it, even after a rename.

## What a module can reach

Each test or run happens in a **separate Node.js process**, started for that run only:

- It can read its own folder and the SDK, nothing else: not the data files, not the accounts, not the
  other modules' settings (Node.js permission model).
- It cannot write files, start programs or worker threads.
- Its environment holds none of the server's variables (passwords, `DATA_DIR`…).
- It receives its own settings, and the map only if its manifest asks for it.
- It is stopped after `CONNECTOR_TIMEOUT_MINUTES` (30 by default; 2 minutes for a test) and limited to
  512 MB of memory.
- Its answer is checked: proposals for an IS that does not exist are dropped, each proposal is kept
  within its IS, and a proposal with malformed ids is refused (listed in the run's details).

The network is **not** restricted: a module that reads the map could send it elsewhere. The Node.js
permission model also guards against mistakes, not against code written to escape it. So the real
protections are who may install a module and what the store lists:

- Only an administrator installs or removes modules.
- The store lists modules whose code was reviewed, and pins the SHA-256 of each package: Strata refuses
  a package that differs from what was reviewed.
- Installing a package from a file (`MODULE_UPLOAD=true`) is off by default.
- `MODULE_REGISTRY=off` turns the store off; `MODULES_DIR` lets you provide reviewed modules yourself.
- Whatever a module proposes still goes through review: nothing reaches the map unless an approver
  accepts it.

## Trying a module

1. Put its folder in a `MODULES_DIR` and restart Strata (`MODULES_DIR=./my-modules npm start`). It appears
   in *Connectors*, marked *Provided by the server*; a manifest problem is listed at the bottom of the
   panel for administrators.
2. `node scripts/connector-sim.mjs` starts fake Cyberwatch, GLPI, phpIPAM and PAN-OS APIs on port 8099
   (`SIM_PORT` to change it): handy to see how the built-in modules do it.
3. The API test `tests/modules.test.mjs` shows how to drive a module from a test: copy it for yours.

## Publishing it in the store

The store's index is [`docs/modules/index.json`](docs/modules/index.json), served at
`https://solidgeeks.github.io/strata/modules/index.json` (`MODULE_REGISTRY`).

1. Publish your module's code in a public repository, under a free licence.
2. Pack it: `node scripts/pack-module.mjs path/to/your-module dist/` checks the manifest the way Strata
   will, writes `your-module-1.0.0.tgz` (the same files always give the same bytes) and prints its
   SHA-256. Attach the package to a release of your repository.
3. Open a pull request that adds your entry to `docs/modules/index.json`: the fields of the manifest,
   plus `url` (the package's address) and `sha256`.
4. The *Modules* workflow checks your entry (`node scripts/check-registry.mjs` does the same locally):
   the package downloads over HTTPS, matches its `sha256`, holds a manifest Strata accepts with the same
   `id`, `version`, `name`, `permissions` and `minStrata` as the entry, and loads in the restricted module
   process with a `run()` function (and `test()`, unless `"live": false`).
5. A maintainer reads the code of that exact package and merges it (`.github/CODEOWNERS` asks for their
   review). A new version is a new pull request with its new `url` and `sha256`.

In the pull request, say what the module reads, which tool and versions you tried it with, and why it
needs what its `permissions` say.

Modules kept in this repository (`modules/`) are packed into `docs/modules/` with
`node scripts/pack-module.mjs modules/<id> --registry docs/modules/index.json`; a test checks that the
package matches the folder.

You can also run your own store: any HTTPS address serving an index in the same format
(`{"strataRegistry": 1, "modules": [...]}`, `url` absolute or relative to the index), set in
`MODULE_REGISTRY`.
