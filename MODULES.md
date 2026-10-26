# Connector modules

A connector module reads a tool you already run (an inventory, a scanner, a firewall, a CMDB, a
spreadsheet…) and turns what it finds into **proposals**: changes to the map that an approver reviews,
then accepts or rejects. A module never writes the map itself.

The four connectors that ship with Strata (Cyberwatch, GLPI, phpIPAM, Palo Alto) are modules like any
other, in [`server/connectors/builtin`](server/connectors/builtin). The modules of the store live in
[`modules/`](modules); [`modules/csv-inventory`](modules/csv-inventory) is a small one to start from.

This guide has two parts:

- **[Using modules](#using-modules)**, for administrators and approvers: install, set up, run, read the
  result, update, remove, provide your own.
- **[Writing a module](#writing-a-module)**, for developers: a first module step by step, then the
  [reference](#reference) (manifest, code, `ctx`, SDK), [what a module can reach](#what-a-module-can-reach),
  [testing](#testing-a-module) and [publishing it in the store](#publishing-it-in-the-store).

# Using modules

Everything happens in *Collaboration › Connectors*. Its *Installed* tab lists the modules this server
has; administrators also see a *Module store* tab.

## The modules available

| Module | Where it comes from | What it reads | Who runs it |
|---|---|---|---|
| Cyberwatch | Built-in | Servers and their CVEs (API v3) | Approvers |
| GLPI | Built-in | Computers, network devices, printers, phones, software, people in charge | Approvers |
| phpIPAM | Built-in | Sections, subnets, VLANs, addresses | Approvers |
| Palo Alto | Built-in | Allow rules, as flows: from the XML API, or a configuration file | Approvers; any contributor for a file |
| CSV inventory | Store | Assets of an IS from a spreadsheet saved as CSV | Any contributor (file import) |
| Nmap scan | Store | Hosts, systems and open ports from `nmap -oX` | Any contributor (file import) |
| NetBox | Store | Devices, virtual machines, VLANs and prefixes | Approvers |

Each module's own README (in [`modules/`](modules)) and the [documentation](https://solidgeeks.github.io/strata/docs.html#connectors)
say what it reads and how it matches what it reads to the map.

## Installing a module from the store

1. *Connectors › Module store* (administrators). Each card says what the module does, its version,
   author, licence, a link to its source, and what it reaches: *reads the map*, *connects to your tool
   over the network*.
2. *Install*. Strata downloads the package, checks it against the SHA-256 the store publishes, and
   refuses it if they differ. A module that needs a newer Strata says *Needs Strata x.y.z* instead.
3. The module now appears under *Installed*, marked *From the store*.

The store is read only when an administrator opens it (*Check the store again* reads it anew). Behind a
proxy or on a network with no Internet access, see [modules of your own](#modules-of-your-own).

## Setting it up

*Settings* on its card (administrators). Besides its own settings, every module has:

- *Enabled* and *Sync automatically every … hours*: both are needed for automatic syncs (0 hours: by
  hand only);
- under *More settings*: the TLS options (*Accept any TLS certificate*, or paste your internal CA) and,
  unless it already asks for one IS, *Limit to these IS* (proposals for other IS are dropped).

Passwords and keys are kept in `data/connectors.json` (mode 600) and never sent back to browsers: a
secret field left as it is keeps its value. Use read-only accounts in your tools.

*Test the connection* (approvers) checks the address and the credentials and says what is wrong.

## Running it

- **A sync with the tool**: *Sync now* (approvers), or automatically every few hours. It runs in the
  background; the card says *Running…*, then shows the result.
- **A file import**, for modules that read files (Palo Alto, CSV inventory, Nmap scan): the button on
  the card (*Import a CSV file*…), then the file and the few settings that can change for one import
  (such as the IS). The module decides who may import: any contributor for the three above.

Either way, **the result is a proposal**, one per IS, that an approver reviews in *Proposals* like any
other. While a module's proposal for an IS is still open, the next run refreshes it instead of opening
another one. When the map already matches, no proposal is created. A proposal from a file counts as the
importer's own: someone else has to approve it (the four-eyes rule).

## Reading the result

- The card shows the last run: when, by whom, from which file, how long, its summary, and a button for
  each proposal it made (*refreshed*: an open proposal was updated; *unchanged*: nothing new since).
- *Recent runs*, under the cards, lists the last runs of every module, failures in red.
- The card's status: *Not set up* (a required setting is empty), *Last run failed*, *Every N h*.
- *Details*, under the last run on the card, lists what was skipped or could not be matched.
- The server log has a line per run, and what the module itself logs, prefixed with its id
  (`docker compose logs strata`).

A failure that you can fix (wrong password, unknown IS, bad file) is shown as the module says it.
Anything else shows as *Unexpected error*, with the details in the server log.

## Updating and removing

- **Update**: when the store has a newer version, its card shows *Update to x.y.z*. Settings are kept.
- **Remove**: *Remove* on the card of a module installed from the store. Its settings go with it; the
  proposals it made stay.
- Built-in modules cannot be removed: left without settings, they do nothing. Modules from
  `MODULES_DIR` are removed there.
- `CONNECTORS=false` turns off every connector, built-in and modules.

## Modules of your own

| Origin | Where | Who puts it there | Removed from the web |
|---|---|---|---|
| Built-in | `server/connectors/builtin` | Strata itself | No |
| Provided by the server | `MODULES_DIR`, one folder per module | The administrator of the machine | No |
| From the store | `DATA_DIR/modules` | An administrator, in *Connectors › Module store* | Yes |

When two modules have the same `id`, the first in this order wins; the other is reported to
administrators at the bottom of *Connectors* (*module folder left out*), with the reason.

- **Docker**: put the module folders in `./modules` next to `docker-compose.yml`, uncomment the
  `./modules:/modules:ro` volume, set `MODULES_DIR=/modules` in `.env`, then `docker compose up -d`.
- **NixOS**: `services.strata.modules = [ ./my-connector ];`.
- **Without Docker**: `MODULES_DIR=/opt/strata-modules` in the service's environment.
- **A package file** (`.tgz`, as `scripts/pack-module.mjs` makes them): with `MODULE_UPLOAD=true`,
  *Module store › Install a package file…*. No checksum is checked: whoever uploads it vouches for it.
- **Your own store**: any HTTPS address serving an index in the store's format (`{"strataRegistry": 1,
  "modules": [...]}`, see [publishing](#publishing-it-in-the-store)), set in `MODULE_REGISTRY`.
  `MODULE_REGISTRY=off` turns the store off.

Strata reads the module folders when it starts: restart it after adding or changing one.

## From a script

Everything above has an API route ([API reference](https://solidgeeks.github.io/strata/api.html#connectors)).
With an API token (*Account › API tokens*), for example a nightly Nmap import by a contributor token:

```bash
nmap -sV -O -oX scan.xml 10.20.0.0/24
jq -n --rawfile x scan.xml '{wait: true, file: {name: "scan.xml", text: $x}, overrides: {site: "lyon"}}' |
  curl -sS -H "Authorization: Bearer $STRATA_TOKEN" -H 'Content-Type: application/json' -H 'X-Requested-With: strata' \
    -X POST https://strata.example.lan/api/connectors/nmap/run --data-binary @-
```

The answer holds the run: its summary and the proposals it opened. (`jq` builds the JSON body around
the file; any tool that does the same works.)

# Writing a module

## Your first module, step by step

This module imports a JSON list of hosts into an IS: it completes the assets already on the map and
creates the others. It reads a file, so it needs no tool to try it. The whole code is below; the
[reference](#reference) explains each part.

**1. A folder with a manifest.** `my-modules/hosts-json/strata-module.json`:

```json
{
  "strataModule": 1,
  "id": "hosts-json",
  "name": "Hosts from JSON",
  "version": "0.1.0",
  "description": "Assets of an IS from a JSON list of hosts",
  "main": "index.mjs",
  "permissions": { "map": true, "network": false },
  "live": false,
  "file": {
    "label": "Import a JSON file",
    "accept": ".json",
    "role": "contributor",
    "fields": ["site"],
    "help": "A list such as [{\"name\": \"web-01\", \"ip\": \"10.10.10.11\", \"os\": \"Debian 12\"}]."
  },
  "fields": [
    { "k": "site", "label": "IS the hosts belong to", "type": "site", "required": true }
  ]
}
```

`"live": false` says it only imports files; `file.role: "contributor"` lets anyone who may propose run
it; `file.fields` lists the settings asked at each import (here, the IS).

**2. The code.** `my-modules/hosts-json/index.mjs`:

```js
export async function run(cfg, ctx) {
  const { state, sdk, file } = ctx;
  const si = state.si[cfg.site];
  if (!si) throw new sdk.ConnectorError('Choose the IS the hosts belong to.');
  let hosts;
  try { hosts = JSON.parse(file.text); } catch { throw new sdk.ConnectorError(`${file.name} is not valid JSON.`); }
  if (!Array.isArray(hosts)) throw new sdk.ConnectorError('Expected a list of hosts: [{"name": …}, …].');

  const idx = sdk.assetIndex(state, [cfg.site]);
  const work = structuredClone(si);           // the IS, in case a "To sort" VLAN has to be added
  const assets = {}, skipped = [];
  for (const h of hosts) {
    if (!h || !h.name) { skipped.push('A host without a name'); continue; }
    const key = sdk.slug(h.name), ip = sdk.isIp(h.ip) ? h.ip : '';
    const id = idx.find({ connector: 'hosts-json', ext: key, name: h.name, ips: ip ? [ip] : [], site: cfg.site });
    if (id) {
      // already on the map: complete it, and remember the link for the next imports
      const a = state.assets[id];
      const next = { ...a, ip: a.ip || ip, os: a.os || h.os || '', ext: { ...(a.ext || {}), 'hosts-json': key } };
      if (JSON.stringify(next) !== JSON.stringify(a)) assets[id] = next;
    } else {
      // new: in the VLAN whose range holds its IP, otherwise in a "To sort" VLAN
      const vlan = (ip && sdk.vlanForIp(work, ip)) || sdk.holdingVlan(work, cfg.site, 'To sort (JSON import)');
      assets[`hj-${cfg.site}-${key}`] = { site: cfg.site, name: h.name, type: 'server', vlan: vlan.id, ip, os: h.os || '', role: '', crit: 2,
        vulns: [], contacts: [], apps: [], notes: `From ${file.name}`, ext: { 'hosts-json': key } };
    }
  }
  const changes = { si: {}, assets };
  if (JSON.stringify(work) !== JSON.stringify(si)) changes.si[cfg.site] = work;
  const summary = `${hosts.length} host(s) read, ${Object.keys(assets).length} asset(s) to create or complete.`;
  ctx.log(summary);
  return {
    proposals: Object.keys(assets).length ? [{ siteId: cfg.site, title: `Hosts from ${file.name}`, description: summary, changes }] : [],
    summary,
    report: { skipped },
  };
}
```

What matters:

- `sdk.assetIndex(...).find(...)` matches a host to an asset: by the link a previous import stored in
  `ext['hosts-json']`, then by name, then by IP. Storing that link makes the next imports find the asset
  even after a rename.
- Documents are sent **whole** (the asset as it should be, not a patch), and only when they change.
- `ConnectorError` is for problems the user can fix: its message is shown as is.

**3. Start Strata with it.** From a clone of Strata (`npm run setup` once), on your machine and
without accounts (everyone is an admin: keep it local):

```bash
MODULES_DIR=./my-modules DATA_DIR=/tmp/strata-dev PORT=8080 npm start
```

Open `http://localhost:8080`, *Load demo (5 IS)*, then *Collaboration › Connectors*: *Hosts from JSON*
is there, marked *Provided by the server*. A mistake in the manifest is listed at the bottom of the
panel instead, with the reason.

**4. Try it.** Save `[{"name": "web-01", "os": "Debian 12"}, {"name": "new-box", "ip": "10.20.0.99"}]`
as `hosts.json`, then *Import a JSON file* on the card, choose the IS *Lyon* and the file. The card
shows the summary and a button to the proposal: open it to see the changes as an approver will. Or
from a terminal:

```bash
jq -n --rawfile x hosts.json '{wait: true, file: {name: "hosts.json", text: $x}, overrides: {site: "lyon"}}' |
  curl -sS -H 'Content-Type: application/json' -H 'X-Requested-With: strata' \
    -X POST http://localhost:8080/api/connectors/hosts-json/run --data-binary @-
```

**5. Change it and run it again.** Each run starts a fresh process that loads `index.mjs` again: no
restart is needed for the code. A change to the manifest needs a restart. `ctx.log(...)` and
`console.log(...)` go to the terminal where Strata runs, prefixed with `[hosts-json]`; an unexpected
error shows its stack there too.

**6. Talk to a tool.** For a sync rather than a file, set `"permissions": {"map": true, "network": true}`,
list in `"live"` the settings a sync needs (such as `["url", "token"]`), add those settings to `fields`
(`"secret": true` for the token), and export a `test(cfg, ctx)` that checks the access. Call the tool with
`sdk.request(url, {headers, tls: cfg.tls})`, which applies the TLS options of the settings and turns
network errors into messages people can act on. The [ACME CMDB example](#the-code) below does both.

**7. Pack and publish it.** See [publishing it in the store](#publishing-it-in-the-store).

## Good practice

- **Propose, don't decide.** Complete what is empty, keep what people typed (entries without `src`, or
  with another connector's `src`), and remove only what your module added itself (`src` set to your id).
- **Be idempotent.** The same input twice gives the same proposal, and no proposal when the map already
  matches: compare before adding a document.
- **Keep the outside id** in `ext[your module id]`, and use `assetIndex` to match.
- **Place new assets** with `vlanForIp`, or in a `holdingVlan` (“To sort”) that people sort afterwards.
- **Explain**: a `summary` in one sentence; the proposal's `description` says what was read and what
  was left out; `report.skipped` and `report.warnings` list the details.
- **Ask for the least**: `"network": false` when the module only reads files; `"map": false` if it
  does not need the map (rare).
- **Read only what you need** from the tool, in pages, `n` at a time with `sdk.pool`; a run is stopped
  after `CONNECTOR_TIMEOUT_MINUTES` (30 by default; 2 minutes for a test).
- **Bundle your libraries** in the module's folder (`node_modules` inside it): a module cannot install
  anything, and Strata gives it nothing but the SDK.

# Reference

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
  sentences) are shown under *Details*, below the last run on the module's card.

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

## Testing a module

1. Try it by hand as in [your first module](#your-first-module-step-by-step): a `MODULES_DIR` and a local
   Strata without accounts.
2. `node scripts/connector-sim.mjs` starts fake Cyberwatch, GLPI, phpIPAM and PAN-OS APIs on port 8099
   (`SIM_PORT` to change it), with data matching the demo's Lyon site: handy to see how the built-in
   modules talk to a tool, and to model a fake API for yours.
3. For automated tests, [`tests/modules.test.mjs`](tests/modules.test.mjs) shows how to start Strata
   with a `MODULES_DIR`, set a module up and run it through the API, then check its proposals. The
   functions of your module are plain JavaScript too: export your parsers (as `csv-inventory` exports
   `parseCsv`) and test them on their own.
4. `node scripts/pack-module.mjs my-modules/hosts-json dist/` checks the manifest exactly as Strata does.

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
needs what its `permissions` say. Before opening it, check that:

- the module has a README: what it reads, how it matches, what the tool needs (a read-only account);
- `test()` gives a useful message for a wrong address, a wrong secret and missing rights;
- running it twice on the same data gives no new proposal;
- nothing typed by hand is overwritten or removed;
- its licence is free and allows Strata's users to run it (AGPL-3.0-or-later is the usual choice).

Modules kept in this repository (`modules/`) are packed into `docs/modules/` with
`node scripts/pack-module.mjs modules/<id> --registry docs/modules/index.json`; a test checks that the
package matches the folder.

You can also run your own store: any HTTPS address serving an index in the same format
(`{"strataRegistry": 1, "modules": [...]}`, `url` absolute or relative to the index), set in
`MODULE_REGISTRY`.

## Compatibility

A module written for `"strataModule": 1` keeps working in every 1.x version of Strata, with the same
`ctx`, the same SDK helpers and the same answer; new helpers and manifest keys may be added. A store
index with `"strataRegistry": 1` keeps being read. See the
[compatibility policy](https://solidgeeks.github.io/strata/api.html#compat).
