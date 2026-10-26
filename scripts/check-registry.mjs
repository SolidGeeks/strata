// SPDX-License-Identifier: AGPL-3.0-or-later
// Checks a module store index before it is published: for every entry, the package it points to is
// downloaded, must match its SHA-256, must hold a manifest Strata accepts whose id, version, name and
// permissions are the ones the index shows, and must load in the restricted module process with a
// run() function (and test(), unless it only imports files). Run by the Modules workflow on every
// pull request that changes the store.
//   node scripts/check-registry.mjs [docs/modules/index.json]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readTgz, sha256 } from '../server/connectors/store.js';
import { readModule, ID_RE, VERSION_RE } from '../server/connectors/modules.js';
import { runModule } from '../server/connectors/runner.js';
import { request } from '../server/connectors/sdk.js';

const index = path.resolve(process.argv[2] || 'docs/modules/index.json');
const strataVersion = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const idx = JSON.parse(fs.readFileSync(index, 'utf8'));
let failed = 0;
const fail = (id, msg) => { failed++; console.error(`✗ ${id}: ${msg}`); };

async function fetchPackage(url) {
  if (!/^[a-z]+:/i.test(url)) return fs.readFileSync(path.join(path.dirname(index), url));
  for (let hop = 0; hop < 6; hop++) {
    const res = await request(url, { headers: { Accept: '*/*' }, timeoutMs: 60000, maxBytes: 20 * 1024 * 1024 });
    if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) { url = new URL(res.headers.location, url).href; continue; }
    if (res.status !== 200) throw new Error(`${url} answered HTTP ${res.status}`);
    return res.body;
  }
  throw new Error('too many redirects');
}

if (idx.strataRegistry !== 1 || !Array.isArray(idx.modules)) { console.error('✗ not a module index (strataRegistry: 1, modules: [...])'); process.exit(1); }
const ids = new Set();
for (const e of idx.modules) {
  const id = e && e.id || '(no id)';
  if (!ID_RE.test(e.id || '') || !VERSION_RE.test(e.version || '') || !/^[0-9a-f]{64}$/.test(e.sha256 || '') || typeof e.url !== 'string') { fail(id, 'id, version, url and sha256 are required'); continue; }
  if (ids.has(e.id)) { fail(id, 'listed twice'); continue; }
  ids.add(e.id);
  if (/^[a-z]+:/i.test(e.url) && !e.url.startsWith('https://')) { fail(id, 'the package must be served over HTTPS'); continue; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `strata-check-${e.id}-`));
  try {
    const buf = await fetchPackage(e.url);
    if (sha256(buf) !== e.sha256) throw new Error(`the package's SHA-256 is ${sha256(buf)}, not the one listed`);
    for (const f of readTgz(buf)) { const to = path.join(dir, f.path); fs.mkdirSync(path.dirname(to), { recursive: true }); fs.writeFileSync(to, f.data); }
    const r = readModule(fs.realpathSync(dir), 'installed', { strataVersion });
    if (!r.ok) throw new Error(`manifest: ${r.error}`);
    const m = r.module;
    for (const k of ['id', 'version', 'name']) if (m[k] !== e[k]) throw new Error(`${k} is “${m[k]}” in the package, “${e[k]}” in the index`);
    for (const k of ['map', 'network']) if (m.permissions[k] !== !!(e.permissions && e.permissions[k])) throw new Error(`permissions.${k} is ${m.permissions[k]} in the package: the index must say the same`);
    if ((m.minStrata || '') !== (e.minStrata || '')) throw new Error(`minStrata is “${m.minStrata}” in the package, “${e.minStrata || ''}” in the index`);
    const fns = await runModule(m, 'exports', {}, { timeoutMs: 30000, log: l => console.log(`  ${l}`) });
    if (!fns.includes('run')) throw new Error('its code has no run() function');
    if (m.live !== false && !fns.includes('test')) throw new Error('its code has no test() function (needed unless "live": false)');
    console.log(`✓ ${e.id} ${e.version}: ${Math.round(buf.length / 1024)} KB, reads ${[m.permissions.map ? 'the map' : '', m.permissions.network ? 'the network' : ''].filter(Boolean).join(' and ') || 'nothing'}, ${fns.join(', ')}`);
  } catch (err) { fail(id, err.message); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
console.log(failed ? `${failed} problem(s)` : `${idx.modules.length} module(s) checked`);
process.exit(failed ? 1 : 0);
