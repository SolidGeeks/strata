// SPDX-License-Identifier: AGPL-3.0-or-later
// Packs a connector module folder into <id>-<version>.tgz for the module store, after checking its
// manifest the way Strata will, and prints the SHA-256 the registry index must give.
//   node scripts/pack-module.mjs modules/csv-inventory [out-folder] [--registry docs/modules/index.json]
// With --registry, the module's entry in that index is added or updated (url relative to the index).
// The package is the same bytes for the same files (fixed dates and owners), so anyone can check it.
import fs from 'node:fs';
import path from 'node:path';
import { readModule, MANIFEST } from '../server/connectors/modules.js';
import { writeTgz, readTgz, sha256 } from '../server/connectors/store.js';

const args = process.argv.slice(2);
const ri = args.indexOf('--registry');
const registry = ri >= 0 ? args.splice(ri, 2)[1] : null;
const [src, outArg] = args;
if (!src) { console.error('Usage: node scripts/pack-module.mjs <module folder> [out folder] [--registry index.json]'); process.exit(2); }
const dir = fs.realpathSync(src);
const r = readModule(dir, 'installed');
if (!r.ok) { console.error(`${MANIFEST}: ${r.error}`); process.exit(1); }
const m = r.module;
const files = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.name.startsWith('.')) continue;
    const p = path.join(d, e.name);
    if (e.isSymbolicLink()) { console.error(`${path.relative(dir, p)}: links are not allowed in a package`); process.exit(1); }
    if (e.isDirectory()) walk(p);
    else if (e.isFile()) files.push({ path: path.relative(dir, p).split(path.sep).join('/'), data: fs.readFileSync(p) });
  }
})(dir);
const tgz = writeTgz(files, m.id);
readTgz(tgz); // the store will read it the same way
const out = path.resolve(outArg || (registry ? path.dirname(registry) : '.'));
fs.mkdirSync(out, { recursive: true });
const file = path.join(out, `${m.id}-${m.version}.tgz`);
fs.writeFileSync(file, tgz);
const sum = sha256(tgz);
console.log(`${path.relative(process.cwd(), file)}  ${files.length} file(s), ${tgz.length} bytes\nsha256 ${sum}`);
if (registry) {
  const idx = fs.existsSync(registry) ? JSON.parse(fs.readFileSync(registry, 'utf8')) : { strataRegistry: 1, modules: [] };
  const entry = {
    id: m.id, name: m.name, version: m.version, description: m.description, author: m.author, license: m.license, homepage: m.homepage,
    badge: m.badge, permissions: m.permissions, ...(m.minStrata ? { minStrata: m.minStrata } : {}),
    url: path.relative(path.dirname(path.resolve(registry)), file).split(path.sep).join('/'), sha256: sum,
  };
  idx.modules = [...idx.modules.filter(x => x.id !== m.id), entry].sort((a, b) => (a.id < b.id ? -1 : 1));
  fs.writeFileSync(registry, JSON.stringify(idx, null, 2) + '\n');
  console.log(`${registry}: ${m.id} ${m.version}`);
}
