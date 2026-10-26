// SPDX-License-Identifier: AGPL-3.0-or-later
// Connector modules: a folder holding strata-module.json (the manifest, read by the server) and the code
// it names (run in a separate process, see runner.js). Modules come from three places, in this order:
//   builtin    server/connectors/builtin, shipped with Strata
//   provided   MODULES_DIR, set up by the administrator of the machine (Docker volume, NixOS option)
//   installed  DATA_DIR/modules, installed from the module store (store.js)
// The first module with a given id wins. The manifest format is described in MODULES.md.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const API_VERSION = 1;
export const MANIFEST = 'strata-module.json';
export const CONNECTORS_DIR = path.dirname(fileURLToPath(import.meta.url));
export const BUILTIN_DIR = path.join(CONNECTORS_DIR, 'builtin');

export const ID_RE = /^[a-z][a-z0-9-]{1,39}$/;
export const VERSION_RE = /^\d{1,4}\.\d{1,4}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,40})?$/;
const KEY_RE = /^[a-zA-Z][a-zA-Z0-9_]{0,39}$/;
const FIELD_TYPES = ['string', 'number', 'bool', 'select', 'multi', 'sites', 'site', 'asset', 'rules', 'text'];
// Settings every module gets from the server (common.js in the manager): a module cannot redefine them
export const COMMON_KEYS = ['enabled', 'everyHours', 'tlsInsecure', 'tlsCa', 'sites'];

const str = (v, max) => typeof v === 'string' && v.length <= max;

// Compares two versions (x.y.z, a pre-release sorting before its release): <0, 0 or >0
export function compareVersions(a, b) {
  const p = v => { const [main, pre] = String(v).split('-', 2); return { n: main.split('.').map(x => +x || 0), pre }; };
  const x = p(a), y = p(b);
  for (let i = 0; i < 3; i++) if (x.n[i] !== y.n[i]) return (x.n[i] || 0) - (y.n[i] || 0);
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

function checkField(f, i) {
  const at = `fields[${i}]`;
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw new Error(`${at} is not an object`);
  if (!str(f.k, 40) || !KEY_RE.test(f.k) || f.k in Object.prototype) throw new Error(`${at}.k must be a setting name (letters, digits, _), not a built-in name like toString`);
  if (COMMON_KEYS.includes(f.k)) throw new Error(`${at}.k: “${f.k}” is a setting every module already has`);
  if (!str(f.label, 200) || !f.label) throw new Error(`${at}.label is missing`);
  const type = f.type ?? 'string';
  if (!FIELD_TYPES.includes(type)) throw new Error(`${at}.type must be one of ${FIELD_TYPES.join(', ')}`);
  for (const k of ['help', 'placeholder']) if (f[k] !== undefined && !str(f[k], 600)) throw new Error(`${at}.${k} must be text`);
  for (const k of ['required', 'secret', 'advanced']) if (f[k] !== undefined && typeof f[k] !== 'boolean') throw new Error(`${at}.${k} must be true or false`);
  if (type === 'select' || type === 'multi') {
    if (!Array.isArray(f.options) || !f.options.length || f.options.length > 100 || !f.options.every(o => Array.isArray(o) && o.length === 2 && str(o[0], 100) && str(o[1], 200)))
      throw new Error(`${at}.options must list [value, label] pairs`);
  }
  const out = { k: f.k, label: f.label };
  if (type !== 'string') out.type = type;
  for (const k of ['help', 'placeholder', 'required', 'secret', 'advanced', 'options']) if (f[k] !== undefined) out[k] = f[k];
  if (f.default !== undefined) {
    const d = f.default, ok = type === 'bool' ? typeof d === 'boolean' : type === 'number' ? typeof d === 'number' && isFinite(d)
      : type === 'multi' ? Array.isArray(d) && d.every(x => str(x, 100)) : str(d, 2000);
    if (!ok) throw new Error(`${at}.default does not fit its type`);
    out.default = d;
  }
  return out;
}

// Checks a manifest and returns a clean copy of it; throws an Error saying what is wrong
export function checkManifest(m, { strataVersion } = {}) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) throw new Error('the manifest is not a JSON object');
  if (m.strataModule !== API_VERSION) throw new Error(`strataModule must be ${API_VERSION} (the module API this Strata understands)`);
  if (!str(m.id, 40) || !ID_RE.test(m.id)) throw new Error('id must be 2 to 40 lower-case letters, digits or dashes, starting with a letter');
  if (!str(m.name, 60) || !m.name.trim()) throw new Error('name is missing');
  if (!str(m.version, 60) || !VERSION_RE.test(m.version)) throw new Error('version must look like 1.2.3');
  if (!str(m.description, 300) || !m.description.trim()) throw new Error('description is missing');
  for (const k of ['author', 'license']) if (m[k] !== undefined && !str(m[k], 100)) throw new Error(`${k} must be text`);
  if (m.homepage !== undefined && !(str(m.homepage, 300) && /^https?:\/\/[^\s]+$/.test(m.homepage))) throw new Error('homepage must be an http(s) address');
  if (m.badge !== undefined && !(str(m.badge, 5) && /^[A-Za-z0-9]+$/.test(m.badge))) throw new Error('badge must be up to 5 letters or digits');
  if (!str(m.main, 200) || !/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*\.m?js$/.test(m.main) || m.main.split('/').some(s => s === '..' || s === '.'))
    throw new Error('main must be the relative path of a .mjs or .js file inside the module');
  if (m.minStrata !== undefined) {
    if (!str(m.minStrata, 60) || !VERSION_RE.test(m.minStrata)) throw new Error('minStrata must look like 1.2.3');
    if (strataVersion && compareVersions(strataVersion, m.minStrata) < 0) throw new Error(`needs Strata ${m.minStrata} or later`);
  }
  const perm = m.permissions ?? {};
  if (typeof perm !== 'object' || Array.isArray(perm)) throw new Error('permissions must be an object');
  for (const k of Object.keys(perm)) if (!['map', 'network'].includes(k) || typeof perm[k] !== 'boolean') throw new Error(`permissions.${k}: only map and network, true or false`);
  if (!Array.isArray(m.fields) || m.fields.length > 60) throw new Error('fields must be a list (60 at most)');
  const fields = m.fields.map(checkField);
  const keys = new Set();
  for (const f of fields) { if (keys.has(f.k)) throw new Error(`the setting “${f.k}” is listed twice`); keys.add(f.k); }
  // live: settings a sync with the tool needs (default: always possible); false: file imports only
  let live = m.live ?? [];
  if (live !== false && !(Array.isArray(live) && live.every(k => keys.has(k)))) throw new Error('live must be false or a list of its settings');
  let file = null;
  if (m.file !== undefined) {
    const f = m.file;
    if (!f || typeof f !== 'object' || Array.isArray(f)) throw new Error('file must be an object');
    if (!str(f.label, 80) || !f.label) throw new Error('file.label is missing');
    if (f.accept !== undefined && !str(f.accept, 200)) throw new Error('file.accept must be text, as in <input accept>');
    if (f.help !== undefined && !str(f.help, 1200)) throw new Error('file.help must be text');
    if (f.role !== undefined && !['contributor', 'approver'].includes(f.role)) throw new Error('file.role must be contributor or approver');
    if (f.fields !== undefined && !(Array.isArray(f.fields) && f.fields.every(k => keys.has(k)))) throw new Error('file.fields must list some of its settings');
    file = { label: f.label, accept: f.accept || '', help: f.help || '', role: f.role || 'approver', fields: f.fields || [] };
  }
  if (live === false && !file) throw new Error('a module with live: false must import files');
  return {
    strataModule: API_VERSION, id: m.id, name: m.name.trim(), version: m.version, description: m.description.trim(),
    author: m.author || '', license: m.license || '', homepage: m.homepage || '',
    badge: (m.badge || m.name.replace(/[^A-Za-z0-9]/g, '').slice(0, 3)).toUpperCase(),
    main: m.main, minStrata: m.minStrata || '',
    permissions: { map: !!perm.map, network: !!perm.network },
    live, file, fields,
  };
}

// Reads the module in a folder: {ok: true, module} or {ok: false, error}
export function readModule(dir, origin, opts = {}) {
  let manifest;
  try { manifest = checkManifest(JSON.parse(fs.readFileSync(path.join(dir, MANIFEST), 'utf8')), opts); }
  catch (e) { return { ok: false, error: e.code === 'ENOENT' ? `no ${MANIFEST}` : e.message }; }
  let main;
  try { main = fs.realpathSync(path.join(dir, manifest.main)); } catch { return { ok: false, error: `${manifest.main} is missing` }; }
  // the code must stay inside the module folder: the module process can read nothing else
  if (!main.startsWith(dir + path.sep)) return { ok: false, error: `${manifest.main} points outside the module` };
  // A .js file is an ES module only under a package.json saying so: built-in modules have Strata's own
  if (main.endsWith('.js') && origin !== 'builtin') {
    let type;
    try { type = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).type; } catch { }
    if (type !== 'module') return { ok: false, error: `${manifest.main}: name it .mjs, or add a package.json with "type": "module"` };
  }
  return { ok: true, module: { ...manifest, dir, origin, mainPath: main } };
}

// Every module of the three places. problems: modules that could not be read, for the administrator
export function discover({ providedDir, installedDir, strataVersion }) {
  const modules = new Map(), problems = [];
  const sources = [[BUILTIN_DIR, 'builtin'], [providedDir, 'provided'], [installedDir, 'installed']];
  for (const [root, origin] of sources) {
    if (!root) continue;
    let names = [];
    try { names = fs.readdirSync(root, { withFileTypes: true }).filter(d => (d.isDirectory() || d.isSymbolicLink()) && !d.name.startsWith('.')).map(d => d.name).sort(); }
    catch (e) { if (e.code !== 'ENOENT') problems.push({ origin, folder: root, error: e.message }); continue; }
    for (const name of names) {
      let dir;
      try { dir = fs.realpathSync(path.join(root, name)); } catch (e) { problems.push({ origin, folder: name, error: `cannot be read (${e.code || e.message})` }); continue; }
      const r = readModule(dir, origin, { strataVersion });
      if (!r.ok) { problems.push({ origin, folder: name, error: r.error }); continue; }
      if (modules.has(r.module.id)) { problems.push({ origin, folder: name, error: `the id “${r.module.id}” is already taken (${modules.get(r.module.id).origin} module)` }); continue; }
      modules.set(r.module.id, r.module);
    }
  }
  return { modules, problems };
}
