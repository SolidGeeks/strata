// SPDX-License-Identifier: AGPL-3.0-or-later
// Module store: the list of modules a registry offers (MODULE_REGISTRY, a JSON index), and installing,
// updating or removing them in DATA_DIR/modules. A package is a .tgz holding the module folder; the
// index pins the SHA-256 of each package, so what gets installed is exactly what the registry reviewed.
// An administrator may also upload a package by hand when MODULE_UPLOAD allows it (no checksum then:
// whoever uploads it vouches for it).
//
// Registry index (format 1):
//   {"strataRegistry": 1, "modules": [{"id", "name", "version", "description", "author", "homepage",
//     "license", "badge", "permissions": {"map", "network"}, "minStrata", "url", "sha256"}]}
// "url" is absolute, or relative to the index.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { request, ConnectorError } from './sdk.js';
import { MANIFEST, ID_RE, VERSION_RE, readModule, compareVersions } from './modules.js';

const MAX_PACKAGE = 20 * 1024 * 1024, MAX_UNPACKED = 60 * 1024 * 1024, MAX_FILES = 2000;
const INDEX_TTL = 10 * 60000;

/* ---------------- .tgz ---------------- */
// Reads a gzip'ed tar archive: [{path, data}] for its regular files. Folders are implied by the paths;
// links, devices and absolute or "../" paths are refused. A single top folder ("package/", as npm pack
// makes, or the module's own name) is removed.
export function readTgz(buf) {
  let tar;
  try { tar = zlib.gunzipSync(buf, { maxOutputLength: MAX_UNPACKED }); }
  catch (e) { throw new ConnectorError(e.code === 'ERR_BUFFER_TOO_LARGE' ? 'The package is too large once unpacked.' : 'This is not a .tgz package.'); }
  const files = [];
  let pos = 0, longName = null, paxPath = null;
  const field = (b, o, n) => { const s = b.subarray(o, o + n); const z = s.indexOf(0); return (z < 0 ? s : s.subarray(0, z)).toString('utf8'); };
  while (pos + 512 <= tar.length) {
    const h = tar.subarray(pos, pos + 512);
    if (h.every(x => x === 0)) break;
    const sum = parseInt(field(h, 148, 8).trim() || '0', 8);
    let check = 0; for (let i = 0; i < 512; i++) check += i >= 148 && i < 156 ? 32 : h[i];
    if (sum !== check) throw new ConnectorError('The package is damaged (tar checksum).');
    const size = parseInt(field(h, 124, 12).trim() || '0', 8), type = String.fromCharCode(h[156] || 48);
    const body = tar.subarray(pos + 512, pos + 512 + size);
    if (body.length < size) throw new ConnectorError('The package is cut short.');
    pos += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') { const m = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(body.toString('utf8')); paxPath = m ? m[1] : null; continue; }
    if (type === 'g') continue;
    if (type === 'L') { longName = field(body, 0, body.length); continue; }
    const prefix = field(h, 345, 155), name = paxPath || longName || (prefix ? `${prefix}/${field(h, 0, 100)}` : field(h, 0, 100));
    paxPath = longName = null;
    if (type === '5') continue;
    if (type !== '0' && type !== '7' && h[156] !== 0) throw new ConnectorError(`The package holds a link or a special file (${name}): not allowed.`);
    const parts = name.replace(/\\/g, '/').split('/').filter(p => p && p !== '.');
    if (name.startsWith('/') || parts.some(p => p === '..') || !parts.length) throw new ConnectorError(`Unsafe path in the package: ${name}`);
    files.push({ path: parts.join('/'), data: Buffer.from(body) });
    if (files.length > MAX_FILES) throw new ConnectorError('The package holds too many files.');
  }
  const tops = new Set(files.map(f => f.path.split('/')[0]));
  if (tops.size === 1 && !files.some(f => !f.path.includes('/'))) for (const f of files) f.path = f.path.split('/').slice(1).join('/');
  if (!files.some(f => f.path === MANIFEST)) throw new ConnectorError(`The package has no ${MANIFEST} at its top.`);
  return files;
}

// Writes a gzip'ed tar archive of files [{path, data}] (ustar, fixed dates and owners: the same files
// always give the same bytes, so a checksum can be published)
export function writeTgz(files, top = 'package') {
  const blocks = [];
  const octal = (n, len) => n.toString(8).padStart(len - 1, '0') + '\0';
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : 1))) {
    const name = `${top}/${f.path}`;
    if (Buffer.byteLength(name) > 100) throw new Error(`path too long for the package: ${name}`);
    const h = Buffer.alloc(512);
    h.write(name, 0, 'utf8');
    h.write(octal(0o644, 8), 100); h.write(octal(0, 8), 108); h.write(octal(0, 8), 116);
    h.write(octal(f.data.length, 12), 124); h.write(octal(0, 12), 136);
    h.fill(32, 148, 156); h[156] = 48; h.write('ustar\0', 257); h.write('00', 263);
    let sum = 0; for (const b of h) sum += b;
    h.write(octal(sum, 7) + ' ', 148);
    blocks.push(h, f.data, Buffer.alloc((512 - (f.data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(blocks), { level: 9 });
}

export const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');

/* ---------------- store ---------------- */
// opts: registryUrl ('' = no store), uploads (bool), installedDir, strataVersion, connectors (manager), log
export function createStore({ registryUrl, uploads, installedDir, strataVersion, connectors, log }) {
  let cache = null;
  // GET, following up to 5 redirects (release downloads redirect to their storage)
  async function fetchBytes(url, max) {
    for (let hop = 0; hop < 6; hop++) {
      const res = await request(url, { headers: { Accept: '*/*' }, timeoutMs: 30000, maxBytes: max });
      if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) { url = new URL(res.headers.location, url).href; if (!/^https?:/.test(url)) break; continue; }
      if (res.status !== 200) throw new ConnectorError(`${new URL(url).host} answered HTTP ${res.status}.`);
      return res.body;
    }
    throw new ConnectorError('Too many redirects.');
  }
  async function index(fresh) {
    if (!registryUrl) throw new ConnectorError('The module store is off on this server (MODULE_REGISTRY).');
    if (!fresh && cache && Date.now() - cache.at < INDEX_TTL) return cache.list;
    let j;
    try { j = JSON.parse((await fetchBytes(registryUrl, 2 * 1024 * 1024)).toString('utf8')); }
    catch (e) { throw new ConnectorError(`The module store cannot be read: ${e.message}`); }
    if (!j || j.strataRegistry !== 1 || !Array.isArray(j.modules)) throw new ConnectorError('The module store answered with something that is not a module index.');
    const list = [];
    for (const m of j.modules.slice(0, 500)) {
      if (!m || !ID_RE.test(m.id || '') || !VERSION_RE.test(m.version || '') || !/^[0-9a-f]{64}$/.test(m.sha256 || '') || typeof m.url !== 'string') continue;
      let url;
      try { url = new URL(m.url, registryUrl).href; } catch { continue; }
      if (!/^https?:/.test(url)) continue;
      const s = (v, n) => (typeof v === 'string' ? v.slice(0, n) : '');
      list.push({
        id: m.id, name: s(m.name, 60) || m.id, version: m.version, description: s(m.description, 300), author: s(m.author, 100),
        homepage: /^https?:\/\//.test(m.homepage || '') ? s(m.homepage, 300) : '', license: s(m.license, 100), badge: s(m.badge, 5),
        permissions: { map: !!m.permissions?.map, network: !!m.permissions?.network }, minStrata: VERSION_RE.test(m.minStrata || '') ? m.minStrata : '',
        url, sha256: m.sha256,
      });
    }
    cache = { at: Date.now(), list };
    return list;
  }
  // The registry's modules, with what is installed here
  async function list(fresh) {
    const mods = await index(fresh);
    return mods.map(m => {
      const here = connectors.module(m.id);
      return {
        ...m, url: undefined, sha256: undefined,
        installed: here ? { version: here.version, origin: here.origin } : null,
        update: !!here && here.origin === 'installed' && compareVersions(m.version, here.version) > 0,
        compatible: !m.minStrata || compareVersions(strataVersion, m.minStrata) >= 0,
      };
    });
  }
  // Unpacks a package into DATA_DIR/modules/<id>, replacing the version there. expect: {id, version} from the index
  async function unpack(buf, expect) {
    const files = readTgz(buf);
    fs.mkdirSync(installedDir, { recursive: true, mode: 0o700 });
    const tmp = fs.mkdtempSync(path.join(installedDir, '.new-'));
    try {
      for (const f of files) {
        const to = path.join(tmp, f.path);
        if (!to.startsWith(tmp + path.sep) || f.path.includes('\0')) throw new ConnectorError(`Unsafe path in the package: ${f.path}`);
        try {
          fs.mkdirSync(path.dirname(to), { recursive: true, mode: 0o755 });
          fs.writeFileSync(to, f.data, { mode: 0o644, flag: 'wx' });
        } catch (e) { throw new ConnectorError(`The package cannot be unpacked (${f.path}: ${e.code || 'error'}).`); }
      }
      const r = readModule(fs.realpathSync(tmp), 'installed', { strataVersion });
      if (!r.ok) throw new ConnectorError(`This module cannot be installed: ${r.error}.`);
      const m = r.module;
      if (expect && (m.id !== expect.id || m.version !== expect.version)) throw new ConnectorError(`The package holds ${m.id} ${m.version}, not ${expect.id} ${expect.version} as the store says.`);
      const other = connectors.module(m.id);
      if (other && other.origin !== 'installed') throw new ConnectorError(`A ${other.origin} module already has the id “${m.id}”.`);
      if (connectors.isRunning(m.id)) throw new ConnectorError(`${m.name} is running: try again when it is done.`);
      const dest = path.join(installedDir, m.id), old = path.join(installedDir, `.old-${m.id}-${Date.now()}`);
      if (fs.existsSync(dest)) fs.renameSync(dest, old);
      try { fs.renameSync(tmp, dest); }
      catch (e) { if (fs.existsSync(old)) fs.renameSync(old, dest); throw new ConnectorError(`The module could not be put in place (${e.code || e.message}).`); }
      fs.rmSync(old, { recursive: true, force: true });
      connectors.reload();
      log(`Module ${m.id} ${m.version} installed${other ? ` (was ${other.version})` : ''}.`);
      return { id: m.id, name: m.name, version: m.version, previous: other ? other.version : null };
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
  async function install(id) {
    const m = (await index(true)).find(x => x.id === id);
    if (!m) throw new ConnectorError(`The store has no module “${id}”.`);
    if (m.minStrata && compareVersions(strataVersion, m.minStrata) < 0) throw new ConnectorError(`${m.name} needs Strata ${m.minStrata} or later.`);
    const buf = await fetchBytes(m.url, MAX_PACKAGE);
    if (sha256(buf) !== m.sha256) throw new ConnectorError(`The package of ${m.name} does not match the checksum the store gives: not installed.`);
    return unpack(buf, { id: m.id, version: m.version });
  }
  async function upload(buf) {
    if (!uploads) throw new ConnectorError('Installing a module from a file is off on this server (MODULE_UPLOAD).');
    if (buf.length > MAX_PACKAGE) throw new ConnectorError('The package is larger than 20 MB.');
    return unpack(buf, null);
  }
  async function remove(id) {
    const m = connectors.module(id);
    if (!m) throw new ConnectorError('Unknown module');
    if (m.origin !== 'installed') throw new ConnectorError(m.origin === 'builtin' ? 'Built-in modules stay: turn them off in their settings.' : 'This module is provided by the server (MODULES_DIR): remove it there.');
    if (connectors.isRunning(id)) throw new ConnectorError(`${m.name} is running: try again when it is done.`);
    fs.rmSync(path.join(installedDir, id), { recursive: true, force: true });
    connectors.reload();
    await connectors.forget(id);
    log(`Module ${id} removed.`);
    return { id };
  }
  return { enabled: !!registryUrl, uploads: !!uploads, list, install, upload, remove };
}
