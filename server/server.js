// SPDX-License-Identifier: AGPL-3.0-or-later
// Strata — self-hosted server (formerly IS Map 3D).
// Zero dependencies: Node.js >= 20. Serves the web app and a small JSON API, stores the map in one JSON
// file, keeps a version history (rollback), named accounts with roles, and proposals that an approver
// reviews before they reach the map. Live updates go out over Server-Sent Events.
import http from 'node:http';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createConnectors } from './connectors/index.js';
import { createStore } from './connectors/store.js';
import { ID_RE as MODULE_ID_RE } from './connectors/modules.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const env = process.env;
// A secret from NAME, or from the file NAME_FILE points to (Docker secrets, systemd credentials, NixOS
// secret managers), so it stays out of the environment and of the Nix store. The file wins; its
// trailing newline is dropped. An unreadable file stops the server: starting without the password
// would start without authentication.
function secret(name) {
  const file = env[name + '_FILE'];
  if (!file) return env[name] || '';
  try { return fs.readFileSync(file, 'utf8').replace(/\r?\n$/, ''); }
  catch (e) { console.error(`${name}_FILE: cannot read ${file}: ${e.message}`); process.exit(1); }
}
const CONFIG = {
  port: parseInt(env.PORT || '8080', 10),
  host: env.HOST || '0.0.0.0',
  dataDir: path.resolve(env.DATA_DIR || path.join(ROOT, 'data')),
  publicDir: path.resolve(env.PUBLIC_DIR || path.join(ROOT, 'public')),
  editUser: env.EDIT_USER || 'admin',
  editPass: secret('EDIT_PASS'),
  viewUser: env.VIEW_USER || 'viewer',
  viewPass: secret('VIEW_PASS'),
  readOnly: /^(1|true|yes)$/i.test(env.READ_ONLY || ''),
  allowSelfApproval: /^(1|true|yes)$/i.test(env.ALLOW_SELF_APPROVAL || ''),
  backupKeep: Math.max(0, parseInt(env.BACKUP_KEEP || '14', 10)),
  backupEveryHours: Math.max(1, parseInt(env.BACKUP_EVERY_HOURS || '24', 10)),
  historyKeep: Math.max(50, parseInt(env.HISTORY_KEEP || '5000', 10)),
  maxImportBytes: parseInt(env.MAX_IMPORT_MB || '20', 10) * 1024 * 1024,
  maxDocBytes: 512 * 1024,
  // Failed sign-ins: 0 turns a limit off
  loginMaxFails: Math.max(0, parseInt(env.LOGIN_MAX_FAILS ?? '10', 10) || 0),
  loginMaxFailsPerAddress: Math.max(0, parseInt(env.LOGIN_MAX_FAILS_PER_ADDRESS ?? '20', 10) || 0),
  loginLockMs: Math.max(1000, (parseFloat(env.LOGIN_LOCK_MINUTES || '15') || 15) * 60000),
  trustProxy: String(env.TRUST_PROXY || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
  // Connector modules: a folder of modules set up by the machine's administrator, the module store
  // (empty or "off": none), installing a package by hand, and how long one run may take
  modulesDir: env.MODULES_DIR ? path.resolve(env.MODULES_DIR) : '',
  moduleRegistry: /^(0|false|no|off|)$/i.test(env.MODULE_REGISTRY ?? 'x') ? '' : (env.MODULE_REGISTRY || 'https://solidgeeks.github.io/strata/modules/index.json'),
  moduleUpload: /^(1|true|yes)$/i.test(env.MODULE_UPLOAD || ''),
  connectorTimeoutMs: Math.max(2000, (parseFloat(env.CONNECTOR_TIMEOUT_MINUTES || '30') || 30) * 60000),
  // AGPL-3.0 section 13: users of a modified version must be offered its source. Point this at your fork.
  sourceUrl: /^https?:\/\//.test(env.SOURCE_URL || '') ? env.SOURCE_URL : 'https://github.com/SolidGeeks/strata',
};
const DB_FILE = path.join(CONFIG.dataDir, 'db.json');
const USERS_FILE = path.join(CONFIG.dataDir, 'users.json');
const HISTORY_FILE = path.join(CONFIG.dataDir, 'history.jsonl');
const PROPOSALS_FILE = path.join(CONFIG.dataDir, 'proposals.json');
const BACKUP_DIR = path.join(CONFIG.dataDir, 'backups');
// Ids and account names become object keys: the names that reach Object.prototype are refused
const ID_RE = /^(?!(?:__proto__|constructor|prototype)$)[A-Za-z0-9_.:@+~-]{1,120}$/;
const USER_RE = /^(?!(?:__proto__|constructor|prototype)$)[A-Za-z0-9_.@-]{1,64}$/;
const ROLES = ['viewer', 'contributor', 'approver', 'admin'];
const RANK = Object.fromEntries(ROLES.map((r, i) => [r, i]));

const log = (...a) => console.log(new Date().toISOString(), ...a);
const clone = o => (o === undefined ? undefined : JSON.parse(JSON.stringify(o)));
const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
// A key looked up in a map read from a request or a file: never an inherited property (toString, __proto__…)
const own = (o, k) => (o != null && Object.hasOwn(o, k) ? o[k] : undefined);
const httpError = (status, message, extra) => Object.assign(new Error(message), { status, extra });

/* ---------------- Storage ---------------- */
let state = { si: {}, assets: {}, wan: [], services: [], rev: 0, updatedAt: null };

// The data files describe the weak spots of the network, the accounts and the connector secrets: readable by
// the server's own user only. Files written by older versions with the default mode are tightened at start.
function protectDataFiles() {
  const files = [DB_FILE, USERS_FILE, HISTORY_FILE, PROPOSALS_FILE, path.join(CONFIG.dataDir, 'connectors.json')];
  try { for (const f of fs.readdirSync(BACKUP_DIR)) files.push(path.join(BACKUP_DIR, f)); } catch { }
  for (const f of files) { try { if ((fs.statSync(f).mode & 0o077) !== 0) fs.chmodSync(f, 0o600); } catch { } }
}
function loadState() {
  fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
  protectDataFiles();
  if (!fs.existsSync(DB_FILE)) { log(`No data yet, starting empty (${DB_FILE})`); return; }
  const p = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  state = {
    si: isObj(p.si) ? p.si : {}, assets: isObj(p.assets) ? p.assets : {},
    wan: Array.isArray(p.wan) ? p.wan : [], services: Array.isArray(p.services) ? p.services : [],
    rev: Number.isInteger(p.rev) ? p.rev : 0, updatedAt: p.updatedAt || null,
  };
  log(`Loaded ${Object.keys(state.si).length} IS, ${Object.keys(state.assets).length} assets, rev ${state.rev}`);
}
// Writes are serialised and atomic (write to a temp file, then rename)
let writeChain = Promise.resolve();
function writeJson(file, data) {
  const text = typeof data === 'string' ? data : JSON.stringify(data);
  writeChain = writeChain.then(async () => {
    const tmp = file + '.tmp';
    await fsp.writeFile(tmp, text, { encoding: 'utf8', mode: 0o600 });
    await fsp.rename(tmp, file);
  }).catch(err => log('ERROR writing', path.basename(file), err.message));
  return writeChain;
}
async function backup(reason) {
  if (!CONFIG.backupKeep || !fs.existsSync(DB_FILE)) return;
  await writeChain;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace(/Z$/, '');
  const dest = path.join(BACKUP_DIR, `db-${stamp}.json`);
  await fsp.copyFile(DB_FILE, dest);
  const files = (await fsp.readdir(BACKUP_DIR)).filter(f => /^db-.*\.json$/.test(f)).sort();
  for (const f of files.slice(0, Math.max(0, files.length - CONFIG.backupKeep))) await fsp.unlink(path.join(BACKUP_DIR, f));
  log(`Backup written (${reason}): ${path.basename(dest)}`);
}

/* ---------------- History ----------------
   One line per changed document: {rev, at, user, batch, label, kind, id, before, after}.
   kind: si | assets | wan | services | all (whole map, for imports). Rolling back replays the
   "before" of later lines, and is itself recorded, so a rollback can be undone too. */
let history = [];
function loadHistory() {
  if (!fs.existsSync(HISTORY_FILE)) return;
  history = fs.readFileSync(HISTORY_FILE, 'utf8').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  // a db.json restored from an older backup: forget the history lines it does not contain
  const ahead = history.filter(h => h.rev > state.rev).length;
  if (ahead) { history = history.filter(h => h.rev <= state.rev); log(`History: dropped ${ahead} changes newer than the data file (restored backup?)`); }
  trimHistory(true);
  log(`History: ${history.length} changes, back to rev ${history.length ? history[0].rev : state.rev}`);
}
function trimHistory(rewrite) {
  if (history.length <= CONFIG.historyKeep && !rewrite) return;
  if (history.length > CONFIG.historyKeep) {
    // keep whole revisions: drop the oldest ones until under the limit
    let cut = history.length - CONFIG.historyKeep;
    while (cut < history.length && history[cut].rev === history[cut - 1]?.rev) cut++;
    history = history.slice(cut);
  }
  writeJson(HISTORY_FILE, history.map(h => JSON.stringify(h)).join('\n') + (history.length ? '\n' : ''));
}
// Applies a list of document changes as ONE revision, records it and tells the clients
async function commitChanges(changes, auth, meta = {}) {
  const real = changes.filter(c => !same(c.before, c.after));
  if (!real.length) return state.rev;
  for (const c of real) applyDoc(state, c.kind, c.id, c.after);
  state.rev += 1;
  state.updatedAt = new Date().toISOString();
  const lines = real.map(c => ({ rev: state.rev, at: state.updatedAt, user: auth.user || '', batch: meta.batch || `r${state.rev}`, label: meta.label || '', kind: c.kind, id: c.id ?? null, before: c.before ?? null, after: c.after ?? null }));
  history.push(...lines);
  await writeJson(DB_FILE, state);
  const text = lines.map(l => JSON.stringify(l)).join('\n') + '\n';
  writeChain = writeChain.then(() => fsp.appendFile(HISTORY_FILE, text, { mode: 0o600 })).catch(e => log('ERROR history', e.message));
  await writeChain;
  trimHistory(false);
  broadcast('change', { rev: state.rev });
  return state.rev;
}
function applyDoc(s, kind, id, value) {
  if (kind === 'si' || kind === 'assets') { if (value == null) delete s[kind][id]; else s[kind][id] = clone(value); }
  else if (kind === 'wan') s.wan = clone(value || []);
  else if (kind === 'services') s.services = clone(value || []);
  else if (kind === 'all') { const v = value || {}; s.si = clone(v.si || {}); s.assets = clone(v.assets || {}); s.wan = clone(v.wan || []); s.services = clone(v.services || []); }
}
const docOf = (s, kind, id) => (kind === 'si' || kind === 'assets') ? (own(s[kind], id) ?? null) : kind === 'wan' ? s.wan : kind === 'services' ? s.services : { si: s.si, assets: s.assets, wan: s.wan, services: s.services };
const change = (kind, id, after) => ({ kind, id, before: clone(docOf(state, kind, id)), after: clone(after) });
// The map as it was right after revision `rev`
function stateAt(rev) {
  if (rev >= state.rev) return clone(state);
  const oldest = history.length ? history[0].rev - 1 : state.rev;
  if (rev < oldest) throw httpError(410, `Version ${rev} is older than the kept history (oldest: ${oldest})`);
  const s = clone({ si: state.si, assets: state.assets, wan: state.wan, services: state.services });
  for (let i = history.length - 1; i >= 0 && history[i].rev > rev; i--) applyDoc(s, history[i].kind, history[i].id, history[i].before);
  return Object.assign(s, { rev });
}
// Every document that differs between the current map and `target`, as changes
function diffTo(target) {
  const out = [];
  for (const kind of ['si', 'assets']) {
    const keys = new Set([...Object.keys(state[kind]), ...Object.keys(target[kind] || {})]);
    for (const id of keys) if (!same(state[kind][id], target[kind]?.[id])) out.push(change(kind, id, target[kind]?.[id] ?? null));
  }
  if (!same(state.wan, target.wan || [])) out.push(change('wan', null, target.wan || []));
  if (!same(state.services, target.services || [])) out.push(change('services', null, target.services || []));
  return out;
}
const nameOfDoc = (kind, doc) => !doc ? '' : kind === 'si' ? (doc.name || '') : kind === 'assets' ? (doc.name || '') : '';

/* ---------------- Proposals ----------------
   A proposal holds the documents a contributor wants to change ("changes", null = delete) and the live
   version of each of them when they were first touched ("base", to detect conflicting edits). */
let proposals = {};
function loadProposals() { if (fs.existsSync(PROPOSALS_FILE)) { try { proposals = JSON.parse(fs.readFileSync(PROPOSALS_FILE, 'utf8')) || {}; } catch { proposals = {}; } } }
const saveProposals = () => { broadcast('proposals', { at: Date.now() }); return writeJson(PROPOSALS_FILE, proposals); };
function cleanChanges(c) {
  const out = { si: {}, assets: {} };
  if (!isObj(c)) return out;
  for (const kind of ['si', 'assets']) if (isObj(c[kind])) for (const [id, doc] of Object.entries(c[kind])) {
    if (!ID_RE.test(id)) throw httpError(400, `Invalid id: ${id}`);
    if (doc !== null && !isObj(doc)) throw httpError(400, `Invalid document for ${id}`);
    out[kind][id] = doc;
  }
  if (Array.isArray(c.wan)) out.wan = c.wan.filter(isObj);
  if (Array.isArray(c.services)) out.services = c.services.filter(isObj);
  return out;
}
function fillBase(p) {
  p.base = p.base || { si: {}, assets: {} };
  for (const kind of ['si', 'assets']) for (const id of Object.keys(p.changes[kind])) if (!Object.hasOwn(p.base[kind], id)) p.base[kind][id] = clone(own(state[kind], id) ?? null);
  if (p.changes.wan && !('wan' in p.base)) p.base.wan = clone(state.wan);
  if (p.changes.services && !('services' in p.base)) p.base.services = clone(state.services);
  // forget the base of documents no longer in the change set
  for (const kind of ['si', 'assets']) for (const id of Object.keys(p.base[kind])) if (!Object.hasOwn(p.changes[kind], id)) delete p.base[kind][id];
  if (!p.changes.wan) delete p.base.wan;
  if (!p.changes.services) delete p.base.services;
}
const countChanges = c => Object.keys(c.si).length + Object.keys(c.assets).length + (c.wan ? 1 : 0) + (c.services ? 1 : 0);
const summaryOf = p => ({ id: p.id, title: p.title, description: p.description, author: p.author, siteId: p.siteId, status: p.status, createdAt: p.createdAt, updatedAt: p.updatedAt, submittedAt: p.submittedAt || null, reviewedBy: p.reviewedBy || null, reviewedAt: p.reviewedAt || null, mergedRev: p.mergedRev || null, changes: countChanges(p.changes), comments: (p.comments || []).length, source: p.source || 'editor', connector: p.connector || null });
function conflictsOf(p) {
  const out = [];
  for (const kind of ['si', 'assets']) for (const [id, b] of Object.entries(p.base[kind] || {})) if (!same(own(state[kind], id), b)) out.push({ kind, id, name: nameOfDoc(kind, own(state[kind], id) || b) });
  if ('wan' in p.base && !same(state.wan, p.base.wan)) out.push({ kind: 'wan', id: null, name: 'Inter-IS links' });
  if ('services' in p.base && !same(state.services, p.base.services)) out.push({ kind: 'services', id: null, name: 'Internet services catalogue' });
  return out;
}

// Proposals prepared by a connector run: one open proposal per connector and IS, refreshed in place
async function upsertProposal({ connector, connectorName, by, uploadedBy, siteId, title, description, changes }) {
  const ch = cleanChanges(changes);
  if (!countChanges(ch)) return null;
  const now = new Date().toISOString(), author = `${connectorName} (connector)`;
  const open = Object.values(proposals).find(p => p.connector === connector && p.siteId === siteId && ['draft', 'submitted'].includes(p.status));
  const note = (p, text) => { p.comments = p.comments || []; p.comments.push({ user: author, at: now, text, kind: 'comment' }); };
  if (open) {
    if (same(open.changes, ch)) return { id: open.id, title: open.title, unchanged: true };
    open.changes = ch; open.base = { si: {}, assets: {} }; fillBase(open);
    open.title = String(title).slice(0, 140); open.description = String(description || '').slice(0, 4000);
    open.status = 'submitted'; open.updatedAt = open.submittedAt = now; open.baseRev = state.rev; open.uploadedBy = uploadedBy || null;
    note(open, `Refreshed by a new ${connectorName} run${by ? ` (started by ${by})` : ''}.`);
    await saveProposals();
    return { id: open.id, title: open.title, refreshed: true };
  }
  const pid = 'p-' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
  const p = { id: pid, title: String(title).slice(0, 140), description: String(description || '').slice(0, 4000), author, siteId: siteId && own(state.si, siteId) ? siteId : null, status: 'submitted', createdAt: now, updatedAt: now, submittedAt: now, baseRev: state.rev, changes: ch, base: { si: {}, assets: {} }, comments: [], source: 'connector', connector, uploadedBy: uploadedBy || null };
  fillBase(p);
  note(p, `Prepared by the ${connectorName} connector${by ? `, run started by ${by}` : ''}. Review the changes on the map, then approve or reject.`);
  proposals[pid] = p; await saveProposals();
  return { id: pid, title: p.title };
}

/* ---------------- Accounts ----------------
   data/users.json: {"users": {"alice": {"role": "approver", "salt": "...", "hash": "...", ...}}}
   EDIT_PASS / VIEW_PASS (from .env) keep working: they (re)create an admin and a viewer at start-up. */
let users = {}, usersMtime = 0;
const hashPass = (pass, salt) => crypto.scryptSync(String(pass), salt, 32).toString('hex');
function loadUsers() {
  try { const st = fs.statSync(USERS_FILE); usersMtime = st.mtimeMs; const p = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); users = isObj(p.users) ? p.users : {}; }
  catch { users = {}; }
  authCache.clear();
}
function saveUsers() { authCache.clear(); return writeJson(USERS_FILE, JSON.stringify({ users }, null, 2)).then(() => { try { usersMtime = fs.statSync(USERS_FILE).mtimeMs; } catch { } }); }
function setUser(name, { role, password, disabled }) {
  const u = own(users, name) || { createdAt: new Date().toISOString() };
  if (role) u.role = role;
  if (password) { u.salt = crypto.randomBytes(16).toString('hex'); u.hash = hashPass(password, u.salt); u.passwordChangedAt = new Date().toISOString(); }
  if (disabled !== undefined) u.disabled = !!disabled;
  users[name] = u;
}
function bootstrapUsers() {
  loadUsers();
  let changed = false;
  if (CONFIG.editPass) {
    const u = own(users, CONFIG.editUser);
    if (!u || !u.hash || hashPass(CONFIG.editPass, u.salt) !== u.hash || u.role !== 'admin' || u.disabled) { setUser(CONFIG.editUser, { role: 'admin', password: CONFIG.editPass, disabled: false }); changed = true; }
  }
  if (CONFIG.viewPass) {
    const u = own(users, CONFIG.viewUser);
    if (!u || !u.hash || hashPass(CONFIG.viewPass, u.salt) !== u.hash) { setUser(CONFIG.viewUser, { role: u?.role || 'viewer', password: CONFIG.viewPass, disabled: false }); changed = true; }
  }
  if (changed) saveUsers();
}
const authEnabled = () => Object.values(users).some(u => u.hash && !u.disabled);

/* ---------------- Client address (behind a trusted reverse proxy) ---------------- */
const ip4 = t => { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t); return m && m.slice(1).every(x => +x < 256) ? m.slice(1).reduce((n, x) => n * 256 + +x, 0) : null; };
const normAddr = a => String(a || '').trim().toLowerCase().replace(/^::ffff:(?=\d+\.)/, '');
const inCidr = (a, c) => { const [base, bits] = c.split('/'), n = ip4(a), b = ip4(base), k = +bits; if (n === null || b === null || !(k >= 0 && k <= 32)) return false; const size = 2 ** (32 - k); return Math.floor(n / size) === Math.floor(b / size); };
const PROXY_SETS = {
  loopback: a => a === '::1' || inCidr(a, '127.0.0.0/8'),
  private: a => PROXY_SETS.loopback(a) || ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some(c => inCidr(a, c)) || /^f[cd][0-9a-f]{2}:/.test(a),
};
// TRUST_PROXY: the proxies whose X-Forwarded-For is believed, as addresses, IPv4 ranges (10.0.0.0/8),
// "loopback" or "private". Unset: the peer address is the client address.
const trustedProxy = a => CONFIG.trustProxy.some(t => PROXY_SETS[t] ? PROXY_SETS[t](a) : t.includes('/') ? inCidr(a, t) : normAddr(t) === a);
function clientAddress(req) {
  const peer = normAddr(req.socket.remoteAddress);
  if (!CONFIG.trustProxy.length || !trustedProxy(peer)) return peer;
  // The right-most address that is not one of our proxies is the client
  const chain = String(req.headers['x-forwarded-for'] || '').split(',').map(normAddr).filter(Boolean);
  for (let i = chain.length - 1; i >= 0; i--) if (!trustedProxy(chain[i])) return chain[i];
  return chain[0] || peer;
}

/* ---------------- Failed sign-ins ---------------- */
// Repeated failed sign-ins for one account, or from one client address, are refused with 429 for
// LOGIN_LOCK_MINUTES, counted over the same time. Only different wrong passwords count: a tab still
// sending an old password does not lock anyone out. A browser already signed in keeps working
// from the address it signed in from.
const failures = { account: new Map(), address: new Map() };
const FAIL_LIMIT = { account: () => CONFIG.loginMaxFails, address: () => CONFIG.loginMaxFailsPerAddress };
function lockedFor(kind, key) {
  const f = failures[kind].get(key), now = Date.now();
  if (!f) return 0;
  if (f.until > now) return f.until - now;
  if (now - f.first > CONFIG.loginLockMs) failures[kind].delete(key);
  return 0;
}
function recordFailure(kind, key, credential) {
  const max = FAIL_LIMIT[kind](), m = failures[kind], now = Date.now();
  if (!max) return;
  let f = m.get(key);
  if (!f || (now - f.first > CONFIG.loginLockMs && f.until <= now)) f = { first: now, seen: new Set(), until: 0 };
  if (f.seen.size < max) f.seen.add(credential);
  if (f.seen.size >= max && f.until <= now) { f.until = now + CONFIG.loginLockMs; log(`Sign-in locked for ${Math.round(CONFIG.loginLockMs / 60000)} min: ${kind} ${JSON.stringify(key)}`); }
  m.delete(key); m.set(key, f);
  if (m.size > 10000) m.delete(m.keys().next().value);
}

// Successful logins are cached for 10 minutes, so scrypt runs once per session, not per request
const authCache = new Map();
// Returns the account and role, null when the credentials are missing or wrong, or {retryAfter} (ms)
// while sign-ins are locked
function authenticate(req) {
  if (!authEnabled()) return { user: '', role: CONFIG.readOnly ? 'viewer' : 'admin', open: true };
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return null;
  const raw = Buffer.from(h.slice(6), 'base64').toString('utf8'), i = raw.indexOf(':');
  const name = i < 1 ? '' : raw.slice(0, i), pass = raw.slice(i + 1);
  const key = crypto.createHash('sha256').update(raw).digest('hex'), hit = authCache.get(key), addr = clientAddress(req);
  const ok = hit && hit.until > Date.now() && hit.addrs.has(addr);
  if (!ok) {
    const wait = Math.max(lockedFor('address', addr), name ? lockedFor('account', name) : 0);
    if (wait) return { retryAfter: wait };
    const u = name ? own(users, name) : undefined;
    let good = !!(u && !u.disabled && u.hash);
    if (good) { const a = Buffer.from(hashPass(pass, u.salt), 'hex'), b = Buffer.from(u.hash, 'hex'); good = a.length === b.length && crypto.timingSafeEqual(a, b); }
    if (!good) { recordFailure('address', addr, key); if (name) recordFailure('account', name, key); return null; }
    failures.account.delete(name);
    const addrs = hit && hit.until > Date.now() ? hit.addrs : new Set();
    addrs.add(addr);
    authCache.set(key, { until: Date.now() + 600000, addrs });
  }
  const u = own(users, name);
  if (!u || u.disabled) return null;
  const role = CONFIG.readOnly ? 'viewer' : (RANK[u.role] !== undefined ? u.role : 'viewer');
  return { user: name, role };
}
const can = (auth, role) => RANK[auth.role] >= RANK[role];
const need = (auth, role) => { if (!can(auth, role)) throw httpError(403, `This needs the ${role} role (you are ${auth.role}).`); };

/* ---------------- Live updates (SSE) ---------------- */
const clients = new Set();
function broadcast(event, data) { const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`; for (const res of clients) res.write(msg); }
setInterval(() => { for (const res of clients) res.write(': ping\n\n'); }, 25000).unref();

/* ---------------- HTTP helpers ---------------- */
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  // no other site's window or page may hold a reference to the app, or load its responses
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
};
function send(res, status, body, headers = {}) {
  const isJson = typeof body !== 'string' && !Buffer.isBuffer(body);
  res.writeHead(status, { ...SEC_HEADERS, 'Content-Type': isJson ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(isJson ? JSON.stringify(body) : body);
}
const fail = (res, status, error, extra) => send(res, status, { error, ...(extra || {}) });
// A body over its limit is no longer kept, but read to its end, so that the 413 answer reaches the client
// (closing the connection at once left it with a network error). Past the limit by more than
// DISCARD_MAX, the connection is cut: nobody waits for a body that large.
const DISCARD_MAX = 64 * 1024 * 1024;
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0, over = false; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (over) { if (size > limit + DISCARD_MAX) req.destroy(); return; }
      if (size > limit) { over = true; chunks.length = 0; return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (over) return reject(httpError(413, 'Payload too large'));
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null); } catch { reject(httpError(400, 'Invalid JSON')); }
    });
    req.on('close', () => { if (over) reject(httpError(413, 'Payload too large')); });
    req.on('error', reject);
  });
}
const batchMeta = req => {
  let label = ''; try { label = decodeURIComponent(req.headers['x-batch-label'] || '').slice(0, 200); } catch { }
  const b = String(req.headers['x-batch'] || '').slice(0, 80);
  return { batch: /^[A-Za-z0-9_.:-]+$/.test(b) ? b : '', label };
};

/* ---------------- Static files ---------------- */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8', '.woff2': 'font/woff2', '.woff': 'font/woff',
  '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
};
async function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath);
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.normalize(path.join(CONFIG.publicDir, rel));
  if (!file.startsWith(CONFIG.publicDir + path.sep)) return fail(res, 403, 'Forbidden');
  let stat;
  try { stat = await fsp.stat(file); } catch { return fail(res, 404, 'Not found'); }
  if (!stat.isFile()) return fail(res, 404, 'Not found');
  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Length': stat.size, 'Cache-Control': rel.startsWith('/vendor/') ? 'public, max-age=604800' : 'no-cache' });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file).pipe(res);
}

/* ---------------- API ---------------- */
async function api(req, res, parts, url, auth) {
  const method = req.method, write = method !== 'GET' && method !== 'HEAD';
  if (write && (!(req.headers['content-type'] || '').startsWith('application/json') || !['strata', 'is-map'].includes(req.headers['x-requested-with'])))
    return fail(res, 400, 'Missing JSON content type or X-Requested-With header'); // blocks cross-site form posts
  const [r1, id, r3] = parts;
  const ok = rev => send(res, 200, { ok: true, rev: rev ?? state.rev });

  if (r1 === 'me' && !id && method === 'GET') return send(res, 200, {
    user: auth.user, role: auth.role, auth: !auth.open, readOnly: CONFIG.readOnly, allowSelfApproval: CONFIG.allowSelfApproval,
    canWrite: can(auth, 'approver'), canPropose: can(auth, 'contributor'), canReview: can(auth, 'approver'), canAdmin: can(auth, 'admin'), connectors: !!connectors, sourceUrl: CONFIG.sourceUrl,
  });
  if (r1 === 'me' && id === 'password' && method === 'PUT') {
    if (auth.open) throw httpError(400, 'Accounts are not enabled on this server.');
    const b = await readBody(req, 4096), u = own(users, auth.user);
    const given = u ? Buffer.from(hashPass(b?.current || '', u.salt), 'hex') : null, stored = u ? Buffer.from(u.hash, 'hex') : null;
    if (!u || given.length !== stored.length || !crypto.timingSafeEqual(given, stored)) throw httpError(403, 'Current password is wrong.');
    if (String(b?.next || '').length < 10) throw httpError(400, 'Use at least 10 characters.');
    setUser(auth.user, { password: b.next }); await saveUsers(); return send(res, 200, { ok: true });
  }
  if (r1 === 'state' && method === 'GET') {
    const at = url.searchParams.get('at');
    return send(res, 200, at !== null ? stateAt(parseInt(at, 10)) : state);
  }
  if (r1 === 'export' && method === 'GET') {
    const stamp = new Date().toISOString().slice(0, 10);
    return send(res, 200, { format: 'strata', version: 3, exportedAt: new Date().toISOString(), si: state.si, assets: state.assets, wan: state.wan, services: state.services },
      { 'Content-Disposition': `attachment; filename="strata-${stamp}.json"` });
  }
  if (r1 === 'events' && method === 'GET') {
    res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write(`retry: 3000\nevent: change\ndata: ${JSON.stringify({ rev: state.rev })}\n\n`);
    clients.add(res); req.on('close', () => clients.delete(res));
    return;
  }

  /* ---- live map: approvers and admins ---- */
  if ((r1 === 'si' || r1 === 'assets') && id !== undefined) {
    if (!ID_RE.test(id)) throw httpError(400, 'Invalid id');
    if (method === 'GET') return own(state[r1], id) ? send(res, 200, own(state[r1], id)) : fail(res, 404, 'Not found');
    need(auth, 'approver');
    if (method === 'PUT') {
      const body = await readBody(req, CONFIG.maxDocBytes);
      if (!isObj(body)) throw httpError(400, 'Body must be a JSON object');
      return ok(await commitChanges([change(r1, id, body)], auth, batchMeta(req)));
    }
    if (method === 'DELETE') return ok(await commitChanges([change(r1, id, null)], auth, batchMeta(req)));
  }
  if (r1 === 'wan' && method === 'PUT') {
    need(auth, 'approver');
    const body = await readBody(req, CONFIG.maxDocBytes);
    if (!isObj(body) || !Array.isArray(body.links)) throw httpError(400, 'Body must be {"links": [...]}');
    return ok(await commitChanges([change('wan', null, body.links.filter(isObj))], auth, batchMeta(req)));
  }
  if (r1 === 'services' && method === 'PUT') {
    need(auth, 'approver');
    const body = await readBody(req, CONFIG.maxDocBytes);
    if (!isObj(body) || !Array.isArray(body.services)) throw httpError(400, 'Body must be {"services": [...]}');
    return ok(await commitChanges([change('services', null, body.services.filter(isObj))], auth, batchMeta(req)));
  }
  if (r1 === 'import' && method === 'POST') {
    need(auth, 'approver');
    const body = await readBody(req, CONFIG.maxImportBytes);
    if (!isObj(body) || !isObj(body.si) || !isObj(body.assets)) throw httpError(400, 'Expected {"si": {...}, "assets": {...}, "wan": [...]}');
    const bad = [...Object.keys(body.si), ...Object.keys(body.assets)].find(k => !ID_RE.test(k));
    if (bad) throw httpError(400, `Invalid id: ${bad}`);
    await backup('before import');
    const next = { si: body.si, assets: body.assets, wan: Array.isArray(body.wan) ? body.wan.filter(isObj) : [], services: Array.isArray(body.services) ? body.services.filter(isObj) : [] };
    return ok(await commitChanges([change('all', null, next)], auth, Object.assign(batchMeta(req), { label: batchMeta(req).label || 'Whole map replaced (import)' })));
  }

  /* ---- history and rollback ---- */
  if (r1 === 'history' && method === 'GET' && !id) {
    const before = parseInt(url.searchParams.get('before') || '0', 10) || Infinity, limit = Math.min(500, parseInt(url.searchParams.get('limit') || '120', 10) || 120);
    const out = [];
    for (let i = history.length - 1; i >= 0 && out.length < limit; i--) {
      const h = history[i]; if (h.rev >= before) continue;
      const doc = h.after || h.before;
      out.push({ rev: h.rev, at: h.at, user: h.user, batch: h.batch, label: h.label, kind: h.kind, id: h.id, op: h.before == null ? 'created' : h.after == null ? 'deleted' : 'updated', name: nameOfDoc(h.kind, doc), site: h.kind === 'assets' ? (doc && doc.site) || null : h.kind === 'si' ? h.id : null });
    }
    return send(res, 200, { rev: state.rev, oldest: history.length ? history[0].rev - 1 : state.rev, entries: out });
  }
  if (r1 === 'history' && method === 'GET' && id) {
    const rev = parseInt(id, 10);
    return send(res, 200, { rev, entries: history.filter(h => h.rev === rev) });
  }
  if (r1 === 'rollback' && method === 'POST') {
    need(auth, 'approver');
    const b = await readBody(req, 4096), rev = parseInt(b?.rev, 10);
    if (!Number.isInteger(rev) || rev < 0 || rev >= state.rev) throw httpError(400, 'Pick a version older than the current one.');
    const target = stateAt(rev);
    await backup(`before rollback to ${rev}`);
    const newRev = await commitChanges(diffTo(target), auth, { batch: `rollback-${Date.now()}`, label: `Restored version ${rev}` });
    return ok(newRev);
  }

  /* ---- proposals ---- */
  if (r1 === 'proposals') {
    if (!id && method === 'GET') return send(res, 200, { proposals: Object.values(proposals).map(summaryOf).sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt))) });
    if (!id && method === 'POST') {
      need(auth, 'contributor');
      const b = await readBody(req, CONFIG.maxImportBytes);
      const title = String(b?.title || '').trim().slice(0, 140);
      if (!title) throw httpError(400, 'Give the proposal a title.');
      const now = new Date().toISOString(), pid = 'p-' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
      const p = { id: pid, title, description: String(b?.description || '').slice(0, 4000), author: auth.user || 'anonymous', siteId: b?.siteId && ID_RE.test(b.siteId) ? b.siteId : null, status: 'draft', createdAt: now, updatedAt: now, baseRev: state.rev, changes: cleanChanges(b?.changes), base: { si: {}, assets: {} }, comments: [], source: b?.source === 'file' ? 'file' : 'editor' };
      fillBase(p); proposals[pid] = p; await saveProposals();
      return send(res, 200, { ok: true, proposal: p });
    }
    const p = own(proposals, id);
    if (!p) throw httpError(404, 'Unknown proposal');
    const mine = p.author === (auth.user || 'anonymous') || auth.open;
    if (!r3 && method === 'GET') return send(res, 200, { proposal: p, conflicts: p.status === 'submitted' || p.status === 'draft' ? conflictsOf(p) : [] });
    if (!r3 && method === 'PUT') {
      need(auth, 'contributor');
      if (!mine && !can(auth, 'admin')) throw httpError(403, 'Only the author can edit this proposal.');
      if (!['draft', 'rejected'].includes(p.status)) throw httpError(409, 'Withdraw the proposal before editing it.');
      const b = await readBody(req, CONFIG.maxImportBytes);
      if (b?.title !== undefined) p.title = String(b.title).trim().slice(0, 140) || p.title;
      if (b?.description !== undefined) p.description = String(b.description).slice(0, 4000);
      if (b?.changes !== undefined) { p.changes = cleanChanges(b.changes); fillBase(p); }
      if (p.status === 'rejected') p.status = 'draft';
      p.updatedAt = new Date().toISOString(); await saveProposals();
      return send(res, 200, { ok: true, proposal: p });
    }
    if (!r3 && method === 'DELETE') {
      if (!(mine && ['draft', 'rejected', 'withdrawn'].includes(p.status)) && !can(auth, 'admin')) throw httpError(403, 'Only the author can delete a draft (or an admin).');
      delete proposals[id]; await saveProposals(); return send(res, 200, { ok: true });
    }
    const b = method === 'POST' ? await readBody(req, 64 * 1024) : null;
    const note = (who, text, kind) => { p.comments = p.comments || []; p.comments.push({ user: who, at: new Date().toISOString(), text: String(text || '').slice(0, 4000), kind }); };
    if (r3 === 'comment' && method === 'POST') {
      need(auth, 'contributor');
      if (!String(b?.text || '').trim()) throw httpError(400, 'Write a comment.');
      note(auth.user, b.text, 'comment'); p.updatedAt = new Date().toISOString(); await saveProposals();
      return send(res, 200, { ok: true, proposal: p });
    }
    if (r3 === 'submit' && method === 'POST') {
      need(auth, 'contributor');
      if (!mine) throw httpError(403, 'Only the author can submit this proposal.');
      if (!countChanges(p.changes)) throw httpError(400, 'This proposal changes nothing yet.');
      p.status = 'submitted'; p.submittedAt = p.updatedAt = new Date().toISOString();
      if (b?.text) note(auth.user, b.text, 'submit');
      await saveProposals(); return send(res, 200, { ok: true, proposal: p });
    }
    if (r3 === 'withdraw' && method === 'POST') {
      if (!mine && !can(auth, 'admin')) throw httpError(403, 'Only the author can withdraw this proposal.');
      if (p.status !== 'submitted') throw httpError(409, 'Only a submitted proposal can be withdrawn.');
      p.status = 'draft'; p.updatedAt = new Date().toISOString(); await saveProposals();
      return send(res, 200, { ok: true, proposal: p });
    }
    if (r3 === 'reject' && method === 'POST') {
      need(auth, 'approver');
      if (p.status !== 'submitted') throw httpError(409, 'Only a submitted proposal can be rejected.');
      p.status = 'rejected'; p.reviewedBy = auth.user; p.reviewedAt = p.updatedAt = new Date().toISOString();
      note(auth.user, b?.text || 'Rejected', 'reject');
      await saveProposals(); return send(res, 200, { ok: true, proposal: p });
    }
    if (r3 === 'approve' && method === 'POST') {
      need(auth, 'approver');
      if (p.status !== 'submitted') throw httpError(409, 'Only a submitted proposal can be approved.');
      // a configuration file someone imported counts as their own proposal (four-eyes rule)
      if ((mine || (p.uploadedBy && p.uploadedBy === auth.user)) && !CONFIG.allowSelfApproval && !auth.open) throw httpError(403, 'Someone else has to approve your own proposal.');
      const conflicts = conflictsOf(p);
      if (conflicts.length && !b?.force) throw httpError(409, 'Some items changed on the map since this proposal was prepared.', { conflicts });
      const ch = [];
      for (const kind of ['si', 'assets']) for (const [did, doc] of Object.entries(p.changes[kind])) ch.push(change(kind, did, doc));
      if (p.changes.wan) ch.push(change('wan', null, p.changes.wan));
      if (p.changes.services) ch.push(change('services', null, p.changes.services));
      const rev = await commitChanges(ch, auth, { batch: `proposal-${p.id}`, label: `Proposal “${p.title}” by ${p.author}, approved by ${auth.user || 'admin'}` });
      p.status = 'approved'; p.reviewedBy = auth.user; p.reviewedAt = p.updatedAt = new Date().toISOString(); p.mergedRev = rev;
      note(auth.user, b?.text || 'Approved', 'approve');
      await saveProposals(); return send(res, 200, { ok: true, rev, proposal: p });
    }
  }

  /* ---- connector modules: the store (admin) ---- */
  if (r1 === 'modules') {
    if (!connectors) throw httpError(404, 'Connectors are off on this server.');
    need(auth, 'admin');
    if (!id && method === 'GET') {
      const out = { store: modStore.enabled, uploads: modStore.uploads, registry: CONFIG.moduleRegistry, modules: [], error: null };
      if (modStore.enabled) { try { out.modules = await modStore.list(url.searchParams.get('fresh') === '1'); } catch (e) { out.error = e.message; } }
      return send(res, 200, out);
    }
    try {
      if (id === 'upload' && !r3 && method === 'POST') {
        const b = await readBody(req, 28 * 1024 * 1024);
        if (typeof b?.data !== 'string') throw httpError(400, 'Send {"data": "<the .tgz in base64>"}.');
        const m = await modStore.upload(Buffer.from(b.data, 'base64'));
        log(`Module ${m.id} ${m.version} uploaded by ${auth.user || 'admin'}`);
        broadcast('connectors', { id: m.id }); return send(res, 200, { ok: true, module: m });
      }
      if (!MODULE_ID_RE.test(id || '')) throw httpError(404, 'Unknown module');
      if (r3 === 'install' && method === 'POST') { const m = await modStore.install(id); log(`Module ${m.id} ${m.version} installed by ${auth.user || 'admin'}`); broadcast('connectors', { id }); return send(res, 200, { ok: true, module: m }); }
      if (!r3 && method === 'DELETE') { await modStore.remove(id); log(`Module ${id} removed by ${auth.user || 'admin'}`); broadcast('connectors', { id }); return send(res, 200, { ok: true }); }
    } catch (e) {
      if (e.constructor.name === 'ConnectorError') throw httpError(400, e.message);
      throw e;
    }
  }

  /* ---- connectors: the built-in modules (Cyberwatch, GLPI, phpIPAM, Palo Alto) and installed ones ---- */
  if (r1 === 'connectors') {
    if (!connectors) throw httpError(404, 'Connectors are off on this server.');
    if (!id && method === 'GET') {
      need(auth, 'contributor');
      const l = connectors.list();
      // without the approver role: only the file imports open to contributors, and only the settings they choose
      if (!can(auth, 'approver')) l.connectors = l.connectors.filter(c => c.file && c.file.role === 'contributor').map(c => ({ ...c, lastRun: null, fields: c.fields.filter(f => c.file.fields.includes(f.k)), settings: Object.fromEntries(c.file.fields.map(k => [k, c.settings[k]])) }));
      if (!can(auth, 'admin')) delete l.problems;
      return send(res, 200, { ...l, canConfigure: can(auth, 'admin'), canRun: can(auth, 'approver'), store: can(auth, 'admin') && (modStore.enabled || modStore.uploads) });
    }
    if (!connectors.exists(id)) throw httpError(404, 'Unknown connector');
    if (!r3 && method === 'PUT') { need(auth, 'admin'); await connectors.update(id, await readBody(req, 128 * 1024)); return send(res, 200, { ok: true, connector: connectors.get(id) }); }
    if (r3 === 'test' && method === 'POST') {
      need(auth, 'approver');
      try { return send(res, 200, { ok: true, message: await connectors.test(id) }); }
      catch (e) { return send(res, 200, { ok: false, message: e.constructor.name === 'ConnectorError' ? e.message : `Unexpected error: ${e.message}` }); }
    }
    if (r3 === 'run' && method === 'POST') {
      const b = await readBody(req, CONFIG.maxImportBytes) || {};
      // {file: {name, text}}; the Palo Alto import also took {xml, fileName}, kept for scripts written for it
      const f = isObj(b.file) && typeof b.file.text === 'string' && b.file.text.length ? { name: b.file.name, text: b.file.text }
        : typeof b.xml === 'string' && b.xml.length ? { name: b.fileName || 'configuration.xml', text: b.xml } : null;
      const m = connectors.module(id);
      if (f && !m.file) throw httpError(400, `${m.name} does not import files.`);
      // a file import may only need the right to propose (the module says so); syncs with a tool need an approver
      need(auth, f && m.file.role === 'contributor' ? 'contributor' : 'approver');
      if (connectors.isRunning(id)) throw httpError(409, 'This connector is already running.');
      if (!f && !connectors.get(id).live) throw httpError(400, m.live === false ? `${m.name} only imports files.` : 'Fill in its settings first.');
      const p = connectors.run(id, { by: auth.user || 'admin', file: f || undefined, overrides: isObj(b.overrides) ? b.overrides : {} });
      if (b.wait) return send(res, 200, { ok: true, run: await p });
      p.catch(() => { });
      return send(res, 202, { ok: true, started: true });
    }
  }

  /* ---- accounts (admin) ---- */
  if (r1 === 'users') {
    need(auth, 'admin');
    if (!id && method === 'GET') return send(res, 200, { users: Object.entries(users).map(([name, u]) => ({ name, role: u.role, disabled: !!u.disabled, createdAt: u.createdAt, passwordChangedAt: u.passwordChangedAt || null })).sort((a, b) => a.name.localeCompare(b.name)) });
    if (id && !USER_RE.test(id)) throw httpError(400, 'Use letters, digits, dot, dash, underscore or @ (64 at most).');
    if (id && method === 'PUT') {
      const b = await readBody(req, 4096);
      if (b?.role !== undefined && !ROLES.includes(b.role)) throw httpError(400, `Role must be one of ${ROLES.join(', ')}.`);
      if (!own(users, id) && !b?.password) throw httpError(400, 'A new account needs a password.');
      if (b?.password && String(b.password).length < 10) throw httpError(400, 'Use at least 10 characters.');
      if (id === auth.user && (b?.disabled || (b?.role && b.role !== 'admin'))) throw httpError(400, 'You cannot remove your own admin access.');
      setUser(id, { role: b?.role || own(users, id)?.role || 'viewer', password: b?.password, disabled: b?.disabled });
      await saveUsers(); return send(res, 200, { ok: true });
    }
    if (id && method === 'DELETE') {
      if (id === auth.user) throw httpError(400, 'You cannot delete your own account.');
      delete users[id]; await saveUsers(); return send(res, 200, { ok: true });
    }
  }
  return fail(res, 404, 'Unknown API route');
}

/* ---------------- Server ---------------- */
const server = http.createServer(async (req, res) => {
  const started = Date.now();
  if (req.url !== '/healthz' && !req.url.startsWith('/api/events')) res.on('finish', () => log(req.method, req.url, res.statusCode, `${Date.now() - started}ms`));
  try {
    const url = new URL(req.url, 'http://localhost');
    try { decodeURIComponent(url.pathname); } catch { return fail(res, 400, 'Malformed URL'); }
    if (url.pathname === '/healthz') return send(res, 200, 'ok');
    const auth = authenticate(req);
    if (auth && auth.retryAfter) {
      const s = Math.ceil(auth.retryAfter / 1000);
      res.writeHead(429, { ...SEC_HEADERS, 'Retry-After': String(s), 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(`Too many failed sign-ins. Try again in ${s >= 120 ? Math.ceil(s / 60) + ' minutes' : s + ' seconds'}.`);
    }
    if (!auth) {
      res.writeHead(401, { ...SEC_HEADERS, 'WWW-Authenticate': 'Basic realm="Strata", charset="UTF-8"', 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Authentication required');
    }
    if (url.pathname.startsWith('/api/')) await api(req, res, url.pathname.slice(5).split('/').filter(Boolean).map(decodeURIComponent), url, auth);
    else if (req.method === 'GET' || req.method === 'HEAD') await serveStatic(req, res, url.pathname);
    else fail(res, 405, 'Method not allowed');
  } catch (err) {
    if (!res.headersSent) fail(res, err.status || 500, err.status ? err.message : 'Internal error', err.extra);
    if (!err.status) log('ERROR', req.method, req.url, err.stack || err.message);
  }
});

loadState();
loadHistory();
const STRATA_VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const MODULES_INSTALLED = path.join(CONFIG.dataDir, 'modules');
const connectors = /^(0|false|no|off)$/i.test(env.CONNECTORS || '') ? null : createConnectors({
  dataDir: CONFIG.dataDir, providedDir: CONFIG.modulesDir, installedDir: MODULES_INSTALLED, strataVersion: STRATA_VERSION, timeoutMs: CONFIG.connectorTimeoutMs,
  getState: () => state, upsertProposal, log, writeJson, broadcast,
});
const modStore = connectors ? createStore({ registryUrl: CONFIG.moduleRegistry, uploads: CONFIG.moduleUpload, installedDir: MODULES_INSTALLED, strataVersion: STRATA_VERSION, connectors, log }) : null;
loadProposals();
bootstrapUsers();
await backup('startup');
setInterval(() => backup('scheduled').catch(e => log('Backup failed:', e.message)), CONFIG.backupEveryHours * 3600 * 1000).unref();
// Accounts edited with scripts/users.mjs while the server runs are picked up within a few seconds
setInterval(() => { try { const m = fs.statSync(USERS_FILE).mtimeMs; if (m !== usersMtime) { loadUsers(); log('Accounts reloaded'); } } catch { } }, 5000).unref();

server.listen(CONFIG.port, CONFIG.host, () => {
  log(`Strata listening on http://${CONFIG.host}:${CONFIG.port}`);
  log(`Data folder: ${CONFIG.dataDir}`);
  if (!authEnabled()) log('WARNING: no account configured (EDIT_PASS empty, no data/users.json): anyone who can reach this port can read and edit the map.');
  else log(`Accounts: ${Object.entries(users).filter(([, u]) => !u.disabled).map(([n, u]) => `${n} (${u.role})`).join(', ')}`);
  if (CONFIG.readOnly) log('READ_ONLY is on: nobody can edit.');
});

const shutdown = sig => { log(`${sig} received, closing`); for (const r of clients) r.end(); server.close(() => writeChain.finally(() => process.exit(0))); setTimeout(() => process.exit(0), 5000).unref(); };
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
