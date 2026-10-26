// SPDX-License-Identifier: AGPL-3.0-or-later
// Shared helpers for the connectors: an HTTP client (self-signed certificates, custom CA, timeouts),
// IPv4 arithmetic, a small XML parser (for PAN-OS) and the rules that match outside records to assets.
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';

export class ConnectorError extends Error {
  constructor(message, extra) { super(message); this.extra = extra; }
}

/* ---------------- HTTP ---------------- */
// opts: {method, headers, body (string|Buffer|object → JSON), timeoutMs, tls: {insecure, ca}, maxBytes}
export function request(url, opts = {}) {
  const u = new URL(url);
  const lib = u.protocol === 'https:' ? https : u.protocol === 'http:' ? http : null;
  if (!lib) return Promise.reject(new ConnectorError(`Unsupported URL scheme: ${u.protocol}`));
  let body = opts.body;
  const headers = { Accept: 'application/json', 'User-Agent': 'strata-connector', ...(opts.headers || {}) };
  if (body !== undefined && body !== null && typeof body === 'object' && !Buffer.isBuffer(body)) {
    body = JSON.stringify(body);
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) headers['Content-Type'] = 'application/json';
  }
  if (body !== undefined && body !== null) headers['Content-Length'] = Buffer.byteLength(body);
  const tls = opts.tls || {};
  const maxBytes = opts.maxBytes || 200 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const req = lib.request(u, {
      method: opts.method || 'GET', headers,
      rejectUnauthorized: !tls.insecure, ca: tls.ca ? [tls.ca] : undefined,
      timeout: opts.timeoutMs || 30000,
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', c => { size += c.length; if (size > maxBytes) { req.destroy(new ConnectorError('Response too large')); return; } chunks.push(c); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, text, json() { try { return JSON.parse(text); } catch { throw new ConnectorError(`${u.host} did not answer JSON (HTTP ${res.statusCode}): ${text.slice(0, 160)}`); } } });
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new ConnectorError(`${u.host} did not answer within ${Math.round((opts.timeoutMs || 30000) / 1000)} s`)));
    req.on('error', e => reject(e instanceof ConnectorError ? e : new ConnectorError(netMessage(e, u))));
    if (body !== undefined && body !== null) req.write(body);
    req.end();
  });
}
function netMessage(e, u) {
  const c = e.code || '';
  if (c === 'ECONNREFUSED') return `${u.host} refused the connection (wrong port, or the service is down)`;
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return `${u.hostname} is not known to the DNS of this server`;
  if (c === 'ETIMEDOUT' || c === 'EHOSTUNREACH' || c === 'ENETUNREACH') return `${u.host} cannot be reached from this server (network or firewall)`;
  if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/.test(c)) return `The TLS certificate of ${u.host} is not trusted (${c}). Paste its CA certificate in the connector settings, or tick “Accept any certificate” on a trusted network.`;
  return `${u.host}: ${e.message}`;
}
export async function expectOk(res, what) {
  if (res.status === 401 || res.status === 403) throw new ConnectorError(`${what}: access refused (HTTP ${res.status}). Check the credentials and their rights.`);
  if (res.status >= 400) throw new ConnectorError(`${what}: HTTP ${res.status} ${res.text.slice(0, 200)}`);
  return res;
}
// Runs fn over items with at most n calls in flight
export async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

/* ---------------- IPv4 ---------------- */
const IP_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
export const isIp = s => { const m = IP_RE.exec(String(s || '').trim()); return !!m && m.slice(1).every(x => +x <= 255); };
export const ipToInt = s => String(s).trim().split('.').reduce((n, x) => n * 256 + (+x), 0);
export const intToIp = n => [24, 16, 8, 0].map(b => Math.floor(n / 2 ** b) % 256).join('.');
// "10.0.0.0/24", "10.0.0.5", "10.0.0.1-10.0.0.9" → {lo, hi} or null
export function parseRange(spec) {
  const s = String(spec || '').trim();
  if (isIp(s)) { const v = ipToInt(s); return { lo: v, hi: v }; }
  let m = /^([\d.]+)\/(\d{1,2})$/.exec(s);
  if (m && isIp(m[1]) && +m[2] <= 32) { const size = 2 ** (32 - +m[2]); const lo = Math.floor(ipToInt(m[1]) / size) * size; return { lo, hi: lo + size - 1 }; }
  m = /^([\d.]+)\s*-\s*([\d.]+)$/.exec(s);
  if (m && isIp(m[1]) && isIp(m[2])) return { lo: ipToInt(m[1]), hi: ipToInt(m[2]) };
  return null;
}
export const inRange = (ip, r) => { if (!isIp(ip) || !r) return false; const v = ipToInt(ip); return v >= r.lo && v <= r.hi; };
const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16'].map(parseRange);
export const isPrivateRange = r => !!r && PRIVATE.some(p => r.lo >= p.lo && r.hi <= p.hi);
export const firstIp = s => { const m = String(s || '').match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/); return m && isIp(m[1]) ? m[1] : ''; };

/* ---------------- Names ---------------- */
export const shortName = s => String(s || '').trim().toLowerCase().split('.')[0];
export const norm = s => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();
export const slug = s => norm(s).replace(/ /g, '-').slice(0, 60) || 'x';
export const hash = s => crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, 10);

// Index of the assets of the map, to find the one an outside record describes.
// Order: the id the connector stored last time (asset.ext[connector]), then the host name, then the IP.
export function assetIndex(state, siteIds) {
  // keys are host names and IPs from the map: no prototype, so an asset named "constructor" is just a name
  const byExt = Object.create(null), byName = Object.create(null), byIp = Object.create(null);
  for (const [id, a] of Object.entries(state.assets)) {
    if (siteIds && !siteIds.includes(a.site)) continue;
    for (const [k, v] of Object.entries(a.ext || {})) byExt[`${k}:${v}`] = id;
    const n = shortName(a.name); if (n) (byName[n] = byName[n] || []).push(id);
    if (isIp(a.ip)) (byIp[a.ip.trim()] = byIp[a.ip.trim()] || []).push(id);
  }
  return {
    find({ connector, ext, name, ips = [], site }) {
      if (ext != null && byExt[`${connector}:${ext}`]) return byExt[`${connector}:${ext}`];
      const pick = list => (list || []).find(id => !site || state.assets[id].site === site) || null;
      const n = shortName(name);
      if (n && byName[n]) { const hit = pick(byName[n]); if (hit) return hit; }
      for (const ip of ips) if (byIp[ip]) { const hit = pick(byIp[ip]); if (hit) return hit; }
      return null;
    },
  };
}
// The VLAN of an IS whose range holds this IP
export function vlanForIp(si, ip) {
  if (!isIp(ip)) return null;
  let best = null, bestSize = Infinity;
  for (const v of si.vlans || []) { const r = parseRange(v.cidr); if (r && inRange(ip, r) && r.hi - r.lo < bestSize) { best = v; bestSize = r.hi - r.lo; } }
  return best;
}
// Finds which IS an outside label (GLPI location, phpIPAM section…) belongs to.
// rules: [{match, si}] tried first (case-insensitive substring or /regex/); then the IS whose name or id appears in the label.
export function siteFor(label, rules, state) {
  const L = String(label || '');
  for (const r of rules || []) {
    if (!r || !r.match || !r.si || !state.si[r.si]) continue;
    const m = /^\/(.+)\/([i]*)$/.exec(r.match);
    if (m ? new RegExp(m[1], m[2] || 'i').test(L) : norm(L).includes(norm(r.match))) return r.si;
  }
  const n = norm(L);
  if (!n) return null;
  const sites = Object.entries(state.si).sort((a, b) => String(b[1].name || '').length - String(a[1].name || '').length);
  for (const [id, s] of sites) { const sn = norm(s.name); if (sn && (` ${n} `).includes(` ${sn} `)) return id; }
  for (const [id] of sites) if ((` ${n} `).includes(` ${norm(id)} `)) return id;
  return null;
}
// A VLAN (and its zone) where assets that match no range can wait to be sorted by hand
export function holdingVlan(si, siteId, label) {
  si.zones = si.zones && si.zones.length ? si.zones : [{ id: 'z-def', name: 'Main zone' }];
  si.vlans = si.vlans || [];
  let v = si.vlans.find(x => x.id === `v-${siteId}-unsorted`);
  if (!v) {
    let z = si.zones.find(x => x.id === `z-${siteId}-imported`);
    if (!z) { z = { id: `z-${siteId}-imported`, name: 'Imported' }; si.zones.push(z); }
    v = { id: `v-${siteId}-unsorted`, num: 0, name: label || 'To sort (imported)', cidr: '', zone: z.id };
    si.vlans.push(v);
  }
  return v;
}

/* ---------------- XML (enough for PAN-OS configurations) ---------------- */
// Returns {name, attrs, children, text}. No DTD, no namespaces handling (prefixes are kept in names).
export function parseXml(src) {
  const s = String(src);
  let i = 0;
  const root = { name: '#root', attrs: {}, children: [], text: '' };
  const stack = [root];
  const ent = t => t.replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos);/gi, (m, e) => e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" })[e.toLowerCase()]);
  while (i < s.length) {
    const lt = s.indexOf('<', i);
    if (lt < 0) { stack[stack.length - 1].text += ent(s.slice(i)); break; }
    if (lt > i) stack[stack.length - 1].text += ent(s.slice(i, lt));
    if (s.startsWith('<!--', lt)) { const e = s.indexOf('-->', lt); i = e < 0 ? s.length : e + 3; continue; }
    if (s.startsWith('<![CDATA[', lt)) { const e = s.indexOf(']]>', lt); stack[stack.length - 1].text += s.slice(lt + 9, e < 0 ? s.length : e); i = e < 0 ? s.length : e + 3; continue; }
    if (s[lt + 1] === '?' || s[lt + 1] === '!') { const e = s.indexOf('>', lt); i = e < 0 ? s.length : e + 1; continue; }
    const gt = findTagEnd(s, lt);
    if (gt < 0) throw new ConnectorError('The XML file is cut short (an element is not closed).');
    const body = s.slice(lt + 1, gt);
    i = gt + 1;
    if (body[0] === '/') {
      const name = body.slice(1).trim();
      while (stack.length > 1) { const top = stack.pop(); if (top.name === name) break; }
      continue;
    }
    const selfClose = body.endsWith('/');
    const inner = selfClose ? body.slice(0, -1) : body;
    const m = /^([^\s/>]+)/.exec(inner);
    if (!m) continue;
    const el = { name: m[1], attrs: {}, children: [], text: '' };
    readAttrs(inner, m[1].length, el.attrs, ent);
    stack[stack.length - 1].children.push(el);
    if (!selfClose) stack.push(el);
  }
  return root;
}
// The attributes of a start tag (name="value" or name='value'), in one pass. A regular expression did this
// before, and took quadratic time on a long tag without "=": a large crafted file stalled the server.
function readAttrs(src, from, out, ent) {
  const n = src.length, space = c => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  let k = from;
  while (k < n) {
    while (k < n && space(src[k])) k++;
    const start = k;
    while (k < n && !space(src[k]) && src[k] !== '=') k++;
    const name = src.slice(start, k);
    while (k < n && space(src[k])) k++;
    if (src[k] !== '=') continue;
    k++;
    while (k < n && space(src[k])) k++;
    const q = src[k];
    if (q !== '"' && q !== "'") continue;
    const end = src.indexOf(q, k + 1);
    if (end < 0) break;
    if (name) out[name] = ent(src.slice(k + 1, end));
    k = end + 1;
  }
}
function findTagEnd(s, from) {
  let q = null;
  for (let k = from + 1; k < s.length; k++) {
    const c = s[k];
    if (q) { if (c === q) q = null; } else if (c === '"' || c === "'") q = c; else if (c === '>') return k;
  }
  return -1;
}
export const kids = (el, name) => (el ? el.children.filter(c => c.name === name) : []);
export const kid = (el, name) => (el ? el.children.find(c => c.name === name) || null : null);
// Follows a path of element names: path(el, 'devices', 'entry', 'vsys') → all matching descendants
export function path(el, ...names) {
  let cur = el ? [el] : [];
  for (const n of names) cur = cur.flatMap(e => kids(e, n));
  return cur;
}
export const txt = el => (el ? el.text.trim() : '');
// Plain text from a fragment of markup (PAN-OS error messages): tags removed until none is left, then any
// stray angle bracket, so nothing that looks like markup survives into a message
export function stripTags(s) {
  let out = String(s ?? ''), prev;
  do { prev = out; out = out.replace(/<[^<>]*>/g, ' '); } while (out !== prev);
  return out.replace(/[<>]/g, ' ').replace(/\s+/g, ' ').trim();
}
export const members = el => (el ? kids(el, 'member').map(txt).filter(Boolean) : []);
