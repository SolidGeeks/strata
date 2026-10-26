// SPDX-License-Identifier: AGPL-3.0-or-later
// GLPI (legacy REST API, apirest.php) → assets: inventory (computers, network devices, printers, phones),
// installed software (→ applications), technician in charge and technical group (→ incident contacts),
// location (→ which IS). Works with GLPI 9.5 and 10 (the "API" setting must be on, with an App-Token if the
// API client asks for one, and a user token: Preferences > Remote access keys).
import { request, expectOk, pool, ConnectorError, assetIndex, siteFor, vlanForIp, holdingVlan, isIp, parseRules } from '../../sdk.js';

function client(cfg) {
  const base = String(cfg.url || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) throw new ConnectorError('Give the GLPI API URL (https://…/apirest.php).');
  if (!cfg.userToken && !(cfg.login && cfg.password)) throw new ConnectorError('Give a user token, or a login and password.');
  let session = null;
  const H = () => ({ ...(cfg.appToken ? { 'App-Token': cfg.appToken } : {}), ...(session ? { 'Session-Token': session } : {}) });
  const c = {
    async open() {
      const auth = cfg.userToken ? `user_token ${cfg.userToken}` : 'Basic ' + Buffer.from(`${cfg.login}:${cfg.password}`).toString('base64');
      const r = await request(`${base}/initSession`, { headers: { ...H(), Authorization: auth }, tls: cfg.tls });
      if (r.status === 400 || r.status === 401) { let m = ''; try { m = [].concat(r.json()).join(' '); } catch { m = r.text.slice(0, 160); } throw new ConnectorError(`GLPI refused the session: ${m}`); }
      await expectOk(r, 'GLPI initSession');
      session = r.json().session_token;
      if (!session) throw new ConnectorError('GLPI did not return a session token.');
    },
    async close() { if (session) { try { await request(`${base}/killSession`, { headers: H(), tls: cfg.tls, timeoutMs: 8000 }); } catch { } session = null; } },
    async get(p, q = {}) {
      const qs = new URLSearchParams(q).toString();
      const r = await request(`${base}/${p}${qs ? `?${qs}` : ''}`, { headers: H(), tls: cfg.tls, timeoutMs: 60000 });
      if (r.status === 404) return null;
      // a list with nothing in it answers 400 ERROR_RANGE_EXCEED_TOTAL on some versions
      if (r.status === 400 && /RANGE_EXCEED/.test(r.text)) return [];
      await expectOk(r, `GLPI ${p}`);
      return r.json();
    },
    async all(itemtype, q = {}) {
      const out = [];
      for (let start = 0; start < 100000; start += 200) {
        const page = await c.get(`${itemtype}/`, { ...q, range: `${start}-${start + 199}` });
        if (!Array.isArray(page) || !page.length) break;
        out.push(...page);
        if (page.length < 200) break;
      }
      return out;
    },
  };
  return c;
}

export async function test(cfg) {
  const c = client(cfg);
  await c.open();
  try {
    const n = {};
    for (const t of cfg.itemtypes && cfg.itemtypes.length ? cfg.itemtypes : ['Computer']) { const p = await c.get(`${t}/`, { range: '0-0', only_id: 'true' }); n[t] = Array.isArray(p) ? 'ok' : '?'; }
    return `Session opened. Readable: ${Object.keys(n).join(', ')}.`;
  } finally { await c.close(); }
}

const name = v => (v && typeof v === 'object' ? (v.completename || v.name || '') : (v == null ? '' : String(v)));
function typeOf(itemtype, typeName, item, os) {
  const t = `${typeName} ${item.name || ''} ${item.comment || ''}`.toLowerCase();
  if (itemtype === 'Printer') return 'printer';
  if (itemtype === 'Phone') return 'phone';
  if (itemtype === 'NetworkEquipment') {
    if (/firewall|pare-feu|\bfw\b|palo|forti|stormshield|checkpoint|sophos/.test(t)) return 'firewall';
    if (/router|routeur|\bl3\b|core/.test(t)) return 'router';
    if (/wi-?fi|access point|borne|\bap\b|wlan/.test(t)) return 'ap';
    if (/vpn/.test(t)) return 'gateway';
    return 'switch';
  }
  if (/esx|hyper-?v|proxmox|hypervis|nutanix|xen/.test(`${t} ${os}`.toLowerCase())) return 'hypervisor';
  if (/domain controller|contr[oô]leur de domaine|\bdc\b/.test(t)) return 'dc';
  if (/server|serveur|srv/.test(t) || /server/i.test(os)) return 'server';
  return 'workstation';
}
// Every IPv4 address found in the network ports block of an item, whatever the GLPI version's layout
function ipsIn(obj) {
  const out = new Set();
  const walk = (v, k) => {
    if (Array.isArray(v)) return v.forEach(x => walk(x, k));
    if (v && typeof v === 'object') { for (const [kk, vv] of Object.entries(v)) if (!/ipnetwork|netmask|gateway/i.test(kk)) walk(vv, kk); return; }
    if (typeof v === 'string' && isIp(v) && !/^(0\.|127\.|255\.)/.test(v) && !/mask|gateway|netmask|network/i.test(k || '')) out.add(v);
  };
  walk(obj);
  return [...out];
}

export async function run(cfg, ctx) {
  const state = ctx.state;
  const c = client(cfg);
  const types = cfg.itemtypes && cfg.itemtypes.length ? cfg.itemtypes : ['Computer', 'NetworkEquipment', 'Printer'];
  const rules = parseRules(cfg.locationRules);
  const exclude = (() => { try { return cfg.softwareExclude ? new RegExp(cfg.softwareExclude, 'i') : null; } catch { return null; } })();
  const maxApps = Math.max(0, Math.min(300, parseInt(cfg.maxApps, 10) || 40));
  await c.open();
  try {
    // dropdowns read once
    const dict = async t => Object.fromEntries((await c.all(t, { expand_dropdowns: 'false' })).map(x => [x.id, x.completename || x.name || '']));
    const [locations, groups, ctypes, ntypes] = await Promise.all([dict('Location'), dict('Group'), types.includes('Computer') ? dict('ComputerType') : {}, types.includes('NetworkEquipment') ? dict('NetworkEquipmentType') : {}]);
    const userCache = new Map(), swCache = new Map(), verCache = new Map();
    const userOf = id => {
      if (!id || id === '0') return null;
      if (!userCache.has(id)) userCache.set(id, (async () => {
        const u = await c.get(`User/${id}`);
        if (!u) return null;
        const emails = await c.get(`User/${id}/UserEmail`).catch(() => []);
        const em = Array.isArray(emails) ? (emails.find(e => +e.is_default) || emails[0] || {}).email || '' : '';
        return { name: [u.firstname, u.realname].filter(Boolean).join(' ') || u.name, phone: u.phone || u.mobile || '', email: em };
      })());
      return userCache.get(id);
    };
    const swName = async (sid, vid) => {
      let sn = sid, vn = vid;
      if (/^\d+$/.test(String(sid))) { if (!swCache.has(sid)) swCache.set(sid, c.get(`Software/${sid}`).then(x => x ? x.name : '').catch(() => '')); sn = await swCache.get(sid); }
      if (/^\d+$/.test(String(vid))) { if (!verCache.has(vid)) verCache.set(vid, c.get(`SoftwareVersion/${vid}`).then(x => x ? x.name : '').catch(() => '')); vn = await verCache.get(vid); }
      return [String(sn || ''), String(vn || '')];
    };

    const items = [];
    for (const t of types) for (const it of await c.all(t, { expand_dropdowns: 'false', is_deleted: '0' })) items.push({ t, it });
    const idx = assetIndex(state);
    const report = { read: items.length, noSite: 0, noSiteSample: [], matched: 0, created: 0, skippedNew: 0 };
    const bySite = {};
    const siCopy = id => { const b = bySite[id] = bySite[id] || { si: null, assets: {}, n: 0 }; if (!b.si) b.si = JSON.parse(JSON.stringify(state.si[id])); return b; };

    await pool(items, 4, async ({ t, it }) => {
      const loc = locations[it.locations_id] || '';
      const site = siteFor(loc, rules, state);
      if (!site) { report.noSite++; if (report.noSiteSample.length < 15) report.noSiteSample.push(`${it.name} (${loc || 'no location'})`); return; }
      const d = await c.get(`${t}/${it.id}`, { expand_dropdowns: 'true', with_networkports: 'true', ...(t === 'Computer' && cfg.importSoftware !== false ? { with_softwares: 'true' } : {}) }) || it;
      const ips = ipsIn(d._networkports || {});
      let os = '';
      if (t === 'Computer') {
        const ios = await c.get(`${t}/${it.id}/Item_OperatingSystem`, { expand_dropdowns: 'true' }).catch(() => null);
        const o = Array.isArray(ios) ? ios[0] : null;
        if (o) os = [name(o.operatingsystems_id), name(o.operatingsystemversions_id), name(o.operatingsystemservicepacks_id)].filter(x => x && x !== '0' && x !== '&nbsp;').join(' ');
      } else if (d.networkequipmentfirmwares_id || d.firmware) os = name(d.networkequipmentfirmwares_id || d.firmware);
      let apps = [];
      if (Array.isArray(d._softwares) && maxApps) {
        const seen = new Set();
        for (const s of d._softwares) {
          const [sn, vn] = await swName(s.softwares_id ?? s.software ?? s.name, s.softwareversions_id ?? s.version ?? '');
          if (!sn || (exclude && exclude.test(sn)) || seen.has(sn.toLowerCase())) continue;
          seen.add(sn.toLowerCase()); apps.push({ name: sn, version: vn, ports: '', src: 'glpi' });
        }
        apps = apps.sort((a, b) => a.name.localeCompare(b.name)).slice(0, maxApps);
      }
      const contacts = [];
      if (cfg.importContacts !== false) {
        const u = await userOf(it.users_id_tech);
        if (u) contacts.push({ name: u.name, role: 'Technical owner', phone: u.phone, email: u.email, dispo: '', src: 'glpi' });
        const g = groups[it.groups_id_tech];
        if (g) contacts.push({ name: g, role: 'Technical owner', phone: '', email: '', dispo: 'Group in charge (GLPI)', src: 'glpi' });
      }
      const typeName = t === 'Computer' ? (ctypes[it.computertypes_id] || '') : t === 'NetworkEquipment' ? (ntypes[it.networkequipmenttypes_id] || '') : '';
      const ext = `${t}/${it.id}`;
      const found = idx.find({ connector: 'glpi', ext, name: it.name, ips, site });
      if (found) {
        const a = state.assets[found];
        const next = { ...a, ext: { ...(a.ext || {}), glpi: ext } };
        if (os) next.os = os;
        if (!next.ip && ips[0]) next.ip = ips[0];
        if (cfg.importSoftware !== false && t === 'Computer') {
          // entries typed by hand keep their ports and notes; the inventory brings the installed version
          const byName = new Map(apps.map(x => [x.name.toLowerCase(), x]));
          const manual = (a.apps || []).filter(x => x.src !== 'glpi').map(m => { const g = byName.get(String(m.name).toLowerCase()); return g && g.version && g.version !== m.version ? { ...m, version: g.version } : m; });
          next.apps = [...manual, ...apps.filter(x => !manual.some(m => String(m.name).toLowerCase() === x.name.toLowerCase()))];
        }
        if (cfg.importContacts !== false && contacts.length) next.contacts = [...(a.contacts || []).filter(x => x.src !== 'glpi'), ...contacts];
        report.matched++;
        if (JSON.stringify(next) !== JSON.stringify(a)) { const b = bySite[a.site] = bySite[a.site] || { si: null, assets: {}, n: 0 }; b.assets[found] = next; b.n++; }
        return;
      }
      if (cfg.createAssets === false) { report.skippedNew++; return; }
      const b = siCopy(site);
      const ip = ips[0] || '';
      const v = vlanForIp(b.si, ip) || holdingVlan(b.si, site, 'To sort (from GLPI)');
      const id = `glpi-${site}-${t.toLowerCase()}-${it.id}`.slice(0, 120);
      b.assets[id] = {
        site, name: String(it.name || `${t} ${it.id}`), type: typeOf(t, typeName, it, os), vlan: v.id, ip, os, role: typeName || '',
        crit: 2, vulns: [], contacts, apps, notes: [it.serial ? `Serial ${it.serial}` : '', it.otherserial ? `Asset tag ${it.otherserial}` : '', loc ? `GLPI location: ${loc}` : ''].filter(Boolean).join(' · '),
        ext: { glpi: ext },
      };
      b.n++; report.created++;
    });

    const proposals = [];
    for (const [siteId, b] of Object.entries(bySite)) {
      const changes = { si: {}, assets: b.assets };
      if (b.si && JSON.stringify(b.si) !== JSON.stringify(state.si[siteId])) changes.si[siteId] = b.si;
      if (!Object.keys(changes.assets).length && !Object.keys(changes.si).length) continue;
      const created = Object.keys(b.assets).filter(id => !state.assets[id]).length;
      proposals.push({
        siteId,
        title: `GLPI: inventory of ${state.si[siteId]?.name || siteId} (${created} new, ${b.n - created} updated)`,
        description: `Read from GLPI on ${new Date().toLocaleString('en-GB')}: ${types.join(', ')}.\nNew assets are placed on the VLAN whose range holds their IP address, or on “To sort (from GLPI)” when none does. Applications and contacts entered by hand are kept.`,
        changes,
      });
    }
    return { proposals, report, summary: `${report.read} item(s) read in GLPI: ${report.matched} matched, ${report.created} new, ${report.noSite} with a location that matches no IS.` };
  } finally { await c.close(); }
}
