// SPDX-License-Identifier: AGPL-3.0-or-later
// Palo Alto Networks (PAN-OS firewall or Panorama) → flows of an IS.
// Source: a configuration file (Device > Setup > Operations > Export named configuration snapshot, or
// Panorama export) uploaded in the app, or the XML API (type=export&category=configuration, read-only key).
// Each "allow" security rule becomes flows: source address objects → assets of the IS (by IP) or the
// Internet / an Internet service (public addresses, FQDN), destination likewise, services → ports, and the
// firewall as the device the flows cross.
import { request, expectOk, ConnectorError, stripTags, parseXml, kids, kid, path, txt, members, parseRange, isPrivateRange, inRange, isIp, slug, hash, norm, intToIp, vlanForIp, holdingVlan } from '../../sdk.js';

// Ports of the most common App-IDs, for rules set to "application-default"
const APP_PORTS = {
  'ssl': ['tcp/443'], 'web-browsing': ['tcp/80'], 'ssh': ['tcp/22'], 'dns': ['udp/53', 'tcp/53'], 'dns-base': ['udp/53'], 'ntp': ['udp/123'], 'ntp-base': ['udp/123'],
  'ms-rdp': ['tcp/3389'], 'smtp': ['tcp/25'], 'smtp-base': ['tcp/25'], 'ldap': ['tcp/389'], 'ms-ds-smb': ['tcp/445'], 'ms-ds-smbv3': ['tcp/445'], 'smb': ['tcp/445'], 'kerberos': ['tcp/88', 'udp/88'],
  'snmp': ['udp/161'], 'snmp-base': ['udp/161'], 'syslog': ['udp/514'], 'ftp': ['tcp/21'], 'telnet': ['tcp/23'], 'mssql-db': ['tcp/1433'], 'mysql': ['tcp/3306'], 'postgres': ['tcp/5432'],
  'oracle': ['tcp/1521'], 'http-proxy': ['tcp/8080'], 'ping': ['icmp'], 'icmp': ['icmp'], 'traceroute': ['icmp'], 'sip': ['udp/5060'], 'rtsp': ['tcp/554'], 'modbus': ['tcp/502'], 's7comm': ['tcp/102'],
  'ms-update': ['tcp/443', 'tcp/80'], 'windows-update': ['tcp/443', 'tcp/80'], 'apt-get': ['tcp/80', 'tcp/443'], 'yum': ['tcp/80', 'tcp/443'], 'eset-update': ['tcp/443', 'tcp/80'], 'ms-office365': ['tcp/443'], 'office365-enterprise-access': ['tcp/443'],
  'rsync': ['tcp/873'], 'ipsec': ['udp/500', 'udp/4500'], 'ike': ['udp/500'], 'openvpn': ['udp/1194'], 'globalprotect': ['tcp/443'], 'radius': ['udp/1812'], 'tacacs-plus': ['tcp/49'], 'vnc': ['tcp/5900'], 'ms-sql': ['tcp/1433'], 'netbios-ns': ['udp/137'], 'msrpc': ['tcp/135'],
};
const RISKY_IN = new Set(['tcp/22', 'tcp/23', 'tcp/3389', 'tcp/445', 'tcp/139', 'tcp/135', 'tcp/5900', 'tcp/1433', 'tcp/3306', 'tcp/5432', 'tcp/502', 'tcp/102', 'udp/161', 'any']);
const PREDEF_SERVICES = { 'service-http': ['tcp/80', 'tcp/8080'], 'service-https': ['tcp/443'] };

/* ---------------- fetching the configuration ---------------- */
async function fetchConfig(cfg) {
  const base = String(cfg.url || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) throw new ConnectorError('Give the URL of the firewall or Panorama (https://…), or import a configuration file.');
  let key = cfg.apiKey;
  if (!key) {
    if (!cfg.user || !cfg.password) throw new ConnectorError('Give an API key, or a user name and password.');
    const r = await request(`${base}/api/?type=keygen`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/xml' }, body: new URLSearchParams({ user: cfg.user, password: cfg.password }).toString(), tls: cfg.tls });
    await expectOk(r, 'PAN-OS keygen');
    const m = /<key>([^<]+)<\/key>/.exec(r.text);
    if (!m) throw new ConnectorError(`PAN-OS refused the user name or password: ${stripTags((/<msg>([\s\S]*?)<\/msg>/.exec(r.text) || [, r.text.slice(0, 160)])[1])}`);
    key = m[1];
  }
  const r = await request(`${base}/api/?type=export&category=configuration`, { headers: { 'X-PAN-KEY': key, Accept: 'application/xml' }, tls: cfg.tls, timeoutMs: 120000 });
  await expectOk(r, 'PAN-OS export');
  if (/<response[^>]*status="error"/.test(r.text)) throw new ConnectorError(`PAN-OS: ${stripTags((/<msg>([\s\S]*?)<\/msg>/.exec(r.text) || [, 'error'])[1])}`);
  return r.text;
}
export async function test(cfg) {
  const xml = await fetchConfig(cfg);
  const p = parseConfig(xml);
  return `Connected: ${p.kind === 'panorama' ? 'Panorama' : 'firewall'}, ${p.rules.length} security rule(s), ${Object.keys(p.objects).length} scope(s).`;
}

/* ---------------- parsing ---------------- */
function findConfig(root) {
  const q = [root];
  while (q.length) { const e = q.shift(); if (e.name === 'config') return e; q.push(...e.children); }
  return null;
}
function objectsOf(el) {
  // keys are object names from the configuration file: no prototype, so "__proto__" or "constructor" are just names
  const o = { address: Object.create(null), group: Object.create(null), service: Object.create(null), svcGroup: Object.create(null), description: Object.create(null) };
  if (!el) return o;
  for (const e of path(el, 'address', 'entry')) {
    const name = e.attrs.name; if (!name) continue;
    const v = kid(e, 'ip-netmask') || kid(e, 'ip-range') || kid(e, 'fqdn') || kid(e, 'ip-wildcard');
    o.address[name] = v ? { kind: v.name === 'fqdn' ? 'fqdn' : v.name === 'ip-wildcard' ? 'wildcard' : 'ip', value: txt(v) } : { kind: 'unknown', value: '' };
    const d = txt(kid(e, 'description')); if (d) o.description[name] = d.slice(0, 120);
  }
  for (const e of path(el, 'address-group', 'entry')) {
    const name = e.attrs.name; if (!name) continue;
    const st = kid(e, 'static');
    o.group[name] = st ? { members: members(st) } : { dynamic: txt(kid(kid(e, 'dynamic'), 'filter')) || 'dynamic' };
  }
  for (const e of path(el, 'service', 'entry')) {
    const name = e.attrs.name; if (!name) continue;
    const proto = kid(e, 'protocol'), out = [];
    for (const pr of ['tcp', 'udp', 'sctp']) { const p = kid(proto, pr); if (p) for (const port of txt(kid(p, 'port')).split(',').map(x => x.trim()).filter(Boolean)) out.push(`${pr}/${port}`); }
    o.service[name] = out;
  }
  for (const e of path(el, 'service-group', 'entry')) { if (e.attrs.name) o.svcGroup[e.attrs.name] = members(kid(e, 'members')); }
  return o;
}
function rulesOf(el, scope, where) {
  return path(el, 'rules', 'entry').map((e, i) => ({
    name: e.attrs.name || `rule-${i + 1}`, scope, where,
    from: members(kid(e, 'from')), to: members(kid(e, 'to')),
    source: members(kid(e, 'source')), destination: members(kid(e, 'destination')),
    service: members(kid(e, 'service')), application: members(kid(e, 'application')),
    action: txt(kid(e, 'action')) || 'allow', disabled: txt(kid(e, 'disabled')) === 'yes',
    negSrc: txt(kid(e, 'negate-source')) === 'yes', negDst: txt(kid(e, 'negate-destination')) === 'yes',
    description: txt(kid(e, 'description')),
  }));
}
export function parseConfig(xml) {
  const root = parseXml(xml);
  const config = findConfig(root);
  if (!config) throw new ConnectorError('This is not a PAN-OS configuration: no <config> element found.');
  const objects = Object.assign(Object.create(null), { shared: objectsOf(kid(config, 'shared')) }), rules = [];
  const shared = kid(config, 'shared');
  const dgs = path(config, 'devices', 'entry', 'device-group', 'entry');
  const vsyses = path(config, 'devices', 'entry', 'vsys', 'entry');
  for (const v of vsyses) {
    const name = v.attrs.name || 'vsys1';
    objects[name] = objectsOf(v);
    rules.push(...rulesOf(kid(kid(v, 'rulebase'), 'security'), name, 'rulebase'));
  }
  for (const where of ['pre-rulebase', 'post-rulebase']) rules.push(...rulesOf(kid(kid(shared, where), 'security'), 'shared', where));
  for (const dg of dgs) {
    const name = dg.attrs.name || 'device-group';
    objects[name] = objectsOf(dg);
    for (const where of ['pre-rulebase', 'post-rulebase']) rules.push(...rulesOf(kid(kid(dg, where), 'security'), name, where));
  }
  // Panorama order: shared pre, device-group pre, device-group post, shared post (the evaluation order of PAN-OS)
  const rank = r => r.where === 'pre-rulebase' ? (r.scope === 'shared' ? 0 : 1) : r.where === 'post-rulebase' ? (r.scope === 'shared' ? 3 : 2) : 1;
  rules.sort((a, b) => rank(a) - rank(b));
  return { kind: dgs.length ? 'panorama' : 'firewall', objects, rules, network: networkOf(config) };
}
// The network side of the configuration, for building an IS: the layer-3 interfaces and sub-interfaces with
// their address and VLAN tag, the zone of each, and the firewall's host name. On Panorama, from its templates.
function networkOf(config) {
  const roots = [config, ...path(config, 'devices', 'entry', 'template', 'entry', 'config')];
  const interfaces = [], zoneOf = Object.create(null);
  let hostname = '';
  for (const root of roots) for (const dev of path(root, 'devices', 'entry')) {
    hostname = hostname || txt(path(dev, 'deviceconfig', 'system', 'hostname')[0]);
    const itf = kid(kid(dev, 'network'), 'interface');
    const add = (e, tag) => {
      const ips = path(e, 'ip', 'entry').map(x => x.attrs.name).filter(Boolean);
      if (e.attrs.name) interfaces.push({ name: e.attrs.name, tag, ips, comment: txt(kid(e, 'comment')) });
    };
    for (const kind of ['ethernet', 'aggregate-ethernet']) for (const e of path(itf, kind, 'entry')) {
      const l3 = kid(e, 'layer3');
      if (l3) add(l3 && { ...l3, attrs: e.attrs, children: [...l3.children, ...kids(e, 'comment')] }, null);
      for (const u of path(l3, 'units', 'entry')) add(u, parseInt(txt(kid(u, 'tag')), 10) || null);
    }
    const vl = kid(itf, 'vlan');
    if (vl) for (const u of path(vl, 'units', 'entry')) add(u, parseInt(txt(kid(u, 'tag')), 10) || parseInt(String(u.attrs.name).split('.')[1], 10) || null);
    for (const v of [...path(dev, 'vsys', 'entry')]) for (const z of path(v, 'zone', 'entry')) {
      const net = kid(z, 'network');
      for (const k of ['layer3', 'layer2', 'virtual-wire', 'tap']) for (const m of members(kid(net, k))) zoneOf[m] = z.attrs.name;
    }
  }
  return { interfaces, zoneOf, hostname };
}

/* ---------------- building the IS ---------------- */
// What the ports opened to an address say about it (the first that matches); a server otherwise
const TYPE_BY_PORT = [
  [['tcp/502', 'tcp/102', 'tcp/44818', 'udp/47808', 'tcp/20000', 'tcp/2404'], 'plc'],
  [['tcp/1433', 'tcp/1521', 'tcp/3306', 'tcp/5432', 'tcp/27017', 'tcp/5022'], 'db'],
  [['tcp/88', 'udp/88', 'tcp/636', 'tcp/3268'], 'dc'],
  [['tcp/554'], 'camera'], [['tcp/9100', 'tcp/631', 'tcp/515'], 'printer'],
  [['tcp/902', 'tcp/3260', 'tcp/8000'], 'hypervisor'],
];
// What the name or description of an address object says (naming conventions: PC-…, TEL-…, CAM-…, SQL-…)
const TYPE_BY_WORD = [
  [['pc', 'ws', 'wks', 'poste', 'postes', 'laptop', 'desktop', 'workstation', 'portable', 'vdi'], 'workstation'],
  [['tel', 'phone', 'voip', 'ipphone', 'telephone', 'sip'], 'phone'],
  [['cam', 'camera', 'cctv', 'video', 'videosurveillance'], 'camera'],
  [['imp', 'prn', 'print', 'printer', 'imprimante', 'mfp'], 'printer'],
  [['ap', 'wifi', 'borne', 'wap'], 'ap'],
  [['plc', 'automate', 'automates', 'rtu'], 'plc'],
  [['cap', 'sensor', 'capteur', 'iot', 'badge', 'badgeuse', 'compteur', 'meter'], 'iot'],
  [['sql', 'db', 'database', 'ora', 'oracle', 'pg', 'postgres', 'mysql', 'mongo'], 'db'],
  [['dc', 'ad', 'adds', 'domain'], 'dc'],
  [['esx', 'esxi', 'hv', 'hyperv', 'hypervisor', 'nutanix', 'san', 'nas', 'storage', 'stockage'], 'hypervisor'],
  [['fw', 'firewall', 'pare'], 'firewall'],
  [['rtr', 'router', 'routeur'], 'router'],
  [['sw', 'switch', 'commutateur', 'net', 'netdev'], 'switch'],
  [['vpn', 'gateway', 'gw'], 'gateway'],
];
// Adds to the IS what the configuration describes and the map lacks: a zone per security zone, a VLAN per
// layer-3 sub-interface (tag and subnet; untagged interfaces get a number from 4001 on, to change), an asset
// per host address object of a private range (in the VLAN whose range holds it), and the firewall. What is
// already there (same zone name, same VLAN number or range, an asset with the same IP) is kept as it is.
function buildIs(parsed, cfg, state, si, assets, netZones) {
  const siteId = cfg.site, N = parsed.network || { interfaces: [], zoneOf: {}, hostname: '' }, stats = { zonesAdded: 0, vlansAdded: 0, assetsAdded: 0, firewallAdded: 0 };
  si.zones = si.zones && si.zones.length ? si.zones : [];
  si.vlans = si.vlans || [];
  const zoneId = name => {
    let z = si.zones.find(x => norm(x.name) === norm(name));
    if (!z) { let id = 'z-pa-' + slug(name); for (let i = 2; si.zones.some(x => x.id === id); i++) id = `z-pa-${slug(name)}-${i}`; z = { id, name: String(name).slice(0, 40) }; si.zones.push(z); stats.zonesAdded++; }
    return z.id;
  };
  const addrOf = name => { for (const o of Object.values(parsed.objects)) { const a = o.address[name]; if (a && a.kind === 'ip') return a.value; } return name; };
  // VLANs from the interfaces of the zones that are not the Internet
  const fwIps = [];
  let untagged = 4001;
  for (const itf of N.interfaces) {
    const zone = N.zoneOf[itf.name];
    for (const raw of itf.ips) {
      const v4 = addrOf(raw), m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(v4);
      if (!m || !isIp(m[1])) continue;
      if (!zone || netZones.includes(norm(zone))) { fwIps.push({ ip: m[1], net: true }); continue; }
      fwIps.push({ ip: m[1], net: false });
      const r = parseRange(`${m[1]}/${m[2]}`), cidr = `${intToIp(r.lo)}/${m[2]}`;
      if (+m[2] >= 31) continue;
      const num = itf.tag && itf.tag >= 1 && itf.tag <= 4094 ? itf.tag : null;
      const same = si.vlans.find(v => v.cidr === cidr) || (num && si.vlans.find(v => +v.num === num));
      if (same) { if (!same.cidr) same.cidr = cidr; continue; }
      let n = num;
      if (!n) { while (si.vlans.some(v => +v.num === untagged)) untagged++; n = untagged++; }
      si.vlans.push({ id: `v-pa-${slug(siteId)}-${n}`, num: n, name: (itf.comment || `${zone} ${itf.name}${num ? '' : ' (untagged)'}`).slice(0, 50), cidr, zone: zoneId(zone) });
      stats.vlansAdded++;
    }
  }
  if (!si.zones.length) si.zones.push({ id: 'z-def', name: 'Main zone' });
  // the ports opened to each address, from the allow rules, to guess its type
  const portsTo = Object.create(null);
  for (const r of parsed.rules) {
    if (r.action !== 'allow' || r.disabled) continue;
    const ports = r.service.flatMap(sv => { const o = Object.values(parsed.objects).map(x => x.service[sv]).find(Boolean); const mm = /^(tcp|udp)[-_/ ]?(\d+)$/i.exec(sv); return o || (mm ? [`${mm[1].toLowerCase()}/${mm[2]}`] : []); });
    for (const d of r.destination) (portsTo[d] = portsTo[d] || new Set()) && ports.forEach(p => portsTo[d].add(p));
  }
  const sources = new Set(parsed.rules.filter(r => r.action === 'allow' && !r.disabled).flatMap(r => r.source));
  // the type: its name or description first, then the ports opened to it, then an address that only opens
  // connections is a workstation, and anything else a server
  const typeOf = (name, desc) => {
    const words = new Set(norm(`${name} ${desc || ''}`).split(' '));
    for (const [list, t] of TYPE_BY_WORD) if (list.some(w => words.has(w))) return t;
    const p = portsTo[name];
    if (p) for (const [list, t] of TYPE_BY_PORT) if (list.some(x => p.has(x))) return t;
    if (!p && sources.has(name)) return 'workstation';
    return 'server';
  };
  // assets from host objects of private ranges that no asset of the IS has yet
  const byIp = new Map(assets.map(([id, a]) => [a.ip, id])), out = {};
  for (const [scope, o] of Object.entries(parsed.objects)) {
    if (cfg.scope && scope !== cfg.scope && scope !== 'shared') continue;
    for (const [name, a] of Object.entries(o.address)) {
      if (a.kind !== 'ip') continue;
      const ip = /^(\d+\.\d+\.\d+\.\d+)(?:\/32)?$/.exec(a.value);
      if (!ip || !isIp(ip[1]) || !isPrivateRange(parseRange(ip[1])) || byIp.has(ip[1]) || fwIps.some(f => f.ip === ip[1])) continue;
      if (Object.keys(out).length >= 5000) break;
      const vlan = vlanForIp(si, ip[1]) || holdingVlan(si, siteId, 'To sort (Palo Alto)');
      let id = `pa-${slug(siteId)}-${slug(name)}`;
      for (let i = 2; state.assets[id] || out[id]; i++) id = `pa-${slug(siteId)}-${slug(name)}-${i}`;
      out[id] = { site: siteId, name: name.slice(0, 80), type: typeOf(name, o.description && o.description[name]), vlan: vlan.id, ip: ip[1], os: '', role: (o.description && o.description[name]) || '', crit: 2, vulns: [], contacts: [], apps: [], notes: 'Created from a Palo Alto address object.', ext: { paloalto: name } };
      byIp.set(ip[1], id); stats.assetsAdded++;
    }
  }
  // the firewall itself: an existing firewall asset at one of its addresses, or a new one
  let firewall = null;
  const inside = fwIps.find(f => !f.net);
  const existing = assets.find(([, a]) => a.type === 'firewall' && fwIps.some(f => f.ip === a.ip)) || (!inside && assets.find(([, a]) => a.type === 'firewall'));
  if (existing) firewall = existing[0];
  else if (inside) {
    const name = N.hostname || 'Palo Alto firewall', id = `pa-${slug(siteId)}-fw-${slug(name)}`;
    if (!state.assets[id]) {
      const vlan = vlanForIp(si, inside.ip) || holdingVlan(si, siteId, 'To sort (Palo Alto)');
      out[id] = { site: siteId, name, type: 'firewall', vlan: vlan.id, ip: inside.ip, os: 'PAN-OS', role: 'Firewall', crit: 3, vulns: [], contacts: [], apps: [], notes: 'Created from the Palo Alto configuration.', ext: { paloalto: 'firewall' } };
      stats.firewallAdded = 1;
    }
    firewall = id;
  }
  // the new assets take part in the rules like the others
  for (const [id, a] of Object.entries(out)) assets.push([id, a]);
  return { assets: out, firewall, stats };
}

/* ---------------- turning rules into flows ---------------- */
export function rulesToChanges(parsed, cfg, state) {
  const siteId = cfg.site;
  const si0 = state.si[siteId];
  if (!si0) throw new ConnectorError('Choose the IS these rules apply to.');
  const si = JSON.parse(JSON.stringify(si0));
  si.flows = si.flows || []; si.services = si.services || [];
  const assets = Object.entries(state.assets).filter(([, a]) => a.site === siteId);
  const netZones = String(cfg.internetZones || 'untrust, internet, outside, wan').split(/[\s,;]+/).map(norm).filter(Boolean);
  // "Build the IS": zones, VLANs, assets and the firewall from the configuration, before the flows
  const built = cfg.build ? buildIs(parsed, cfg, state, si, assets, netZones) : null;
  const newAssets = built ? built.assets : {};
  const fw = cfg.firewall && state.assets[cfg.firewall] && state.assets[cfg.firewall].site === siteId ? cfg.firewall : built && built.firewall ? built.firewall : null;
  const maxExpand = Math.max(1, parseInt(cfg.maxExpand, 10) || 12);
  const scopeFilter = String(cfg.scope || '').trim();
  const warn = [], skipped = [];
  const lookup = (scope, kind, name) => {
    for (const s of [scope, 'shared', ...Object.keys(parsed.objects)]) { const v = parsed.objects[s] && parsed.objects[s][kind][name]; if (v !== undefined) return v; }
    return undefined;
  };
  // Leaves of an address member: [{kind:'ip'|'fqdn', value, obj}] (groups expanded)
  const leaves = (scope, name, seen = new Set()) => {
    if (seen.has(name)) return []; seen.add(name);
    if (parseRange(name)) return [{ kind: 'ip', value: name, obj: name }];
    const a = lookup(scope, 'address', name);
    if (a) return [{ ...a, obj: name }];
    const g = lookup(scope, 'group', name);
    if (g && g.members) return g.members.flatMap(m => leaves(scope, m, seen));
    if (g && g.dynamic) { warn.push(`Dynamic address group “${name}” (${g.dynamic}) cannot be resolved from the configuration.`); return []; }
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(name)) return [{ kind: 'fqdn', value: name, obj: name }];
    warn.push(`Unknown address object “${name}”.`); return [];
  };
  const svcIdFor = (label, hosts) => {
    const lower = hosts.map(h => h.toLowerCase());
    const all = [...(state.services || []).map(s => ({ s, site: false })), ...si.services.map(s => ({ s, site: true }))];
    const hit = all.find(({ s }) => (s.hosts || []).some(h => lower.includes(String(h).toLowerCase())));
    if (hit) return 'svc:' + hit.s.id;
    const id = 'pa-' + slug(label);
    let s = si.services.find(x => x.id === id);
    if (!s) { s = { id, name: label, category: 'Other', hosts: [], ports: [], notes: 'Created from a Palo Alto address object.' }; si.services.push(s); }
    for (const h of hosts) if (!s.hosts.includes(h)) s.hosts.push(h);
    return 'svc:' + id;
  };
  // Endpoints a rule member stands for, in this IS
  const endpoints = (scope, name, zones, ruleName, side) => {
    if (name === 'any') {
      if (zones.some(z => netZones.includes(norm(z)))) return ['internet'];
      skipped.push(`Rule “${ruleName}”: ${side === 'src' ? 'source' : 'destination'} “any” in zone ${zones.join(', ') || 'any'} is too broad to draw.`);
      return [];
    }
    const L = leaves(scope, name);
    const out = new Set(), external = [];
    for (const l of L) {
      if (l.kind === 'fqdn') { external.push(l.value); continue; }
      if (l.kind !== 'ip') { warn.push(`Address “${l.obj}” (${l.kind}) is not supported.`); continue; }
      const r = parseRange(l.value);
      if (!r) { warn.push(`Address “${l.obj}” has an unreadable value: ${l.value}.`); continue; }
      const inside = assets.filter(([, a]) => inRange(a.ip, r)).map(([id]) => id);
      if (inside.length > maxExpand) { skipped.push(`Rule “${ruleName}”: “${l.obj}” (${l.value}) covers ${inside.length} assets, more than ${maxExpand}.`); continue; }
      if (inside.length) { inside.forEach(id => out.add(id)); continue; }
      if (isPrivateRange(r)) { skipped.push(`Rule “${ruleName}”: no asset of the IS at ${l.value} (“${l.obj}”).`); continue; }
      external.push(l.value);
    }
    if (external.length) out.add(svcIdFor(name, external));
    return [...out];
  };
  const portsOf = (scope, r) => {
    const out = new Set();
    for (const s of r.service) {
      if (s === 'any') { out.add('any'); continue; }
      if (s === 'application-default') {
        const apps = r.application.filter(a => a !== 'any');
        if (!apps.length) { out.add('any'); continue; }
        for (const a of apps) ((Object.hasOwn(APP_PORTS, a) && APP_PORTS[a]) || [`app/${a}`]).forEach(p => out.add(p));
        continue;
      }
      if (Object.hasOwn(PREDEF_SERVICES, s)) { PREDEF_SERVICES[s].forEach(p => out.add(p)); continue; }
      const expand = (n, seen = new Set()) => {
        if (seen.has(n)) return; seen.add(n);
        const v = lookup(scope, 'service', n); if (v) { v.forEach(p => out.add(p)); return; }
        const g = lookup(scope, 'svcGroup', n); if (g) { g.forEach(m => expand(m, seen)); return; }
        const m = /^(tcp|udp)[-_/ ]?(\d+)$/i.exec(n); if (m) { out.add(`${m[1].toLowerCase()}/${m[2]}`); return; }
        warn.push(`Unknown service “${n}”.`);
      };
      expand(s);
    }
    return [...out];
  };

  const vlanOfId = id => (newAssets[id] || state.assets[id] || {}).vlan;
  const sameVlan = (a, b) => !a.startsWith('svc:') && a !== 'internet' && !b.startsWith('svc:') && b !== 'internet' && vlanOfId(a) && vlanOfId(a) === vlanOfId(b);
  const imported = new Map(); // key src>dst>port → flow
  let used = 0, ignored = 0;
  for (const r of parsed.rules) {
    if (scopeFilter && r.scope !== scopeFilter && r.scope !== 'shared') continue;
    if (r.disabled || r.action !== 'allow') { ignored++; continue; }
    if (r.negSrc || r.negDst) { skipped.push(`Rule “${r.name}”: negated source or destination is not drawn.`); continue; }
    const S = [...new Set(r.source.flatMap(m => endpoints(r.scope, m, r.from, r.name, 'src')))];
    const D = [...new Set(r.destination.flatMap(m => endpoints(r.scope, m, r.to, r.name, 'dst')))];
    const P = portsOf(r.scope, r);
    if (!S.length || !D.length || !P.length) continue;
    let n = 0;
    for (const s of S) for (const d of D) {
      if (s === d) continue;
      const net = x => x === 'internet' || x.startsWith('svc:');
      if (net(s) && net(d)) continue;
      for (const p of P) {
        const key = `${s}>${d}>${p}`;
        if (imported.has(key)) { imported.get(key).pan.rules.push(r.name); continue; }
        if (++n > 400) break;
        const risk = net(s) && RISKY_IN.has(p);
        imported.set(key, {
          id: 'f-pa-' + hash(key), src: s, dst: d, port: p, vol: 1, risk,
          note: `Palo Alto rule “${r.name}”${r.description ? ` — ${r.description.slice(0, 120)}` : ''}${r.application.length && !r.application.includes('any') ? ` · App-ID: ${r.application.join(', ')}` : ''}${risk ? ' · administration or database port open from the Internet' : ''}`,
          ...(fw && s !== fw && d !== fw && !(built && sameVlan(s, d)) ? { via: [fw] } : {}),
          pan: { rules: [r.name], scope: r.scope },
        });
      }
    }
    if (n > 400) warn.push(`Rule “${r.name}” would draw more than 400 flows: cut at 400.`);
    used++;
  }

  // Merge into the flows of the IS: existing flows with the same source, destination and port are kept
  const keyOf = f => `${f.src}>${f.dst}>${f.port}`;
  const existing = new Map(si.flows.map(f => [keyOf(f), f]));
  let added = 0, tagged = 0, removed = 0;
  for (const [k, f] of imported) {
    const old = existing.get(k);
    // a flow already on the map (drawn by hand, or imported earlier) is left as it is
    if (old) { if (old.pan && JSON.stringify(old.pan) !== JSON.stringify(f.pan)) old.pan = f.pan; else tagged++; }
    else { si.flows.push(f); added++; }
  }
  if (cfg.removeStale !== false) {
    const before = si.flows.length;
    si.flows = si.flows.filter(f => !f.pan || imported.has(keyOf(f)));
    removed = before - si.flows.length;
  }
  // the empty lists added above are no change: compare the IS as it was, with them
  const changed = JSON.stringify(si) !== JSON.stringify({ ...si0, flows: si0.flows || [], services: si0.services || [] }) || Object.keys(newAssets).length > 0;
  return {
    changes: changed ? { si: { [siteId]: si }, assets: newAssets } : null,
    stats: { rules: parsed.rules.length, used, ignored, flows: imported.size, added, tagged, removed, services: si.services.length - (si0.services || []).length, ...(built ? built.stats : {}) },
    warnings: [...new Set(warn)].slice(0, 40), skipped: [...new Set(skipped)].slice(0, 60),
  };
}

export async function run(cfg, ctx) {
  const xml = ctx.file ? ctx.file.text : await fetchConfig(cfg);
  const parsed = parseConfig(xml);
  const res = rulesToChanges(parsed, cfg, ctx.state);
  const siName = ctx.state.si[cfg.site]?.name || cfg.site;
  const st = res.stats;
  const summary = `${cfg.build ? `IS built: ${st.zonesAdded} new zone(s), ${st.vlansAdded} new VLAN(s), ${st.assetsAdded} new asset(s)${st.firewallAdded ? ' and the firewall' : ''}; ` : ''}${st.rules} rule(s) read (${parsed.kind}), ${st.used} allow rule(s) drawn, ${st.ignored} deny or disabled ignored; ${st.added} new flow(s), ${st.removed} removed, ${st.services} new Internet service(s).`;
  return {
    proposals: res.changes ? [{
      siteId: cfg.site,
      title: `Palo Alto: rules of ${ctx.file?.name || cfg.url || 'the firewall'} → ${siName}`,
      description: `${summary}\n${res.skipped.length ? `\nNot drawn:\n- ${res.skipped.slice(0, 25).join('\n- ')}` : ''}${res.warnings.length ? `\n\nWarnings:\n- ${res.warnings.slice(0, 15).join('\n- ')}` : ''}`.slice(0, 4000),
      changes: res.changes,
    }] : [],
    report: { ...st, skipped: res.skipped, warnings: res.warnings },
    summary,
  };
}
