// SPDX-License-Identifier: AGPL-3.0-or-later
// Palo Alto Networks (PAN-OS firewall or Panorama) → flows of an IS.
// Source: a configuration file (Device > Setup > Operations > Export named configuration snapshot, or
// Panorama export) uploaded in the app, or the XML API (type=export&category=configuration, read-only key).
// Each "allow" security rule becomes flows: source address objects → assets of the IS (by IP) or the
// Internet / an Internet service (public addresses, FQDN), destination likewise, services → ports, and the
// firewall as the device the flows cross.
import { request, expectOk, ConnectorError, stripTags, parseXml, kids, kid, path, txt, members, parseRange, isPrivateRange, inRange, isIp, slug, hash, norm } from '../../sdk.js';

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
  const o = { address: Object.create(null), group: Object.create(null), service: Object.create(null), svcGroup: Object.create(null) };
  if (!el) return o;
  for (const e of path(el, 'address', 'entry')) {
    const name = e.attrs.name; if (!name) continue;
    const v = kid(e, 'ip-netmask') || kid(e, 'ip-range') || kid(e, 'fqdn') || kid(e, 'ip-wildcard');
    o.address[name] = v ? { kind: v.name === 'fqdn' ? 'fqdn' : v.name === 'ip-wildcard' ? 'wildcard' : 'ip', value: txt(v) } : { kind: 'unknown', value: '' };
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
  return { kind: dgs.length ? 'panorama' : 'firewall', objects, rules };
}

/* ---------------- turning rules into flows ---------------- */
export function rulesToChanges(parsed, cfg, state) {
  const siteId = cfg.site;
  const si0 = state.si[siteId];
  if (!si0) throw new ConnectorError('Choose the IS these rules apply to.');
  const si = JSON.parse(JSON.stringify(si0));
  si.flows = si.flows || []; si.services = si.services || [];
  const assets = Object.entries(state.assets).filter(([, a]) => a.site === siteId);
  const fw = cfg.firewall && state.assets[cfg.firewall] && state.assets[cfg.firewall].site === siteId ? cfg.firewall : null;
  const netZones = String(cfg.internetZones || 'untrust, internet, outside, wan').split(/[\s,;]+/).map(norm).filter(Boolean);
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
          ...(fw && s !== fw && d !== fw ? { via: [fw] } : {}),
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
  const changed = JSON.stringify(si) !== JSON.stringify(si0);
  return {
    changes: changed ? { si: { [siteId]: si }, assets: {} } : null,
    stats: { rules: parsed.rules.length, used, ignored, flows: imported.size, added, tagged, removed, services: si.services.length - (si0.services || []).length },
    warnings: [...new Set(warn)].slice(0, 40), skipped: [...new Set(skipped)].slice(0, 60),
  };
}

export async function run(cfg, ctx) {
  const xml = ctx.file ? ctx.file.text : await fetchConfig(cfg);
  const parsed = parseConfig(xml);
  const res = rulesToChanges(parsed, cfg, ctx.state);
  const siName = ctx.state.si[cfg.site]?.name || cfg.site;
  const st = res.stats;
  const summary = `${st.rules} rule(s) read (${parsed.kind}), ${st.used} allow rule(s) drawn, ${st.ignored} deny or disabled ignored; ${st.added} new flow(s), ${st.removed} removed, ${st.services} new Internet service(s).`;
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
