// SPDX-License-Identifier: AGPL-3.0-or-later
// Nmap scan: imports an Nmap XML report (nmap -oX) into one IS, as a proposal. Hosts that are up are
// matched to the assets of the IS (by IP, then by name); assets get the system Nmap guessed and, as
// the listening ports of their applications, the open ports and the service behind each one. Hosts
// missing from the map can be created. Nothing is removed: a port Nmap did not see may just have
// been filtered.

// Ports that say what an unknown host is, the first match wins
const TYPE_HINTS = [
  ['dc', ['tcp/88', 'tcp/389'], true], ['db', ['tcp/1433', 'tcp/1521', 'tcp/3306', 'tcp/5432', 'tcp/27017']], ['printer', ['tcp/9100', 'tcp/515', 'tcp/631']],
  ['phone', ['udp/5060', 'tcp/5060']], ['camera', ['tcp/554']], ['plc', ['tcp/502', 'tcp/102', 'udp/47808']], ['hypervisor', ['tcp/902', 'tcp/8006']],
];
const typeOf = (ports, os) => {
  for (const [t, list, all] of TYPE_HINTS) if (all ? list.every(p => ports.includes(p)) : list.some(p => ports.includes(p))) return t;
  if (/windows (7|8|10|11|xp|vista)/i.test(os)) return 'workstation';
  if (/cisco ios|junos|routeros|switch/i.test(os)) return 'switch';
  return 'server';
};

// The report as {hosts: [{ip, names, os, accuracy, ports: [{port, name, product, version}]}], args}
export function parseNmap(xml, sdk) {
  let root;
  try { root = sdk.kid(sdk.parseXml(xml), 'nmaprun'); } catch (e) { throw new sdk.ConnectorError(`This is not an Nmap XML report: ${e.message}`); }
  if (!root) throw new sdk.ConnectorError('This is not an Nmap XML report (no <nmaprun>): save the scan with -oX.');
  const hosts = [];
  for (const h of sdk.kids(root, 'host')) {
    const st = sdk.kid(h, 'status');
    if (st && st.attrs.state !== 'up') continue;
    const ip = (sdk.kids(h, 'address').find(a => a.attrs.addrtype === 'ipv4') || {}).attrs?.addr || '';
    if (!sdk.isIp(ip)) continue;
    const names = sdk.kids(sdk.kid(h, 'hostnames'), 'hostname').map(n => n.attrs.name).filter(Boolean);
    const matches = sdk.kids(sdk.kid(h, 'os'), 'osmatch').map(m => ({ name: m.attrs.name || '', accuracy: +m.attrs.accuracy || 0 })).sort((a, b) => b.accuracy - a.accuracy);
    const ports = [];
    for (const p of sdk.kids(sdk.kid(h, 'ports'), 'port')) {
      const state = sdk.kid(p, 'state');
      if (!state || state.attrs.state !== 'open') continue;
      const svc = sdk.kid(p, 'service');
      ports.push({ port: `${p.attrs.protocol || 'tcp'}/${p.attrs.portid}`, name: svc?.attrs.name || '', product: svc?.attrs.product || '', version: svc?.attrs.version || '' });
    }
    hosts.push({ ip, names, os: matches[0]?.name || '', accuracy: matches[0]?.accuracy || 0, ports });
  }
  return { hosts, args: root.attrs.args || '', at: root.attrs.startstr || '' };
}

// The applications of an asset, completed with the services Nmap saw (one per product, or per service
// name); ports as a list, the way the app saves them
function mergeApps(apps, ports) {
  const out = (apps || []).map(a => ({ ...a }));
  const portList = a => String(Array.isArray(a.ports) ? a.ports.join(', ') : a.ports || '').split(/[\s,;]+/).filter(Boolean);
  const groups = new Map();
  for (const p of ports) {
    const name = p.product || (p.name ? p.name.toUpperCase() : '') || `Service on ${p.port}`;
    const g = groups.get(name) || { name, version: p.version, ports: [] };
    g.ports.push(p.port); groups.set(name, g);
  }
  for (const g of groups.values()) {
    const known = out.find(a => String(a.name || '').toLowerCase() === g.name.toLowerCase() || portList(a).some(p => g.ports.includes(p)));
    if (known) {
      const ps = [...new Set([...portList(known), ...g.ports])];
      if (ps.length !== portList(known).length || !Array.isArray(known.ports)) known.ports = ps;
      if (!known.version && g.version) known.version = g.version;
    } else out.push({ name: g.name, version: g.version || '', ports: g.ports, src: 'nmap' });
  }
  return out;
}

export async function run(cfg, ctx) {
  const { state, sdk } = ctx;
  const sid = cfg.site, si = state.si[sid];
  if (!si) throw new sdk.ConnectorError('Choose the IS the scanned hosts belong to.');
  if (!ctx.file) throw new sdk.ConnectorError('This module imports an Nmap XML report: choose one.');
  const scan = parseNmap(ctx.file.text, sdk);
  if (!scan.hosts.length) throw new sdk.ConnectorError('The report holds no host that is up.');
  const work = JSON.parse(JSON.stringify(si));
  const idx = sdk.assetIndex(state, [sid]);
  const assets = {}, report = { hosts: scan.hosts.length, matched: 0, created: 0, updated: 0, unchanged: 0, skipped: [] };
  for (const h of scan.hosts) {
    const name = sdk.shortName(h.names[0] || '');
    const id = idx.find({ connector: 'nmap', ext: h.ip, name, ips: [h.ip], site: sid });
    const os = h.accuracy >= (+cfg.minAccuracy || 0) ? h.os : '';
    if (id) {
      report.matched++;
      const a = state.assets[id], next = { ...a, apps: mergeApps(a.apps, h.ports), ext: { ...(a.ext || {}), nmap: h.ip } };
      if (!next.ip) next.ip = h.ip;
      if (cfg.updateOs !== false && os && !next.os) next.os = os;
      if (JSON.stringify(next) === JSON.stringify(a)) { report.unchanged++; continue; }
      assets[id] = next; report.updated++;
    } else if (cfg.createAssets !== false) {
      const v = sdk.vlanForIp(work, h.ip) || sdk.holdingVlan(work, sid, 'To sort (Nmap scan)');
      const nid = `nmap-${sid}-${h.ip.replace(/\./g, '-')}`;
      assets[nid] = {
        site: sid, name: name || h.ip, type: typeOf(h.ports.map(p => p.port), h.os), vlan: v.id, ip: h.ip, os, role: '', crit: 2,
        vulns: [], contacts: [], apps: mergeApps([], h.ports), notes: `Found by Nmap${scan.at ? ` on ${scan.at}` : ''}${h.os && !os ? ` (OS guess: ${h.os}, ${h.accuracy}%)` : ''}`, ext: { nmap: h.ip },
      };
      report.created++;
    } else if (report.skipped.length < 40) report.skipped.push(`${h.ip}${name ? ` (${name})` : ''}: not on the map`);
  }
  const changes = { si: {}, assets };
  if (JSON.stringify(work) !== JSON.stringify(si)) changes.si[sid] = work;
  const summary = `${report.hosts} host(s) up in the scan: ${report.matched} on the map (${report.updated} updated), ${report.created} new.`;
  ctx.log(summary);
  return {
    proposals: Object.keys(assets).length ? [{
      siteId: sid,
      title: `Nmap: ${ctx.file.name} → ${si.name || sid}`,
      description: `${summary}${scan.args ? `\nScan: ${scan.args}` : ''}${changes.si[sid] ? '\nHosts outside every VLAN range wait in “To sort (Nmap scan)”.' : ''}\nOpen ports become listening ports of the applications; nothing is removed.`,
      changes,
    }] : [],
    report: { skipped: report.skipped },
    summary,
  };
}
