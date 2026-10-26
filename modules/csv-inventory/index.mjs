// SPDX-License-Identifier: AGPL-3.0-or-later
// CSV inventory: an example Strata connector module (see MODULES.md). It imports assets from a CSV file
// into one IS, as a proposal: new assets are created, those already on the map (same name or IP) are
// updated. It only uses what Strata gives it: the map (ctx.state), the file (ctx.file) and the SDK
// (ctx.sdk). It needs no network.

const TYPES = {
  server: 'server', srv: 'server', serveur: 'server', 'domain controller': 'dc', dc: 'dc', database: 'db', db: 'db',
  hypervisor: 'hypervisor', storage: 'hypervisor', firewall: 'firewall', fw: 'firewall', gateway: 'gateway', vpn: 'gateway',
  router: 'router', switch: 'switch', 'load balancer': 'switch', workstation: 'workstation', pc: 'workstation', laptop: 'workstation',
  printer: 'printer', imprimante: 'printer', phone: 'phone', ap: 'ap', 'access point': 'ap', camera: 'camera', plc: 'plc', iot: 'iot',
};
const COLUMNS = {
  name: ['name', 'hostname', 'host', 'nom', 'asset'], ip: ['ip', 'ip address', 'address', 'adresse ip'], type: ['type', 'kind'],
  os: ['os', 'system', 'operating system', 'système'], role: ['role', 'rôle', 'description', 'function'], vlan: ['vlan'],
  crit: ['criticality', 'crit', 'criticité'], notes: ['notes', 'comment', 'comments'],
};

// Splits CSV text into rows, with quoted fields ("a, b" and "" for a quote) and the separator guessed
// from the header line
export function parseCsv(text) {
  text = String(text).replace(/^﻿/, '');
  const head = text.split(/\r?\n/, 1)[0];
  const sep = [';', '\t', ','].map(c => [c, head.split(c).length]).sort((a, b) => b[1] - a[1])[0][0];
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; continue; }
    if (c === '"' && cell === '') q = true;
    else if (c === sep) { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; }
    else cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return rows.map(r => r.map(x => x.trim())).filter(r => r.some(Boolean));
}

const critOf = v => { const s = String(v || '').toLowerCase(); if (/^[123]$/.test(s)) return +s; if (/high|haute|élev|crit/.test(s)) return 3; if (/med|moy/.test(s)) return 2; if (/low|faible|bas/.test(s)) return 1; return 0; };

export async function run(cfg, ctx) {
  const { state, sdk } = ctx;
  const sid = cfg.site, si = state.si[sid];
  if (!si) throw new sdk.ConnectorError('Choose the IS the assets belong to.');
  if (!ctx.file) throw new sdk.ConnectorError('This module imports a CSV file: choose one.');
  const rows = parseCsv(ctx.file.text);
  if (rows.length < 2) throw new sdk.ConnectorError('The file has no line under its header.');
  const header = rows[0].map(h => sdk.norm(h));
  const col = {};
  for (const [k, names] of Object.entries(COLUMNS)) { const i = header.findIndex(h => names.some(n => sdk.norm(n) === h)); if (i >= 0) col[k] = i; }
  if (col.name === undefined) throw new sdk.ConnectorError(`No “name” column in the header (${rows[0].join(', ')}).`);

  const work = JSON.parse(JSON.stringify(si));
  const idx = sdk.assetIndex(state, [sid]);
  const assets = {}, report = { lines: rows.length - 1, created: 0, updated: 0, unchanged: 0, skipped: [] };
  const vlanOf = (v, ip) => {
    const t = String(v || '').trim();
    if (t) { const hit = (work.vlans || []).find(x => String(x.num) === t || sdk.norm(x.name) === sdk.norm(t) || x.id === t); if (hit) return hit.id; }
    const byIp = sdk.vlanForIp(work, ip); if (byIp) return byIp.id;
    return sdk.holdingVlan(work, sid, 'To sort (CSV import)').id;
  };
  const seen = new Set();
  rows.slice(1).forEach((r, n) => {
    const get = k => (col[k] === undefined ? '' : String(r[col[k]] || '').trim());
    const name = get('name'), ip = sdk.firstIp(get('ip'));
    if (!name) { report.skipped.push(`Line ${n + 2}: no name`); return; }
    const key = sdk.slug(name);
    if (seen.has(key)) { report.skipped.push(`Line ${n + 2}: ${name} is listed twice`); return; }
    seen.add(key);
    const type = TYPES[sdk.norm(get('type'))] || (get('type') ? null : cfg.defaultType || 'server');
    if (!type) report.skipped.push(`Line ${n + 2}: type “${get('type')}” unknown, ${cfg.defaultType || 'server'} used`);
    const id = idx.find({ connector: 'csv', ext: key, name, ips: ip ? [ip] : [], site: sid });
    const crit = critOf(get('crit'));
    if (id) {
      if (!cfg.updateExisting) { report.unchanged++; return; }
      const a = state.assets[id], next = { ...a, ext: { ...(a.ext || {}), csv: key } };
      if (ip) next.ip = ip;
      if (get('type') && type) next.type = type;
      for (const k of ['os', 'role', 'notes']) if (get(k)) next[k] = get(k);
      if (crit) next.crit = crit;
      if (get('vlan')) next.vlan = vlanOf(get('vlan'), next.ip);
      if (JSON.stringify(next) === JSON.stringify(a)) { report.unchanged++; return; }
      assets[id] = next; report.updated++;
    } else {
      const nid = `csv-${sid}-${key}`.slice(0, 120);
      assets[nid] = {
        site: sid, name, type: type || cfg.defaultType || 'server', vlan: vlanOf(get('vlan'), ip), ip, os: get('os'), role: get('role'),
        crit: crit || 2, vulns: [], contacts: [], apps: [], notes: get('notes') || `From ${ctx.file.name}`, ext: { csv: key },
      };
      report.created++;
    }
  });
  const changes = { si: {}, assets };
  if (JSON.stringify(work) !== JSON.stringify(si)) changes.si[sid] = work;
  const summary = `${report.lines} line(s) read: ${report.created} new asset(s), ${report.updated} updated, ${report.unchanged} unchanged${report.skipped.length ? `, ${report.skipped.length} remark(s)` : ''}.`;
  ctx.log(summary);
  return {
    proposals: Object.keys(assets).length ? [{
      siteId: sid,
      title: `CSV inventory: ${ctx.file.name} → ${si.name || sid}`,
      description: `${summary}${changes.si[sid] ? '\nAssets without a VLAN wait in “To sort (CSV import)”: move them where they belong.' : ''}${report.skipped.length ? `\n\n- ${report.skipped.slice(0, 30).join('\n- ')}` : ''}`,
      changes,
    }] : [],
    report: { skipped: report.skipped.slice(0, 40) },
    summary,
  };
}
