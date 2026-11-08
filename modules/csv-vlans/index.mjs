// SPDX-License-Identifier: AGPL-3.0-or-later
// CSV VLANs: a Strata connector module (see MODULES.md). It reads the VLANs of a CSV file (number, name,
// address range, and optionally a zone), lets people choose which ones to bring into an IS and the zone of
// each (preview, then the import with ctx.picks), and proposes the IS with those VLANs. Nothing changes on
// the map until an approver accepts the proposal. It needs no network.

const COLUMNS = {
  num: ['vlan', 'vlan id', 'vlanid', 'vid', 'vlan number', 'number', 'num', 'numero', 'n', 'no', 'tag'],
  name: ['name', 'nom', 'vlan name', 'description', 'desc', 'label', 'libelle'],
  cidr: ['cidr', 'subnet', 'network', 'prefix', 'range', 'reseau', 'sous reseau', 'plage', 'ip range', 'address range', 'prefixe', 'adresse'],
  zone: ['zone', 'group', 'groupe', 'vlan group'],
};

// Splits CSV text into rows, with quoted fields ("a; b" and "" for a quote) and the separator guessed
// from the first line
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

const vlanNum = v => { const m = /^\s*(?:vlan\s*)?(\d{1,4})\s*$/i.exec(String(v ?? '')); const n = m ? +m[1] : NaN; return n >= 1 && n <= 4094 ? n : null; };
const looksCidr = v => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(String(v || '').trim());

// The VLANs of the file: [{num, name, cidr, zone, line, warn}], and what was left out
export function readVlans(text, sdk) {
  const rows = parseCsv(text);
  if (!rows.length) throw new sdk.ConnectorError('The file is empty.');
  const head = rows[0].map(h => sdk.norm(h)), col = {};
  for (const [k, names] of Object.entries(COLUMNS)) { const i = head.findIndex(h => names.includes(h)); if (i >= 0) col[k] = i; }
  let body = rows.slice(1), first = 2;
  if (col.num === undefined) {
    // no header (or one we do not know): each column is told by what it holds, in the order the file has
    const sample = rows.slice(0, 50), width = Math.max(...sample.map(r => r.length));
    const share = (i, test) => sample.filter(r => r[i] && test(r[i])).length / Math.max(1, sample.filter(r => r[i]).length);
    for (let i = 0; i < width; i++) {
      if (col.cidr === undefined && share(i, looksCidr) > 0.6) col.cidr = i;
      else if (col.num === undefined && share(i, x => vlanNum(x) !== null) > 0.6) col.num = i;
      else if (col.name === undefined && share(i, x => !looksCidr(x) && vlanNum(x) === null) > 0.6) col.name = i;
    }
    if (col.num === undefined) throw new sdk.ConnectorError(`No column of VLAN numbers (1 to 4094) in this file. First line: ${rows[0].join(', ').slice(0, 120)}`);
    if (vlanNum(rows[0][col.num]) !== null) { body = rows; first = 1; }
  }
  const vlans = [], skipped = [], seen = new Set();
  body.forEach((r, i) => {
    const line = i + first, num = vlanNum(r[col.num]);
    if (num === null) { skipped.push(`Line ${line}: no VLAN number from 1 to 4094 (${String(r[col.num] ?? '').slice(0, 30) || 'empty'}).`); return; }
    if (seen.has(num)) { skipped.push(`Line ${line}: VLAN ${num} again, left out (the first one is kept).`); return; }
    seen.add(num);
    const cidr = col.cidr !== undefined ? String(r[col.cidr] || '').trim() : '', warn = [];
    if (cidr && !sdk.parseRange(cidr)) warn.push('range not understood');
    vlans.push({ num, name: (col.name !== undefined ? String(r[col.name] || '').trim() : '').slice(0, 50) || `VLAN ${num}`, cidr: cidr.slice(0, 60), zone: (col.zone !== undefined ? String(r[col.zone] || '').trim() : '').slice(0, 40), line, warn });
  });
  if (!vlans.length) throw new sdk.ConnectorError('No VLAN with a number from 1 to 4094 in this file.');
  return { vlans, skipped };
}

const zonesOf = si => (Array.isArray(si.zones) && si.zones.length ? si.zones : [{ id: 'z-def', name: 'Main zone' }]);

// Before the import: the VLANs of the file, ticked when new, with the zone the file or the IS suggests
export async function preview(cfg, ctx) {
  const { state, sdk } = ctx, si = state.si[cfg.site];
  if (!si) throw new sdk.ConnectorError('Choose the IS the VLANs go to.');
  const { vlans, skipped } = readVlans(ctx.file.text, sdk), zones = zonesOf(si);
  const have = new Map((si.vlans || []).map(v => [+v.num, v]));
  const items = vlans.map(v => {
    const ex = have.get(v.num), exZone = ex && zones.find(z => z.id === ex.zone);
    const same = ex && ex.name === v.name && (!v.cidr || ex.cidr === v.cidr);
    return {
      key: String(v.num), label: `VLAN ${v.num} · ${v.name}`, detail: v.cidr,
      tags: ex ? [same ? 'already in the IS, the same' : 'already in the IS: ticked, it is updated'] : [],
      warn: v.warn, on: !ex, zone: v.zone || (exZone ? exZone.name : ''),
    };
  });
  const n = items.filter(i => i.on).length;
  return { items, skipped, summary: `${vlans.length} VLAN(s) in ${ctx.file.name}, ${n} not yet in IS ${si.name || cfg.site}.` };
}

export async function run(cfg, ctx) {
  const { state, sdk } = ctx, sid = cfg.site, si = state.si[sid];
  if (!si) throw new sdk.ConnectorError('Choose the IS the VLANs go to.');
  if (!ctx.file) throw new sdk.ConnectorError('This module imports a CSV file: choose one.');
  const { vlans, skipped } = readVlans(ctx.file.text, sdk);
  const work = JSON.parse(JSON.stringify(si));
  work.zones = JSON.parse(JSON.stringify(zonesOf(si)));
  work.vlans = Array.isArray(work.vlans) ? work.vlans : [];
  const picks = ctx.picks, report = { skipped, warnings: [] }, newZones = [];
  // a zone by its id, or by its name ("new:<name>", or a name from the file or the settings): created when missing
  const zoneByName = name => {
    let z = work.zones.find(x => sdk.norm(x.name) === sdk.norm(name));
    if (!z) {
      let id = `z-csv-${sdk.slug(name)}`;
      for (let i = 2; work.zones.some(x => x.id === id); i++) id = `z-csv-${sdk.slug(name)}-${i}`;
      z = { id, name: String(name).slice(0, 40) };
      work.zones.push(z); newZones.push(z.name);
    }
    return z.id;
  };
  const zoneOf = (choice, fileZone, current) => {
    if (choice) {
      if (choice.startsWith('new:') && choice.slice(4).trim()) return zoneByName(choice.slice(4).trim());
      if (work.zones.some(z => z.id === choice)) return choice;
      report.warnings.push(`Zone ${choice} is not in the IS: the zone of the file or the default one is used.`);
    }
    if (fileZone) return zoneByName(fileZone);
    if (current) return current;
    if (cfg.defaultZone) return zoneByName(cfg.defaultZone);
    return work.zones[work.zones.length - 1].id;
  };
  let added = 0, updated = 0, same = 0;
  for (const v of vlans) {
    const pick = picks ? picks[String(v.num)] : null;
    if (picks && !pick) continue;
    const i = work.vlans.findIndex(x => +x.num === v.num), ex = i >= 0 ? work.vlans[i] : null;
    // without a choice (a script), a VLAN already in the IS is only updated when the settings say so
    if (ex && !picks && !cfg.updateExisting) { same++; continue; }
    const zone = zoneOf(pick && pick.zone, v.zone, ex && ex.zone);
    if (ex) {
      const next = { ...ex, name: v.name, zone };
      if (v.cidr && !v.warn.length) next.cidr = v.cidr;
      if (next.zone !== ex.zone) delete next.place;
      if (JSON.stringify(next) === JSON.stringify(ex)) { same++; continue; }
      work.vlans[i] = next; updated++;
    } else {
      let id = `v-csv-${sdk.slug(sid)}-${v.num}`;
      for (let k = 2; work.vlans.some(x => x.id === id); k++) id = `v-csv-${sdk.slug(sid)}-${v.num}-${k}`;
      work.vlans.push({ id, num: v.num, name: v.name, cidr: v.warn.length ? '' : v.cidr, zone });
      if (v.warn.length) report.warnings.push(`VLAN ${v.num}: range “${v.cidr}” not understood, left empty.`);
      added++;
    }
  }
  const summary = `${vlans.length} VLAN(s) read${picks ? `, ${Object.keys(picks).length} chosen` : ''}: ${added} to add, ${updated} to update${same ? `, ${same} unchanged` : ''}${newZones.length ? `; new zone(s): ${newZones.join(', ')}` : ''}.`;
  ctx.log(summary);
  const changed = added || updated;
  return {
    proposals: changed ? [{ siteId: sid, title: `VLANs from ${ctx.file.name}`, description: summary + (skipped.length ? ` ${skipped.length} line(s) left out.` : ''), changes: { si: { [sid]: work }, assets: {} } }] : [],
    summary,
    report,
  };
}
