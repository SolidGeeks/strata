// SPDX-License-Identifier: AGPL-3.0-or-later
// phpIPAM → VLANs and addresses of the IS.
// API: /api/{app_id}/sections/, sections/{id}/subnets/, vlan/, tools/locations/, subnets/{id}/addresses/
// Authentication: the app code of an API application with "SSL with App code token" security (header
// "token"), or a user (POST /api/{app_id}/user/ returns a token).
import { request, ConnectorError, assetIndex, siteFor, parseRange, inRange, vlanForIp, isIp, pool, parseRules } from '../../sdk.js';

function client(cfg) {
  const base = String(cfg.url || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) throw new ConnectorError('Give the phpIPAM API URL (https://…/api).');
  if (!cfg.appId) throw new ConnectorError('Give the API application id.');
  if (!cfg.token && !(cfg.user && cfg.password)) throw new ConnectorError('Give the app code, or a user name and password.');
  const root = `${base}/${encodeURIComponent(cfg.appId)}`;
  let token = cfg.token || null;
  const login = async () => {
    const r = await request(`${root}/user/`, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(`${cfg.user}:${cfg.password}`).toString('base64') }, tls: cfg.tls });
    const j = r.json();
    if (!j.success || !j.data || !j.data.token) throw new ConnectorError(`phpIPAM refused the user: ${j.message || r.status}`);
    token = j.data.token;
  };
  return async (p) => {
    if (!token) await login();
    const r = await request(`${root}/${p}`, { headers: { token, 'phpipam-token': token }, tls: cfg.tls, timeoutMs: 60000 });
    let j; try { j = r.json(); } catch (e) { if (r.status === 401 || r.status === 403) throw new ConnectorError('phpIPAM refused the token.'); throw e; }
    if (j.success === false || (j.code && j.code >= 400)) {
      if (j.code === 404 || /no .*found|not found/i.test(j.message || '')) return [];
      if (j.code === 401 || j.code === 403) throw new ConnectorError(`phpIPAM refused access: ${j.message || j.code}`);
      throw new ConnectorError(`phpIPAM ${p}: ${j.message || j.code}`);
    }
    return j.data ?? [];
  };
}

export async function test(cfg) {
  const get = client(cfg);
  const s = await get('sections/');
  return `Connected: ${Array.isArray(s) ? s.length : 0} section(s).`;
}

export async function run(cfg, ctx) {
  const state = ctx.state;
  const get = client(cfg);
  const rules = parseRules(cfg.sectionRules);
  const arr = v => (Array.isArray(v) ? v : v && typeof v === 'object' ? Object.values(v) : []);
  const sections = arr(await get('sections/'));
  const vlans = Object.fromEntries(arr(await get('vlan/')).map(v => [String(v.vlanId ?? v.id), v]));
  let locations = {};
  try { locations = Object.fromEntries(arr(await get('tools/locations/')).map(l => [String(l.id), l.name || ''])); } catch { locations = {}; }
  const subnets = [];
  for (const s of sections) for (const n of arr(await get(`sections/${s.id}/subnets/`))) if (n.subnet && +n.isFolder !== 1) subnets.push({ ...n, sectionName: s.name || '' });

  // existing VLAN ranges of every IS
  const byCidr = {};
  for (const [sid, si] of Object.entries(state.si)) for (const v of si.vlans || []) { const r = parseRange(v.cidr); if (r) byCidr[`${r.lo}-${r.hi}`] = { sid, vid: v.id }; }

  const report = { subnets: subnets.length, mapped: 0, noSite: 0, noSiteSample: [], noVlan: 0, vlansNew: 0, vlansUpdated: 0, assetsUpdated: 0, assetsNew: 0, ipConflicts: [] };
  const work = {};
  const W = sid => (work[sid] = work[sid] || { si: JSON.parse(JSON.stringify(state.si[sid])), assets: {}, subnets: [] });
  for (const n of subnets) {
    const cidr = `${n.subnet}/${n.mask}`, r = parseRange(cidr);
    if (!r) continue;
    const known = byCidr[`${r.lo}-${r.hi}`];
    const label = [n.sectionName, locations[String(n.location)] || '', n.description || ''].join(' / ');
    const sid = known ? known.sid : siteFor(label, rules, state);
    if (!sid) { report.noSite++; if (report.noSiteSample.length < 15) report.noSiteSample.push(`${cidr} (${label.replace(/^ \/ | \/ $/g, '')})`); continue; }
    report.mapped++;
    const w = W(sid);
    const v = vlans[String(n.vlanId)] || null;
    let target = known ? w.si.vlans.find(x => x.id === known.vid) : null;
    if (!target && v) target = (w.si.vlans || []).find(x => +x.num === +v.number);
    if (target) {
      const before = JSON.stringify(target);
      if (!target.cidr) target.cidr = cidr;
      if (cfg.updateNames && v && v.name && target.name !== v.name) target.name = v.name;
      target.ext = { ...(target.ext || {}), ipam: String(n.id) };
      if (JSON.stringify(target) !== before) report.vlansUpdated++;
    } else if (v && cfg.createVlans !== false) {
      w.si.zones = w.si.zones && w.si.zones.length ? w.si.zones : [{ id: 'z-def', name: 'Main zone' }];
      let z = w.si.zones.find(x => x.id === `z-${sid}-imported`);
      if (!z) { z = { id: `z-${sid}-imported`, name: 'Imported' }; w.si.zones.push(z); }
      let id = `v-${sid}-${v.number}`; let k = 2; while (w.si.vlans.some(x => x.id === id)) id = `v-${sid}-${v.number}-${k++}`;
      target = { id, num: +v.number, name: v.name || n.description || `VLAN ${v.number}`, cidr, zone: z.id, ext: { ipam: String(n.id) } };
      w.si.vlans.push(target); report.vlansNew++;
    } else if (!v) { report.noVlan++; }
    w.subnets.push({ id: n.id, cidr, r, vlanId: target ? target.id : null });
  }

  // addresses: fill or check the IP of the assets, move them to the VLAN of their subnet
  for (const [sid, w] of Object.entries(work)) {
    const idx = assetIndex(state, [sid]);
    await pool(w.subnets, 4, async sn => {
      const addrs = arr(await get(`subnets/${sn.id}/addresses/`));
      for (const ad of addrs) {
        const ip = String(ad.ip || ad.ip_addr || '').trim(); if (!isIp(ip)) continue;
        const host = String(ad.hostname || '').trim();
        const id = idx.find({ connector: 'ipam', ext: ad.id, name: host, ips: [ip], site: sid });
        if (id) {
          const a = w.assets[id] || state.assets[id];
          const next = { ...a, ext: { ...(a.ext || {}), ipam: String(ad.id) } };
          if (!next.ip) next.ip = ip;
          else if (next.ip.trim() !== ip && host) report.ipConflicts.push(`${a.name}: ${next.ip} on the map, ${ip} in phpIPAM`);
          if (cfg.moveAssets !== false && sn.vlanId && next.vlan !== sn.vlanId && inRange(next.ip, sn.r)) next.vlan = sn.vlanId;
          if (JSON.stringify(next) !== JSON.stringify(state.assets[id])) w.assets[id] = next;
        } else if (cfg.createAssets && host && sn.vlanId) {
          const nid = `ipam-${sid}-${String(ad.id)}`.slice(0, 120);
          w.assets[nid] = { site: sid, name: host.split('.')[0], type: 'server', vlan: sn.vlanId, ip, os: '', role: String(ad.description || ''), crit: 2, vulns: [], contacts: [], apps: [], notes: `From phpIPAM${ad.mac ? ` · MAC ${ad.mac}` : ''}`, ext: { ipam: String(ad.id) } };
        }
      }
    });
    // assets already on the map whose IP lies in a subnet, even if phpIPAM does not list the address
    if (cfg.moveAssets !== false) for (const [id, a0] of Object.entries(state.assets)) {
      if (a0.site !== sid) continue;
      const a = w.assets[id] || a0;
      const sn = w.subnets.find(s => s.vlanId && inRange(a.ip, s.r));
      if (sn && a.vlan !== sn.vlanId && !vlanForIpExact(w.si, a)) w.assets[id] = { ...a, vlan: sn.vlanId };
    }
  }
  const proposals = [];
  for (const [sid, w] of Object.entries(work)) {
    const changes = { si: {}, assets: w.assets };
    if (JSON.stringify(w.si) !== JSON.stringify(state.si[sid])) changes.si[sid] = w.si;
    const nA = Object.keys(w.assets).length;
    report.assetsNew += Object.keys(w.assets).filter(id => !state.assets[id]).length;
    report.assetsUpdated += Object.keys(w.assets).filter(id => state.assets[id]).length;
    if (!nA && !Object.keys(changes.si).length) continue;
    proposals.push({
      siteId: sid,
      title: `phpIPAM: VLANs and addresses of ${state.si[sid]?.name || sid}`,
      description: `Read from phpIPAM on ${new Date().toLocaleString('en-GB')}: ${w.subnets.length} subnet(s). New VLANs go to the “Imported” zone: move them to their zone in “Zones, contacts”.${report.ipConflicts.length ? `\n\nIP addresses that differ (not changed):\n- ${report.ipConflicts.slice(0, 20).join('\n- ')}` : ''}`.slice(0, 4000),
      changes,
    });
  }
  report.ipConflicts = report.ipConflicts.slice(0, 30);
  return { proposals, report, summary: `${report.subnets} subnet(s) in phpIPAM, ${report.mapped} matched to an IS (${report.noSite} without); ${report.vlansNew} new VLAN(s), ${report.vlansUpdated} updated; ${report.assetsUpdated} asset(s) updated, ${report.assetsNew} new.` };
}
// true when the asset already sits on a VLAN whose own range holds its IP (a more specific range wins)
function vlanForIpExact(si, a) { const v = vlanForIp(si, a.ip); return !!v && v.id === a.vlan; }
