// SPDX-License-Identifier: AGPL-3.0-or-later
// NetBox: reads the devices, virtual machines, VLANs and prefixes of NetBox (REST API, read-only token)
// and proposes them for each IS. A NetBox site goes to an IS through rules (or the IS whose name
// appears in it). VLANs are matched by number and get their prefix as range; devices and virtual
// machines are matched to assets (link kept in ext.netbox, then name, then primary IPv4), and fill in
// the address, system and type the asset lacks. Nothing typed by hand is overwritten, nothing removed.

const TYPES = [
  [/firewall|\bfw\b/i, 'firewall'], [/router|\bcore\b/i, 'router'], [/switch|load.?balancer/i, 'switch'], [/vpn|gateway/i, 'gateway'],
  [/domain.?controller|\bdc\b|active.?directory/i, 'dc'], [/database|\bdb\b|sql/i, 'db'], [/hypervisor|esx|proxmox|storage|san|nas/i, 'hypervisor'],
  [/access.?point|wi-?fi|\bap\b/i, 'ap'], [/printer/i, 'printer'], [/phone|voip/i, 'phone'], [/camera|cctv/i, 'camera'],
  [/plc|scada|ics/i, 'plc'], [/workstation|desktop|laptop|\bpc\b/i, 'workstation'], [/iot|sensor|pdu|ups/i, 'iot'],
];
const typeOf = role => { for (const [re, t] of TYPES) if (re.test(role || '')) return t; return 'server'; };
const name = o => (o && (o.name || o.display || o.slug)) || '';

function client(cfg, sdk) {
  const base = String(cfg.url || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) throw new sdk.ConnectorError('Give the NetBox address, starting with https://');
  const origin = new URL(base).origin;
  const headers = { Authorization: `Token ${cfg.token}`, Accept: 'application/json' };
  const get = async url => {
    const res = await sdk.request(url, { headers, tls: cfg.tls, timeoutMs: 60000 });
    await sdk.expectOk(res, 'NetBox');
    return res.json();
  };
  return {
    status: () => get(`${base}/api/status/`),
    // every object of a list, page after page (NetBox gives the next page's address)
    async all(path, query = '') {
      const out = [];
      let url = `${base}/api/${path}/?limit=${Math.max(1, Math.min(1000, +cfg.pageSize || 500))}${query}`;
      for (let n = 0; url && n < 1000; n++) {
        const page = await get(url);
        if (!page || !Array.isArray(page.results)) throw new sdk.ConnectorError(`NetBox answered ${path} without a list of results.`);
        out.push(...page.results);
        // NetBox behind a proxy may give another host in "next": keep the one of the settings
        url = page.next ? origin + (n => n.pathname + n.search)(new URL(page.next, base)) : null;
      }
      return out;
    },
  };
}

export async function test(cfg, { sdk }) {
  const s = await client(cfg, sdk).status();
  if (!s || !s['netbox-version']) throw new sdk.ConnectorError('This address does not answer like NetBox (no /api/status/).');
  return `Connected to NetBox ${s['netbox-version']}.`;
}

export async function run(cfg, ctx) {
  const { state, sdk } = ctx;
  const nb = client(cfg, sdk);
  const rules = sdk.parseRules(cfg.siteRules);
  const statuses = new Set(Array.isArray(cfg.statuses) && cfg.statuses.length ? cfg.statuses : ['active', 'staged']);
  const [sites, vlans, prefixes, devices, vms] = await Promise.all([
    nb.all('dcim/sites'), nb.all('ipam/vlans'), nb.all('ipam/prefixes'), nb.all('dcim/devices'),
    cfg.includeVms === false ? [] : nb.all('virtualization/virtual-machines'),
  ]);

  // NetBox site → IS
  const isOf = new Map(), report = { sites: sites.length, mapped: 0, noSite: 0, noSiteSample: [], vlansNew: 0, vlansUpdated: 0, assetsNew: 0, assetsUpdated: 0, skipped: [] };
  for (const s of sites) {
    const sid = sdk.siteFor([s.name, s.slug, name(s.region)].filter(Boolean).join(' / '), rules, state);
    if (sid) { isOf.set(s.id, sid); report.mapped++; } else { report.noSite++; if (report.noSiteSample.length < 15) report.noSiteSample.push(s.name || s.slug); }
  }
  const work = {};
  const W = sid => (work[sid] = work[sid] || { si: JSON.parse(JSON.stringify(state.si[sid])), assets: {} });

  // VLANs, with the range of the prefix tied to them
  const cidrOf = new Map();
  for (const p of prefixes) if (p.vlan && p.vlan.id && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(p.prefix || '')) cidrOf.set(p.vlan.id, p.prefix);
  for (const v of vlans) {
    const sid = v.site && isOf.get(v.site.id);
    if (!sid) continue;
    const w = W(sid), cidr = cidrOf.get(v.id) || '';
    w.si.vlans = w.si.vlans || [];
    let t = w.si.vlans.find(x => x.ext && String(x.ext.netbox) === String(v.id)) || w.si.vlans.find(x => +x.num === +v.vid);
    if (t) {
      const before = JSON.stringify(t);
      if (!t.cidr && cidr) t.cidr = cidr;
      t.ext = { ...(t.ext || {}), netbox: String(v.id) };
      if (JSON.stringify(t) !== before) report.vlansUpdated++;
    } else if (cfg.createVlans !== false) {
      w.si.zones = w.si.zones && w.si.zones.length ? w.si.zones : [{ id: 'z-def', name: 'Main zone' }];
      let z = w.si.zones.find(x => x.id === `z-${sid}-imported`);
      if (!z) { z = { id: `z-${sid}-imported`, name: 'Imported' }; w.si.zones.push(z); }
      let id = `v-${sid}-${v.vid}`, k = 2; while (w.si.vlans.some(x => x.id === id)) id = `v-${sid}-${v.vid}-${k++}`;
      w.si.vlans.push({ id, num: +v.vid, name: v.name || `VLAN ${v.vid}`, cidr, zone: z.id, ext: { netbox: String(v.id) } });
      report.vlansNew++;
    }
  }

  // devices and virtual machines
  const idxBySite = new Map();
  const items = [...devices.map(d => ({ d, vm: false })), ...vms.map(d => ({ d, vm: true }))];
  for (const { d, vm } of items) {
    const st = d.status && (d.status.value || d.status);
    if (st && !statuses.has(String(st))) continue;
    const sid = d.site && isOf.get(d.site.id);
    if (!sid) continue;
    const w = W(sid);
    if (!idxBySite.has(sid)) idxBySite.set(sid, sdk.assetIndex(state, [sid]));
    const ip = sdk.firstIp(d.primary_ip4 && d.primary_ip4.address), key = `${vm ? 'vm' : 'device'}:${d.id}`;
    const role = name(d.role || d.device_role), os = name(d.platform);
    const id = idxBySite.get(sid).find({ connector: 'netbox', ext: key, name: d.name, ips: ip ? [ip] : [], site: sid });
    if (id) {
      const a = w.assets[id] || state.assets[id], next = { ...a, ext: { ...(a.ext || {}), netbox: key } };
      if (!next.ip && ip) next.ip = ip;
      if (!next.os && os) next.os = os;
      if (!next.role && role) next.role = role;
      if (JSON.stringify(next) !== JSON.stringify(state.assets[id])) { w.assets[id] = next; report.assetsUpdated++; }
    } else if (cfg.createAssets !== false) {
      if (!d.name && !ip) continue;
      const v = sdk.vlanForIp(w.si, ip) || sdk.holdingVlan(w.si, sid, 'To sort (NetBox)');
      const nid = `netbox-${sid}-${vm ? 'vm' : 'dev'}-${d.id}`;
      w.assets[nid] = {
        site: sid, name: sdk.shortName(d.name) || ip, type: typeOf(role), vlan: v.id, ip, os, role, crit: 2,
        vulns: [], contacts: [], apps: [], notes: `From NetBox${vm ? ' (virtual machine)' : ''}${d.serial ? ` · serial ${d.serial}` : ''}`, ext: { netbox: key },
      };
      report.assetsNew++;
    }
  }

  const proposals = [];
  for (const [sid, w] of Object.entries(work)) {
    const changes = { si: {}, assets: w.assets };
    if (JSON.stringify(w.si) !== JSON.stringify(state.si[sid])) changes.si[sid] = w.si;
    if (!Object.keys(w.assets).length && !Object.keys(changes.si).length) continue;
    proposals.push({
      siteId: sid,
      title: `NetBox: ${state.si[sid].name || sid}`,
      description: `Read from NetBox: VLANs, prefixes, devices${cfg.includeVms === false ? '' : ' and virtual machines'} of the sites that belong to this IS. New VLANs go to the “Imported” zone; devices outside every VLAN range wait in “To sort (NetBox)”. Nothing typed by hand is overwritten.`,
      changes,
    });
  }
  const summary = `${report.sites} NetBox site(s), ${report.mapped} matched to an IS (${report.noSite} without); ${report.vlansNew} new VLAN(s), ${report.vlansUpdated} updated; ${report.assetsNew} new asset(s), ${report.assetsUpdated} updated.`;
  return { proposals, report, summary };
}
