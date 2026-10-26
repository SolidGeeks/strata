// SPDX-License-Identifier: AGPL-3.0-or-later
// Cyberwatch → vulnerabilities of the assets.
// API v3: GET /api/v3/vulnerabilities/servers (paginated list), then GET /api/v3/vulnerabilities/servers/{id}
// for each server that matches an asset of the map (its "cve_announcements": cve_code, score, level…).
// Authentication: HTTP Basic with the API access key and secret key (current Cyberwatch documentation), or
// the older "API Auth" HMAC-SHA256 signature for instances that still need it.
import crypto from 'node:crypto';
import { request, expectOk, pool, ConnectorError, assetIndex, isIp, firstIp } from '../../sdk.js';

const SEV_RANK = { none: 0, low: 1, med: 2, high: 3, crit: 4 };
const sevFromCvss = s => s >= 9 ? 'crit' : s >= 7 ? 'high' : s >= 4 ? 'med' : s > 0 ? 'low' : 'none';
function sevOf(c, score) {
  const l = String(c.level || c.severity || '').toLowerCase();
  if (/crit/.test(l)) return 'crit';
  if (/high/.test(l)) return 'high';
  if (/med/.test(l)) return 'med';
  if (/low/.test(l)) return 'low';
  return sevFromCvss(score ?? 0);
}
const scoreOf = c => {
  for (const v of [c.score, c.cvss_v3?.base_score, c.cvss_v3_score, c.cvss?.base_score, c.cvss_score, typeof c.cvss === 'number' ? c.cvss : null]) if (v !== undefined && v !== null && v !== '' && isFinite(+v)) return Math.round(+v * 10) / 10;
  return null;
};

// EPSS (probability of exploitation, 0 to 1) and presence on the CISA KEV list, when Cyberwatch gives them
const epssOf = c => {
  for (const v of [c.epss?.score, c.epss?.epss, typeof c.epss === 'object' ? null : c.epss, c.epss_score]) if (v !== undefined && v !== null && v !== '' && isFinite(+v) && +v >= 0) return +v > 1 ? Math.min(1, +v / 100) : +v;
  return null;
};
const kevOf = c => [c.cisa_kev, c.kev, c.known_exploited, c.exploited_in_the_wild, c.cisa?.kev].some(v => v === true || v === 'true' || v === 1);

function client(cfg) {
  const base = String(cfg.url || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) throw new ConnectorError('Give the Cyberwatch URL (https://…).');
  if (!cfg.accessKey || !cfg.secretKey) throw new ConnectorError('Give the API access key and secret key.');
  return async (p, query = {}) => {
    const qs = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== '')).toString();
    const uri = p + (qs ? `?${qs}` : '');
    const headers = { Accept: 'application/json' };
    if (cfg.auth === 'hmac') {
      const date = new Date().toUTCString(), type = 'application/json', md5 = '';
      const sig = crypto.createHmac('sha256', String(cfg.secretKey)).update(['GET', type, md5, uri, date].join(',')).digest('base64');
      Object.assign(headers, { Date: date, 'Content-Type': type, Authorization: `CyberWatch APIAuth-HMAC-SHA256 ${cfg.accessKey}:${sig}` });
    } else headers.Authorization = 'Basic ' + Buffer.from(`${cfg.accessKey}:${cfg.secretKey}`).toString('base64');
    const res = await request(base + uri, { headers, tls: cfg.tls, timeoutMs: 60000 });
    await expectOk(res, `Cyberwatch ${p}`);
    return res.json();
  };
}

export async function test(cfg) {
  const get = client(cfg);
  const ping = await get('/api/v3/ping');
  const list = await get(cfg.serversPath || '/api/v3/vulnerabilities/servers', { page: 1, per_page: 1 });
  return `Connected${ping && ping.uuid ? ` (instance ${String(ping.uuid).slice(0, 8)}…)` : ''}. ${Array.isArray(list) ? 'The server list answers.' : ''}`.trim();
}

const addrList = s => {
  const out = new Set();
  for (const a of [].concat(s.addresses || [], s.ip_addresses || [], s.address || [], s.ip || [])) {
    const v = typeof a === 'string' ? a : a && (a.value || a.address || a.ip);
    if (isIp(v)) out.add(v.trim()); else { const f = firstIp(v); if (f) out.add(f); }
  }
  return [...out];
};

export async function run(cfg, ctx) {
  const get = client(cfg);
  const state = ctx.state;
  const sites = cfg.sites && cfg.sites.length ? cfg.sites : null;
  const idx = assetIndex(state, sites);
  // 1. every server known to Cyberwatch
  const servers = [];
  for (let page = 1; page <= 500; page++) {
    const list = await get(cfg.serversPath || '/api/v3/vulnerabilities/servers', { page, per_page: 100 });
    const arr = Array.isArray(list) ? list : (list && Array.isArray(list.data) ? list.data : []);
    servers.push(...arr);
    if (arr.length < 100) break;
  }
  // 2. match them to assets
  const matched = [], unmatched = [];
  for (const s of servers) {
    const ips = addrList(s);
    const id = idx.find({ connector: 'cyberwatch', ext: s.id, name: s.hostname || s.name, ips });
    if (id) matched.push({ s, id }); else unmatched.push(s.hostname || s.name || `#${s.id}`);
  }
  // 3. their vulnerabilities
  const min = SEV_RANK[cfg.minLevel] ?? 2, cap = Math.max(1, Math.min(500, parseInt(cfg.maxPerAsset, 10) || 40));
  const changesBySite = {};
  let total = 0;
  await pool(matched, 6, async ({ s, id }) => {
    const d = await get(`${cfg.serversPath || '/api/v3/vulnerabilities/servers'}/${encodeURIComponent(s.id)}`);
    const list = (d && (d.cve_announcements || d.vulnerabilities || d.cves)) || [];
    const vulns = list
      .filter(c => cfg.includeIgnored || !(c.ignored === true || c.active === false))
      .map(c => { const score = scoreOf(c); const sev = sevOf(c, score); const v = { id: String(c.cve_code || c.code || c.id || ''), title: String(c.title || c.content || c.summary || '').replace(/\s+/g, ' ').slice(0, 160), cvss: score, sev, src: 'cyberwatch' }; const ep = epssOf(c); if (ep !== null) v.epss = Math.round(ep * 1e5) / 1e5; if (kevOf(c)) v.kev = true; return v; })
      .filter(v => v.id && SEV_RANK[v.sev] >= min)
      .sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || (b.cvss ?? 0) - (a.cvss ?? 0))
      .slice(0, cap);
    const a = state.assets[id];
    // Cyberwatch owns the CVE entries of the assets it scans; findings typed by hand ("Config.", notes…) stay
    const kept = (a.vulns || []).filter(v => v.src !== 'cyberwatch' && !/^CVE-\d{4}-\d+$/i.test(String(v.id || '')));
    const next = { ...a, vulns: [...vulns, ...kept], ext: { ...(a.ext || {}), cyberwatch: s.id } };
    if (!next.os && d && d.os && (d.os.name || typeof d.os === 'string')) next.os = String(d.os.name || d.os);
    if (JSON.stringify(next) !== JSON.stringify(a)) {
      (changesBySite[a.site] = changesBySite[a.site] || { assets: {}, n: 0, cves: 0 });
      changesBySite[a.site].assets[id] = next; changesBySite[a.site].n++; changesBySite[a.site].cves += vulns.length;
    }
    total += vulns.length;
  });
  const proposals = Object.entries(changesBySite).map(([siteId, c]) => ({
    siteId,
    title: `Cyberwatch: vulnerabilities of ${state.si[siteId]?.name || siteId} (${c.n} asset${c.n > 1 ? 's' : ''})`,
    description: `Vulnerabilities read from Cyberwatch on ${new Date().toLocaleString('en-GB')}.\n${c.cves} CVE${c.cves > 1 ? 's' : ''} at “${cfg.minLevel || 'med'}” severity or above, at most ${cap} per asset. Findings entered by hand (not CVE) are kept.`,
    changes: { si: {}, assets: c.assets },
  }));
  return {
    proposals,
    report: { servers: servers.length, matched: matched.length, unmatched: unmatched.length, unmatchedSample: unmatched.slice(0, 15), cves: total },
    summary: `${servers.length} server(s) in Cyberwatch, ${matched.length} matched to an asset, ${unmatched.length} not found on the map; ${total} CVE(s) kept.`,
  };
}
