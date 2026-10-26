// SPDX-License-Identifier: AGPL-3.0-or-later
// Connector simulator: fake Cyberwatch, GLPI, phpIPAM, PAN-OS and NetBox APIs on http://localhost:8099, with data
// that matches the Lyon IS of the demo. Use it to try the connectors before plugging in the real tools:
//   node scripts/connector-sim.mjs
// then, in Collaboration > Connectors > Settings (credentials of the simulator):
//   Cyberwatch  http://localhost:8099/cw              access key AK, secret key SK
//   GLPI        http://localhost:8099/glpi/apirest.php App-Token APP, user token UT, rule "Lyon = lyon"
//   phpIPAM     http://localhost:8099/ipam/api        app id strata, token TK
//   Palo Alto   http://localhost:8099/pan             API key KEY123, IS lyon, firewall lyo-fw-edge
//   NetBox      http://localhost:8099/netbox          API token NBT (NetBox module, from the store)
import http from 'node:http';
const B = s => 'Basic ' + Buffer.from(s).toString('base64');
const j = (res, code, o, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...h }); res.end(JSON.stringify(o)); };
const x = (res, code, s) => { res.writeHead(code, { 'Content-Type': 'application/xml' }); res.end(s); };

/* Cyberwatch */
const CW = [
  { id: 101, hostname: 'web-01.lyon.example.com', addresses: ['10.10.10.11'], cves: [['CVE-2023-44487', 7.5, 'level_high'], ['CVE-2024-6387', 8.1, 'level_high'], ['CVE-2023-38408', 9.8, 'level_critical'], ['CVE-2022-1234', 3.1, 'level_low']] },
  { id: 102, hostname: 'APP-ERP', addresses: [{ value: '10.20.0.20' }], cves: [['CVE-2021-44228', 10, 'level_critical'], ['CVE-2022-22965', 9.8, 'level_critical', true]] },
  { id: 103, hostname: 'unknown-host', addresses: ['10.20.0.250'], cves: [['CVE-2020-0001', 7.0, 'level_high']] },
  { id: 104, hostname: 'srv-x', addresses: ['172.11.20.10'], cves: [['CVE-2023-4863', 8.8, 'level_high']] },
];
/* GLPI */
const GL = {
  Location: [{ id: 1, name: 'Building A', completename: 'France > Lyon > Building A' }, { id: 2, name: 'Madrid', completename: 'Spain > Madrid' }],
  Group: [{ id: 5, name: 'Infra', completename: 'IT > Infra Lyon' }],
  ComputerType: [{ id: 1, name: 'Server' }, { id: 2, name: 'Laptop' }],
  NetworkEquipmentType: [{ id: 1, name: 'Switch' }, { id: 2, name: 'Firewall' }],
  Computer: [
    { id: 11, name: 'web-01', locations_id: 1, users_id_tech: 7, groups_id_tech: 5, computertypes_id: 1, serial: 'SN-W01' },
    { id: 12, name: 'srv-print-01', locations_id: 1, users_id_tech: 7, groups_id_tech: 5, computertypes_id: 1, serial: 'SN-P01' },
    { id: 13, name: 'lab-pc-9', locations_id: 1, users_id_tech: 0, groups_id_tech: 0, computertypes_id: 2 },
    { id: 14, name: 'mad-pc-1', locations_id: 2, users_id_tech: 0, groups_id_tech: 0, computertypes_id: 2 },
  ],
  NetworkEquipment: [{ id: 21, name: 'fw-lab', locations_id: 1, users_id_tech: 7, groups_id_tech: 5, networkequipmenttypes_id: 2 }],
  Printer: [],
  Software: { 1: 'Nginx', 2: 'OpenSSL', 3: 'KB5034441', 4: 'CUPS' }, SoftwareVersion: { 10: '1.24.0', 20: '3.0.2', 30: '1', 40: '2.4.1' },
  sw: { 11: [[1, 10], [2, 20], [3, 30]], 12: [[4, 40], [2, 20]], 13: [] },
  ip: { 11: '10.10.10.11', 12: '10.20.0.50', 13: '10.99.1.5', 14: '192.168.7.7', 21: '10.40.0.99' },
  os: { 11: ['Ubuntu', '24.04'], 12: ['Windows Server', '2022'], 13: ['Windows', '11'] },
};
/* phpIPAM */
const IPAM = {
  sections: [{ id: 1, name: 'Lyon' }, { id: 2, name: 'Lab Madrid' }],
  vlans: [{ vlanId: 1, number: 20, name: 'SRV' }, { vlanId: 2, number: 60, name: 'Lab' }, { vlanId: 3, number: 30, name: 'USERS' }],
  subnets: { 1: [{ id: 100, subnet: '10.20.0.0', mask: '24', vlanId: 1, description: 'Servers' }, { id: 101, subnet: '10.60.0.0', mask: '24', vlanId: 2, description: 'Lab' }, { id: 102, subnet: '10.30.0.0', mask: '23', vlanId: 3 }, { id: 103, subnet: '10.70.0.0', mask: '24', vlanId: 0, description: 'no vlan' }], 2: [{ id: 200, subnet: '192.168.7.0', mask: '24', vlanId: 0 }] },
  addresses: { 100: [{ id: 1, ip: '10.20.0.50', hostname: 'srv-print-01' }, { id: 2, ip: '10.20.0.21', hostname: 'db-erp.lyon' }, { id: 4, ip: '10.20.0.99', hostname: 'new-host' }], 101: [{ id: 3, ip: '10.60.0.10', hostname: 'lab-pc-9' }], 102: [] },
};
const PAN = `<?xml version="1.0"?>
<config version="10.2.0"><shared><address><entry name="eset-update"><fqdn>update.eset.com</fqdn></entry></address></shared>
<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<address>
 <entry name="web-01"><ip-netmask>10.10.10.11</ip-netmask></entry>
 <entry name="web-02"><ip-netmask>10.10.10.12/32</ip-netmask></entry>
 <entry name="rproxy"><ip-netmask>10.10.10.30</ip-netmask></entry>
 <entry name="bastion"><ip-netmask>10.40.0.10</ip-netmask></entry>
 <entry name="lan-users"><ip-netmask>10.30.0.0/23</ip-netmask></entry>
 <entry name="srv-net"><ip-netmask>10.20.0.0/24</ip-netmask></entry>
 <entry name="ubuntu-archive"><fqdn>archive.ubuntu.com</fqdn></entry>
 <entry name="ubuntu-security"><fqdn>security.ubuntu.com</fqdn></entry>
 <entry name="partner-sftp"><ip-netmask>203.0.113.10</ip-netmask></entry>
 <entry name="ghost"><ip-netmask>10.20.0.240</ip-netmask></entry>
</address>
<address-group>
 <entry name="web-servers"><static><member>web-01</member><member>web-02</member></static></entry>
 <entry name="ubuntu-mirrors"><static><member>ubuntu-archive</member><member>ubuntu-security</member></static></entry>
 <entry name="dyn-tagged"><dynamic><filter>'quarantine'</filter></dynamic></entry>
</address-group>
<service><entry name="tcp-8443"><protocol><tcp><port>8443</port></tcp></protocol></entry><entry name="web-alt"><protocol><tcp><port>8080,8443</port></tcp></protocol></entry></service>
<service-group><entry name="web-svcs"><members><member>tcp-8443</member><member>service-https</member></members></entry></service-group>
<rulebase><security><rules>
 <entry name="in-web"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>any</member></source><destination><member>rproxy</member></destination><service><member>service-https</member></service><application><member>any</member></application><action>allow</action></entry>
 <entry name="rp-to-web"><from><member>dmz</member></from><to><member>dmz</member></to><source><member>rproxy</member></source><destination><member>web-servers</member></destination><service><member>tcp-8443</member></service><application><member>any</member></application><action>allow</action></entry>
 <entry name="admin-ssh"><from><member>untrust</member></from><to><member>admin</member></to><source><member>any</member></source><destination><member>bastion</member></destination><service><member>application-default</member></service><application><member>ssh</member></application><action>allow</action><description>temporary vendor access</description></entry>
 <entry name="av-updates"><from><member>trust</member></from><to><member>untrust</member></to><source><member>lan-users</member></source><destination><member>eset-update</member></destination><service><member>application-default</member></service><application><member>ssl</member><member>web-browsing</member></application><action>allow</action></entry>
 <entry name="srv-updates"><from><member>trust</member></from><to><member>untrust</member></to><source><member>srv-net</member></source><destination><member>ubuntu-mirrors</member></destination><service><member>service-http</member></service><application><member>any</member></application><action>allow</action></entry>
 <entry name="sftp-partner"><from><member>trust</member></from><to><member>untrust</member></to><source><member>web-01</member></source><destination><member>partner-sftp</member></destination><service><member>tcp-22</member></service><application><member>any</member></application><action>allow</action></entry>
 <entry name="trust-any"><from><member>trust</member></from><to><member>trust</member></to><source><member>any</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>allow</action></entry>
 <entry name="ghost-rule"><from><member>trust</member></from><to><member>trust</member></to><source><member>ghost</member></source><destination><member>web-01</member></destination><service><member>service-https</member></service><action>allow</action></entry>
 <entry name="quarantine"><from><member>trust</member></from><to><member>untrust</member></to><source><member>dyn-tagged</member></source><destination><member>any</member></destination><service><member>any</member></service><action>deny</action></entry>
 <entry name="old"><from><member>trust</member></from><to><member>untrust</member></to><source><member>web-02</member></source><destination><member>partner-sftp</member></destination><service><member>tcp-22</member></service><action>allow</action><disabled>yes</disabled></entry>
</rules></security></rulebase></entry></vsys></entry></devices></config>`;
export { PAN };

/* NetBox (4.x layout: device role in "role", sites by slug; paginated 2 by 2 to exercise "next") */
const NB = {
  sites: [{ id: 1, name: 'Lyon HQ', slug: 'lyon-hq', region: { name: 'France' } }, { id: 2, name: 'Oslo office', slug: 'oslo', region: { name: 'Norway' } }],
  vlans: [{ id: 10, vid: 20, name: 'SRV', site: { id: 1, name: 'Lyon HQ', slug: 'lyon-hq' } }, { id: 11, vid: 70, name: 'LAB-NB', site: { id: 1, name: 'Lyon HQ', slug: 'lyon-hq' } }, { id: 12, vid: 5, name: 'OSLO', site: { id: 2, name: 'Oslo office', slug: 'oslo' } }],
  prefixes: [{ id: 1, prefix: '10.20.0.0/24', vlan: { id: 10, vid: 20, name: 'SRV' } }, { id: 2, prefix: '10.70.0.0/24', vlan: { id: 11, vid: 70, name: 'LAB-NB' } }],
  devices: [
    { id: 1, name: 'app-erp', status: { value: 'active' }, role: { name: 'Application server', slug: 'app-server' }, platform: { name: 'RHEL 9' }, site: { id: 1, name: 'Lyon HQ', slug: 'lyon-hq' }, primary_ip4: { address: '10.20.0.20/24' }, serial: 'SN-ERP' },
    { id: 2, name: 'nb-sw-70', status: { value: 'active' }, role: { name: 'Access switch', slug: 'switch' }, platform: null, site: { id: 1, name: 'Lyon HQ', slug: 'lyon-hq' }, primary_ip4: { address: '10.70.0.2/24' } },
    { id: 3, name: 'old-box', status: { value: 'decommissioning' }, role: { name: 'Server', slug: 'server' }, site: { id: 1, name: 'Lyon HQ', slug: 'lyon-hq' }, primary_ip4: { address: '10.20.0.250/24' } },
    { id: 4, name: 'oslo-fw', status: { value: 'active' }, role: { name: 'Firewall', slug: 'firewall' }, site: { id: 2, name: 'Oslo office', slug: 'oslo' }, primary_ip4: { address: '10.5.0.1/24' } },
  ],
  vms: [{ id: 7, name: 'vm-reports', status: { value: 'active' }, role: null, platform: { name: 'Ubuntu 24.04' }, site: { id: 1, name: 'Lyon HQ', slug: 'lyon-hq' }, primary_ip4: { address: '10.20.0.77/24' } }],
};
const NB_PATHS = { 'dcim/sites': 'sites', 'ipam/vlans': 'vlans', 'ipam/prefixes': 'prefixes', 'dcim/devices': 'devices', 'virtualization/virtual-machines': 'vms' };

const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'), p = u.pathname, auth = req.headers.authorization || '';
  // Cyberwatch
  if (p.startsWith('/cw/')) {
    if (auth !== B('AK:SK') && !/^CyberWatch APIAuth-HMAC-SHA256 AK:/.test(auth)) return j(res, 401, { error: 'unauthorized' });
    if (p === '/cw/api/v3/ping') return j(res, 200, { uuid: 'abcd1234-ffff' });
    if (p === '/cw/api/v3/vulnerabilities/servers') { const page = +u.searchParams.get('page') || 1, per = +u.searchParams.get('per_page') || 100; return j(res, 200, CW.slice((page - 1) * per, page * per).map(s => ({ id: s.id, hostname: s.hostname, addresses: s.addresses, cve_announcements_count: s.cves.length }))); }
    const m = /^\/cw\/api\/v3\/vulnerabilities\/servers\/(\d+)$/.exec(p);
    if (m) { const s = CW.find(x => x.id === +m[1]); return s ? j(res, 200, { id: s.id, hostname: s.hostname, os: { name: 'Ubuntu 22.04' }, cve_announcements: s.cves.map(([c, sc, l, ign]) => ({ cve_code: c, score: sc, level: l, ignored: !!ign, active: true, content: `Description of ${c}`, epss: Math.round(sc * 9) / 100, cisa_kev: sc >= 9.8 })) }) : j(res, 404, {}); }
    return j(res, 404, {});
  }
  // GLPI
  if (p.startsWith('/glpi/apirest.php')) {
    const r = p.slice('/glpi/apirest.php/'.length).replace(/\/$/, '');
    if (req.headers['app-token'] !== 'APP') return j(res, 400, ['ERROR_WRONG_APP_TOKEN_PARAMETER', 'missing app token']);
    if (r === 'initSession') return auth === 'user_token UT' ? j(res, 200, { session_token: 'S1' }) : j(res, 401, ['ERROR_GLPI_LOGIN_USER_TOKEN', 'bad token']);
    if (req.headers['session-token'] !== 'S1') return j(res, 401, ['ERROR_SESSION_TOKEN_INVALID', '']);
    if (r === 'killSession') return j(res, 200, {});
    const seg = r.split('/');
    const exp = u.searchParams.get('expand_dropdowns') === 'true';
    const range = (u.searchParams.get('range') || '0-49').split('-').map(Number);
    if (seg.length === 1 && GL[seg[0]] && Array.isArray(GL[seg[0]])) { const all = GL[seg[0]]; const sl = all.slice(range[0], range[1] + 1); if (range[0] >= all.length && all.length) return j(res, 400, ['ERROR_RANGE_EXCEED_TOTAL', '']); return j(res, sl.length < all.length ? 206 : 200, sl, { 'Content-Range': `${range[0]}-${range[1]}/${all.length}` }); }
    if (seg[0] === 'User' && seg.length === 2) return j(res, 200, { id: 7, name: 'jdupont', firstname: 'Jean', realname: 'Dupont', phone: '+33 4 00 00 00 07' });
    if (seg[0] === 'User' && seg[2] === 'UserEmail') return j(res, 200, [{ email: 'jean.dupont@example.com', is_default: 1 }]);
    if (seg[0] === 'Software') return j(res, 200, { id: +seg[1], name: GL.Software[seg[1]] });
    if (seg[0] === 'SoftwareVersion') return j(res, 200, { id: +seg[1], name: GL.SoftwareVersion[seg[1]] });
    if ((seg[0] === 'Computer' || seg[0] === 'NetworkEquipment') && seg.length === 3 && seg[2] === 'Item_OperatingSystem') { const o = GL.os[seg[1]]; return j(res, 200, o ? [{ operatingsystems_id: o[0], operatingsystemversions_id: o[1], operatingsystemservicepacks_id: 0 }] : []); }
    if ((seg[0] === 'Computer' || seg[0] === 'NetworkEquipment') && seg.length === 2) {
      const it = GL[seg[0]].find(z => z.id === +seg[1]); if (!it) return j(res, 404, ['ERROR_ITEM_NOT_FOUND']);
      const out = { ...it, locations_id: exp ? 'France > Lyon > Building A' : it.locations_id };
      out._networkports = { NetworkPortEthernet: [{ netport_id: 1, name: 'eth0', NetworkName: { id: 3, name: it.name, FQDNs: [], IPAddress: [{ id: 9, name: GL.ip[it.id], IPNetwork: [{ id: 1, name: 'net', address: '10.0.0.0', netmask: '255.255.255.0', gateway: '10.0.0.254' }] }] } }] };
      if (u.searchParams.get('with_softwares') === 'true') out._softwares = (GL.sw[it.id] || []).map(([s, v]) => ({ softwares_id: s, softwareversions_id: v }));
      return j(res, 200, out);
    }
    return j(res, 404, ['ERROR_RESOURCE_NOT_FOUND_NOR_COMMONDBTM']);
  }
  // phpIPAM
  if (p.startsWith('/ipam/api/strata/')) {
    const r = p.slice('/ipam/api/strata/'.length).replace(/\/$/, '');
    if (req.headers.token !== 'TK') return j(res, 403, { code: 403, success: false, message: 'Invalid token' });
    const ok = d => j(res, 200, { code: 200, success: true, data: d });
    if (r === 'sections') return ok(IPAM.sections);
    if (r === 'vlan') return ok(IPAM.vlans);
    if (r === 'tools/locations') return j(res, 200, { code: 404, success: false, message: 'No objects found' });
    let m = /^sections\/(\d+)\/subnets$/.exec(r); if (m) return ok(IPAM.subnets[m[1]] || []);
    m = /^subnets\/(\d+)\/addresses$/.exec(r); if (m) { const a = IPAM.addresses[m[1]]; return a && a.length ? ok(a) : j(res, 200, { code: 404, success: false, message: 'No addresses found' }); }
    return j(res, 200, { code: 404, success: false, message: 'Not found' });
  }
  // PAN-OS
  if (p === '/pan/api/') {
    const t = u.searchParams.get('type');
    if (t === 'keygen') return x(res, 200, '<response status="success"><result><key>KEY123</key></result></response>');
    if (req.headers['x-pan-key'] !== 'KEY123') return x(res, 403, '<response status="error"><msg><line>Invalid credentials.</line></msg></response>');
    if (t === 'export') return x(res, 200, PAN);
  }
  // NetBox
  if (p.startsWith('/netbox/api/')) {
    if (auth !== 'Token NBT') return j(res, 403, { detail: 'Invalid token' });
    const r = p.slice('/netbox/api/'.length).replace(/\/$/, '');
    if (r === 'status') return j(res, 200, { 'netbox-version': '4.1.6', 'python-version': '3.12' });
    const list = NB[NB_PATHS[r]];
    if (!list) return j(res, 404, { detail: 'Not found.' });
    const off = +u.searchParams.get('offset') || 0, lim = 2;
    const next = off + lim < list.length ? `http://${req.headers.host}${p}?limit=${lim}&offset=${off + lim}` : null;
    return j(res, 200, { count: list.length, next, previous: null, results: list.slice(off, off + lim) });
  }
  j(res, 404, { error: 'nope' });
});
const PORT = +(process.env.SIM_PORT || 8099);
srv.listen(PORT, '127.0.0.1', () => console.log('mock on ' + PORT));
