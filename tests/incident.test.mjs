// SPDX-License-Identifier: AGPL-3.0-or-later
// Unit tests of public/incident.js: incident mode and the anonymised AI prompts. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const ctx = {};
runInNewContext(readFileSync(new URL('../public/incident.js', import.meta.url), 'utf8'), ctx);
const I = ctx.StrataIncident;
const J = x => JSON.parse(JSON.stringify(x));

// A small compiled IS: the Internet reaches a web server through the edge firewall, the web server calls a
// database, a workstation reaches the file server, the backup server pulls from it
function site() {
  const asset = (id, type, role, crit, vlan, extra = {}) => Object.assign({ id, name: id, type, role, crit, vlan, ip: '10.0.0.' + id.length, os: 'Debian 12.4', vulns: [], contacts: [], apps: [] }, extra);
  const assets = [
    asset('fw', 'firewall', 'Edge firewall', 3, 'v1'),
    asset('web-01', 'server', 'Customer portal', 2, 'v1', { vulns: [{ id: 'CVE-2021-44228', title: 'Log4Shell', cvss: 10, sev: 'crit', kev: true, epss: 0.97 }], contacts: [{ name: 'Web team', role: 'Technical owner', phone: '+33 1 00 00 00 01', email: 'web@acme.example', dispo: 'Business hours' }] }),
    asset('db-01', 'db', 'ERP database', 3, 'v2', { contacts: [{ name: 'Jeanne Martin', role: 'On-call', phone: '+33 1 00 00 00 02', email: '', dispo: '24/7' }] }),
    asset('pc-01', 'workstation', 'Accounting workstation', 1, 'v3'),
    asset('file-01', 'server', 'File server', 2, 'v2'),
    asset('bk-01', 'server', 'Backup server', 3, 'v2'),
  ];
  const flow = (id, src, dst, port, via = [], extra = {}) => Object.assign({ id, src, dst, port, via, vol: 10, risk: false, note: '' }, extra);
  const flows = [
    flow('f1', 'internet', 'web-01', 'tcp/443', ['fw']),
    flow('f2', 'web-01', 'db-01', 'tcp/5432', ['fw']),
    flow('f3', 'pc-01', 'file-01', 'tcp/445'),
    flow('f4', 'bk-01', 'file-01', 'tcp/445'),
    flow('f5', 'pc-01', 'svc:m365', 'tcp/443'),
    flow('f6', 'pc-01', 'db-01', 'tcp/5432', [], { risk: true, note: 'Workstation straight to the database' }),
  ];
  const byId = {}; assets.forEach(a => { byId[a.id] = a; });
  const vlans = [{ id: 'v1', num: 10, name: 'DMZ', cidr: '10.10.0.0/24', zone: 'Exposed' }, { id: 'v2', num: 20, name: 'Servers', cidr: '10.20.0.0/24', zone: 'Core' }, { id: 'v3', num: 30, name: 'Users', cidr: '10.30.0.0/24', zone: 'Office' }];
  const vlanById = {}; vlans.forEach(v => { vlanById[v.id] = v; });
  const business = [{ id: 'b1', name: 'ERP', crit: 3, owner: 'Finance director', assets: ['db-01'] }, { id: 'b2', name: 'Portal', crit: 2, owner: 'Paul Durand', assets: ['web-01'] }];
  return { name: 'Lyon', assets, byId, flows, vlans, vlanById, business, bizById: { b1: business[0], b2: business[1] }, svcById: { 'svc:m365': { name: 'Microsoft 365', category: 'SaaS' } },
    contacts: [{ name: 'SOC', role: 'On-call', phone: '+33 1 00 00 00 09', email: 'soc@acme.example', dispo: '24/7' }], expo: { 'web-01': 1, 'db-01': 2 }, critIds: ['fw', 'db-01', 'bk-01'] };
}

test('clean: keeps known states only and gives an empty incident for anything else', () => {
  assert.deepEqual(J(I.clean({ on: 1, marks: { a: 'compromised', b: 'pwned' }, cuts: ['f1', 2] })), { on: true, marks: { a: 'compromised' }, cuts: ['f1'], run: null, log: [] });
  assert.deepEqual(J(I.clean('x')), J(I.empty()));
});

test('selectors: assets by state, type, role, vulnerability, exposure, reach and consumers', () => {
  const s = site(), inc = I.clean({ marks: { 'pc-01': 'compromised', 'web-01': 'suspected' } });
  assert.deepEqual(J(I.selectAssets(s, inc, 'affected')).sort(), ['pc-01', 'web-01']);
  assert.deepEqual(J(I.selectAssets(s, inc, 'compromised')), ['pc-01']);
  assert.deepEqual(J(I.selectAssets(s, inc, 'type:db')), ['db-01']);
  assert.deepEqual(J(I.selectAssets(s, inc, 'role:backup')), ['bk-01']);
  assert.deepEqual(J(I.selectAssets(s, inc, 'vuln:{cve}', { cve: 'CVE-2021-44228' })), ['web-01']);
  assert.deepEqual(J(I.selectAssets(s, inc, 'vuln:{cve}', {})), [], 'a missing parameter selects nothing');
  assert.deepEqual(J(I.selectAssets(s, inc, 'exposed:internet')), ['web-01']);
  assert.deepEqual(J(I.selectAssets(s, inc, 'reach:compromised')).sort(), ['db-01', 'file-01']);
  assert.deepEqual(J(I.selectAssets(s, inc, 'consumers:id:file-01')).sort(), ['bk-01', 'pc-01']);
  assert.equal(I.resolve(s, inc, 'flows:compromised').kind, 'flows');
  assert.deepEqual(J(I.resolve(s, inc, 'business:affected').items.map(b => b.id)), ['b2']);
});

test('flows to cut: Internet first, cut at the firewall crossed, isolated hosts count as cut', () => {
  const s = site(), inc = I.clean({ marks: { 'web-01': 'compromised' } });
  const rows = I.flowsToCut(s, inc, ['web-01']);
  assert.equal(rows[0].f.id, 'f1', 'the way in from the Internet comes first');
  assert.equal(rows[0].prio, 1);
  assert.equal(rows[0].at.id, 'fw');
  assert.match(rows[1].why.join(' '), /critical asset db-01/);
  const pc = I.flowsToCut(s, I.clean({ marks: { 'pc-01': 'contained' } }), ['pc-01']);
  assert.ok(pc.every(r => r.cut && r.iso));
  assert.equal(I.cutPoint(s, s.flows[2]).id, null);
  assert.match(I.cutPoint(s, s.flows[2]).label, /host/);
});

test('who to call: on-call first, then owners, business owners and the IS contacts', () => {
  const s = site(), list = J(I.callList(s, ['db-01', 'web-01']));
  assert.deepEqual(list.map(c => c.name), ['Jeanne Martin', 'SOC', 'Web team', 'Finance director', 'Paul Durand']);
  assert.deepEqual(list[0].why, ['db-01']);
});

test('playbook run: decisions move along the edges and their effects mark the assets', () => {
  const s = site(), pb = I.PLAYBOOKS['PB-010'], inc = I.empty();
  inc.run = I.start({ ref: 'IR-1', name: 'x', mode: 'exercise', severity: 'Critical', params: { cve: 'CVE-2021-44228' } }, pb, 0);
  assert.equal(inc.run.cur, 'exposure');
  I.advance(s, inc, pb, 'found');
  assert.deepEqual(J(I.advance(s, inc, pb, 'mitigate', 'Yes')), [['web-01', 'suspected']]);
  assert.equal(inc.run.answers.found, 'Yes');
  assert.deepEqual(J(I.route(pb, inc.run)), ['start', 'exposure', 'found', 'mitigate', 'hunt', 'comp', 'major', 'review', 'end'], 'the route ahead follows the first edge out of each step');
  I.advance(s, inc, pb, 'hunt'); I.advance(s, inc, pb, 'comp'); I.advance(s, inc, pb, 'review', 'No'); I.advance(s, inc, pb, 'end');
  assert.equal(inc.run.closed, true);
});

test('prompts: nothing identifying reaches the text, and the answer comes back with real names', () => {
  const s = site(), { P, risk, play } = I.prompts(s, 'db-01', { lang: 'en' });
  for (const t of [risk, play]) {
    assert.deepEqual(J(I.leaks(s, t, '')), []);
    for (const x of ['db-01', 'web-01', '10.20.0.0/24', 'Jeanne Martin', 'acme.example', 'Lyon']) assert.ok(!t.includes(x), x);
  }
  assert.match(risk, /ASSET-T/);
  assert.match(risk, /Log4Shell \(KEV\)/, 'neighbours keep their exploited vulnerabilities');
  assert.match(play, /schema: muster\/v1/);
  assert.ok(!/ERP/.test(risk.split('## What I need')[0].replace('ERP database', '')), 'business names are replaced by default');
  const back = I.reidentify(s, 'Isolate ASSET-T and watch ASSET-01 in SEG-1.', P);
  assert.match(back, /Isolate db-01 and watch/);
  assert.match(back, /VLAN 20/);
  assert.deepEqual(J(I.leaks(s, 'call Jeanne Martin', '')), ['Jeanne Martin']);
  assert.deepEqual(J(I.leaks(s, 'Acme Corp runs it', 'Acme Corp')), ['Acme Corp']);
  const v = I.prompts(s, 'db-01', { lang: 'fr', versions: false }).risk;
  assert.match(v, /Debian 12\.x/);
  assert.match(v, /Tu es architecte/);
});

test('yamlCheck: counts muster/v1 playbooks and flags unknown step types', () => {
  assert.equal(I.yamlCheck('no yaml'), null);
  assert.deepEqual(J(I.yamlCheck('schema: muster/v1\nsteps:\n  - id: a\n    type: start\n    targets: ["affected"]\n  - id: b\n    type: banana\n')), { blocks: 1, steps: 2, bad: ['banana'], targets: 1 });
});

test('demo feed: builds the two Muster examples from the map', () => {
  const s = site();
  const f = J(I.demoFeed(s));
  assert.deepEqual(f.map(x => x.pb), ['PB-001', 'PB-010']);
  assert.deepEqual(f[0].assets, ['file-01', 'pc-01']);
  assert.equal(f[1].params.cve, 'CVE-2021-44228');
});
