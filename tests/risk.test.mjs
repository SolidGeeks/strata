// SPDX-License-Identifier: AGPL-3.0-or-later
// Unit tests of public/risk.js (the risk register) and public/baselines.js. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const ctx = {};
for (const f of ['risk.js', 'baselines.js']) runInNewContext(readFileSync(new URL(`../public/${f}`, import.meta.url), 'utf8'), ctx);
const R = ctx.StrataRisk, B = ctx.StrataBaselines;
const J = x => JSON.parse(JSON.stringify(x));

// A small compiled IS: a web server published on the Internet with a known exploited flaw, a VPN gateway,
// an internal database and a workstation that reaches nothing
function site() {
  const asset = (id, type, role, crit, extra = {}) => Object.assign({ id, name: id, type, role, crit, os: 'Debian 12', vulns: [], ports: [], exp: 'none' }, extra);
  const assets = [
    asset('web', 'server', 'Customer portal', 2, { exp: 'internet', ports: [{ port: 'tcp/443', level: 'internet', from: ['internet'] }], vulns: [{ id: 'CVE-2021-44228', title: 'Log4Shell', cvss: 10, sev: 'crit', kev: true, epss: 0.97 }] }),
    asset('vpn', 'gateway', 'Remote-access VPN', 3, { exp: 'internet', ports: [{ port: 'udp/443', level: 'internet', from: ['internet'] }] }),
    asset('db', 'db', 'ERP database', 3, { exp: 'inter', ports: [{ port: 'tcp/5432', level: 'inter', from: ['web'] }] }),
    asset('pc', 'workstation', 'Accounting workstation', 1),
  ];
  const s = { assets, flows: [{ src: 'internet', dst: 'web', port: 'tcp/443' }, { src: 'web', dst: 'db', port: 'tcp/5432' }], svcById: {}, expo: { web: 1, vpn: 1, db: 2 }, bizCrit: {} };
  s.byId = Object.fromEntries(assets.map(a => [a.id, a]));
  return s;
}
const opts = (doc = {}, extra = {}) => Object.assign({ settings: R.settings(doc, B), baselines: B }, extra);
const ids = rows => rows.map(r => r.threat.id);

test('the catalogue: 30 threats with valid sources, ATT&CK techniques and ENISA families', () => {
  assert.equal(R.THREATS.length, 30);
  assert.equal(new Set(R.THREATS.map(t => t.id)).size, 30, 'threat ids are unique');
  for (const t of R.THREATS) {
    assert.ok(t.base >= 1 && t.base <= 4 && t.severity >= 1 && t.severity <= 4, t.id);
    assert.ok(t.actors.every(a => R.ACTORS.some(x => x.id === a)), `${t.id}: unknown risk source`);
    assert.ok(t.enisa.every(a => R.ENISA.some(x => x.id === a)), `${t.id}: unknown ENISA family`);
    assert.ok(t.attack.every(a => /^T\d{4}(\.\d{3})?$/.test(a)), `${t.id}: malformed ATT&CK technique`);
  }
});

test('the baselines: ANSSI, NIST CSF 2.0, CIS v8.1 and ISO 27001 point only at threats of the catalogue', () => {
  assert.deepEqual(J(B.map(b => [b.id, b.requirements.length])), [['anssi', 42], ['nist-csf', 106], ['cis-v8', 153], ['iso27001', 93]]);
  const known = new Set(R.THREATS.map(t => t.id));
  for (const b of B) for (const r of b.requirements) {
    assert.ok(r.id && r.title, `${b.id}: a requirement without id or title`);
    for (const [id, share, effect] of r.threats) {
      assert.ok(known.has(id), `${b.id} ${r.id}: unknown threat ${id}`);
      assert.ok(share > 0 && share < 1 && ['likelihood', 'impact'].includes(effect), `${b.id} ${r.id}: bad link to ${id}`);
    }
  }
  // every threat can be reduced by at least one requirement of some baseline
  for (const t of R.THREATS) assert.ok(B.some(b => b.requirements.some(r => r.threats.some(x => x[0] === t.id))), `${t.id} has no requirement`);
});

test('the landscape of an asset follows its exposure, type, role and vulnerabilities', () => {
  const s = site(), of = id => ids(R.assess(s, s.byId[id], opts({}, { hops: s.expo[id] })));
  assert.ok(of('web').includes('exploit-public'), 'Internet-facing service');
  assert.ok(of('web').includes('known-exploited'), 'a vulnerability on the KEV list');
  assert.ok(of('vpn').includes('remote-access'), 'a VPN gateway');
  assert.ok(!of('web').includes('remote-access'), 'a web server on 443 is not a remote access');
  assert.ok(!of('db').includes('exploit-public'), 'the database is not on the Internet');
  assert.deepEqual(J(of('pc').filter(x => x === 'exploit-public' || x === 'known-exploited')), []);
  const why = R.assess(s, s.byId.web, opts()).find(r => r.threat.id === 'known-exploited').why;
  assert.deepEqual(J(why), ['known exploited: CVE-2021-44228']);
});

test('the matrix: configurable from 3×3 to 5×5, anything out of shape falls back on the default', () => {
  const d = R.defaultMatrix();
  assert.equal(d.cells.length, 4);
  assert.equal(d.cells[0][0], 0, 'unlikely and minor is low');
  assert.equal(d.cells[3][3], 3, 'very likely and critical is critical');
  const m = R.cleanMatrix({ likelihood: ['a', 'b', 'c', 'd', 'e'], impact: ['x', 'y', 'z'], cells: [[0]], accept: 2 });
  assert.equal(m.cells.length, 5);
  assert.equal(m.cells[0].length, 3);
  assert.equal(m.accept, 2);
  assert.deepEqual(J(m.likelihood), ['a', 'b', 'c', 'd', 'e']);
  assert.equal(R.cleanMatrix({ likelihood: [1, 2], impact: new Array(9).fill('i') }).likelihood.length, 3, 'sizes are kept between 3 and 5');
  assert.deepEqual(J(R.cellOf(d, 0.99, 0.99)), { l: 3, i: 3, level: 'crit' });
  assert.deepEqual(J(R.cellOf(d, 0, 0)), { l: 0, i: 0, level: 'low' });
});

test('requirements applied lower the residual risk; planned ones only the target', () => {
  const s = site(), a = s.byId.vpn;
  const first = R.assess(s, a, opts({}, { hops: 1 })).find(r => r.threat.id === 'remote-access');
  assert.ok(first.requirements.length > 0, 'ANSSI is enabled by default');
  const [q1, q2] = first.requirements.filter(r => r.effect === 'likelihood');
  a.risk = R.setTreatment(a, 'remote-access', { req: q1.key, status: 'applied' });
  a.risk = R.setTreatment(a, 'remote-access', { req: q2.key, status: 'planned' });
  const after = R.assess(s, a, opts({}, { hops: 1 })).find(r => r.threat.id === 'remote-access');
  assert.ok(Math.abs(after.pResidual - first.p * (1 - q1.strength)) < 1e-9, 'one applied requirement removes its share');
  assert.equal(after.p, first.p, 'the inherent risk does not move');
  assert.ok(R.LEVELS.indexOf(after.target.level) <= R.LEVELS.indexOf(after.residual.level));
  assert.equal(after.requirements.find(r => r.key === q2.key).status, 'planned');
});

test('treatments: decisions, exclusion, threats added by hand, and nothing left behind', () => {
  const s = site(), a = s.byId.pc;
  a.risk = R.setTreatment(a, 'phishing', { decision: 'accept', note: 'Isolated workstation' });
  a.risk = R.setTreatment(a, 'hypervisor-mass', { add: true });
  a.risk = R.setTreatment(a, 'hypervisor-mass', { exclude: true });
  assert.deepEqual(J(a.risk), { threats: { phishing: { decision: 'accept', note: 'Isolated workstation' } }, excluded: ['hypervisor-mass'], added: ['hypervisor-mass'] });
  const rows = R.assess(s, a, opts());
  const rw = rows.find(r => r.threat.id === 'hypervisor-mass');
  assert.deepEqual(J(rw.why), ['added by hand']);
  assert.equal(rw.excluded, true);
  a.risk = R.setTreatment(a, 'phishing', { decision: 'treat', note: '' });
  a.risk = R.setTreatment(a, 'hypervisor-mass', { exclude: false });
  a.risk = R.setTreatment(a, 'hypervisor-mass', { add: false });
  assert.equal(a.risk, undefined, 'an asset back to its defaults keeps no risk field');
});

test('settings: baselines enabled, custom threats and baselines, threats disabled, risk sources', () => {
  const s = site(), a = s.byId.db;
  const doc = {
    baselines: ['nist-csf', 'custom:mine', 'nope'],
    custom: [{ id: 'mine', name: 'House rules', requirements: [{ id: 'H1', title: 'Database firewall', threats: [['data-theft', 0.5, 'likelihood'], ['ghost', 2, 'x']] }] }],
    threats: { custom: [{ id: 'erp-fraud', name: 'ERP fraud', when: { role: 'erp' }, base: 3, severity: 4, actors: ['insider'] }], disabled: ['data-theft'] },
  };
  const S = R.settings(doc, B);
  assert.deepEqual(J(S.baselines), ['nist-csf', 'custom:mine'], 'unknown baselines are dropped');
  assert.deepEqual(J(S.custom[0].requirements[0].threats.map(t => [t.id, t.strength, t.effect])), [['data-theft', 0.5, 'likelihood'], ['ghost', 0.9, 'likelihood']]);
  const rows = R.assess(s, a, opts(doc, { hops: 2 }));
  assert.ok(ids(rows).includes('custom:erp-fraud'), 'a custom threat applies on its own conditions');
  assert.ok(!ids(rows).includes('data-theft'), 'a disabled threat is left out');
  // a risk source rated 0 for this IS takes away the likelihood of its threats
  const none = R.assess(s, a, opts(doc, { hops: 2, landscape: { actors: { insider: 0 } } })).find(r => r.threat.id === 'custom:erp-fraud');
  assert.equal(none.p, 0);
});

test('the register of an IS counts each risk once per cell, without the excluded ones', () => {
  const s = site();
  s.byId.web.risk = { excluded: ['exploit-public'] };
  const reg = R.register(s, opts());
  assert.ok(reg.rows.every(r => !(r.asset.id === 'web' && r.threat.id === 'exploit-public')));
  const total = g => g.flat().reduce((x, y) => x + y, 0);
  assert.equal(total(reg.inherent), reg.rows.length);
  assert.equal(total(reg.residual), reg.rows.length);
});
