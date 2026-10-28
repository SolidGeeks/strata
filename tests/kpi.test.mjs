// SPDX-License-Identifier: AGPL-3.0-or-later
// Unit tests of public/kpi.js: the key figures of the dashboard. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const ctx = {};
runInNewContext(readFileSync(new URL('../public/kpi.js', import.meta.url), 'utf8'), ctx);
const K = ctx.StrataKpi, J = x => JSON.parse(JSON.stringify(x)), DAY = 86400000;
const NOW = Date.parse('2026-10-01T12:00:00Z'), ago = d => new Date(NOW - d * DAY).toISOString();

function map() {
  return {
    si: {
      a: { name: 'A', flows: [
        { src: 'internet', dst: 'web', port: 'tcp/443' }, { src: 'internet', dst: 'web', port: 'tcp/80' },
        { src: 'internet', dst: 'jump', port: 'tcp/3389', risk: true }, { src: 'web', dst: 'db', port: 'tcp/5432' }] },
      b: { name: 'B', flows: [] },
    },
    assets: {
      web: { site: 'a', name: 'web', crit: 2, contacts: [{ name: 'Web team', role: 'Technical owner' }], ext: { cyberwatch: 12 },
        vulns: [{ id: 'CVE-1', cvss: 9.8, firstSeen: ago(40), kev: true }, { id: 'CVE-2', sev: 'high', firstSeen: ago(10) }] },
      jump: { site: 'a', name: 'jump', crit: 3, contacts: [{ name: '', role: 'Technical owner' }], vulns: [{ id: 'CVE-3', sev: 'med', src: 'nessus', firstSeen: ago(200) }] },
      db: { site: 'a', name: 'db', crit: 3, contacts: [{ name: 'DBA', role: 'Business owner' }] },
      pc: { site: 'b', name: 'pc', crit: 1, contacts: [{ name: 'Desk', role: 'On-call' }] },
      lost: { site: 'gone', name: 'lost' },
    },
  };
}

test('exposure: assets and ports the Internet reaches, administration ports among them', () => {
  const m = K.measure(map(), NOW, {});
  assert.equal(m.assets, 4, 'an asset of a deleted IS does not count');
  assert.deepEqual(J(m.exposure), { assets: 2, share: 50, ports: 3, admin: 1, risky: 1 });
  assert.equal(K.measure(map(), NOW, {}, 'b').exposure.assets, 0, 'one IS only');
});

test('vulnerabilities: their age from first seen, the median of critical and high, those past their deadline', () => {
  const v = K.measure(map(), NOW, {}).vulns;
  assert.equal(v.open, 3);
  assert.deepEqual([v.crit, v.high, v.med, v.kev], [1, 1, 1, 1]);
  assert.equal(v.median, 25, 'median of 40 and 10 days');
  assert.deepEqual(J(v.ages), [1, 1, 0, 0]);
  assert.equal(v.late, 2, 'critical after 15 days and medium after 90 are late; high at 10 days is not');
  const o = K.measure(map(), NOW, {}).oldest;
  assert.deepEqual(J(o.map(x => [x.id, x.days, x.late])), [['CVE-1', 40, true], ['CVE-2', 10, false]]);
});

test('owner and scan coverage', () => {
  const m = K.measure(map(), NOW, {});
  assert.deepEqual(J(m.owners), { covered: 2, share: 50, critical: 2, criticalCovered: 1 }, 'a contact needs a name and an owner role');
  assert.deepEqual(J(m.scans), { covered: 2, share: 50 }, 'known to a scanner by its id, or by a vulnerability it reported');
});

test('first seen: from the history of the map, oldest first; already there when it starts is a lower bound', () => {
  const h = [
    { at: ago(100), kind: 'assets', id: 'x', before: { vulns: [{ id: 'OLD' }] }, after: { vulns: [{ id: 'OLD' }, { id: 'NEW' }] } },
    { at: ago(5), kind: 'assets', id: 'x', before: { vulns: [{ id: 'OLD' }, { id: 'NEW' }] }, after: { vulns: [{ id: 'OLD' }, { id: 'NEW' }, { id: 'LATE' }] } },
    { at: ago(2), kind: 'all', before: { assets: {} }, after: { assets: { y: { vulns: [{ id: 'IMP', firstSeen: ago(300) }] } } } },
  ];
  const s = K.firstSeen(h);
  assert.equal(s['x|OLD'].at, ago(100));
  assert.equal(s['x|OLD'].before, true);
  assert.equal(s['x|NEW'].at, ago(100));
  assert.equal(s['x|LATE'].at, ago(5));
  assert.equal(s['y|IMP'].at, ago(300), "a scanner's own date wins");
  const raw = { si: { s: {} }, assets: { x: { site: 's', vulns: [{ id: 'OLD', sev: 'crit' }, { id: 'LATE', sev: 'high' }] } } };
  const m = K.measure(raw, NOW, s);
  assert.deepEqual(J(m.oldest.map(v => [v.id, v.days, v.approx])), [['OLD', 100, true], ['LATE', 5, false]]);
  assert.equal(m.vulns.approx, true);
});

test('points: the end of each period, oldest first, the last one now', () => {
  const p = K.points(NOW, 3, 7);
  assert.deepEqual(J(p), [NOW - 14 * DAY, NOW - 7 * DAY, NOW]);
});

test('an empty map measures without failing', () => {
  const m = K.measure({ si: {}, assets: {} }, NOW, {});
  assert.equal(m.assets, 0);
  assert.equal(m.owners.share, null);
  assert.equal(m.vulns.median, null);
});
