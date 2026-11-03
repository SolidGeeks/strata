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

test('first seen: the map before the history dates the vulnerabilities of assets never edited since', () => {
  const base = { assets: { web: { site: 'a', vulns: [{ id: 'CVE-1', sev: 'crit' }] }, db: { site: 'a', vulns: [{ id: 'CVE-2', sev: 'crit' }, { id: 'S', sev: 'high', firstSeen: ago(300) }] } } };
  const raw = { si: { a: {} }, assets: { web: { site: 'a', vulns: [{ id: 'CVE-1', sev: 'crit' }], note: 'x' }, db: base.assets.db } };
  const h = [{ rev: 2, at: ago(100), kind: 'assets', id: 'web', before: base.assets.web, after: raw.assets.web }];
  const s = K.firstSeen(h, base);
  assert.deepEqual(J(s['db|CVE-2']), { at: ago(100), before: true });
  assert.equal(s['db|S'].at, ago(300), "a scanner's own date wins");
  const m = K.measure(raw, NOW, s);
  assert.deepEqual(J(m.oldest.map(v => [v.asset, v.id, v.days, v.approx])), [['db', 'S', 300, false], ['db', 'CVE-2', 100, true], ['web', 'CVE-1', 100, true]]);
  assert.equal(m.vulns.median, 100);
  assert.equal(m.vulns.late, 3);
  // without a history, an undated vulnerability is 0 days old at least: marked as a lower bound, not late
  const none = K.measure(raw, NOW, K.firstSeen([], base));
  assert.deepEqual(J(none.oldest.map(v => [v.id, v.days, v.approx, v.late])), [['S', 300, false, true], ['CVE-2', 0, true, false], ['CVE-1', 0, true, false]]);
  assert.equal(none.vulns.approx, true);
});

test("severity 'none' has no deadline and is left out of the counts", () => {
  const raw = { si: { a: {} }, assets: { x: { site: 'a', vulns: [{ id: '1', sev: 'none', firstSeen: ago(400) }, { id: '2', cvss: 0, firstSeen: ago(400) }, { id: '3', sev: 'none', cvss: 7.5, firstSeen: ago(400) }] } } };
  const v = K.measure(raw, NOW, {}).vulns;
  assert.deepEqual([v.open, v.low, v.high, v.late], [1, 0, 1, 1], "a CVSS above 0 wins over 'none'");
});
