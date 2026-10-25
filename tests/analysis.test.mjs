// SPDX-License-Identifier: AGPL-3.0-or-later
// Unit tests of public/analysis.js, the graph analysis shared by the 3D model and the 2D diagram. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const ctx = {};
runInNewContext(readFileSync(new URL('../public/analysis.js', import.meta.url), 'utf8'), ctx);
const A = ctx.StrataAnalysis;
const flow = (id, src, dst, via = [], port = 'tcp/443') => ({ id, src, dst, via, port });

test('lanes: each flow crossing a device gets its own lane, in a stable order', () => {
  const flows = [flow('f3', 'web', 'db', ['fw']), flow('f1', 'app', 'db', ['fw', 'core']), flow('f2', 'internet', 'web', ['fw']), flow('f4', 'pc', 'db')];
  const L = A.lanes(flows);
  assert.deepEqual(Object.keys(L).sort(), ['core', 'fw']);
  assert.equal(L.fw.n, 3);
  // ordered by source name: app, internet, web
  assert.deepEqual({ ...L.fw.idx }, { f1: 0, f2: 1, f3: 2 });
  assert.equal(L.core.n, 1);
  // the same flows in another order give the same lanes
  assert.deepEqual({ ...A.lanes(flows.slice().reverse()).fw.idx }, { ...L.fw.idx });
});

test('flow colours: flows sharing a device never share a colour while the palette lasts', () => {
  const flows = Array.from({ length: 6 }, (_, i) => flow('f' + i, 's' + i, 'd' + i, ['fw']));
  const C = A.flowColours(flows, 10);
  assert.equal(new Set(Object.values(C)).size, 6);
  // flows that share nothing may reuse a colour
  const apart = A.flowColours([flow('a', 'x', 'y', ['fw1']), flow('b', 'x', 'y', ['fw2'])], 10);
  assert.equal(apart.a, apart.b);
});

test('flow colours: past the palette, the least used colour at that device is reused', () => {
  const flows = Array.from({ length: 7 }, (_, i) => flow('f' + i, 's' + i, 'd' + i, ['fw']));
  const C = A.flowColours(flows, 3);
  const count = [0, 0, 0];
  Object.values(C).forEach(c => count[c]++);
  assert.deepEqual(count.sort(), [2, 2, 3]);
  // a flow through two devices avoids the colours of both
  const two = A.flowColours([flow('a', 'p', 'q', ['fw1', 'fw2']), flow('b', 'p', 'r', ['fw1']), flow('c', 'p', 's', ['fw2'])], 3);
  assert.notEqual(two.a, two.b);
  assert.notEqual(two.a, two.c);
});
