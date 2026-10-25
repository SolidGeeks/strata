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
// results come from another realm (the vm context): compare them as plain data
const J = x => JSON.parse(JSON.stringify(x));

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

// A small IS: customers reach web through the edge firewall; web calls app, app calls db; app logs to siem
const site = () => {
  const assets = {
    fw: { id: 'fw', type: 'firewall', apps: [] },
    web: { id: 'web', type: 'server', apps: [{ name: 'Nginx', version: '1.22', ports: ['tcp/443'] }] },
    app: { id: 'app', type: 'server', apps: [{ name: 'Tomcat', version: '9', ports: ['tcp/8080'] }] },
    db: { id: 'db', type: 'db', apps: [{ name: 'PostgreSQL', version: '15', ports: ['tcp/5432'] }] },
    siem: { id: 'siem', type: 'server', apps: [] },
    pc1: { id: 'pc1', type: 'workstation', vlan: 'v30', apps: [] },
    pc2: { id: 'pc2', type: 'workstation', vlan: 'v30', apps: [] },
  };
  return {
    byId: assets, svcById: { 'svc:upd': { name: 'Updates' } },
    flows: [
      flow('f1', 'internet', 'web', ['fw'], 'tcp/443'), flow('f2', 'web', 'app', [], 'tcp/8080'), flow('f3', 'app', 'db', [], 'tcp/5432'),
      flow('f4', 'app', 'siem', [], 'udp/514'), flow('f5', 'db', 'svc:upd', [], 'tcp/443'), flow('f6', 'pc1', 'app', [], 'tcp/8080'), flow('f7', 'pc2', 'app', [], 'tcp/8080'),
    ],
    business: [{ id: 'shop', name: 'Online shop', crit: 3, assets: ['web'] }, { id: 'acct', name: 'Accounting', crit: 2, assets: ['app'] }],
  };
};

test('business dependencies: own assets, what they call, equipment crossed, Internet services', () => {
  const d = A.dependencies(site(), { assets: ['web'] });
  assert.deepEqual(Object.keys(d.assets).sort(), ['app', 'db', 'fw', 'web']);
  assert.equal(d.assets.web.direct, true);
  assert.deepEqual([...d.assets.db.path], ['web', 'app', 'db']);
  assert.equal(d.assets.db.how, 'called');
  // the edge firewall is in front of the web server
  assert.equal(d.assets.fw.how, 'crossed');
  assert.deepEqual([...d.services], ['svc:upd']);
  // syslog to the SIEM is not a dependency, and the clients of the app are not either
  assert.equal(d.assets.siem, undefined);
  assert.equal(d.assets.pc1, undefined);
});

test('business impact: every asset lists the services it would hit, own services first', () => {
  const I = A.businessImpact(site());
  assert.deepEqual(J(I.byAsset.app.map(x => [x.id, x.direct])), [['acct', true], ['shop', false]]);
  assert.deepEqual(J(I.byAsset.db.map(x => x.id)), ['shop', 'acct']);
  assert.deepEqual(J(I.byAsset.web.map(x => x.id)), ['shop']);
  assert.equal(I.byAsset.pc1, undefined);
  assert.deepEqual(Object.keys(I.byBusiness).sort(), ['acct', 'shop']);
});

test('application view: one node per application, clients grouped, columns follow the flows', () => {
  const G = A.appGraph(site());
  const at = Object.fromEntries(G.nodes.map(n => [n.key, n]));
  assert.ok(at['app:nginx'] && at['app:tomcat'] && at['app:postgresql']);
  assert.deepEqual([...at['app:tomcat'].hosts], ['app']);
  // the two workstations are one group of clients
  const cl = G.nodes.filter(n => n.kind === 'clients');
  assert.equal(cl.length, 1);
  assert.deepEqual([...cl[0].hosts].sort(), ['pc1', 'pc2']);
  // the two client flows to Tomcat are one edge
  assert.equal(G.edges.find(e => e.from === cl[0].key && e.to === 'app:tomcat').flows.length, 2);
  assert.equal(at.internet.rank, 0);
  assert.equal(at['app:nginx'].rank, 1);
  assert.equal(at['app:tomcat'].rank, 1);
  assert.equal(at['app:postgresql'].rank, 2);
  // the SIEM listens on no recorded application: it shows as itself
  assert.equal(at['asset:siem'].kind, 'asset');
});

test('addresses: the first free host of a VLAN range, skipping the network address and those in use', () => {
  assert.equal(A.nextFreeIp('10.20.0.0/24', []), '10.20.0.1');
  assert.equal(A.nextFreeIp('10.20.0.0/24', ['10.20.0.1', '10.20.0.2', '10.20.0.4']), '10.20.0.3');
  // a range written from one of its hosts still starts at its network address
  assert.equal(A.nextFreeIp('10.30.1.7/23', ['10.30.0.1']), '10.30.0.2');
  // full range: nothing to suggest (broadcast excluded)
  assert.equal(A.nextFreeIp('192.168.1.0/30', ['192.168.1.1', '192.168.1.2']), null);
  assert.equal(A.nextFreeIp('10.0.0.8/31', ['10.0.0.8']), '10.0.0.9');
  assert.equal(A.nextFreeIp('not a range', []), null);
  assert.equal(A.nextFreeIp('', []), null);
});

test('addresses: inside or outside a range', () => {
  assert.equal(A.inCidr('10.20.0.15', '10.20.0.0/24'), true);
  assert.equal(A.inCidr('10.20.1.15', '10.20.0.0/24'), false);
  assert.equal(A.inCidr('10.30.1.200', '10.30.0.0/23'), true);
  assert.equal(A.inCidr('10.20.0.300', '10.20.0.0/24'), false);
  assert.equal(A.inCidr('fe80::1', '10.20.0.0/24'), false);
});
