// SPDX-License-Identifier: AGPL-3.0-or-later
// Palo Alto module: building an IS from a configuration (zones, VLANs from the interfaces, assets from the
// address objects, the firewall), then the rules as flows. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig, rulesToChanges } from '../server/connectors/builtin/paloalto/index.js';

const XML = `<config><devices><entry name="localhost.localdomain">
  <deviceconfig><system><hostname>FW-PARIS</hostname></system></deviceconfig>
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.2/29"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="10.0.0.1/24"/></ip>
      <units>
        <entry name="ethernet1/2.20"><tag>20</tag><ip><entry name="10.20.0.1/24"/></ip><comment>Servers</comment></entry>
        <entry name="ethernet1/2.30"><tag>30</tag><ip><entry name="gw-users"/></ip><comment>Users</comment></entry>
      </units></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="trust"><network><layer3><member>ethernet1/2</member><member>ethernet1/2.20</member></layer3></network></entry>
      <entry name="users"><network><layer3><member>ethernet1/2.30</member></layer3></network></entry>
    </zone>
    <address>
      <entry name="gw-users"><ip-netmask>10.30.0.1/23</ip-netmask></entry>
      <entry name="SQL-01"><ip-netmask>10.20.0.10</ip-netmask><description>ERP database</description></entry>
      <entry name="app-01"><ip-netmask>10.20.0.11/32</ip-netmask></entry>
      <entry name="plc-line"><ip-netmask>10.0.0.50</ip-netmask></entry>
      <entry name="host-77"><ip-netmask>10.30.0.77</ip-netmask></entry>
      <entry name="lost"><ip-netmask>192.168.99.9</ip-netmask></entry>
      <entry name="users-net"><ip-netmask>10.30.0.0/23</ip-netmask></entry>
      <entry name="partner"><ip-netmask>203.0.113.10</ip-netmask></entry>
    </address>
    <service><entry name="tcp-502"><protocol><tcp><port>502</port></tcp></protocol></entry></service>
    <rulebase><security><rules>
      <entry name="app-db"><from><member>trust</member></from><to><member>trust</member></to><source><member>app-01</member></source><destination><member>SQL-01</member></destination><application><member>any</member></application><service><member>tcp-1433</member></service><action>allow</action></entry>
      <entry name="users-app"><from><member>users</member></from><to><member>trust</member></to><source><member>host-77</member></source><destination><member>app-01</member></destination><application><member>any</member></application><service><member>tcp-443</member></service><action>allow</action></entry>
      <entry name="scada"><from><member>trust</member></from><to><member>trust</member></to><source><member>app-01</member></source><destination><member>plc-line</member></destination><application><member>any</member></application><service><member>tcp-502</member></service><action>allow</action></entry>
      <entry name="web-in"><from><member>untrust</member></from><to><member>trust</member></to><source><member>any</member></source><destination><member>app-01</member></destination><application><member>any</member></application><service><member>tcp-443</member></service><action>allow</action></entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>`;

const build = state => rulesToChanges(parseConfig(XML), { site: 'p', build: true }, state);

test('Palo Alto, build the IS: zones, VLANs from the interfaces, assets from the address objects, the firewall', () => {
  const r = build({ si: { p: { name: 'Paris' } }, assets: {}, services: [] });
  const si = r.changes.si.p, A = r.changes.assets, by = n => Object.values(A).find(a => a.name === n);
  // zones of the interfaces that are not the Internet (and the zone of "To sort", for the host outside them)
  assert.deepEqual(si.zones.map(z => z.name), ['trust', 'users', 'Imported']);
  // a VLAN per subnet: tagged sub-interfaces keep their tag, the untagged interface gets 4001; an interface
  // address given as an object is read through it; the comment names the VLAN
  assert.deepEqual(si.vlans.filter(v => !/unsorted$/.test(v.id)).map(v => [v.num, v.name, v.cidr, si.zones.find(z => z.id === v.zone).name]),
    [[4001, 'trust ethernet1/2 (untagged)', '10.0.0.0/24', 'trust'], [20, 'Servers', '10.20.0.0/24', 'trust'], [30, 'Users', '10.30.0.0/23', 'users']]);
  // the type: from the name or description, from the ports opened to it, a client only is a workstation
  assert.equal(by('SQL-01').type, 'db');
  assert.equal(by('SQL-01').role, 'ERP database');
  assert.equal(by('plc-line').type, 'plc');
  assert.equal(by('host-77').type, 'workstation');
  assert.equal(by('app-01').type, 'server');
  assert.equal(by('SQL-01').vlan, si.vlans.find(v => v.num === 20).id);
  // a host outside every VLAN waits in "To sort"; ranges, public addresses and the firewall's own are no assets
  assert.match(by('lost').vlan, /unsorted$/);
  for (const n of ['users-net', 'partner', 'gw-users']) assert.equal(by(n), undefined, n);
  // the firewall: its host name, its inside address
  const fw = Object.entries(A).find(([, a]) => a.type === 'firewall');
  assert.deepEqual([fw[1].name, fw[1].ip], ['FW-PARIS', '10.0.0.1']);
  // flows: through the firewall when they change VLAN or come from the Internet, not inside a VLAN
  const f = (s, d) => si.flows.find(x => x.src === s && x.dst === d);
  const id = n => Object.entries(A).find(([, a]) => a.name === n)[0];
  assert.equal(f(id('app-01'), id('SQL-01')).via, undefined);
  assert.deepEqual(f(id('host-77'), id('app-01')).via, [fw[0]]);
  assert.deepEqual(f('internet', id('app-01')).via, [fw[0]]);
  assert.equal(r.stats.vlansAdded, 3);
  assert.equal(r.stats.assetsAdded, 5);
});

test('Palo Alto, build the IS: what the map has is kept, and the same file again changes nothing', () => {
  const first = build({ si: { p: { name: 'Paris', zones: [{ id: 'z9', name: 'TRUST' }], vlans: [{ id: 'mine', num: 20, name: 'My servers', zone: 'z9' }] } },
    assets: { mydb: { site: 'p', name: 'erp-db', type: 'db', vlan: 'mine', ip: '10.20.0.10' } }, services: [] });
  const si = first.changes.si.p;
  assert.equal(si.vlans.find(v => v.num === 20).id, 'mine', 'the VLAN of the map is kept, and gets its range');
  assert.equal(si.vlans.find(v => v.num === 20).cidr, '10.20.0.0/24');
  assert.equal(si.zones.filter(z => /trust/i.test(z.name)).length, 1, 'a zone of the same name is reused');
  assert.ok(!Object.values(first.changes.assets).some(a => a.ip === '10.20.0.10'), 'an asset already at that IP is not created again');
  const state = { si: { p: si }, assets: { mydb: { site: 'p', name: 'erp-db', type: 'db', vlan: 'mine', ip: '10.20.0.10' }, ...first.changes.assets }, services: [] };
  assert.equal(build(state).changes, null);
});

test('Palo Alto without "build": an empty IS gives nothing to draw, and no empty proposal', () => {
  const r = rulesToChanges(parseConfig(XML), { site: 'p' }, { si: { p: { name: 'Paris' } }, assets: {}, services: [] });
  assert.equal(r.changes, null);
  assert.ok(r.skipped.some(x => /no asset of the IS at 10\.20\.0\.10/.test(x)));
});
