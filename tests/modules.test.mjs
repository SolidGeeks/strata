// SPDX-License-Identifier: AGPL-3.0-or-later
// Connector modules: the built-in ones run through their own process against the connector simulator,
// what a module process can and cannot reach, file imports, and the module store (install, checksum,
// upload, removal). Run with: npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import zlib from 'node:zlib';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readTgz, writeTgz, sha256 } from '../server/connectors/store.js';
import { checkManifest, compareVersions } from '../server/connectors/modules.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tmp = fs.mkdtempSync(join(tmpdir(), 'strata-mod-'));
const dataDir = join(tmp, 'data'), modulesDir = join(tmp, 'provided');
const port = 8800 + Math.floor(Math.random() * 300), simPort = port + 400, regPort = port + 800;
const base = `http://127.0.0.1:${port}`, sim = `http://127.0.0.1:${simPort}`;
const PASS = { admin: 'admin-pass-123', alice: 'alice-pass-123', bob: 'bob-pass-1234' };
const procs = [];
let registry, tamper = false;

// A small Lyon IS that matches the simulator's data
const STATE = {
  si: { lyon: { name: 'Lyon', zones: [{ id: 'z1', name: 'Main' }], vlans: [{ id: 'v10', num: 10, name: 'DMZ', cidr: '10.10.10.0/24', zone: 'z1' }, { id: 'v20', num: 20, name: 'Servers', cidr: '10.20.0.0/24', zone: 'z1' }] } },
  assets: {
    'web-01': { site: 'lyon', name: 'web-01', type: 'server', vlan: 'v10', ip: '10.10.10.11', crit: 2, vulns: [], contacts: [], apps: [], flows: [] },
    'app-erp': { site: 'lyon', name: 'app-erp', type: 'server', vlan: 'v20', ip: '10.20.0.20', crit: 3, vulns: [], contacts: [], apps: [], flows: [] },
    'lyo-fw-edge': { site: 'lyon', name: 'lyo-fw-edge', type: 'firewall', vlan: 'v10', ip: '10.10.10.1', crit: 3, vulns: [], contacts: [], apps: [], flows: [] },
  },
  wan: [], services: [],
};

const mod = (dir, manifest, code) => {
  fs.mkdirSync(join(modulesDir, dir), { recursive: true });
  fs.writeFileSync(join(modulesDir, dir, 'strata-module.json'), JSON.stringify({ strataModule: 1, version: '1.0.0', description: 'Test module', main: 'index.mjs', fields: [], ...manifest }));
  if (code) fs.writeFileSync(join(modulesDir, dir, 'index.mjs'), code);
};

function start(cmd, args, env, ready) {
  const p = spawn(process.execPath, [cmd, ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(p);
  return new Promise((res, rej) => { p.stdout.on('data', d => { if (String(d).includes(ready)) res(); }); p.on('exit', c => rej(new Error(`${cmd} exit ${c}`))); });
}

before(async () => {
  // what a module process may reach: the answer comes back as the test message
  mod('spy', { id: 'spy', name: 'Spy' }, `
    import fs from 'node:fs';
    const tryIt = f => { try { f(); return 'allowed'; } catch (e) { return e.code || e.message; } };
    export async function test(cfg, ctx) {
      const cp = await import('node:child_process');
      return JSON.stringify({
        dataFile: tryIt(() => fs.readFileSync(${JSON.stringify(join(dataDir, 'users.json'))})),
        write: tryIt(() => fs.writeFileSync(${JSON.stringify(join(tmp, 'x.txt'))}, 'x')),
        spawn: tryIt(() => cp.execFileSync('/bin/true')),
        password: process.env.EDIT_PASS ?? null, dataDir: process.env.DATA_DIR ?? null,
        settings: Object.keys(cfg).sort(), sdk: typeof ctx.sdk.request, map: ctx.state,
      });
    }`);
  mod('slow', { id: 'slow', name: 'Slow' }, 'export function test() { return new Promise(() => setInterval(() => {}, 1000)); }');
  mod('crash', { id: 'crash', name: 'Crash' }, 'export function test() { process.exit(3); }');
  // answers, but leaves a timer running; its proposals reach past its own IS
  mod('sloppy', { id: 'sloppy', name: 'Sloppy', permissions: { map: true } }, `
    export function test() { setInterval(() => {}, 1000); return 'answered'; }
    export function run(cfg, { state }) {
      setInterval(() => {}, 1000);
      return { summary: 'done', proposals: [{ siteId: 'lyon', title: 'Sloppy', changes: {
        si: { lyon: { ...state.si.lyon, name: 'Lyon (sloppy)' }, paris: { name: 'Paris' } },
        assets: { 'web-01': { ...state.assets['web-01'], os: 'sloppy' }, 'elsewhere': { site: 'paris', name: 'x' }, 'app-erp': { ...state.assets['app-erp'], site: 'paris' } },
        wan: [{ a: 'lyon', b: 'paris' }], services: [] } }] };
    }`);
  fs.symlinkSync(join(tmp, 'nowhere'), join(modulesDir, 'dangling'));
  mod('broken', { id: 'Not An Id', name: 'Broken' }, 'export function test() {}');
  mod('taken', { id: 'glpi', name: 'Fake GLPI' }, 'export function test() {}');

  // the registry: the committed index and package, or a tampered checksum
  registry = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    if (p === '/index.json') {
      const idx = JSON.parse(fs.readFileSync(join(root, 'docs/modules/index.json'), 'utf8'));
      if (tamper) idx.modules.find(m => m.id === 'csv-inventory').sha256 = '0'.repeat(64);
      res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(idx));
    }
    if (p === '/pkg/csv.tgz') { res.writeHead(302, { Location: '/csv-inventory-1.0.0.tgz' }); return res.end(); }
    const f = join(root, 'docs/modules', p.slice(1));
    if (/^\/[\w.-]+\.tgz$/.test(p) && fs.existsSync(f)) { res.writeHead(200); return res.end(fs.readFileSync(f)); }
    res.writeHead(404); res.end();
  });
  await new Promise(r => registry.listen(regPort, '127.0.0.1', r));

  await start(join(root, 'scripts/connector-sim.mjs'), [], { SIM_PORT: String(simPort) }, 'mock on');
  await start(join(root, 'server/server.js'), [], {
    PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: PASS.admin,
    MODULES_DIR: modulesDir, MODULE_REGISTRY: `http://127.0.0.1:${regPort}/index.json`, MODULE_UPLOAD: 'true', CONNECTOR_TIMEOUT_MINUTES: '0.05',
  }, 'listening');
  for (const [name, role] of [['alice', 'contributor'], ['bob', 'approver']]) assert.equal((await api('admin', 'PUT', `/api/users/${name}`, { role, password: PASS[name] })).status, 200);
  assert.equal((await api('admin', 'POST', '/api/import', STATE)).status, 200);
});
after(async () => {
  for (const p of procs) if (p.exitCode === null) await new Promise(res => { p.once('exit', res); p.kill(); });
  if (registry) registry.close();
  fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5 });
});

async function api(user, method, path, body) {
  const r = await fetch(base + path, {
    method,
    headers: { Authorization: 'Basic ' + Buffer.from(`${user}:${PASS[user]}`).toString('base64'), ...(body !== undefined ? { 'Content-Type': 'application/json', 'X-Requested-With': 'strata' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, data: await r.json().catch(() => null) };
}
const csvFile = text => ({ name: 'inventory.csv', text });

test('the built-in modules, the server-provided ones, and the folders that are not modules', async () => {
  const r = await api('admin', 'GET', '/api/connectors');
  const by = Object.fromEntries(r.data.connectors.map(c => [c.id, c]));
  for (const id of ['cyberwatch', 'glpi', 'phpipam', 'paloalto']) assert.equal(by[id].origin, 'builtin', id);
  assert.equal(by.paloalto.badge, 'FW');
  assert.deepEqual(by.paloalto.file.fields, ['site', 'firewall', 'scope']);
  assert.equal(by.spy.origin, 'provided');
  assert.equal(by.glpi.name, 'GLPI', 'a provided module cannot take a built-in id');
  const problems = r.data.problems.map(p => p.folder + ': ' + p.error).join('\n');
  assert.match(problems, /broken: id must be/);
  assert.match(problems, /taken: the id “glpi” is already taken/);
  // a contributor only sees the file imports open to them, with their own settings
  const a = await api('alice', 'GET', '/api/connectors');
  assert.deepEqual(a.data.connectors.map(c => c.id), ['paloalto']);
  assert.deepEqual(Object.keys(a.data.connectors[0].settings).sort(), ['firewall', 'scope', 'site']);
  assert.equal(a.data.problems, undefined);
});

test('a built-in module syncs from its tool in its own process', async () => {
  assert.equal((await api('admin', 'PUT', '/api/connectors/cyberwatch', { url: `${sim}/cw`, accessKey: 'AK', secretKey: 'SK', minLevel: 'low' })).status, 200);
  const t = await api('bob', 'POST', '/api/connectors/cyberwatch/test', {});
  assert.equal(t.data.ok, true, t.data.message);
  const r = await api('bob', 'POST', '/api/connectors/cyberwatch/run', { wait: true });
  assert.equal(r.data.run.ok, true, r.data.run.error);
  assert.equal(r.data.run.proposals.length, 1);
  const p = (await api('bob', 'GET', `/api/proposals/${r.data.run.proposals[0].id}`)).data.proposal;
  assert.ok(p.changes.assets['web-01'].vulns.length > 0);
  assert.equal(p.connector, 'cyberwatch');
  // a wrong password is an expected error, said plainly
  await api('admin', 'PUT', '/api/connectors/cyberwatch', { secretKey: 'wrong' });
  const bad = await api('bob', 'POST', '/api/connectors/cyberwatch/test', {});
  assert.equal(bad.data.ok, false);
  assert.doesNotMatch(bad.data.message, /Unexpected/);
});

test('file imports: a contributor imports a firewall configuration, a sync still needs an approver', async () => {
  const xml = await (await fetch(`${sim}/pan/api/?type=export&category=configuration`, { headers: { 'X-PAN-KEY': 'KEY123' } })).text();
  assert.match(xml, /<config/);
  assert.equal((await api('alice', 'POST', '/api/connectors/paloalto/run', { wait: true })).status, 403);
  const r = await api('alice', 'POST', '/api/connectors/paloalto/run', { wait: true, file: { name: 'running-config.xml', text: xml }, overrides: { site: 'lyon', firewall: 'lyo-fw-edge', scope: '', url: 'http://evil' } });
  assert.equal(r.status, 200);
  assert.equal(r.data.run.ok, true, r.data.run.error);
  assert.equal(r.data.run.file, 'running-config.xml');
  assert.match(r.data.run.summary, /rule\(s\) read/);
  // the older form of the same request still works
  const old = await api('alice', 'POST', '/api/connectors/paloalto/run', { wait: true, xml, fileName: 'old.xml', overrides: { site: 'lyon' } });
  assert.equal(old.data.run.ok, true, old.data.run.error);
  assert.equal((await api('alice', 'POST', '/api/connectors/cyberwatch/run', { wait: true, file: csvFile('a') })).status, 400);
});

test('a module process cannot read the data files, write, start programs or see the server passwords', async () => {
  const r = await api('bob', 'POST', '/api/connectors/spy/test', {});
  assert.equal(r.data.ok, true, r.data.message);
  const seen = JSON.parse(r.data.message);
  assert.equal(seen.dataFile, 'ERR_ACCESS_DENIED');
  assert.equal(seen.write, 'ERR_ACCESS_DENIED');
  assert.equal(seen.spawn, 'ERR_ACCESS_DENIED');
  assert.equal(seen.password, null);
  assert.equal(seen.dataDir, null);
  assert.equal(seen.sdk, 'function');
  assert.equal(seen.map, undefined, 'a test gets no map');
  // its own settings only: nothing of the Cyberwatch module set up earlier
  assert.deepEqual(seen.settings, ['enabled', 'everyHours', 'tls', 'tlsInsecure']);
});

test('a module that answers is done at once, and its proposal stays within its IS', async () => {
  const t0 = Date.now();
  const t = await api('bob', 'POST', '/api/connectors/sloppy/test', {});
  assert.equal(t.data.message, 'answered');
  const r = await api('bob', 'POST', '/api/connectors/sloppy/run', { wait: true });
  assert.ok(Date.now() - t0 < 2500, 'an open timer held the run');
  assert.equal(r.data.run.ok, true, r.data.run.error);
  const p = (await api('bob', 'GET', `/api/proposals/${r.data.run.proposals[0].id}`)).data.proposal;
  assert.deepEqual(Object.keys(p.changes.si), ['lyon']);
  assert.deepEqual(Object.keys(p.changes.assets), ['web-01']);
  assert.equal(p.changes.wan, undefined);
  assert.equal(p.changes.services, undefined);
  const problems = (await api('admin', 'GET', '/api/connectors')).data.problems.map(x => x.folder).join(' ');
  assert.match(problems, /dangling/, 'a broken link is reported, the server still starts');
});

test('a module that hangs is stopped, one that crashes is reported', async () => {
  const t0 = Date.now();
  const r = await api('bob', 'POST', '/api/connectors/slow/test', {});
  assert.equal(r.data.ok, false);
  assert.match(r.data.message, /stopped/);
  assert.ok(Date.now() - t0 < 20000);
  const c = await api('bob', 'POST', '/api/connectors/crash/test', {});
  assert.equal(c.data.ok, false);
  assert.match(c.data.message, /exit code 3/);
});

test('the store: install a module, import a file with it, then remove it', async () => {
  assert.equal((await api('bob', 'GET', '/api/modules')).status, 403);
  const l = await api('admin', 'GET', '/api/modules');
  assert.equal(l.data.store, true);
  const csv = l.data.modules.find(m => m.id === 'csv-inventory');
  assert.ok(csv, JSON.stringify(l.data));
  assert.equal(csv.installed, null);
  assert.deepEqual(csv.permissions, { map: true, network: false });
  assert.equal(csv.sha256, undefined);

  const i = await api('admin', 'POST', '/api/modules/csv-inventory/install', {});
  assert.equal(i.status, 200, JSON.stringify(i.data));
  assert.equal(i.data.module.version, '1.0.0');
  assert.ok(fs.existsSync(join(dataDir, 'modules/csv-inventory/strata-module.json')));
  assert.equal((await api('admin', 'GET', '/api/modules')).data.modules.find(m => m.id === 'csv-inventory').installed.origin, 'installed');

  // a contributor imports a CSV file into Lyon: one asset updated, two new, one in the holding VLAN
  const text = 'Name;IP;Type;OS;Role;Criticality\nweb-01;10.10.10.11;server;Debian 12;Front end;high\nnew-db;10.20.0.31;database;;ERP database;3\n"printer, hall";;printer;;;\n';
  const r = await api('alice', 'POST', '/api/connectors/csv-inventory/run', { wait: true, file: csvFile(text), overrides: { site: 'lyon' } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.run.ok, true, r.data.run.error);
  assert.match(r.data.run.summary, /3 line\(s\) read: 2 new asset\(s\), 1 updated/);
  const p = (await api('admin', 'GET', `/api/proposals/${r.data.run.proposals[0].id}`)).data.proposal;
  assert.equal(p.changes.assets['web-01'].os, 'Debian 12');
  assert.equal(p.changes.assets['web-01'].crit, 3);
  assert.equal(p.changes.assets['csv-lyon-new-db'].vlan, 'v20');
  assert.equal(p.changes.assets['csv-lyon-new-db'].type, 'db');
  assert.equal(p.changes.assets['csv-lyon-printer-hall'].vlan, 'v-lyon-unsorted');
  // a live sync makes no sense for it
  assert.equal((await api('bob', 'POST', '/api/connectors/csv-inventory/run', { wait: true })).status, 400);

  // built-in and server-provided modules cannot be removed from the web
  assert.equal((await api('admin', 'DELETE', '/api/modules/glpi', {})).status, 400);
  assert.equal((await api('admin', 'DELETE', '/api/modules/spy', {})).status, 400);
  await api('admin', 'PUT', '/api/connectors/csv-inventory', { updateExisting: false });
  assert.equal((await api('admin', 'DELETE', '/api/modules/csv-inventory', {})).status, 200);
  assert.ok(!fs.existsSync(join(dataDir, 'modules/csv-inventory')));
  assert.equal((await api('admin', 'GET', '/api/connectors')).data.connectors.some(c => c.id === 'csv-inventory'), false);
  assert.equal(JSON.parse(fs.readFileSync(join(dataDir, 'connectors.json'), 'utf8')).connectors['csv-inventory'], undefined, 'its settings are forgotten');
});

test('store modules: an Nmap scan imported by a contributor, NetBox synced by an approver', async () => {
  for (const id of ['nmap', 'netbox']) assert.equal((await api('admin', 'POST', `/api/modules/${id}/install`, {})).status, 200, id);
  // Nmap: app-erp gets its system and services, a new host is created as a database
  const xml = fs.readFileSync(join(root, 'tests/fixtures/nmap-scan.xml'), 'utf8');
  const n = await api('alice', 'POST', '/api/connectors/nmap/run', { wait: true, file: { name: 'scan.xml', text: xml }, overrides: { site: 'lyon' } });
  assert.equal(n.data.run.ok, true, n.data.run.error);
  assert.match(n.data.run.summary, /2 host\(s\) up in the scan: 1 on the map \(1 updated\), 1 new/);
  let p = (await api('admin', 'GET', `/api/proposals/${n.data.run.proposals[0].id}`)).data.proposal;
  assert.equal(p.changes.assets['app-erp'].os, 'Linux 5.0 - 5.14');
  assert.deepEqual(p.changes.assets['app-erp'].apps.map(a => [a.name, a.ports]), [['OpenSSH', ['tcp/22']], ['Apache Tomcat', ['tcp/8080']]]);
  assert.equal(p.changes.assets['nmap-lyon-10-20-0-31'].type, 'db');
  assert.equal(p.changes.assets['nmap-lyon-10-20-0-31'].os, '', 'an OS guess below 90% is not kept');
  assert.match((await api('alice', 'POST', '/api/connectors/nmap/run', { wait: true, file: { name: 'x.xml', text: '<config/>' }, overrides: { site: 'lyon' } })).data.run.error, /not an Nmap XML report/);

  // NetBox, through the simulator: the Lyon HQ site is the lyon IS, Oslo has no IS
  await api('admin', 'PUT', '/api/connectors/netbox', { url: `${sim}/netbox`, token: 'NBT', siteRules: 'Lyon HQ = lyon' });
  const t = await api('bob', 'POST', '/api/connectors/netbox/test', {});
  assert.equal(t.data.message, 'Connected to NetBox 4.1.6.');
  const r = await api('bob', 'POST', '/api/connectors/netbox/run', { wait: true });
  assert.equal(r.data.run.ok, true, r.data.run.error);
  assert.match(r.data.run.summary, /2 NetBox site\(s\), 1 matched to an IS \(1 without\); 1 new VLAN\(s\), 1 updated; 2 new asset\(s\), 1 updated/);
  p = (await api('admin', 'GET', `/api/proposals/${r.data.run.proposals[0].id}`)).data.proposal;
  const vlans = p.changes.si.lyon.vlans;
  assert.equal(vlans.find(v => v.num === 70).cidr, '10.70.0.0/24');
  assert.equal(p.changes.assets['app-erp'].os, 'RHEL 9');
  assert.equal(p.changes.assets['netbox-lyon-dev-2'].type, 'switch');
  assert.equal(p.changes.assets['netbox-lyon-dev-2'].vlan, vlans.find(v => v.num === 70).id);
  assert.equal(p.changes.assets['netbox-lyon-vm-7'].os, 'Ubuntu 24.04');
  assert.ok(!Object.keys(p.changes.assets).some(k => k.includes('dev-3')), 'a decommissioning device is left out');
  await api('admin', 'PUT', '/api/connectors/netbox', { token: 'wrong' });
  assert.match((await api('bob', 'POST', '/api/connectors/netbox/test', {})).data.message, /access refused/);
  for (const id of ['nmap', 'netbox']) assert.equal((await api('admin', 'DELETE', `/api/modules/${id}`, {})).status, 200);
});

test('the store refuses a package that does not match its checksum', async () => {
  tamper = true;
  try {
    const r = await api('admin', 'POST', '/api/modules/csv-inventory/install', {});
    assert.equal(r.status, 400);
    assert.match(r.data.error, /checksum/);
    assert.ok(!fs.existsSync(join(dataDir, 'modules/csv-inventory')));
  } finally { tamper = false; }
  assert.equal((await api('admin', 'POST', '/api/modules/nope/install', {})).status, 400);
});

test('uploading a package by hand, and the packages that are refused', async () => {
  const files = id => [
    { path: 'strata-module.json', data: Buffer.from(JSON.stringify({ strataModule: 1, id, name: 'Hello', version: '0.1.0', description: 'Says hello', main: 'index.mjs', fields: [] })) },
    { path: 'index.mjs', data: Buffer.from("export const test = () => 'hello';") },
  ];
  const up = buf => api('admin', 'POST', '/api/modules/upload', { data: buf.toString('base64') });
  const ok = await up(writeTgz(files('hello')));
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal((await api('bob', 'POST', '/api/connectors/hello/test', {})).data.message, 'hello');
  assert.equal((await api('admin', 'DELETE', '/api/modules/hello', {})).status, 200);

  assert.match((await up(writeTgz(files('glpi')))).data.error, /builtin module already has the id/);
  assert.match((await up(Buffer.from('not a package'))).data.error, /not a \.tgz/);
  const evil = writeTgz([...files('evil'), { path: 'x/../../escape.mjs', data: Buffer.from('') }], 'evil');
  assert.match((await up(evil)).data.error, /Unsafe path/);
  assert.equal(fs.readdirSync(join(dataDir, 'modules')).filter(n => n !== '.' && !n.startsWith('.')).length, 0);
  assert.equal((await api('bob', 'POST', '/api/modules/upload', { data: '' })).status, 403);
});

test('package reader and manifest checks', () => {
  const man = { strataModule: 1, id: 'acme', name: 'Acme', version: '1.0.0', description: 'x', main: 'index.mjs', fields: [] };
  assert.equal(checkManifest(man).badge, 'ACM');
  assert.throws(() => checkManifest({ ...man, strataModule: 2 }), /strataModule/);
  assert.throws(() => checkManifest({ ...man, main: '../x.mjs' }), /main/);
  assert.throws(() => checkManifest({ ...man, fields: [{ k: 'enabled', label: 'x' }] }), /every module already has/);
  assert.throws(() => checkManifest({ ...man, fields: [{ k: 'toString', label: 'x' }] }), /built-in name/);
  assert.throws(() => checkManifest({ ...man, permissions: { files: true } }), /permissions/);
  assert.throws(() => checkManifest({ ...man, live: false }), /must import files/);
  assert.throws(() => checkManifest({ ...man, minStrata: '99.0.0' }, { strataVersion: '0.8.0' }), /needs Strata 99/);
  assert.ok(compareVersions('0.10.0', '0.9.1') > 0 && compareVersions('1.0.0-rc.1', '1.0.0') < 0 && compareVersions('1.2.3', '1.2.3') === 0);
  // the top folder goes, whatever its name; a link inside a package is refused
  const tgz = writeTgz([{ path: 'strata-module.json', data: Buffer.from('{}') }, { path: 'lib/a.mjs', data: Buffer.from('') }], 'anything');
  assert.deepEqual(readTgz(tgz).map(f => f.path), ['lib/a.mjs', 'strata-module.json']);
  const tar = zlib.gunzipSync(tgz);
  tar[156] = '2'.charCodeAt(0);
  tar.fill(32, 148, 156);
  let sum = 0; for (let i = 0; i < 512; i++) sum += tar[i];
  tar.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  assert.throws(() => readTgz(zlib.gzipSync(tar)), /link or a special file/);
  assert.throws(() => readTgz(writeTgz([{ path: 'index.mjs', data: Buffer.from('') }])), /no strata-module.json/);
});

test('the store package of the example module is the module in this repository', () => {
  const idx = JSON.parse(fs.readFileSync(join(root, 'docs/modules/index.json'), 'utf8'));
  for (const e of idx.modules) {
    const buf = fs.readFileSync(join(root, 'docs/modules', e.url));
    assert.equal(sha256(buf), e.sha256, `${e.url}: run node scripts/pack-module.mjs modules/${e.id} --registry docs/modules/index.json`);
    const files = readTgz(buf);
    const src = join(root, 'modules', e.id);
    assert.deepEqual(files.map(f => f.path).sort(), fs.readdirSync(src).sort());
    for (const f of files) assert.ok(f.data.equals(fs.readFileSync(join(src, f.path))), `${f.path} differs from modules/${e.id}: pack it again`);
    const man = checkManifest(JSON.parse(fs.readFileSync(join(src, 'strata-module.json'), 'utf8')));
    assert.equal(man.version, e.version);
  }
});
