// SPDX-License-Identifier: AGPL-3.0-or-later
// Connector hardening, without the server: what the parent takes from a module process (message and log
// budgets, the first answer only, the size of a proposal), the module store's HTTPS rule and its check
// of the package against the index, the XML parser, Palo Alto stale flows and the store modules'
// matching. Run with: npm test
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readModule } from '../server/connectors/modules.js';
import { runModule } from '../server/connectors/runner.js';
import { createConnectors, MAX_PROPOSAL_BYTES } from '../server/connectors/index.js';
import { createStore, writeTgz, sha256, storeUrlAllowed } from '../server/connectors/store.js';
import * as sdk from '../server/connectors/sdk.js';
import { parseConfig, rulesToChanges } from '../server/connectors/builtin/paloalto/index.js';
import * as nmap from '../modules/nmap/index.mjs';
import * as csv from '../modules/csv-inventory/index.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const strataVersion = JSON.parse(fs.readFileSync(join(root, 'package.json'), 'utf8')).version;
const tmp = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'strata-limits-')));
after(() => fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5 }));

const manifest = (id, extra = {}) => ({ strataModule: 1, id, name: id, version: '1.0.0', description: 'Test module', main: 'index.mjs', fields: [], ...extra });
function makeModule(parent, id, code, extra) {
  const dir = join(parent, id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(join(dir, 'strata-module.json'), JSON.stringify(manifest(id, extra)));
  fs.writeFileSync(join(dir, 'index.mjs'), code);
  const r = readModule(dir, 'provided', { strataVersion });
  assert.ok(r.ok, r.error);
  return r.module;
}

test('a module that sends too much to the server is stopped and its run fails', async () => {
  const m = makeModule(tmp, 'flood', `export async function run() {
    const big = 'x'.repeat(256 * 1024);
    for (let i = 0; i < 64; i++) await new Promise(r => process.send({ junk: big }, r));
    return 'never';
  }`);
  await assert.rejects(runModule(m, 'run', {}, { timeoutMs: 30000, maxMessageBytes: 2 * 1024 * 1024 }), /sent more than 2 MB to the server and was stopped/);
  // one answer too large on its own
  const m2 = makeModule(tmp, 'bigresult', `export function run() { return 'y'.repeat(3 * 1024 * 1024); }`);
  await assert.rejects(runModule(m2, 'run', {}, { timeoutMs: 30000, maxMessageBytes: 2 * 1024 * 1024 }), /sent more than 2 MB/);
});

test('the first answer of a module is final, later messages are ignored', async () => {
  const m = makeModule(tmp, 'twice', `export async function run() {
    await new Promise(r => process.send({ ok: true, result: 'first' }, r));
    await new Promise(r => process.send({ ok: false, error: 'second' }, r));
    return 'third';
  }`);
  assert.equal(await runModule(m, 'run', {}, { timeoutMs: 30000 }), 'first');
});

test('module log lines are cut at 2000 characters, and a run has a log budget', async () => {
  const m = makeModule(tmp, 'chatty', `export async function run(cfg, ctx) {
    const line = 'z'.repeat(10000);
    for (let i = 0; i < 300; i++) await new Promise(r => process.send({ log: line }, r));
    return 'done';
  }`);
  const lines = [];
  assert.equal(await runModule(m, 'run', {}, { timeoutMs: 30000, log: l => lines.push(l), maxLogLines: 50 }), 'done');
  const kept = lines.filter(l => l.includes('zzz'));
  assert.equal(kept.length, 50);
  assert.ok(kept.every(l => l.length <= 2000 + '[chatty] '.length), 'each line is cut');
  assert.equal(lines.filter(l => /log truncated/.test(l)).length, 1);
});

test('a proposal larger than the limit is refused, the run goes on', async () => {
  const provided = join(tmp, 'provided-big');
  makeModule(provided, 'bulky', `export function run(cfg, { state }) {
    const big = 'b'.repeat(${MAX_PROPOSAL_BYTES + 1024});
    return { summary: 'done', proposals: [
      { siteId: 'lyon', changes: { si: { lyon: { ...state.si.lyon, notes: big } }, assets: {} } },
      { siteId: 'lyon', changes: { si: { lyon: { ...state.si.lyon, name: 'Lyon 2' } }, assets: {} } },
    ] };
  }
  export function test() { return 'ok'; }`, { permissions: { map: true } });
  const state = { si: { lyon: { name: 'Lyon', zones: [], vlans: [] } }, assets: {} };
  const made = [];
  const c = createConnectors({
    dataDir: tmp, providedDir: provided, installedDir: join(tmp, 'none'), strataVersion, timeoutMs: 60000,
    getState: () => state, upsertProposal: async p => { made.push(p); return { id: 'p1', title: p.title }; },
    log: () => { }, writeJson: async (f, s) => fs.writeFileSync(f, s), broadcast: () => { },
  });
  const rec = await c.run('bulky', { by: 'test' });
  assert.equal(rec.ok, true, rec.error);
  assert.equal(made.length, 1);
  assert.equal(made[0].changes.si.lyon.name, 'Lyon 2');
  assert.match(rec.report.warnings.join('\n'), /changes too large/);
});

/* ---------------- module store ---------------- */
test('the store reads over HTTPS only, plain HTTP from this machine only', async () => {
  for (const u of ['https://example.com/i.json', 'http://127.0.0.1:8/i.json', 'http://localhost/i.json', 'http://[::1]:9/x']) assert.ok(storeUrlAllowed(u), u);
  for (const u of ['http://example.com/i.json', 'http://127.0.0.1.evil.com/', 'ftp://example.com/x', 'file:///etc/passwd', 'not a url']) assert.ok(!storeUrlAllowed(u), u);
  const stub = { module: () => null, isRunning: () => false, reload() { }, forget: async () => { } };
  const s = createStore({ registryUrl: 'http://example.com/index.json', installedDir: join(tmp, 'inst0'), strataVersion, connectors: stub, log() { } });
  await assert.rejects(s.list(true), /not an HTTPS address/);
});

test('the store skips plain HTTP packages, refuses HTTP redirects and packages that differ from the index', async () => {
  const pkg = (id, perms) => writeTgz([
    { path: 'strata-module.json', data: Buffer.from(JSON.stringify(manifest(id, { name: 'Good', permissions: perms }))) },
    { path: 'index.mjs', data: Buffer.from('export const run = () => null; export const test = () => "ok";') },
  ]);
  const files = { '/good.tgz': pkg('good', { map: true }), '/sneaky.tgz': pkg('sneaky', { map: true, network: true }) };
  const entry = (id, url, buf, extra = {}) => ({ id, name: 'Good', version: '1.0.0', permissions: { map: true, network: false }, url, sha256: sha256(buf), ...extra });
  const index = { strataRegistry: 1, modules: [
    entry('good', '/redirect.tgz', files['/good.tgz']),
    entry('sneaky', 'sneaky.tgz', files['/sneaky.tgz']),
    entry('renamed', 'good.tgz', files['/good.tgz'], { name: 'Other' }),
    entry('plain', 'http://example.com/plain.tgz', files['/good.tgz']),
  ] };
  const srv = http.createServer((req, res) => {
    if (req.url === '/index.json') return res.end(JSON.stringify(index));
    if (req.url === '/redirect.tgz') { res.writeHead(302, { Location: 'http://example.com/good.tgz' }); return res.end(); }
    if (files[req.url]) return res.end(files[req.url]);
    res.writeHead(404); res.end();
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  try {
    const stub = { module: () => null, isRunning: () => false, reload() { }, forget: async () => { } };
    const s = createStore({ registryUrl: `http://127.0.0.1:${srv.address().port}/index.json`, installedDir: join(tmp, 'inst'), strataVersion, connectors: stub, log() { } });
    assert.deepEqual((await s.list(true)).map(m => m.id), ['good', 'sneaky', 'renamed'], 'the plain HTTP entry is left out');
    await assert.rejects(s.install('good'), /only follows HTTPS/);
    // the package of "renamed" says id "good": refused before its name is even compared
    await assert.rejects(s.install('renamed'), /holds good 1\.0\.0, not renamed/);
    await assert.rejects(s.install('sneaky'), /does not match what the store says \(permissions\.network is true, not false\)/);
    // the same package, under another name in the index
    index.modules[0] = entry('good', 'good.tgz', files['/good.tgz'], { name: 'Not Good' });
    await assert.rejects(s.install('good'), /its name is “Good”, not “Not Good”/);
    assert.ok(!fs.existsSync(join(tmp, 'inst', 'good')) && !fs.existsSync(join(tmp, 'inst', 'sneaky')));
  } finally { srv.close(); }
});

/* ---------------- XML ---------------- */
test('XML: a stray closing tag is ignored, an out-of-range character reference stays text', () => {
  const r = sdk.parseXml('<nmaprun><host></bogus><status state="up"/></host><host/></nmaprun>');
  assert.deepEqual(r.children.map(c => c.name), ['nmaprun']);
  assert.deepEqual(r.children[0].children.map(c => c.name), ['host', 'host']);
  assert.equal(r.children[0].children[0].children[0].name, 'status');
  const e = sdk.parseXml('<a x="&#x110000;">&#99999999;&#xD800;&#65;&amp;</a>').children[0];
  assert.equal(e.text, '&#99999999;&#xD800;A&');
  assert.equal(e.attrs.x, '&#x110000;');
});

/* ---------------- Palo Alto ---------------- */
test('Palo Alto: a large file is read, and stale flows are removed only from the scope imported', () => {
  const t0 = Date.now();
  assert.equal(parseConfig('<a>' + '<b/>'.repeat(200000) + '<config/></a>').kind, 'firewall');
  const many = '<entry name="r"><source><member>any</member></source></entry>'.repeat(130000);
  assert.equal(parseConfig(`<config><devices><entry><vsys><entry name="vsys1"><rulebase><security><rules>${many}</rules></security></rulebase></entry></vsys></entry></devices></config>`).rules.length, 130000);
  assert.ok(Date.now() - t0 < 20000);

  const rule = scope => ({ name: `r-${scope}`, scope, where: 'pre-rulebase', from: [], to: [], source: ['10.0.0.1'], destination: ['10.0.0.2'], service: ['tcp-443'], application: [], action: 'allow', disabled: false, negSrc: false, negDst: false, description: '' });
  const parsed = { kind: 'panorama', objects: {}, rules: [rule('dg-a')] };
  const flow = (scope, port) => ({ id: `f-${scope}-${port}`, src: 'a', dst: 'b', port, pan: { rules: ['old'], scope } });
  const state = {
    si: { s: { name: 'S', flows: [flow('dg-a', 'tcp/22'), flow('dg-b', 'tcp/23'), flow('shared', 'tcp/24'), { id: 'hand', src: 'a', dst: 'b', port: 'tcp/25' }] } },
    assets: { a: { site: 's', name: 'a', ip: '10.0.0.1' }, b: { site: 's', name: 'b', ip: '10.0.0.2' } },
  };
  const ids = cfg => rulesToChanges(parsed, { site: 's', ...cfg }, state).changes.si.s.flows.map(f => f.id).filter(id => !id.startsWith('f-pa-'));
  assert.deepEqual(ids({ scope: 'dg-a' }), ['f-dg-b-tcp/23', 'hand'], 'a scoped import leaves other device groups alone');
  assert.deepEqual(ids({ scope: '' }), ['hand'], 'an import of every scope removes every stale imported flow');
});

/* ---------------- store modules ---------------- */
test('Nmap: a host is matched by IP before its name', async () => {
  const state = { si: { s1: { name: 'S', vlans: [], zones: [] } }, assets: {
    a1: { site: 's1', name: 'web', ip: '10.0.0.5', apps: [] }, a2: { site: 's1', name: 'x', ip: '10.0.0.9', apps: [] } } };
  const host = (ip, name) => `<host><status state="up"/><address addr="${ip}" addrtype="ipv4"/><hostnames><hostname name="${name}"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>`;
  const xml = `<nmaprun>${host('10.0.0.9', 'web.example')}${host('10.0.0.77', 'web.example')}</nmaprun>`;
  const r = await nmap.run({ site: 's1' }, { state, sdk, file: { name: 'f', text: xml }, log() { } });
  const assets = r.proposals[0].changes.assets;
  assert.ok(assets.a2, 'the IP wins over the name of another asset');
  assert.ok(assets.a1, 'with no asset at its IP, the name is used');
  assert.equal(assets.a1.ip, '10.0.0.5');
  assert.equal(Object.keys(assets).length, 2);
});

test('CSV inventory: a type such as "constructor" is unknown, not a built-in name', async () => {
  const state = { si: { s1: { name: 'S', vlans: [], zones: [] } }, assets: {} };
  const r = await csv.run({ site: 's1' }, { state, sdk, file: { name: 'i.csv', text: 'name;type\nh1;constructor\nh2;toString\n' }, log() { } });
  const a = r.proposals[0].changes.assets;
  assert.equal(a['csv-s1-h1'].type, 'server');
  assert.equal(a['csv-s1-h2'].type, 'server');
  assert.equal(r.report.skipped.length, 2);
});
