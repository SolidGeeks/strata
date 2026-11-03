// SPDX-License-Identifier: AGPL-3.0-or-later
// Data integrity and refusals: a corrupt accounts file never opens the map, a failed write is not answered "ok",
// READ_ONLY refuses every write, imports hold objects only, an approver approves what they reviewed, and a
// server without accounts does not listen on the network. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const PASS = 'admin-pass-123';
const wait = ms => new Promise(r => setTimeout(r, ms));

function start(extra = {}, dataDir = mkdtempSync(join(tmpdir(), 'strata-integrity-'))) {
  const port = 10100 + Math.floor(Math.random() * 800);
  const proc = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: PASS, VIEW_PASS: '', CONNECTORS: 'false', MODULE_REGISTRY: 'off', ...extra },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  const stop = () => new Promise(res => { if (proc.exitCode !== null) return res(); proc.once('exit', res); proc.kill(); });
  return new Promise((res, rej) => {
    proc.stdout.on('data', d => { out += d; if (String(d).includes('listening')) res({ port, dataDir, stop, log: () => out }); });
    proc.stderr.on('data', d => { out += d; });
    proc.on('exit', code => rej(Object.assign(new Error(`exit ${code}`), { code, log: out })));
  });
}
async function call(port, method, path, body, user = 'admin', pass = PASS) {
  const headers = { 'X-Requested-With': 'strata' };
  if (user) headers.Authorization = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
  if (method !== 'GET') headers['Content-Type'] = 'application/json';
  const r = await fetch(`http://127.0.0.1:${port}/api/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { }
  return { status: r.status, body: j };
}

test('a users.json that cannot be read never opens the map: kept on reload, refused at start', async () => {
  const s = await start();
  try {
    assert.equal((await call(s.port, 'GET', 'me', undefined, '')).status, 401);
    writeFileSync(join(s.dataDir, 'users.json'), '{"users": {');
    await wait(6000); // the accounts file is checked every 5 s
    assert.equal((await call(s.port, 'GET', 'me', undefined, '')).status, 401, 'no account must not mean open');
    assert.equal((await call(s.port, 'GET', 'me')).status, 200, 'the accounts loaded before are kept');
    assert.match(s.log(), /users\.json cannot be read/);
  } finally { await s.stop(); }
  await assert.rejects(start({}, s.dataDir), e => e.code === 1 && /cannot be read/.test(e.log));
  rmSync(s.dataDir, { recursive: true, force: true });
});

test('a proposals file that cannot be read is moved aside, not overwritten', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'strata-integrity-'));
  writeFileSync(join(dir, 'proposals.json'), '{broken', { mode: 0o600 });
  const s = await start({}, dir);
  try {
    assert.ok(readdirSync(dir).some(f => f.startsWith('proposals.json.unreadable-')));
    assert.match(s.log(), /proposals\.json cannot be read/);
  } finally { await s.stop(); rmSync(dir, { recursive: true, force: true }); }
});

test('a write that fails is answered with an error (directory in the way), and the map in memory is unchanged', async () => {
  const s = await start();
  try {
    assert.equal((await call(s.port, 'PUT', 'si/s1', { name: 'One' })).status, 200);
    mkdirSync(join(s.dataDir, 'db.json.tmp'));
    const r = await call(s.port, 'PUT', 'si/s2', { name: 'Two' });
    assert.ok(r.status >= 500, `got ${r.status}`);
    assert.equal((await call(s.port, 'GET', 'si/s2')).status, 404);
    const st = await call(s.port, 'GET', 'state');
    assert.equal(st.body.rev, 1);
    rmSync(join(s.dataDir, 'db.json.tmp'), { recursive: true });
    assert.equal((await call(s.port, 'PUT', 'si/s2', { name: 'Two' })).body.rev, 2);
  } finally { await s.stop(); rmSync(s.dataDir, { recursive: true, force: true }); }
});

test('an import holds objects only', async () => {
  const s = await start();
  try {
    const r = await call(s.port, 'POST', 'import', { si: { a: 5, b: null }, assets: { x: [1, 2] } });
    assert.equal(r.status, 400);
    assert.equal((await call(s.port, 'GET', 'kpi')).status, 200);
  } finally { await s.stop(); rmSync(s.dataDir, { recursive: true, force: true }); }
});

test('an approver approves the version they reviewed; READ_ONLY refuses withdraw, delete and password changes', async () => {
  const s = await start();
  try {
    assert.equal((await call(s.port, 'PUT', 'users/carol', { role: 'contributor', password: 'carol-pass-123' })).status, 200);
    assert.equal((await call(s.port, 'PUT', 'users/bob', { role: 'approver', password: 'bob-pass-1234' })).status, 200);
    assert.equal((await call(s.port, 'PUT', 'users/x', { role: 'viewer', password: { a: 1 } })).status, 400);
    assert.equal((await call(s.port, 'PUT', 'si/s1', { name: 'One' })).status, 200);
    const p = (await call(s.port, 'POST', 'proposals', { title: 'Rename', changes: { si: { s1: { name: 'Uno' } } } }, 'carol', 'carol-pass-123')).body.proposal;
    await call(s.port, 'POST', `proposals/${p.id}/submit`, {}, 'carol', 'carol-pass-123');
    const seen = (await call(s.port, 'GET', `proposals/${p.id}`, undefined, 'bob', 'bob-pass-1234')).body.proposal.updatedAt;
    // carol reworks it after bob opened it
    await call(s.port, 'POST', `proposals/${p.id}/withdraw`, {}, 'carol', 'carol-pass-123');
    await wait(5);
    await call(s.port, 'PUT', `proposals/${p.id}`, { changes: { si: { s1: { name: 'Something else' } } } }, 'carol', 'carol-pass-123');
    await call(s.port, 'POST', `proposals/${p.id}/submit`, {}, 'carol', 'carol-pass-123');
    const stale = await call(s.port, 'POST', `proposals/${p.id}/approve`, { updatedAt: seen }, 'bob', 'bob-pass-1234');
    assert.equal(stale.status, 409);
    assert.equal(stale.body.changed, true);
    assert.equal((await call(s.port, 'GET', 'si/s1')).body.name, 'One');
  } finally { await s.stop(); }
  const ro = await start({ READ_ONLY: 'true' }, s.dataDir);
  try {
    const list = (await call(ro.port, 'GET', 'proposals')).body.proposals;
    assert.equal((await call(ro.port, 'POST', `proposals/${list[0].id}/withdraw`, {}, 'carol', 'carol-pass-123')).status, 403);
    assert.equal((await call(ro.port, 'DELETE', `proposals/${list[0].id}`, undefined, 'carol', 'carol-pass-123')).status, 403);
    assert.equal((await call(ro.port, 'PUT', 'me/password', { current: 'carol-pass-123', next: 'carol-pass-456' }, 'carol', 'carol-pass-123')).status, 403);
  } finally { await ro.stop(); rmSync(s.dataDir, { recursive: true, force: true }); }
});

test('without any account, the server does not listen on the network unless ALLOW_OPEN=true', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'strata-integrity-'));
  try {
    await assert.rejects(start({ EDIT_PASS: '', HOST: '0.0.0.0' }, dir), e => e.code === 1 && /ALLOW_OPEN/.test(e.log));
    const s = await start({ EDIT_PASS: '', HOST: '0.0.0.0', ALLOW_OPEN: 'true' }, dir);
    await s.stop();
    const l = await start({ EDIT_PASS: '' }, dir); // 127.0.0.1
    await l.stop();
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.ok(!existsSync(dir));
});

test('incidents: a save made on an older version is refused, and new timeline entries carry the saver\'s name', async () => {
  const s = await start();
  try {
    assert.equal((await call(s.port, 'PUT', 'users/carol', { role: 'contributor', password: 'carol-pass-123' })).status, 200);
    assert.equal((await call(s.port, 'PUT', 'si/s1', { name: 'One' })).status, 200);
    const a = await call(s.port, 'PUT', 'incidents/s1', { on: true, marks: {}, log: [{ at: Date.now(), msg: 'Opened', by: 'someone-else' }], rev: 0 });
    assert.equal(a.status, 200);
    assert.equal(a.body.incident.rev, 1);
    assert.equal(a.body.incident.log[0].by, 'admin');
    const b = await call(s.port, 'PUT', 'incidents/s1', { on: true, marks: {}, log: [], rev: 0 }, 'carol', 'carol-pass-123');
    assert.equal(b.status, 409);
    const c = await call(s.port, 'PUT', 'incidents/s1', { on: true, marks: {}, log: [...a.body.incident.log, { at: Date.now(), msg: 'Cut', by: 'admin' }], rev: 1 }, 'carol', 'carol-pass-123');
    assert.equal(c.status, 200);
    assert.deepEqual(c.body.incident.log.map(l => l.by), ['admin', 'carol']);
    assert.equal((await call(s.port, 'PUT', 'incidents/s1', { on: true, run: { big: 'x'.repeat(300 * 1024) } })).status, 413);
  } finally { await s.stop(); rmSync(s.dataDir, { recursive: true, force: true }); }
});

test('Muster: no redirect is followed, and a list holding anything but incidents does not stop the server', async () => {
  const http = await import('node:http');
  const { createMuster } = await import('../server/muster.js');
  let gotPassword = false, mode = 'redirect';
  const other = http.createServer((req, res) => { req.on('data', () => { gotPassword = true; }); req.on('end', () => res.end('{}')); });
  await new Promise(r => other.listen(0, '127.0.0.1', r));
  const fake = http.createServer((req, res) => {
    if (req.url === '/api/auth/login') {
      if (mode === 'redirect') { res.writeHead(307, { Location: `http://127.0.0.1:${other.address().port}/steal` }); return res.end(); }
      res.writeHead(200, { 'Set-Cookie': 'muster_session=abc; HttpOnly' }); return res.end('{}');
    }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify([null, 1, { id: 'INC-1', rev: 2 }, { id: '../x' }]));
  });
  await new Promise(r => fake.listen(0, '127.0.0.1', r));
  try {
    const m = createMuster({ url: `http://127.0.0.1:${fake.address().port}`, user: 'strata', password: 'S3CRET', pollMs: 60000 });
    let st = await m.refresh();
    assert.equal(st.ok, false);
    assert.match(st.error, /redirect/);
    await wait(100);
    assert.equal(gotPassword, false, 'the password went to the redirect target');
    mode = 'ok';
    st = await m.refresh();
    assert.equal(st.ok, true);
    assert.deepEqual(st.incidents.map(i => i.id), ['INC-1']);
  } finally { fake.close(); other.close(); }
});

test('documents are checked for shape: ids inside an IS, lists and text, on the live map, in imports and in proposals', async () => {
  const s = await start();
  try {
    const bad = { name: 'x', vlans: [{ id: 'v2"><img src=x onerror=alert(1)>', name: 'DMZ' }] };
    assert.equal((await call(s.port, 'PUT', 'si/s1', bad)).status, 400);
    assert.equal((await call(s.port, 'PUT', 'si/s1', { name: 'x', vlans: 5 })).status, 400);
    assert.equal((await call(s.port, 'PUT', 'assets/a1', { name: { a: 1 }, site: 's1' })).status, 400);
    assert.equal((await call(s.port, 'POST', 'import', { si: { s1: bad }, assets: {} })).status, 400);
    assert.equal((await call(s.port, 'POST', 'proposals', { title: 't', changes: { si: { s1: bad } } })).status, 400);
    assert.equal((await call(s.port, 'PUT', 'si/s1', { name: 'One', vlans: [{ id: 'v-1', name: 'DMZ', zone: 'z-1' }], zones: [{ id: 'z-1', name: 'Front' }], flows: [{ id: 'f-1', src: 'internet', dst: 'a1', port: 'tcp/443', via: [] }] })).status, 200);
  } finally { await s.stop(); rmSync(s.dataDir, { recursive: true, force: true }); }
});
