// SPDX-License-Identifier: AGPL-3.0-or-later
// The connection to Muster: a stand-in Muster server, a real Strata server signed in to it. Run with: npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = mkdtempSync(join(tmpdir(), 'strata-muster-'));
const port = 9300 + Math.floor(Math.random() * 300), mport = port + 400;
const base = `http://127.0.0.1:${port}`;
const PASS = { admin: 'admin-pass-123', alice: 'alice-pass-123', vic: 'vic-pass-1234' };
let server, fake;

// Muster as Strata sees it: a sign-in that sets a cookie, the X-Muster header on writes, the incident routes
const seen = [];
const inc = { id: 'inc_1', ref: 'INC-2026-0001', name: 'Ransom note', pbCode: 'PB-001', pbName: 'Ransomware', v: 3, status: 'active', rev: 1, mode: 'live', severity: 'Critical',
  graph: { nodes: [{ id: 'start', type: 'start' }, { id: 'triage', type: 'action', checklist: ['a'] }, { id: 'end', type: 'end' }], edges: [{ id: 'e1', from: 'start', to: 'triage' }, { id: 'e2', from: 'triage', to: 'end' }] },
  steps: [{ id: 'start', edge: 'e1' }, { id: 'triage' }], checks: {}, log: [], strata: { site: 'lyon', assets: ['file-01'], params: {}, marks: {}, names: {} } };
function fakeMuster(req, res) {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    const json = (code, data, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...h }); res.end(JSON.stringify(data)); };
    const b = body ? JSON.parse(body) : {};
    seen.push({ method: req.method, url: req.url, body: b, cookie: req.headers.cookie || '', csrf: req.headers['x-muster'] });
    if (req.url === '/api/auth/login') return b.username === 'strata' && b.password === 'right' ? json(200, { user: {} }, { 'Set-Cookie': 'muster_session=tok1; HttpOnly' }) : json(401, { error: 'Wrong username or password' });
    if (req.headers.cookie !== 'muster_session=tok1') return json(401, { error: 'Sign in to continue' });
    if (req.method !== 'GET' && req.headers['x-muster'] !== '1') return json(403, { error: 'Missing X-Muster header' });
    if (req.url === '/api/incidents') return json(200, [{ id: inc.id, ref: inc.ref, status: inc.status, rev: inc.rev, strata: inc.strata }]);
    if (req.url === '/api/incidents/inc_1') return json(200, inc);
    if (req.url === '/api/incidents/inc_1/advance') { if (b.edgeId !== 'e2') return json(422, { error: 'That route does not leave the current step' }); inc.steps.at(-1).edge = 'e2'; inc.steps.push({ id: 'end' }); inc.status = 'closed'; inc.rev++; return json(200, inc); }
    if (req.url === '/api/incidents/inc_1/strata') { inc.strata.marks = b.marks; inc.log.push(...b.log); inc.rev++; return json(200, inc); }
    json(404, { error: 'Not found' });
  });
}
const as = user => (method, path, body) => fetch(base + path, {
  method, headers: { Authorization: 'Basic ' + Buffer.from(`${user}:${PASS[user]}`).toString('base64'), ...(body ? { 'Content-Type': 'application/json', 'X-Requested-With': 'strata' } : {}) },
  body: body ? JSON.stringify(body) : undefined,
}).then(async r => ({ status: r.status, data: await r.json().catch(() => null) }));

before(async () => {
  fake = createServer(fakeMuster);
  await new Promise(r => fake.listen(mport, '127.0.0.1', r));
  server = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: PASS.admin, CONNECTORS: 'false',
      MUSTER_URL: `http://127.0.0.1:${mport}`, MUSTER_USER: 'strata', MUSTER_PASSWORD: 'right', MUSTER_POLL_SECONDS: '60' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  await new Promise((res, rej) => { server.stdout.on('data', d => { if (String(d).includes('listening')) res(); }); server.on('exit', c => rej(new Error('exit ' + c))); });
  for (const [name, role] of [['alice', 'contributor'], ['vic', 'viewer']]) assert.equal((await as('admin')('PUT', `/api/users/${name}`, { role, password: PASS[name] })).status, 200);
});
after(async () => {
  if (server && server.exitCode === null) await new Promise(res => { server.once('exit', res); server.kill(); });
  await new Promise(r => fake.close(r));
  rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 });
});

test('Muster: Strata signs in once, lists and reads incidents for every role', async () => {
  const me = await as('vic')('GET', '/api/me');
  assert.deepEqual(me.data.muster, { url: `http://127.0.0.1:${mport}` });
  const list = await as('vic')('GET', '/api/muster');
  assert.equal(list.status, 200);
  assert.equal(list.data.ok, true);
  assert.deepEqual(list.data.incidents.map(i => i.id), ['inc_1']);
  const one = await as('vic')('GET', '/api/muster/incidents/inc_1');
  assert.equal(one.data.ref, 'INC-2026-0001');
  assert.equal(seen.filter(s => s.url === '/api/auth/login').length, 1, 'the session is kept');
  assert.equal((await as('vic')('GET', '/api/muster/incidents/bad%20id')).status, 400);
});

test('Muster: contributors move a response along and report back, viewers cannot', async () => {
  assert.equal((await as('vic')('POST', '/api/muster/incidents/inc_1/advance', { edgeId: 'e2' })).status, 403);
  const wrong = await as('alice')('POST', '/api/muster/incidents/inc_1/advance', { edgeId: 'e1' });
  assert.equal(wrong.status, 422, 'Muster refusals reach the user');
  assert.match(wrong.data.error, /does not leave the current step/);
  const r = await as('alice')('POST', '/api/muster/incidents/inc_1/strata', { site: 'lyon', marks: { 'lyo-file-01': 'compromised' }, names: { 'lyo-file-01': 'file-01' }, log: [{ msg: 'file-01 marked compromised', kind: 'warn', by: 'someone else' }] });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const sent = seen.filter(s => s.url === '/api/incidents/inc_1/strata').at(-1);
  assert.equal(sent.csrf, '1');
  assert.deepEqual(sent.body.log, [{ msg: 'file-01 marked compromised', kind: 'warn', by: 'alice' }], 'the author is the Strata account, not what the page claims');
  const ok = await as('alice')('POST', '/api/muster/incidents/inc_1/advance', { edgeId: 'e2' });
  assert.equal(ok.data.status, 'closed');
});

test('Muster: an expired session is opened again, an unreachable Muster gives a clear error', async () => {
  const logins = seen.filter(s => s.url === '/api/auth/login').length;
  inc.rev++; // the stand-in forgets the session: the next call answers 401 once
  const old = fakeMuster;
  fake.removeAllListeners('request');
  let first = true;
  fake.on('request', (req, res) => { if (first && req.url !== '/api/auth/login') { first = false; res.writeHead(401, { 'Content-Type': 'application/json' }); res.end('{"error":"Sign in to continue"}'); return; } old(req, res); });
  assert.equal((await as('vic')('GET', '/api/muster/incidents/inc_1')).status, 200);
  assert.equal(seen.filter(s => s.url === '/api/auth/login').length, logins + 1);
  await new Promise(r => fake.close(r));
  const down = await as('vic')('GET', '/api/muster/incidents/inc_1');
  assert.equal(down.status, 502);
  assert.match(down.data.error, /cannot be reached/);
  fake = createServer(fakeMuster);
  await new Promise(r => fake.listen(mport, '127.0.0.1', r));
});
