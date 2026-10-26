// SPDX-License-Identifier: AGPL-3.0-or-later
// Failed sign-ins: locks per account and per client address, the client address behind a trusted
// reverse proxy, and browsers already signed in. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ADMIN = 'admin-pass-123';
const LOCK_MS = 1800; // LOGIN_LOCK_MINUTES=0.03

// Starts a server with these settings; resolves with {port, stop} once it listens
function start(extra) {
  const dataDir = mkdtempSync(join(tmpdir(), 'strata-signin-'));
  const port = 9400 + Math.floor(Math.random() * 500);
  const proc = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: ADMIN, VIEW_PASS: '', CONNECTORS: 'false', LOGIN_LOCK_MINUTES: '0.03', TRUST_PROXY: '', ...extra },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const stop = () => new Promise(res => { if (proc.exitCode !== null) return res(); proc.once('exit', res); proc.kill(); }).then(() => rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 }));
  let out = '';
  return new Promise((res, rej) => {
    proc.stdout.on('data', d => { out += d; if (String(d).includes('listening')) res({ port, stop, log: () => out }); });
    proc.on('exit', code => rej(new Error(`exit ${code}`)));
  });
}
// GET /api/state as user:pass, from a client address given by X-Forwarded-For (only believed behind a trusted proxy)
async function get(port, user, pass, from) {
  const headers = { Authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') };
  if (from) headers['X-Forwarded-For'] = from;
  const r = await fetch(`http://127.0.0.1:${port}/api/state`, { headers });
  await r.arrayBuffer();
  return { status: r.status, retryAfter: r.headers.get('retry-after') };
}
async function addUser(port, name, password) {
  const r = await fetch(`http://127.0.0.1:${port}/api/users/${name}`, {
    method: 'PUT',
    headers: { Authorization: 'Basic ' + Buffer.from(`admin:${ADMIN}`).toString('base64'), 'Content-Type': 'application/json', 'X-Requested-With': 'strata' },
    body: JSON.stringify({ role: 'viewer', password }),
  });
  assert.equal(r.status, 200);
}
const wait = ms => new Promise(r => setTimeout(r, ms));

test('an account is locked after LOGIN_MAX_FAILS different wrong passwords, then unlocked', async () => {
  const s = await start({ LOGIN_MAX_FAILS: '3', LOGIN_MAX_FAILS_PER_ADDRESS: '100' });
  try {
    await addUser(s.port, 'alice', 'alice-pass-123');
    for (const p of ['wrong-1', 'wrong-2', 'wrong-3']) assert.equal((await get(s.port, 'alice', p)).status, 401);
    // locked: even the right password is refused, with the time to wait
    const r = await get(s.port, 'alice', 'alice-pass-123');
    assert.equal(r.status, 429);
    assert.ok(+r.retryAfter >= 1 && +r.retryAfter <= 2, `Retry-After ${r.retryAfter}`);
    // another account from the same address is not affected
    assert.equal((await get(s.port, 'admin', ADMIN)).status, 200);
    await wait(LOCK_MS + 300);
    assert.equal((await get(s.port, 'alice', 'alice-pass-123')).status, 200);
  } finally { await s.stop(); }
});

test('the same wrong password sent again and again (a tab with an old password) locks nobody out', async () => {
  const s = await start({ LOGIN_MAX_FAILS: '3', LOGIN_MAX_FAILS_PER_ADDRESS: '3' });
  try {
    for (let i = 0; i < 10; i++) assert.equal((await get(s.port, 'admin', 'old-password')).status, 401);
    assert.equal((await get(s.port, 'admin', ADMIN)).status, 200);
  } finally { await s.stop(); }
});

test('a client address is locked after LOGIN_MAX_FAILS_PER_ADDRESS, read from X-Forwarded-For behind a trusted proxy only', async () => {
  const s = await start({ LOGIN_MAX_FAILS: '100', LOGIN_MAX_FAILS_PER_ADDRESS: '4', TRUST_PROXY: 'loopback' });
  try {
    // guesses on several accounts from one client
    for (const [u, p] of [['root', 'a'], ['bob', 'b'], ['admin', 'c'], ['eve', 'd']]) assert.equal((await get(s.port, u, p, '203.0.113.7')).status, 401);
    assert.equal((await get(s.port, 'admin', ADMIN, '203.0.113.7')).status, 429);
    // another client behind the same proxy is not affected
    assert.equal((await get(s.port, 'admin', ADMIN, '203.0.113.8')).status, 200);
    // proxies of our own in the chain are skipped; a client cannot pass for another by adding to it
    assert.equal((await get(s.port, 'admin', ADMIN, '203.0.113.9, 203.0.113.7, 127.0.0.1')).status, 429);
  } finally { await s.stop(); }

  // Without TRUST_PROXY, X-Forwarded-For is ignored: the failures count against the peer address
  const t = await start({ LOGIN_MAX_FAILS: '100', LOGIN_MAX_FAILS_PER_ADDRESS: '2' });
  try {
    assert.equal((await get(t.port, 'admin', 'x', '198.51.100.1')).status, 401);
    assert.equal((await get(t.port, 'admin', 'y', '198.51.100.2')).status, 401);
    assert.equal((await get(t.port, 'admin', ADMIN, '198.51.100.3')).status, 429);
  } finally { await t.stop(); }
});

test('a browser already signed in keeps working from its address while the account is locked', async () => {
  const s = await start({ LOGIN_MAX_FAILS: '3', LOGIN_MAX_FAILS_PER_ADDRESS: '100', TRUST_PROXY: '127.0.0.1' });
  try {
    assert.equal((await get(s.port, 'admin', ADMIN, '192.0.2.10')).status, 200);
    // someone else guesses the admin password from elsewhere
    for (const p of ['guess-1', 'guess-2', 'guess-3']) assert.equal((await get(s.port, 'admin', p, '192.0.2.66')).status, 401);
    // the signed-in browser goes on; the right password from any other address waits
    assert.equal((await get(s.port, 'admin', ADMIN, '192.0.2.10')).status, 200);
    assert.equal((await get(s.port, 'admin', ADMIN, '192.0.2.66')).status, 429);
    assert.equal((await get(s.port, 'admin', ADMIN, '192.0.2.11')).status, 429);
  } finally { await s.stop(); }
});

test('an account name cannot write fake lines into the log', async () => {
  const s = await start({ LOGIN_MAX_FAILS: '1', LOGIN_MAX_FAILS_PER_ADDRESS: '100' });
  try {
    assert.equal((await get(s.port, 'x\n2026-01-01T00:00:00.000Z FAKE', 'a')).status, 401);
    await wait(200);
    assert.match(s.log(), /Sign-in locked .*account "x\\n2026/);
    assert.doesNotMatch(s.log(), /^2026-01-01T00:00:00.000Z FAKE/m);
  } finally { await s.stop(); }
});
