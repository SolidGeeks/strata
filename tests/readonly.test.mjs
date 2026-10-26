// SPDX-License-Identifier: AGPL-3.0-or-later
// READ_ONLY=true freezes the map for everyone, admins included: they read, nobody writes.
// Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('READ_ONLY=true: an admin can read, and every write is refused with 403', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'strata-readonly-'));
  const port = 9200 + Math.floor(Math.random() * 90), pass = 'admin-pass-123';
  const server = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: pass, VIEW_PASS: '', CONNECTORS: 'false', READ_ONLY: 'true' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const call = async (method, path, body) => {
    const r = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: { Authorization: 'Basic ' + Buffer.from(`admin:${pass}`).toString('base64'), ...(body ? { 'Content-Type': 'application/json', 'X-Requested-With': 'strata' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: r.status, data: await r.json().catch(() => null) };
  };
  try {
    await new Promise((res, rej) => { server.stdout.on('data', d => { if (String(d).includes('listening')) res(); }); server.on('exit', c => rej(new Error('exit ' + c))); });
    // reading works
    assert.equal((await call('GET', '/api/state')).status, 200);
    const me = await call('GET', '/api/me');
    assert.equal(me.status, 200);
    assert.equal(me.data.readOnly, true);
    assert.equal(me.data.canWrite, false);
    // every kind of write is refused, the admin's included
    for (const [method, path, body] of [
      ['PUT', '/api/si/frozen', { name: 'Frozen' }],
      ['DELETE', '/api/assets/x', {}],
      ['PUT', '/api/wan', { links: [] }],
      ['PUT', '/api/services', { services: [] }],
      ['POST', '/api/import', { si: {}, assets: {} }],
      ['POST', '/api/rollback', { rev: 0 }],
      ['POST', '/api/proposals', { title: 'Not now' }],
      ['PUT', '/api/users/alice', { role: 'viewer', password: 'alice-pass-123' }],
    ]) assert.equal((await call(method, path, body)).status, 403, `${method} ${path}`);
    assert.equal((await call('GET', '/api/state')).data.rev, 0, 'the map did not move');
  } finally {
    await new Promise(res => { if (server.exitCode !== null) return res(); server.once('exit', res); server.kill(); });
    rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 });
  }
});
