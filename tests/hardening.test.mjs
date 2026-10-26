// SPDX-License-Identifier: AGPL-3.0-or-later
// Security review fixes: the PAN-OS XML parser takes linear time, and the data files are readable by the
// server's user only. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseXml } from '../server/connectors/sdk.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('XML: a long start tag without "=" is read in linear time', () => {
  const t = Date.now();
  parseXml(`<config><x ${'a'.repeat(300000)}/></config>`);
  assert.ok(Date.now() - t < 1000, `took ${Date.now() - t} ms`);
  // attributes are read as before
  const el = parseXml(`<e  name = "a&amp;b" b='x' bare c="1" d="" />`).children[0];
  assert.deepEqual({ ...el.attrs }, { name: 'a&b', b: 'x', c: '1', d: '' });
});

test('data files are readable by the server user only, including those of older versions', { skip: process.platform === 'win32' }, async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'strata-perm-'));
  mkdirSync(join(dataDir, 'backups'));
  // a proposals file as an older version left it, readable by everyone
  writeFileSync(join(dataDir, 'proposals.json'), '{}', { mode: 0o644 });
  const port = 9300 + Math.floor(Math.random() * 90), pass = 'admin-pass-123';
  const proc = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: pass, VIEW_PASS: '', CONNECTORS: 'false' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  try {
    await new Promise((res, rej) => { proc.stdout.on('data', d => { if (String(d).includes('listening')) res(); }); proc.on('exit', c => rej(new Error('exit ' + c))); });
    const r = await fetch(`http://127.0.0.1:${port}/api/si/s1`, {
      method: 'PUT', body: JSON.stringify({ name: 'IS one' }),
      headers: { Authorization: 'Basic ' + Buffer.from(`admin:${pass}`).toString('base64'), 'Content-Type': 'application/json', 'X-Requested-With': 'strata' },
    });
    assert.equal(r.status, 200);
    await new Promise(res => setTimeout(res, 200));
    for (const f of ['db.json', 'users.json', 'history.jsonl', 'proposals.json']) {
      const mode = statSync(join(dataDir, f)).mode & 0o777;
      assert.equal(mode & 0o077, 0, `${f} is ${mode.toString(8)}`);
    }
  } finally {
    await new Promise(res => { if (proc.exitCode !== null) return res(); proc.once('exit', res); proc.kill(); });
    rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 });
  }
});
