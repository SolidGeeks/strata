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
import { auth } from './session.mjs';
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
      headers: { ...(await auth(`http://127.0.0.1:${port}`, 'admin', pass)), 'Content-Type': 'application/json', 'X-Requested-With': 'strata' },
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

test('a large IS (3500 flows) can be saved, and the history stops at HISTORY_MAX_MB', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'strata-big-'));
  const port = 9300 + Math.floor(Math.random() * 90) + 100, pass = 'admin-pass-123', base = `http://127.0.0.1:${port}`;
  const proc = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: pass, VIEW_PASS: '', CONNECTORS: 'false', HISTORY_MAX_MB: '1' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  let out = '';
  try {
    await new Promise((res, rej) => { proc.stdout.on('data', d => { out += d; if (String(d).includes('listening')) res(); }); proc.on('exit', c => rej(new Error('exit ' + c))); });
    const h = { ...(await auth(base, 'admin', pass)), 'Content-Type': 'application/json', 'X-Requested-With': 'strata' };
    // an IS of 150 VLANs and 3500 flows with notes, about 700 KB: above the old 512 KB limit
    const doc = n => ({ name: 'Big', zones: [{ id: 'z1', name: 'Main' }], vlans: Array.from({ length: 150 }, (_, i) => ({ id: 'v' + i, num: i + 1, name: 'VLAN ' + i, zone: 'z1' })),
      flows: Array.from({ length: 3500 }, (_, i) => ({ id: `f${i}`, src: `a${i}`, dst: `b${i}`, port: 'tcp/443', vol: n, risk: false, note: `Palo Alto rule “R${i}” — a note long enough to look like a real one, edit ${n}` })) });
    assert.ok(JSON.stringify(doc(0)).length > 512 * 1024);
    for (let n = 0; n < 4; n++) {
      const r = await fetch(`${base}/api/si/big`, { method: 'PUT', headers: h, body: JSON.stringify(doc(n)) });
      assert.equal(r.status, 200, `save ${n}: ${await r.text()}`);
    }
    // each change keeps the IS before and after it (more than 1 MB): only the latest is kept
    const hist = await (await fetch(`${base}/api/history?limit=50`, { headers: h })).json();
    assert.equal(hist.entries.length, 1, JSON.stringify(hist.entries.map(e => e.rev)));
    assert.equal(hist.rev, 4);
    assert.ok(statSync(join(dataDir, 'history.jsonl')).size < 2 * 1024 * 1024);
    assert.match(out, /History: \d+ oldest change\(s\) dropped \(limits: 5000 changes, 1 MB\)/);
    // and still more than MAX_DOC_MB is refused
    const huge = { ...doc(9), notes: 'x'.repeat(9 * 1024 * 1024) };
    assert.equal((await fetch(`${base}/api/si/big`, { method: 'PUT', headers: h, body: JSON.stringify(huge) })).status, 413);
  } finally {
    await new Promise(res => { if (proc.exitCode !== null) return res(); proc.once('exit', res); proc.kill(); });
    rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 });
  }
});
