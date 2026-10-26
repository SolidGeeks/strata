// SPDX-License-Identifier: AGPL-3.0-or-later
// Secrets read from files (EDIT_PASS_FILE, VIEW_PASS_FILE), as Docker secrets, systemd credentials and
// NixOS secret managers provide them. Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// Starts a server with these settings; resolves with {port, stop} once it listens, or rejects with its exit code
function start(extra) {
  const dataDir = mkdtempSync(join(tmpdir(), 'strata-secrets-'));
  const port = 8800 + Math.floor(Math.random() * 500);
  const proc = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', CONNECTORS: 'false', EDIT_PASS: '', VIEW_PASS: '', ...extra },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  proc.stderr.on('data', d => { err += d; });
  const stop = () => new Promise(res => { if (proc.exitCode !== null) return res(); proc.once('exit', res); proc.kill(); }).then(() => rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 }));
  return new Promise((res, rej) => {
    proc.stdout.on('data', d => { if (String(d).includes('listening')) res({ port, stop }); });
    proc.on('exit', code => { rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 }); rej(Object.assign(new Error(`exit ${code}`), { code, err })); });
  });
}
const status = (port, user, pass) => fetch(`http://127.0.0.1:${port}/api/state`, { headers: { Authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } }).then(r => r.status);

test('EDIT_PASS_FILE and VIEW_PASS_FILE: the passwords come from the files, which win over the variables', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'strata-cred-'));
  writeFileSync(join(dir, 'edit'), 'from-the-file-123\n'); // a trailing newline, as most tools write it
  writeFileSync(join(dir, 'view'), 'viewer-file-1234');
  const s = await start({ EDIT_PASS: 'from-the-variable', EDIT_PASS_FILE: join(dir, 'edit'), VIEW_PASS_FILE: join(dir, 'view') });
  try {
    assert.equal(await status(s.port, 'admin', 'from-the-file-123'), 200);
    assert.equal(await status(s.port, 'admin', 'from-the-file-123\n'), 401);
    assert.equal(await status(s.port, 'admin', 'from-the-variable'), 401);
    assert.equal(await status(s.port, 'viewer', 'viewer-file-1234'), 200);
  } finally {
    await s.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unreadable secret file stops the server instead of starting it without a password', async () => {
  await assert.rejects(start({ EDIT_PASS_FILE: join(tmpdir(), 'strata-no-such-file') }), e => e.code === 1 && /EDIT_PASS_FILE/.test(e.err));
});
