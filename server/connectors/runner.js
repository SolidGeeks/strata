// SPDX-License-Identifier: AGPL-3.0-or-later
// Starts a connector module in a child process (host.js) for one test or run, and waits for its answer.
// The child gets the Node.js permission model (reads its module folder and the SDK only; no writing, no
// child processes, no worker threads), a memory cap, a time limit and an environment without the
// server's variables: a module sees its own settings, and the map only if its manifest asks for it.
// This keeps a faulty module from reaching the data files and the other connectors' secrets; it is
// not a sandbox for hostile code (the network stays open), which is why the store lists reviewed
// modules only (MODULES.md).
import { fork } from 'node:child_process';
import path from 'node:path';
import { ConnectorError } from './sdk.js';
import { CONNECTORS_DIR } from './modules.js';

const HOST = path.join(CONNECTORS_DIR, 'host.js');
// Node.js 22.13 and later call it --permission, older versions --experimental-permission; one
// --allow-fs-read per folder either way (comma-separated lists stopped working in Node.js 20.7)
const FLAG = process.allowedNodeEnvironmentFlags.has('--permission') ? '--permission' : '--experimental-permission';
const KEEP_ENV = ['TZ', 'LANG', 'LC_ALL', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR'];

export function permissionArgs(dirs) {
  return [FLAG, ...dirs.map(d => `--allow-fs-read=${d}`)];
}

// op: 'test' | 'run'; payload: {cfg, state, file}; resolves with the module's result
export function runModule(mod, op, payload, { timeoutMs = 30 * 60000, log = () => { } } = {}) {
  return new Promise((resolve, reject) => {
    const env = {};
    for (const k of KEEP_ENV) if (process.env[k]) env[k] = process.env[k];
    const child = fork(HOST, [], {
      cwd: mod.dir, env,
      execArgv: [...permissionArgs([CONNECTORS_DIR, mod.dir]), '--max-old-space-size=512', '--disable-proto=throw'],
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    let answer = null, tail = '';
    const out = d => { const s = String(d); tail = (tail + s).slice(-2000); for (const l of s.split('\n')) if (l.trim()) log(`[${mod.id}] ${l.slice(0, 500)}`); };
    child.stdout.on('data', out);
    child.stderr.on('data', out);
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new ConnectorError(`${mod.name} took longer than ${Math.round(timeoutMs / 60000) || 1} min and was stopped.`));
    }, timeoutMs);
    let done = false;
    const finish = (err, value) => { if (done) return; done = true; clearTimeout(timer); err ? reject(err) : resolve(value); };
    child.on('message', m => {
      if (m && typeof m.log === 'string') return log(`[${mod.id}] ${m.log}`);
      answer = m;
      // the answer is in: a timer or a socket the module left open must not hold the run
      if (m && m.ok) { finish(null, m.result); setTimeout(() => child.kill('SIGKILL'), 1000).unref(); }
    });
    child.on('error', e => finish(new Error(`The ${mod.name} module could not start: ${e.message}`)));
    child.on('exit', code => {
      if (answer && answer.ok) return finish(null, answer.result);
      if (answer) {
        if (answer.stack) log(`[${mod.id}] ${answer.stack}`);
        const e = answer.expected ? new ConnectorError(answer.error) : new Error(answer.error);
        return finish(e);
      }
      const last = tail.trim().split('\n').pop() || '';
      finish(new Error(`The ${mod.name} module stopped (exit code ${code})${last ? `: ${last.slice(0, 300)}` : ''}`));
    });
    child.send({ op, main: mod.mainPath, ...payload });
  });
}
