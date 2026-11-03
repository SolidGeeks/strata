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

// What the parent takes from a module process: messages count against a byte budget (their JSON size,
// the form they travel in), and log lines against a line and byte budget of their own. A module that
// goes past the message budget is stopped and its run fails; extra log lines are dropped.
export const MAX_MESSAGE_BYTES = 64 * 1024 * 1024;
export const MAX_LOG_LINE = 2000, MAX_LOG_LINES = 2000, MAX_LOG_BYTES = 1024 * 1024;

// op: 'test' | 'run'; payload: {cfg, state, file}; resolves with the module's result
export function runModule(mod, op, payload, { timeoutMs = 30 * 60000, log = () => { }, maxMessageBytes = MAX_MESSAGE_BYTES, maxLogLines = MAX_LOG_LINES, maxLogBytes = MAX_LOG_BYTES } = {}) {
  return new Promise((resolve, reject) => {
    const env = {};
    for (const k of KEEP_ENV) if (process.env[k]) env[k] = process.env[k];
    const child = fork(HOST, [], {
      cwd: mod.dir, env,
      execArgv: [...permissionArgs([CONNECTORS_DIR, mod.dir]), '--max-old-space-size=512', '--disable-proto=throw'],
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    let answer = null, tail = '', received = 0, logLines = 0, logBytes = 0, logCut = false, tooMuch = null;
    // one line of the module's log, within the run's log budget
    const logLine = l => {
      const line = String(l).slice(0, MAX_LOG_LINE);
      if (logCut) return;
      if (logLines + 1 > maxLogLines || logBytes + line.length > maxLogBytes) {
        logCut = true;
        return log(`[${mod.id}] log truncated: more than ${maxLogLines} lines or ${Math.round(maxLogBytes / 1024)} KB, the rest of this run's log is dropped`);
      }
      logLines++; logBytes += line.length;
      log(`[${mod.id}] ${line}`);
    };
    const out = d => { const s = String(d); tail = (tail + s).slice(-2000); for (const l of s.split('\n')) if (l.trim()) logLine(l.slice(0, 500)); };
    child.stdout.on('data', out);
    child.stderr.on('data', out);
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new ConnectorError(`${mod.name} took longer than ${Math.round(timeoutMs / 60000) || 1} min and was stopped.`));
    }, timeoutMs);
    let done = false;
    const finish = (err, value) => { if (done) return; done = true; clearTimeout(timer); err ? reject(err) : resolve(value); };
    child.on('message', m => {
      // the answer is final: whatever comes after it is ignored
      if (done || answer || tooMuch) return;
      let size;
      try { size = JSON.stringify(m)?.length || 0; } catch { size = Infinity; }
      received += size;
      if (received > maxMessageBytes) {
        tooMuch = new ConnectorError(`${mod.name} sent more than ${Math.round(maxMessageBytes / 1048576)} MB to the server and was stopped.`);
        child.kill('SIGKILL');
        return finish(tooMuch);
      }
      if (m && typeof m.log === 'string') return logLine(m.log);
      // anything else that is not an answer ({ok: true | false, ...}) is ignored
      if (!m || typeof m !== 'object' || typeof m.ok !== 'boolean') return;
      answer = m;
      // the answer is in: a timer or a socket the module left open must not hold the run
      if (m && m.ok) { finish(null, m.result); setTimeout(() => child.kill('SIGKILL'), 1000).unref(); }
    });
    child.on('error', e => finish(new Error(`The ${mod.name} module could not start: ${e.message}`)));
    child.on('exit', code => {
      if (tooMuch) return finish(tooMuch);
      if (answer && answer.ok) return finish(null, answer.result);
      if (answer) {
        if (answer.stack) log(`[${mod.id}] ${String(answer.stack).slice(0, 4000)}`);
        const e = answer.expected ? new ConnectorError(String(answer.error ?? '').slice(0, 2000)) : new Error(String(answer.error ?? '').slice(0, 2000));
        return finish(e);
      }
      const last = tail.trim().split('\n').pop() || '';
      finish(new Error(`The ${mod.name} module stopped (exit code ${code})${last ? `: ${last.slice(0, 300)}` : ''}`));
    });
    child.send({ op, main: mod.mainPath, ...payload });
  });
}
