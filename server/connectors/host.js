// SPDX-License-Identifier: AGPL-3.0-or-later
// Runs one connector module operation in its own process, started by runner.js with the Node.js
// permission model: this process reads only its module's folder and the SDK, cannot write files or start
// other processes, and its environment holds none of the server's settings or passwords.
// Messages: in {op: 'test' | 'run', main, cfg, state, file}; out {log} while it works, then
// {ok: true, result} or {ok: false, error, expected}.
import { pathToFileURL } from 'node:url';
import * as sdk from './sdk.js';

const send = m => new Promise(res => process.send(m, () => res()));
process.once('message', async ({ op, main, cfg, state, file }) => {
  try {
    const mod = await import(pathToFileURL(main).href);
    const fn = mod[op];
    if (typeof fn !== 'function') throw new sdk.ConnectorError(`This module has no ${op}() function.`);
    const ctx = { state, file: file || null, sdk, log: (...a) => { process.send({ log: a.map(String).join(' ').slice(0, 2000) }); } };
    const result = await fn(cfg, ctx);
    await send({ ok: true, result: result === undefined ? null : JSON.parse(JSON.stringify(result)) });
  } catch (e) {
    const expected = e?.name === 'ConnectorError' || e instanceof sdk.ConnectorError;
    await send({ ok: false, expected, error: String(e?.message || e).slice(0, 2000), stack: expected ? undefined : String(e?.stack || '').slice(0, 4000) });
  }
  // whatever the module left open (a timer, a socket), its work is done
  process.exit(0);
});
