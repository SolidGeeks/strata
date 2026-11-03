// SPDX-License-Identifier: AGPL-3.0-or-later
// Connection to Muster, the incident response playbooks. Strata signs in to Muster with an account of its own
// (the analyst role: it moves responses along and writes to their timeline), lists the incidents, and passes on
// what the people working on the map do: the answers to decisions, the tasks ticked, the state of the assets and
// the flows cut. Muster's own API, with its own session cookie and CSRF header; nothing is stored here.
const COOKIE = 'muster_session';
const ID_RE = /^[A-Za-z0-9_-]{1,80}$/;
const MAX_BYTES = 8 * 1024 * 1024;
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
// The body as JSON, read up to maxBytes: a Muster (or anything in the way) that answers without end must not fill
// this server's memory
async function readJson(r, maxBytes = MAX_BYTES) {
  if (+r.headers.get('content-length') > maxBytes) { await r.body?.cancel(); throw new Error(`answer over ${maxBytes >> 20} MB`); }
  const chunks = []; let n = 0;
  if (r.body) for await (const c of r.body) { n += c.length; if (n > maxBytes) throw new Error(`answer over ${maxBytes >> 20} MB`); chunks.push(c); }
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : {};
}

export function createMuster({ url, user, password, pollMs = 10000, timeoutMs = 10000, maxBytes = MAX_BYTES, log = () => {}, onChange = () => {} }) {
  const base = String(url).replace(/\/+$/, '');
  if (/^http:/i.test(base) && !/^http:\/\/(localhost|127\.|\[::1\])/i.test(base)) log(`WARNING: MUSTER_URL is plain http: the password of ${user} crosses the network in clear. Use https.`);
  let cookie = '', sig = '', timer = null, stopped = false, fails = 0, signingIn = null;
  let status = { ok: false, error: 'Not checked yet', checkedAt: null, incidents: [] };
  const fail = (code, message) => Object.assign(new Error(message), { status: code });

  // No redirect is followed: a redirect to another host would carry the password there (a 307 repeats the POST),
  // or have this server fetch another address for whoever reads the answer
  async function login() {
    let r;
    try {
      r = await fetch(base + '/api/auth/login', { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/json', 'X-Muster': '1' }, body: JSON.stringify({ username: user, password }), signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) { throw fail(502, `Muster cannot be reached at ${base} (${e.cause?.code || e.message})`); }
    if (r.status >= 300 && r.status < 400) throw fail(502, `Muster answered the sign-in with a redirect (${r.status}): check MUSTER_URL`);
    if (!r.ok) { const d = await readJson(r, 65536).catch(() => ({})); throw fail(502, `Muster refused the sign-in of ${user}: ${String(d.error || r.status).slice(0, 200)}`); }
    await r.body?.cancel();
    const m = new RegExp(`${COOKIE}=([^;]+)`).exec(r.headers.get('set-cookie') || '');
    if (!m) throw fail(502, 'Muster answered the sign-in without a session');
    cookie = `${COOKIE}=${m[1]}`;
  }
  // One call to Muster; a session that has expired is opened again once
  async function call(method, path, body, again = true) {
    // one sign-in at a time, shared by the calls that need it
    if (!cookie) { signingIn ||= login().finally(() => { signingIn = null; }); await signingIn; }
    let r;
    try {
      r = await fetch(base + path, {
        method, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
        headers: { Cookie: cookie, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(method !== 'GET' ? { 'X-Muster': '1' } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) { throw fail(502, `Muster cannot be reached at ${base} (${e.cause?.code || e.message})`); }
    if (r.status === 401 && again) { await r.body?.cancel(); cookie = ''; return call(method, path, body, false); }
    if (r.status >= 300 && r.status < 400) { await r.body?.cancel(); throw fail(502, `Muster answered with a redirect (${r.status}), which is not followed`); }
    let data;
    try { data = await readJson(r, maxBytes); } catch (e) { if (r.ok) throw fail(502, `Muster: unreadable answer (${e.message})`); data = {}; }
    // Muster's refusals (a route that does not leave the current step, a role…) reach the user as they are
    if (!r.ok) throw fail(r.status >= 500 || r.status === 401 ? 502 : r.status, `Muster: ${String((isObj(data) && data.error) || 'error ' + r.status).slice(0, 300)}`);
    return data;
  }
  async function poll() {
    try {
      const list = await call('GET', '/api/incidents');
      // only incidents with an id this server can use: anything else in the list is left out, not trusted
      status = { ok: true, error: '', checkedAt: new Date().toISOString(), incidents: (Array.isArray(list) ? list : []).filter(i => isObj(i) && ID_RE.test(String(i.id))).slice(0, 2000) };
      fails = 0;
    } catch (e) {
      if (status.ok) log(`Muster: ${e.message}`);
      status = { ...status, ok: false, error: e.message, checkedAt: new Date().toISOString() };
      fails++;
    }
    try {
      const next = JSON.stringify([status.ok, status.error, status.incidents.map(i => [i.id, i.rev, i.status])]);
      if (next !== sig) { sig = next; onChange(); }
    } catch (e) { log(`Muster: ${e.message}`); }
    return status;
  }
  // The next poll starts once this one is over (a slow Muster does not pile up calls), later after failures: a wrong
  // password is not tried every few seconds, which could lock the account in Muster
  function schedule() {
    if (stopped) return;
    const wait = fails ? Math.min(pollMs * 2 ** Math.min(fails - 1, 6), 10 * 60000) : pollMs;
    timer = setTimeout(() => { poll().catch(() => { }).finally(schedule); }, wait);
    timer.unref?.();
  }
  const incPath = (id, r = '') => { if (!ID_RE.test(String(id))) throw fail(400, 'Invalid Muster incident id'); return `/api/incidents/${id}${r}`; };
  // After a change: read the list again at once, so every Strata page follows
  const then = async p => { const out = await p; await poll().catch(() => { }); return out; };

  return {
    url: base,
    start() { stopped = false; poll().catch(() => { }).finally(schedule); },
    stop() { stopped = true; clearTimeout(timer); },
    status: () => status,
    refresh: poll,
    incident: id => call('GET', incPath(id)),
    advance: (id, edgeId) => then(call('POST', incPath(id, '/advance'), { edgeId: String(edgeId || '') })),
    task: (id, nodeId, index, done) => then(call('POST', incPath(id, '/tasks'), { nodeId: String(nodeId || ''), index, done: !!done })),
    report: (id, body) => then(call('POST', incPath(id, '/strata'), body)),
  };
}
