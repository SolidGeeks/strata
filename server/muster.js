// SPDX-License-Identifier: AGPL-3.0-or-later
// Connection to Muster, the incident response playbooks. Strata signs in to Muster with an account of its own
// (the analyst role: it moves responses along and writes to their timeline), lists the incidents, and passes on
// what the people working on the map do: the answers to decisions, the tasks ticked, the state of the assets and
// the flows cut. Muster's own API, with its own session cookie and CSRF header; nothing is stored here.
const COOKIE = 'muster_session';
const ID_RE = /^[A-Za-z0-9_-]{1,80}$/;

export function createMuster({ url, user, password, pollMs = 10000, timeoutMs = 10000, log = () => {}, onChange = () => {} }) {
  const base = String(url).replace(/\/+$/, '');
  let cookie = '', sig = '', timer = null;
  let status = { ok: false, error: 'Not checked yet', checkedAt: null, incidents: [] };
  const fail = (code, message) => Object.assign(new Error(message), { status: code });

  async function login() {
    let r;
    try {
      r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Muster': '1' }, body: JSON.stringify({ username: user, password }), signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) { throw fail(502, `Muster cannot be reached at ${base} (${e.cause?.code || e.message})`); }
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw fail(502, `Muster refused the sign-in of ${user}: ${d.error || r.status}`); }
    const m = new RegExp(`${COOKIE}=([^;]+)`).exec(r.headers.get('set-cookie') || '');
    if (!m) throw fail(502, 'Muster answered the sign-in without a session');
    cookie = `${COOKIE}=${m[1]}`;
  }
  // One call to Muster; a session that has expired is opened again once
  async function call(method, path, body, again = true) {
    if (!cookie) await login();
    let r;
    try {
      r = await fetch(base + path, {
        method, signal: AbortSignal.timeout(timeoutMs),
        headers: { Cookie: cookie, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(method !== 'GET' ? { 'X-Muster': '1' } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) { throw fail(502, `Muster cannot be reached at ${base} (${e.cause?.code || e.message})`); }
    if (r.status === 401 && again) { cookie = ''; return call(method, path, body, false); }
    const data = await r.json().catch(() => ({}));
    // Muster's refusals (a route that does not leave the current step, a role…) reach the user as they are
    if (!r.ok) throw fail(r.status >= 500 || r.status === 401 ? 502 : r.status, `Muster: ${data.error || 'error ' + r.status}`);
    return data;
  }
  async function poll() {
    try {
      const list = await call('GET', '/api/incidents');
      status = { ok: true, error: '', checkedAt: new Date().toISOString(), incidents: Array.isArray(list) ? list : [] };
    } catch (e) {
      if (status.ok) log(`Muster: ${e.message}`);
      status = { ...status, ok: false, error: e.message, checkedAt: new Date().toISOString() };
    }
    const next = JSON.stringify([status.ok, status.error, status.incidents.map(i => [i.id, i.rev, i.status])]);
    if (next !== sig) { sig = next; onChange(); }
    return status;
  }
  const incPath = (id, r = '') => { if (!ID_RE.test(String(id))) throw fail(400, 'Invalid Muster incident id'); return `/api/incidents/${id}${r}`; };
  // After a change: read the list again at once, so every Strata page follows
  const then = async p => { const out = await p; await poll(); return out; };

  return {
    url: base,
    start() { poll(); timer = setInterval(poll, pollMs); timer.unref?.(); },
    stop() { clearInterval(timer); },
    status: () => status,
    refresh: poll,
    incident: id => call('GET', incPath(id)),
    advance: (id, edgeId) => then(call('POST', incPath(id, '/advance'), { edgeId: String(edgeId || '') })),
    task: (id, nodeId, index, done) => then(call('POST', incPath(id, '/tasks'), { nodeId: String(nodeId || ''), index, done: !!done })),
    report: (id, body) => then(call('POST', incPath(id, '/strata'), body)),
  };
}
