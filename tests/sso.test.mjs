// SPDX-License-Identifier: AGPL-3.0-or-later
// Single sign-on: OpenID Connect against a fake provider (discovery, PKCE, ID token checks, roles from
// groups, session cookie, sign-out), trusted proxy headers, API tokens and LOCAL_LOGIN. Run with: npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import crypto from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyJwt } from '../server/sso.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tmp = fs.mkdtempSync(join(tmpdir(), 'strata-sso-'));
const port = 10300 + Math.floor(Math.random() * 200), idpPort = port + 300, hdrPort = port + 600;
const base = `http://127.0.0.1:${port}`, idp = `http://127.0.0.1:${idpPort}`;
const procs = [];
let provider;

/* ---- the fake provider ---- */
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' };
const codes = new Map();
// what the next ID token says, changed by the tests
let next = {};
const sign = (claims, key = privateKey, kid = 'k1') => {
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`;
};

before(async () => {
  provider = http.createServer(async (req, res) => {
    const u = new URL(req.url, idp);
    const json = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname === '/.well-known/openid-configuration') return json(200, { issuer: idp, authorization_endpoint: `${idp}/authorize`, token_endpoint: `${idp}/token`, jwks_uri: `${idp}/jwks`, end_session_endpoint: `${idp}/logout` });
    if (u.pathname === '/jwks') return json(200, { keys: [jwk] });
    if (u.pathname === '/authorize') {
      // signs the person in at once and sends them back with a code, to the one redirect URI registered
      // for Strata, as a real provider does
      const callback = `${base}/auth/oidc/callback`;
      if (u.searchParams.get('redirect_uri') !== callback || u.searchParams.get('client_id') !== 'strata') return json(400, { error: 'invalid_request' });
      const code = crypto.randomBytes(8).toString('hex');
      codes.set(code, { nonce: u.searchParams.get('nonce'), challenge: u.searchParams.get('code_challenge'), redirect: callback });
      res.writeHead(302, { Location: `${callback}?code=${code}&state=${encodeURIComponent(u.searchParams.get('state') || '')}` });
      return res.end();
    }
    if (u.pathname === '/token' && req.method === 'POST') {
      let body = ''; for await (const c of req) body += c;
      const f = new URLSearchParams(body), c = codes.get(f.get('code'));
      codes.delete(f.get('code'));
      if (req.headers.authorization !== 'Basic ' + Buffer.from('strata:s3cret').toString('base64')) return json(401, { error: 'invalid_client' });
      if (!c || f.get('redirect_uri') !== c.redirect) return json(400, { error: 'invalid_grant' });
      if (crypto.createHash('sha256').update(f.get('code_verifier') || '').digest('base64url') !== c.challenge) return json(400, { error: 'invalid_grant', error_description: 'PKCE' });
      const now = Math.floor(Date.now() / 1000);
      const claims = { iss: idp, aud: 'strata', sub: 'u-1', preferred_username: 'carol', groups: ['soc'], nonce: c.nonce, iat: now, exp: now + 300, ...next.claims };
      return json(200, { id_token: next.token ? next.token(claims) : sign(claims), access_token: 'x', token_type: 'Bearer' });
    }
    json(404, {});
  });
  await new Promise(r => provider.listen(idpPort, '127.0.0.1', r));
  const env = {
    HOST: '127.0.0.1', EDIT_USER: 'admin', EDIT_PASS: 'admin-pass-123', CONNECTORS: 'false', MODULE_REGISTRY: 'off',
    SSO_ISSUER: idp, SSO_CLIENT_ID: 'strata', SSO_CLIENT_SECRET: 's3cret', SSO_NAME: 'Test IdP', PUBLIC_URL: base,
    SSO_ROLE_APPROVER: 'soc', SSO_ROLE_VIEWER: 'staff', LOCAL_LOGIN: 'admins',
  };
  await start({ ...env, PORT: String(port), DATA_DIR: join(tmp, 'a') });
  // a second server behind a "proxy" that signs people in with headers; TRUST_PROXY is loopback
  await start({ HOST: '127.0.0.1', EDIT_USER: 'admin', EDIT_PASS: 'admin-pass-123', CONNECTORS: 'false', MODULE_REGISTRY: 'off', PORT: String(hdrPort), DATA_DIR: join(tmp, 'b'), SSO_HEADER_TRUST: '127.0.0.1', SSO_HEADER_USER: 'Remote-User', SSO_HEADER_GROUPS: 'Remote-Groups', SSO_ROLE_CONTRIBUTOR: 'it' });
});
after(async () => {
  for (const p of procs) if (p.exitCode === null) await new Promise(res => { p.once('exit', res); p.kill(); });
  provider.close();
  fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5 });
});
function start(env) {
  const p = spawn(process.execPath, [join(root, 'server/server.js')], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(p);
  return new Promise((res, rej) => { p.stdout.on('data', d => { if (String(d).includes('listening')) res(); }); p.on('exit', c => rej(new Error('exit ' + c))); });
}

// The browser's part: follows the sign-in, keeps the cookies Strata sets
async function signIn() {
  const jar = {};
  const keep = r => { for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); jar[kv.slice(0, i)] = kv.slice(i + 1); } };
  const cookies = () => Object.entries(jar).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join('; ');
  let r = await fetch(`${base}/auth/oidc/start`, { redirect: 'manual' });
  assert.equal(r.status, 302);
  keep(r);
  const auth = new URL(r.headers.get('location'));
  assert.equal(auth.searchParams.get('code_challenge_method'), 'S256');
  r = await fetch(auth, { redirect: 'manual' });
  r = await fetch(r.headers.get('location'), { redirect: 'manual', headers: { Cookie: cookies() } });
  keep(r);
  return { status: r.status, location: r.headers.get('location'), cookie: cookies(), text: r.status === 302 ? '' : await r.text() };
}
const api = (path, cookie, init = {}) => fetch(base + path, { ...init, headers: { ...(cookie ? { Cookie: cookie } : {}), ...(init.body ? { 'Content-Type': 'application/json', 'X-Requested-With': 'strata' } : {}), ...init.headers } });
const basic = (u, p) => ({ Authorization: 'Basic ' + Buffer.from(`${u}:${p}`).toString('base64') });

test('a page without a session goes to the sign-in page; the API answers 401 without a password prompt', async () => {
  const r = await fetch(`${base}/`, { redirect: 'manual' });
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), `${base}/auth/login`);
  const login = await (await fetch(`${base}/auth/login`)).text();
  assert.match(login, /Sign in with Test IdP/);
  assert.match(login, /Sign in with a local account/);
  const a = await fetch(`${base}/api/me`);
  assert.equal(a.status, 401);
  assert.equal(a.headers.get('www-authenticate'), null);
  // "Sign in with a local account": the password prompt is asked at the root, so the browser then sends it everywhere
  assert.ok(login.includes(`href="${base}/?local"`) && login.includes(`href="${base}/auth/oidc/start"`));
  const l = await fetch(`${base}/?local`, { redirect: 'manual' });
  assert.equal(l.status, 401);
  assert.match(l.headers.get('www-authenticate'), /^Basic/);
  assert.equal((await fetch(`${base}/?local`, { headers: basic('admin', 'admin-pass-123') })).status, 200);
});

test('OpenID Connect: groups give the role, the session cookie signs in, sign-out ends it', async () => {
  next = {};
  const s = await signIn();
  assert.equal(s.status, 302, s.text);
  assert.equal(s.location, `${base}/`);
  const me = await (await api('/api/me', s.cookie)).json();
  assert.equal(me.user, 'carol');
  assert.equal(me.role, 'approver');
  assert.equal(me.via, 'sso');
  // the session writes like any account, and is named in the history
  const w = await api('/api/si/sso-test', s.cookie, { method: 'PUT', body: JSON.stringify({ name: 'SSO test' }) });
  assert.equal(w.status, 200);
  const h = await (await api('/api/history?limit=1', s.cookie)).json();
  assert.equal(h.entries ? h.entries[0].user : (h.history || h)[0].user, 'carol');
  // no password to change here
  assert.equal((await api('/api/me/password', s.cookie, { method: 'PUT', body: JSON.stringify({ current: 'x', next: 'y'.repeat(12) }) })).status, 400);
  const out = await api('/auth/logout', s.cookie, { method: 'POST', body: '{}' });
  const o = await out.json();
  assert.match(o.location, new RegExp(`^${idp}/logout\\?id_token_hint=`));
  assert.equal((await api('/api/me', s.cookie)).status, 401, 'the session is gone');

  next = { claims: { groups: ['staff', 'other'] } };
  const v = await signIn();
  assert.equal((await (await api('/api/me', v.cookie)).json()).role, 'viewer');
});

test('OpenID Connect: refused ID tokens and people with no group', async () => {
  const refused = async (n, re) => { next = n; const s = await signIn(); assert.notEqual(s.status, 302, `accepted: ${JSON.stringify(n.claims || {})}`); assert.match(s.text, re); };
  await refused({ claims: { groups: ['nobody'] } }, /no group that gives access/);
  await refused({ claims: { aud: 'another-app' } }, /another application/);
  await refused({ claims: { iss: 'https://evil.example' } }, /another issuer/);
  await refused({ claims: { exp: Math.floor(Date.now() / 1000) - 3600 } }, /expired/);
  await refused({ claims: { nonce: 'replayed' } }, /does not answer this sign-in/);
  await refused({ claims: { preferred_username: 'bad name!' } }, /does not accept the user name/);
  await refused({ token: c => sign(c, other.privateKey) }, /signature is wrong/);
  await refused({ token: c => sign(c).replace(/\.[^.]+\./, '.' + Buffer.from(JSON.stringify({ ...c, groups: ['soc'], preferred_username: 'mallory' })).toString('base64url') + '.') }, /signature is wrong/);
  next = {};
  // a callback that this browser did not start
  const r = await fetch(`${base}/auth/oidc/callback?code=x&state=forged`);
  assert.equal(r.status, 400);
  assert.match(await r.text(), /expired or was not started from this browser/);
});

test('verifyJwt refuses "none" and unknown algorithms', () => {
  const p = Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url');
  for (const alg of ['none', 'HS256']) {
    const h = Buffer.from(JSON.stringify({ alg })).toString('base64url');
    assert.throws(() => verifyJwt(`${h}.${p}.`, { keys: [jwk] }), /not accepted/);
  }
});

test('LOCAL_LOGIN=admins: the local admin keeps a way in, other local accounts do not', async () => {
  assert.equal((await api('/api/users/bob', null, { method: 'PUT', headers: basic('admin', 'admin-pass-123'), body: JSON.stringify({ role: 'approver', password: 'bob-pass-12345' }) })).status, 200);
  assert.equal((await api('/api/me', null, { headers: basic('admin', 'admin-pass-123') })).status, 200);
  // refused like a wrong password: the answer says nothing of bob's password
  assert.equal((await api('/api/me', null, { headers: basic('bob', 'bob-pass-12345') })).status, 401);
  assert.equal((await api('/api/me', null, { headers: basic('bob', 'wrong-password') })).status, 401);
});

test('a provider name that is also a local account, or an unverified e-mail, is refused', async () => {
  const refused = async (claims, re) => { next = { claims }; const s = await signIn(); assert.notEqual(s.status, 302); assert.match(s.text, re); };
  await refused({ preferred_username: 'admin' }, /also a local account/);
  await refused({ preferred_username: undefined, email: 'zoe@example.org', email_verified: false }, /not verified/);
  next = { claims: { preferred_username: undefined, email: 'zoe@example.org', email_verified: true } };
  assert.equal((await signIn()).status, 302);
  next = {};
});

test('a sign-in finishes once; an admin can end every session', async () => {
  next = {};
  // the same callback, replayed with its cookie, is refused
  const jar = {};
  let r = await fetch(`${base}/auth/oidc/start`, { redirect: 'manual' });
  for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); jar[kv.slice(0, i)] = kv.slice(i + 1); }
  const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  r = await fetch(r.headers.get('location'), { redirect: 'manual' });
  const back = r.headers.get('location');
  assert.equal((await fetch(back, { redirect: 'manual', headers: { Cookie: cookie } })).status, 302);
  const again = await fetch(back, { redirect: 'manual', headers: { Cookie: cookie } });
  assert.equal(again.status, 400);
  const s = await signIn();
  assert.equal((await api('/api/me', s.cookie)).status, 200);
  const end = await (await api('/api/sessions', null, { method: 'DELETE', headers: basic('admin', 'admin-pass-123'), body: '{}' })).json();
  assert.ok(end.ended >= 1);
  assert.equal((await api('/api/me', s.cookie)).status, 401);
});

test('headers need SSO_HEADER_TRUST with exact addresses', async () => {
  const run = env => new Promise(res => { const p = spawn(process.execPath, [join(root, 'server/server.js')], { env: { ...process.env, PORT: '0', HOST: '127.0.0.1', DATA_DIR: join(tmp, 'c'), CONNECTORS: 'false', ...env }, stdio: ['ignore', 'ignore', 'pipe'] }); let err = ''; p.stderr.on('data', d => { err += d; }); p.on('exit', c => res({ code: c, err })); setTimeout(() => p.kill(), 5000); });
  let r = await run({ SSO_HEADER_USER: 'Remote-User' });
  assert.equal(r.code, 1); assert.match(r.err, /SSO_HEADER_TRUST/);
  r = await run({ SSO_HEADER_USER: 'Remote-User', SSO_HEADER_TRUST: '10.0.0.0/8' });
  assert.equal(r.code, 1); assert.match(r.err, /no range/);
});

test('API tokens: created by an admin, shown once, used as Bearer, revoked', async () => {
  const admin = basic('admin', 'admin-pass-123');
  const c = await (await api('/api/tokens', null, { method: 'POST', headers: admin, body: JSON.stringify({ name: 'ci', role: 'contributor', days: 7 }) })).json();
  assert.match(c.token, /^stk_[0-9a-f]{16}_/);
  const bearer = { Authorization: `Bearer ${c.token}` };
  const me = await (await api('/api/me', null, { headers: bearer })).json();
  assert.equal(me.user, 'token:ci');
  assert.equal(me.role, 'contributor');
  assert.equal(me.via, 'token');
  assert.equal((await api('/api/si/x', null, { method: 'PUT', headers: bearer, body: '{"name":"x"}' })).status, 403, 'a contributor token does not write the map');
  const list = await (await api('/api/tokens', null, { headers: admin })).json();
  assert.equal(list.tokens.length, 1);
  assert.equal(list.tokens[0].hash, undefined);
  assert.ok(list.tokens[0].lastUsedAt);
  assert.equal(JSON.stringify(JSON.parse(fs.readFileSync(join(tmp, 'a/tokens.json'), 'utf8'))).includes(c.token.slice('stk_'.length + 17)), false, 'the secret is not stored');
  assert.equal((fs.statSync(join(tmp, 'a/tokens.json')).mode & 0o777).toString(8), '600');
  assert.equal((await api('/api/me', null, { headers: { Authorization: `Bearer ${c.token.slice(0, -2)}xx` } })).status, 401);
  assert.equal((await api('/api/tokens', null, { headers: bearer })).status, 403, 'only admins manage tokens');
  assert.equal((await api('/api/tokens', null, { method: 'POST', headers: admin, body: JSON.stringify({ name: 'ci', role: 'viewer' }) })).status, 400, 'names are unique');
  assert.equal((await api(`/api/tokens/${c.id}`, null, { method: 'DELETE', headers: admin, body: '{}' })).status, 200);
  assert.equal((await api('/api/me', null, { headers: bearer })).status, 401, 'revoked');
});

test('trusted proxy headers: believed from a trusted proxy only, groups give the role', async () => {
  const h = (headers) => fetch(`http://127.0.0.1:${hdrPort}/api/me`, { headers });
  const me = await (await h({ 'Remote-User': 'dave', 'Remote-Groups': 'staff, it' })).json();
  assert.equal(me.user, 'dave');
  assert.equal(me.role, 'contributor');
  assert.equal(me.via, 'header');
  const none = await h({ 'Remote-User': 'eve', 'Remote-Groups': 'staff' });
  assert.equal(none.status, 403);
  assert.equal((await h({ 'Remote-User': 'admin', 'Remote-Groups': 'it' })).status, 403, 'a local account name');
  // the other server trusts no proxy: the same headers are ignored there
  const r = await fetch(`${base}/api/me`, { headers: { 'Remote-User': 'dave', 'Remote-Groups': 'soc' } });
  assert.equal(r.status, 401);
});
