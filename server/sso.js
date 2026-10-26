// SPDX-License-Identifier: AGPL-3.0-or-later
// Single sign-on and API tokens, next to the local accounts of server.js:
//   - OpenID Connect (Entra ID, Keycloak, Authentik, Google Workspace, Okta…): authorization code flow
//     with PKCE, ID token checked against the provider's keys, then a session cookie;
//   - trusted proxy headers (Authelia, oauth2-proxy, Pomerium…): the user and groups a proxy listed in
//     TRUST_PROXY puts in headers;
//   - API tokens for scripts: created by an admin, shown once, stored hashed, with a role and an expiry.
// Roles come from the provider's groups (SSO_ROLE_ADMIN, _APPROVER, _CONTRIBUTOR, _VIEWER); a person in
// none of them gets SSO_DEFAULT_ROLE, or no access.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { request } from './connectors/sdk.js';

const ROLES = ['viewer', 'contributor', 'approver', 'admin'];
const b64url = buf => Buffer.from(buf).toString('base64url');
const rand = n => b64url(crypto.randomBytes(n));
const sha256 = s => crypto.createHash('sha256').update(s).digest();
const list = v => String(v || '').split(',').map(s => s.trim()).filter(Boolean);

// The settings, from the environment (and secret() for the client secret)
export function ssoConfig(env, secret) {
  const roles = {};
  for (const r of ROLES) roles[r] = list(env[`SSO_ROLE_${r.toUpperCase()}`]);
  const local = String(env.LOCAL_LOGIN || 'all').toLowerCase();
  return {
    issuer: String(env.SSO_ISSUER || '').replace(/\/+$/, ''),
    clientId: env.SSO_CLIENT_ID || '',
    clientSecret: secret('SSO_CLIENT_SECRET'),
    tokenAuth: env.SSO_TOKEN_AUTH === 'post' ? 'post' : 'basic',
    name: env.SSO_NAME || 'single sign-on',
    scopes: env.SSO_SCOPES || 'openid profile email',
    userClaim: env.SSO_USER_CLAIM || 'preferred_username',
    groupsClaim: env.SSO_GROUPS_CLAIM || 'groups',
    roles,
    defaultRole: ROLES.includes(env.SSO_DEFAULT_ROLE) ? env.SSO_DEFAULT_ROLE : '',
    headerUser: (env.SSO_HEADER_USER || '').toLowerCase(),
    headerGroups: (env.SSO_HEADER_GROUPS || '').toLowerCase(),
    headerTrust: list(env.SSO_HEADER_TRUST).map(a => a.toLowerCase()),
    publicUrl: String(env.PUBLIC_URL || '').replace(/\/+$/, ''),
    sessionMs: Math.max(0.1, parseFloat(env.SESSION_HOURS || '8') || 8) * 3600000,
    localLogin: ['all', 'admins', 'off'].includes(local) ? local : 'all',
  };
}

/* ---------------- JWT (ID tokens) ---------------- */
const ALGS = {
  RS256: { hash: 'sha256' }, RS384: { hash: 'sha384' }, RS512: { hash: 'sha512' },
  PS256: { hash: 'sha256', pss: 32 }, PS384: { hash: 'sha384', pss: 48 }, PS512: { hash: 'sha512', pss: 64 },
  ES256: { hash: 'sha256', ec: true }, ES384: { hash: 'sha384', ec: true }, ES512: { hash: 'sha512', ec: true },
  EdDSA: { hash: null },
};
// Checks a JWT's signature with one of the keys (JWK set) and returns its claims; throws otherwise
export function verifyJwt(token, jwks) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('the ID token is not a JWT');
  let header, claims;
  try { header = JSON.parse(Buffer.from(parts[0], 'base64url')); claims = JSON.parse(Buffer.from(parts[1], 'base64url')); }
  catch { throw new Error('the ID token cannot be read'); }
  const alg = ALGS[header.alg];
  if (!alg || !Object.hasOwn(ALGS, header.alg)) throw new Error(`the ID token is signed with ${header.alg}, which is not accepted`);
  const keys = (jwks && Array.isArray(jwks.keys) ? jwks.keys : []).filter(k => !k.use || k.use === 'sig');
  const candidates = header.kid ? keys.filter(k => k.kid === header.kid) : keys;
  const data = Buffer.from(`${parts[0]}.${parts[1]}`), sig = Buffer.from(parts[2], 'base64url');
  for (const jwk of candidates) {
    let key;
    try { key = crypto.createPublicKey({ key: jwk, format: 'jwk' }); } catch { continue; }
    const opts = alg.pss ? { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: alg.pss } : alg.ec ? { key, dsaEncoding: 'ieee-p1363' } : key;
    try { if (crypto.verify(alg.hash, data, opts, sig)) return { header, claims }; } catch { }
  }
  throw new Error(candidates.length ? 'the ID token signature is wrong' : 'no key of the provider matches the ID token');
}

// opts: config (ssoConfig), dataDir, log, writeJson, userRe; peerAddress(req): the TCP peer's address;
// localUser(name): the local account of that name, if any
export function createSso({ config, dataDir, log, writeJson, peerAddress, localUser, userRe }) {
  const C = config;
  const oidc = !!(C.issuer && C.clientId);
  const header = !!C.headerUser;
  if (oidc && !/^https?:\/\//.test(C.publicUrl)) throw new Error('SSO_ISSUER is set: also set PUBLIC_URL, the address users open Strata at (https://strata.example.org)');
  // the headers are believed from these exact addresses only: a range would let anything in it claim any user
  if (header && !C.headerTrust.length) throw new Error('SSO_HEADER_USER is set: also set SSO_HEADER_TRUST, the address of the sign-in proxy (127.0.0.1 when it runs on this machine)');
  for (const a of C.headerTrust) if (!/^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/.test(a) || a.includes('/')) throw new Error(`SSO_HEADER_TRUST: “${a}” is not an address (one address per proxy, no range)`);
  if (C.localLogin !== 'all' && !oidc && !header) throw new Error(`LOCAL_LOGIN=${C.localLogin} needs single sign-on (SSO_ISSUER or SSO_HEADER_USER): nobody could sign in`);
  const secure = C.publicUrl.startsWith('https://');
  // __Host- cookies cannot be set by another (sub)domain; they need Secure, so over HTTPS only
  const SESSION = secure ? '__Host-strata_session' : 'strata_session', STATE = secure ? '__Host-strata_oidc' : 'strata_oidc';
  const redirectUri = `${C.publicUrl}/auth/oidc/callback`;

  /* ---- roles ---- */
  // The highest role whose groups the person is in, or the default role, or '' (no access)
  function roleOf(groups) {
    const set = new Set(groups.map(String));
    for (const r of [...ROLES].reverse()) if (C.roles[r].some(g => set.has(g))) return r;
    return C.defaultRole;
  }

  /* ---- sessions (in memory: a restart signs SSO users out) ---- */
  const sessions = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, s] of sessions) if (s.exp < now) sessions.delete(k); }, 600000).unref();
  const cookie = (name, value, maxAgeS) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}; Max-Age=${maxAgeS}`;
  function readCookie(req, name) {
    for (const part of String(req.headers.cookie || '').split(';')) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim(); }
    return '';
  }
  function fromSession(req) {
    const id = readCookie(req, SESSION);
    const s = id && sessions.get(id);
    if (!s || s.exp < Date.now()) { if (s) sessions.delete(id); return null; }
    return { user: s.user, role: s.role, via: 'sso', sessionId: id };
  }

  /* ---- trusted proxy headers ---- */
  function fromHeaders(req) {
    if (!header || !C.headerTrust.includes(peerAddress(req))) return null;
    const raw = req.headers[C.headerUser];
    if (Array.isArray(raw)) return { denied: 'The sign-in proxy sent the user header twice.' };
    const user = String(raw || '').trim();
    if (!user) return null;
    if (!userRe.test(user)) return { denied: 'The sign-in proxy gave a user name Strata does not accept.' };
    if (localUser(user)) return { denied: `“${user}” is also a local account: rename one of them.` };
    const groups = C.headerGroups ? String(req.headers[C.headerGroups] || '').split(/[,;|]/).map(s => s.trim()).filter(Boolean) : [];
    const role = roleOf(groups);
    return role ? { user, role, via: 'header' } : { denied: `${user} is in no group that gives access to Strata.` };
  }

  /* ---- OpenID Connect ---- */
  let disco = null, jwks = null, discoFail = 0;
  async function getJson(url, what) {
    const res = await request(url, { timeoutMs: 15000, maxBytes: 1024 * 1024 });
    if (res.status !== 200) throw new Error(`${what}: ${new URL(url).host} answered HTTP ${res.status}`);
    return res.json();
  }
  async function discovery() {
    if (disco && Date.now() - disco.at < 3600000) return disco.doc;
    if (Date.now() - discoFail < 30000) throw new Error('the provider could not be reached a moment ago: try again in 30 seconds');
    let doc;
    try { doc = await getJson(`${C.issuer}/.well-known/openid-configuration`, 'OpenID discovery'); }
    catch (e) { discoFail = Date.now(); throw e; }
    if (String(doc.issuer || '').replace(/\/+$/, '') !== C.issuer) throw new Error(`the provider calls itself ${doc.issuer}, not ${C.issuer} (SSO_ISSUER)`);
    for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) if (!/^https?:\/\//.test(doc[k] || '')) throw new Error(`the provider gives no ${k}`);
    disco = { at: Date.now(), doc };
    return doc;
  }
  async function keys(refresh) {
    if (!refresh && jwks && Date.now() - jwks.at < 3600000) return jwks.set;
    if (refresh && jwks && Date.now() - jwks.at < 60000) return jwks.set; // a new key: fetch again, at most once a minute
    jwks = { at: Date.now(), set: await getJson((await discovery()).jwks_uri, 'Provider keys') };
    return jwks.set;
  }
  // The sign-in under way lives in a cookie signed with a key of this process (state, nonce, PKCE
  // verifier, expiry): nothing is kept on the server, so starting sign-ins cannot fill its memory
  const KEY = crypto.randomBytes(32);
  const mac = v => crypto.createHmac('sha256', KEY).update(v).digest('base64url');
  const seal = o => { const v = b64url(JSON.stringify(o)); return `${v}.${mac(v)}`; };
  function unseal(c) {
    const [v, m] = String(c || '').split('.');
    if (!v || !m || m.length !== 43 || !crypto.timingSafeEqual(Buffer.from(mac(v)), Buffer.from(m))) return null;
    try { return JSON.parse(Buffer.from(v, 'base64url')); } catch { return null; }
  }
  async function start() {
    const d = await discovery();
    const state = rand(24), nonce = rand(24), verifier = rand(48);
    const u = new URL(d.authorization_endpoint);
    for (const [k, v] of Object.entries({ response_type: 'code', client_id: C.clientId, redirect_uri: redirectUri, scope: C.scopes, state, nonce, code_challenge: b64url(sha256(verifier)), code_challenge_method: 'S256' })) u.searchParams.set(k, v);
    return { location: u.href, setCookie: cookie(STATE, seal({ state, nonce, verifier, exp: Date.now() + 600000 }), 600) };
  }
  // The provider sends the person back with ?code&state: returns {user, role} or throws a message to show
  // each started sign-in finishes once; and a client address finishes at most 30 an hour, so nobody
  // can make Strata hammer the provider's token endpoint
  const used = new Map(), perAddr = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, t] of used) if (t < now) used.delete(k); perAddr.clear(); }, 3600000).unref();
  async function callback(req, url, addr) {
    const state = url.searchParams.get('state') || '', code = url.searchParams.get('code') || '';
    if (url.searchParams.get('error')) throw new Error('The identity provider did not sign you in. Try again, or ask an administrator.');
    const p = unseal(readCookie(req, STATE));
    if (!p || p.exp < Date.now() || !state || p.state !== state || used.has(state)) throw new Error('This sign-in link has expired or was not started from this browser: sign in again.');
    const n = (perAddr.get(addr) || 0) + 1;
    perAddr.set(addr, n);
    if (n > 30) throw new Error('Too many sign-ins from this address: try again in an hour.');
    used.set(state, p.exp);
    const d = await discovery();
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: p.verifier });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
    if (C.tokenAuth === 'post') { form.set('client_id', C.clientId); if (C.clientSecret) form.set('client_secret', C.clientSecret); }
    else headers.Authorization = 'Basic ' + Buffer.from(`${encodeURIComponent(C.clientId)}:${encodeURIComponent(C.clientSecret)}`).toString('base64');
    const res = await request(d.token_endpoint, { method: 'POST', headers, body: form.toString(), timeoutMs: 15000, maxBytes: 1024 * 1024 });
    let tok; try { tok = JSON.parse(res.text); } catch { tok = {}; }
    if (res.status !== 200 || !tok.id_token) throw new Error(`The provider did not give an ID token (HTTP ${res.status}${tok.error ? `: ${String(tok.error_description || tok.error).slice(0, 200)}` : ''}).`);
    let v;
    try { v = verifyJwt(tok.id_token, await keys()); }
    catch (e) { if (/no key/.test(e.message)) v = verifyJwt(tok.id_token, await keys(true)); else throw e; }
    const c = v.claims, now = Date.now() / 1000;
    if (String(c.iss || '').replace(/\/+$/, '') !== C.issuer) throw new Error('The ID token comes from another issuer.');
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (!aud.includes(C.clientId) || (aud.length > 1 && c.azp && c.azp !== C.clientId)) throw new Error('The ID token is meant for another application.');
    if (!(c.exp > now - 60)) throw new Error('The ID token has expired: check the clock of this server.');
    if (c.iat && c.iat > now + 120) throw new Error('The ID token is dated in the future: check the clock of this server.');
    if (c.nonce !== p.nonce) throw new Error('The ID token does not answer this sign-in.');
    // the name, from the claim chosen; an e-mail address only once the provider has verified it
    const fromEmail = !c[C.userClaim] && c.email || C.userClaim === 'email';
    const user = String(c[C.userClaim] || c.email || c.sub || '');
    if (fromEmail && c.email_verified !== true) throw new Error('The provider gives an e-mail address it has not verified: Strata cannot use it as a name.');
    if (!userRe.test(user)) throw new Error(`Strata does not accept the user name the provider gives (${C.userClaim}).`);
    if (localUser(user)) throw new Error(`“${user}” is also a local account here: an administrator has to rename one of them.`);
    const g = c[C.groupsClaim];
    const groups = Array.isArray(g) ? g : typeof g === 'string' ? g.split(/[\s,]+/).filter(Boolean) : [];
    const role = roleOf(groups);
    if (!role) throw Object.assign(new Error(`${user} is in no group that gives access to Strata. Ask an administrator.`), { denied: true });
    const sid = rand(32);
    sessions.set(sid, { user, role, exp: Date.now() + C.sessionMs, idToken: tok.id_token });
    log(`SSO sign-in: ${JSON.stringify(user)} as ${role}`);
    return { user, role, setCookie: [cookie(SESSION, sid, Math.round(C.sessionMs / 1000)), cookie(STATE, '', 0)] };
  }
  async function logout(sessionId) {
    const s = sessions.get(sessionId);
    sessions.delete(sessionId);
    let location = `${C.publicUrl}/auth/login?out=1`;
    if (s && oidc) {
      try {
        const d = await discovery();
        if (d.end_session_endpoint) { const u = new URL(d.end_session_endpoint); u.searchParams.set('id_token_hint', s.idToken); u.searchParams.set('post_logout_redirect_uri', location); location = u.href; }
      } catch { }
    }
    return { location, setCookie: cookie(SESSION, '', 0) };
  }
  // An administrator ends every single sign-on session (after a group change, or someone leaving)
  function endSessions(by) { const n = sessions.size; sessions.clear(); log(`${n} single sign-on session(s) ended by ${JSON.stringify(by)}`); return n; }

  /* ---- API tokens (DATA_DIR/tokens.json, mode 600) ---- */
  const FILE = path.join(dataDir, 'tokens.json');
  let tokens = {};
  try { if (fs.existsSync(FILE)) { const t = JSON.parse(fs.readFileSync(FILE, 'utf8')).tokens; if (t && typeof t === 'object') tokens = t; } } catch (e) { log('tokens.json unreadable, no API token:', e.message); }
  const saveTokens = () => writeJson(FILE, JSON.stringify({ tokens }, null, 2)).then(() => { try { fs.chmodSync(FILE, 0o600); } catch { } });
  const TOKEN_RE = /^stk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
  function fromToken(req) {
    const h = String(req.headers.authorization || '');
    if (!h.startsWith('Bearer ')) return null;
    const m = TOKEN_RE.exec(h.slice(7).trim());
    const t = m && Object.hasOwn(tokens, m[1]) ? tokens[m[1]] : null;
    // an unknown, wrong or expired token is no sign-in at all (401)
    if (!t) return null;
    const a = sha256(m[2]), b = Buffer.from(t.hash, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    if (t.expiresAt && Date.parse(t.expiresAt) < Date.now()) return null;
    t.lastUsedAt = new Date().toISOString();
    return { user: `token:${t.name}`, role: t.role, via: 'token', tokenId: m[1] };
  }
  const publicToken = (id, t) => ({ id, name: t.name, role: t.role, createdBy: t.createdBy, createdAt: t.createdAt, expiresAt: t.expiresAt, lastUsedAt: t.lastUsedAt || null });
  async function createToken({ name, role, days, by }) {
    if (!/^[A-Za-z0-9_.-]{1,40}$/.test(String(name || ''))) throw Object.assign(new Error('Name it with letters, digits, dot, dash or underscore (40 at most).'), { status: 400 });
    if (!ROLES.includes(role)) throw Object.assign(new Error(`Role must be one of ${ROLES.join(', ')}.`), { status: 400 });
    if (Object.values(tokens).some(t => t.name === name)) throw Object.assign(new Error('A token already has this name.'), { status: 400 });
    const d = Math.round(+days || 90);
    if (!(d >= 1 && d <= 730)) throw Object.assign(new Error('A token lasts 1 to 730 days.'), { status: 400 });
    const id = crypto.randomBytes(8).toString('hex'), secretPart = rand(32);
    tokens[id] = { name, role, hash: sha256(secretPart).toString('hex'), createdBy: by, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + d * 86400000).toISOString() };
    await saveTokens();
    log(`API token ${JSON.stringify(name)} (${role}, ${d} days) created by ${JSON.stringify(by)}`);
    return { token: `stk_${id}_${secretPart}`, ...publicToken(id, tokens[id]) };
  }
  async function deleteToken(id, by) {
    if (!Object.hasOwn(tokens, id)) return false;
    log(`API token ${JSON.stringify(tokens[id].name)} revoked by ${JSON.stringify(by)}`);
    delete tokens[id];
    await saveTokens();
    return true;
  }

  return {
    oidc, header, name: C.name, localLogin: C.localLogin, publicUrl: C.publicUrl,
    // anyone could sign in some way other than a local account
    enabled: () => oidc || header || Object.keys(tokens).length > 0,
    fromSession, fromHeaders, fromToken, start, callback, logout, endSessions, sessionCount: () => sessions.size,
    listTokens: () => Object.entries(tokens).map(([id, t]) => publicToken(id, t)).sort((a, b) => a.name.localeCompare(b.name)),
    createToken, deleteToken,
  };
}

/* ---------------- Sign-in page ---------------- */
const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
// base: PUBLIC_URL, or '' (links from the root)
export function loginPage({ ssoName, oidc, local, message, out, base = '' }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · Strata</title>
<style>:root{color-scheme:light dark;--bg:#f4f3ef;--fg:#1c1d1f;--muted:#55595f;--line:#d8d6cf;--accent:#1c1d1f;--accent-fg:#f4f3ef;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#16181b;--fg:#ecebe6;--muted:#a9adb3;--line:#33363b;--accent:#ecebe6;--accent-fg:#16181b;--bad:#ff8a7a}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{width:min(380px,calc(100vw - 32px));border:1px solid var(--line);border-radius:4px;padding:28px 24px}
h1{margin:0 0 4px;font-size:22px;letter-spacing:.02em}p{margin:0 0 16px;color:var(--muted)}
a.btn{display:block;text-align:center;padding:11px 14px;border-radius:3px;text-decoration:none;font-weight:600;margin-top:10px}
a.primary{background:var(--accent);color:var(--accent-fg)}a.second{border:1px solid var(--line);color:var(--fg)}
.msg{color:var(--bad);border-left:3px solid var(--bad);padding:6px 10px;margin:0 0 16px}.ok{color:var(--muted)}</style></head>
<body><main><h1>Strata</h1><p>Map of the information systems</p>
${message ? `<p class="msg" role="alert">${escHtml(message)}</p>` : out ? '<p class="ok">You are signed out.</p>' : ''}
${oidc ? `<a class="btn primary" href="${escHtml(base)}/auth/oidc/start">Sign in with ${escHtml(ssoName)}</a>` : ''}
${local ? `<a class="btn ${oidc ? 'second' : 'primary'}" href="${escHtml(base)}/?local">Sign in with a local account</a>` : ''}
</main></body></html>`;
}
