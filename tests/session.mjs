// SPDX-License-Identifier: AGPL-3.0-or-later
// Signs a local account in with the sign-in form (POST /auth/login) and keeps its session cookie, per
// server, account and password: the tests send it as the browser does. HTTP Basic is gone since 0.11.
const cache = new Map();
// base: http://127.0.0.1:port (with or without a trailing slash); extra: headers of the sign-in request
export async function login(base, user, pass, extra = {}) {
  const r = await fetch(new URL('/auth/login', base), {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/json', ...extra },
    body: JSON.stringify({ user, password: pass }),
  });
  await r.arrayBuffer();
  const set = r.headers.get('set-cookie') || '';
  return { status: r.status, retryAfter: r.headers.get('retry-after'), cookie: r.ok ? set.split(';')[0] : '' };
}
// The headers that sign this account in ({} when the password is wrong: the request then gets a 401)
export async function auth(base, user, pass, extra) {
  if (!user) return {};
  const key = `${base}|${user}|${pass}`;
  if (!cache.has(key)) {
    const r = await login(base, user, pass, extra);
    if (!r.cookie) return {};
    cache.set(key, r.cookie);
  }
  return { Cookie: cache.get(key) };
}
export const forget = () => cache.clear();
