// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser walk-through of the interface (Playwright, Chromium): an admin signs in, loads the demo and
// sees the 3D model and the 2D diagram; a contributor proposes a change, an approver sees it
// highlighted and approves it. Any JavaScript error in a page fails the test.
// Run with: npm run test:e2e (once: npx playwright install chromium)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = mkdtempSync(join(tmpdir(), 'strata-e2e-'));
const port = 9900 + Math.floor(Math.random() * 90);
const base = `http://127.0.0.1:${port}/`;
const PASS = { admin: 'admin-pass-123', alice: 'alice-pass-123', bob: 'bob-pass-12345' };
let server, browser;
const errors = [];

before(async () => {
  server = spawn(process.execPath, [join(root, 'server/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, EDIT_USER: 'admin', EDIT_PASS: PASS.admin, VIEW_PASS: '', CONNECTORS: 'false' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  await new Promise((res, rej) => { server.stdout.on('data', d => { if (String(d).includes('listening')) res(); }); server.on('exit', c => rej(new Error('exit ' + c))); });
  for (const [name, role] of [['alice', 'contributor'], ['bob', 'approver']]) {
    const r = await api('admin', 'PUT', `api/users/${name}`, { role, password: PASS[name] });
    assert.equal(r.status, 200);
  }
  // WebGL without a GPU: SwiftShader
  browser = await chromium.launch({ args: ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
});
after(async () => {
  if (browser) await browser.close();
  if (server && server.exitCode === null) await new Promise(res => { server.once('exit', res); server.kill(); });
  rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 });
});

function api(user, method, path, body) {
  return fetch(base + path, {
    method,
    headers: { Authorization: 'Basic ' + Buffer.from(`${user}:${PASS[user]}`).toString('base64'), ...(body ? { 'Content-Type': 'application/json', 'X-Requested-With': 'strata' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  }).then(async r => ({ status: r.status, data: await r.json().catch(() => null) }));
}
// A signed-in page; every page error and console error is recorded and fails the test
async function signIn(user) {
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 }, httpCredentials: { username: user, password: PASS[user] } });
  const page = await ctx.newPage();
  page.on('pageerror', e => errors.push(`${user}: ${e.message}`));
  page.on('console', m => { if (m.type() === 'error') errors.push(`${user} console: ${m.text()}`); });
  await page.goto(base);
  await page.waitForSelector('#siteList');
  return page;
}
async function openIs(page, id) {
  await page.click(`#siteList [data-site="${id}"]`);
  await page.click('#det [data-open]');
  await page.waitForFunction(() => document.body.classList.contains('has-det') === false || !!document.querySelector('#viewSw:not([hidden])'));
}
// Distinct colours in a screenshot of an element, counted in the page itself (no image library)
async function colours(page, selector) {
  const png = (await page.locator(selector).screenshot()).toString('base64');
  return page.evaluate(async src => {
    const img = new Image(); img.src = 'data:image/png;base64,' + src; await img.decode();
    const c = document.createElement('canvas'); c.width = img.width; c.height = img.height;
    const x = c.getContext('2d'); x.drawImage(img, 0, 0);
    const d = x.getImageData(0, 0, c.width, c.height).data, seen = new Set();
    for (let i = 0; i < d.length; i += 4 * 7) seen.add((d[i] >> 3) << 10 | (d[i + 1] >> 3) << 5 | (d[i + 2] >> 3));
    return seen.size;
  }, png);
}

// Share of the pixels that differ between two screenshots of the same size
async function changed(page, a, b) {
  return page.evaluate(async ([a, b]) => {
    const load = async src => { const img = new Image(); img.src = 'data:image/png;base64,' + src; await img.decode(); const c = document.createElement('canvas'); c.width = img.width; c.height = img.height; const x = c.getContext('2d'); x.drawImage(img, 0, 0); return x.getImageData(0, 0, c.width, c.height).data; };
    const [p, q] = [await load(a), await load(b)];
    let diff = 0;
    for (let i = 0; i < p.length; i += 4) if (Math.abs(p[i] - q[i]) + Math.abs(p[i + 1] - q[i + 1]) + Math.abs(p[i + 2] - q[i + 2]) > 30) diff++;
    return diff / (p.length / 4);
  }, [a.toString('base64'), b.toString('base64')]);
}

test('walk-through: demo, 3D model, 2D diagram, then a proposal from draft to approval', async () => {
  // 1. The admin signs in on an empty map and loads the demo
  const admin = await signIn('admin');
  await admin.click('#empty [data-act="demo"]');
  await admin.waitForFunction(() => document.querySelectorAll('#siteList [data-site]').length === 5);

  // 2. The 3D model of an IS renders: a WebGL canvas with a real picture, not a blank one
  await openIs(admin, 'lyon');
  await admin.waitForSelector('#scene canvas');
  assert.ok(await admin.evaluate(() => { const c = document.querySelector('#scene canvas'); return !!(c.getContext('webgl2') || c.getContext('webgl')); }), 'the 3D view has no WebGL context');
  await admin.waitForTimeout(1500);
  const n3d = await colours(admin, '#scene canvas');
  assert.ok(n3d > 40, `the 3D view looks blank (${n3d} colours)`);

  // The middle button moves the view across the screen; a middle click selects nothing
  const box = await admin.locator('#scene canvas').boundingBox(), cx = box.x + box.width / 2, cy = box.y + box.height / 2;
  const still = await admin.locator('#scene canvas').screenshot();
  await admin.mouse.move(cx, cy);
  await admin.mouse.down({ button: 'middle' });
  await admin.mouse.move(cx + 260, cy, { steps: 12 }); // sideways: zooming would ignore it
  await admin.mouse.up({ button: 'middle' });
  await admin.waitForTimeout(800);
  const moved = await admin.locator('#scene canvas').screenshot();
  const share = await changed(admin, still, moved);
  assert.ok(share > 0.05, `the view did not move with the middle button (${(share * 100).toFixed(1)}% of the pixels changed)`);
  await admin.mouse.click(cx, cy, { button: 'middle' });
  await admin.waitForTimeout(300);
  assert.equal(await admin.evaluate(() => document.body.classList.contains('has-det')), false, 'a middle click opened a sheet');
  await admin.click('#resetBtn');
  await admin.waitForTimeout(1000);

  // 3. The 2D diagram shows the same IS
  await admin.click('#viewSeg [data-v="2d"]');
  await admin.waitForSelector('#flatSvg text');
  const text2d = await admin.locator('#flatSvg').textContent();
  for (const name of ['fw-edge', 'web-01', 'db-erp']) assert.ok(text2d.includes(name), `the 2D diagram does not show ${name}`);

  // 4. A contributor proposes a change in a draft: the role of web-01
  const alice = await signIn('alice');
  await openIs(alice, 'lyon');
  await alice.click('#newPropBtn');
  await alice.fill('#fTitle', 'web-01 is the customer portal');
  await alice.click('#frm button[type="submit"]');
  await alice.waitForSelector('#modebar:not([hidden]) [data-mb="submit"]');
  await alice.fill('#search', 'web-01');
  await alice.press('#search', 'Enter');
  await alice.click('#det [data-edit-asset]');
  await alice.fill('#fRole', 'Customer portal (front end)');
  await alice.click('#frm button[type="submit"]');
  await alice.waitForFunction(() => /1 change/.test(document.querySelector('#modebar').textContent));
  await alice.click('#modebar [data-mb="submit"]');
  await alice.waitForFunction(async () => !document.querySelector('#modebar [data-mb="submit"]'));
  // the map itself has not moved
  const before = await api('admin', 'GET', 'api/state');
  const web01 = Object.values(before.data.assets).find(a => a.name === 'web-01');
  assert.notEqual(web01.role, 'Customer portal (front end)');

  // 5. An approver opens it: the change is listed and highlighted on the diagram, then approved
  const bob = await signIn('bob');
  await openIs(bob, 'lyon');
  await bob.click('#ctl [data-collab="proposals"]');
  await bob.click('#det [data-open-prop]');
  await bob.waitForSelector('#det [data-prop-approve]');
  assert.match(await bob.locator('#modebar').textContent(), /Review/);
  assert.match(await bob.locator('#det').textContent(), /web-01/);
  await bob.click('#viewSeg [data-v="2d"]');
  await bob.waitForSelector('#flatSvg text');
  assert.match(await bob.locator('#flatSvg').textContent(), /CHANGED/, 'the changed asset is not highlighted');
  await bob.click('#det [data-prop-approve]');
  await bob.waitForSelector('#modebar', { state: 'hidden' });
  const after = await api('admin', 'GET', 'api/state');
  assert.equal(after.data.assets[web01.id].role, 'Customer portal (front end)');
  assert.equal(after.data.rev, before.data.rev + 1);

  assert.deepEqual(errors, [], 'JavaScript errors in the pages');
});
