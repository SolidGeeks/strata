// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser walk-through of the interface (Playwright, Chromium): an admin signs in, loads the demo and
// sees the 3D model and the 2D diagram; a contributor proposes a change, an approver sees it
// highlighted and approves it. Any JavaScript error in a page fails the test.
// Run with: npm run test:e2e (once: npx playwright install chromium)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auth } from './session.mjs';
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
  browser = await chromium.launch({ ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}), args: ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
});
after(async () => {
  if (browser) await browser.close();
  if (server && server.exitCode === null) await new Promise(res => { server.once('exit', res); server.kill(); });
  rmSync(dataDir, { recursive: true, force: true, maxRetries: 5 });
});

async function api(user, method, path, body) {
  return fetch(base + path, {
    method,
    headers: { ...(await auth(base, user, PASS[user])), ...(body ? { 'Content-Type': 'application/json', 'X-Requested-With': 'strata' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  }).then(async r => ({ status: r.status, data: await r.json().catch(() => null) }));
}
// A signed-in page; every page error and console error is recorded and fails the test
async function signIn(user) {
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  // the sign-in form, as a person would fill it
  const login = await ctx.newPage();
  await login.goto(base);
  await login.fill('#u', user);
  await login.fill('#p', PASS[user]);
  await Promise.all([login.waitForURL(u => !String(u).includes('/auth/')), login.click('button[type=submit]')]);
  await login.close();
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

test('incident mode: a Muster incident opens on the map, a contributor works it, others see it live', async () => {
  // runs after the walk-through: the demo is loaded
  const alice = await signIn('alice');
  await openIs(alice, 'lyon');
  const bob = await signIn('bob');
  await openIs(bob, 'lyon');

  // the contributor switches incident mode on and opens the ransomware example
  await alice.click('#incBtn');
  await alice.click('#det [data-inc-open="0"]');
  await alice.waitForSelector('#det .inc-run');
  await alice.click('#det [data-inc-go]');
  await alice.click('#det [data-inc-lbl="Yes"]');
  await alice.waitForFunction(() => /Isolate affected hosts/.test(document.querySelector('#det .inc-step.cur')?.textContent || ''));
  const text = await alice.locator('#det').textContent();
  for (const s of ['file-01', 'pc-acct-01', 'Who to call', 'Flows to cut', 'Reachable next']) assert.ok(text.includes(s), `the incident sheet lacks ${s}`);
  // the step points at the flows to cut, and cutting one is recorded
  await alice.click('#det .inc-tg [data-inc-cut]');
  await alice.waitForFunction(() => /Flow cut at/.test(document.querySelector('#det .inc-log')?.textContent || ''));
  // the 2D diagram shows the marks
  await alice.click('#viewSeg [data-v="2d"]');
  await alice.waitForSelector('#flatSvg text');
  assert.match(await alice.locator('#flatSvg').textContent(), /COMPROMISED/);

  // the approver's page follows without a reload
  await bob.waitForFunction(() => /Incident mode/i.test(document.querySelector('#cart .incband')?.textContent || ''));
  const saved = await api('bob', 'GET', 'api/incidents');
  assert.equal(saved.data.incidents.lyon.run.cur, 'isolate');
  assert.equal(saved.data.incidents.lyon.cuts.length, 1);

  // the anonymised prompts of an asset name nothing that identifies it
  await alice.fill('#search', 'db-erp');
  await alice.press('#search', 'Enter');
  await alice.click('#det [data-ai-asset]');
  await alice.waitForSelector('#ai-risk');
  const prompt = await alice.locator('#ai-risk').textContent();
  for (const s of ['db-erp', '10.20.0.21', 'Lyon', 'example.com']) assert.ok(!prompt.includes(s), `the prompt leaks ${s}`);
  assert.match(prompt, /ASSET-T/);

  assert.deepEqual(errors, [], 'JavaScript errors in the pages');
});

test('risk register: threats per asset on the matrix, requirements applied, settings saved', async () => {
  const bob = await signIn('bob');
  await openIs(bob, 'lyon');
  await bob.click('#lensSeg [data-lens="risk"]');
  await bob.waitForSelector('#lensBody .rk-tab tbody tr');
  const rows = await bob.locator('#lensBody .rk-tab tbody tr').count();
  assert.ok(rows > 20, `the register of Lyon lists only ${rows} risks`);
  // a cell of the matrix filters the register
  await bob.locator('#lensBody [data-cell^="residual:"]').filter({ hasText: /\d/ }).first().click();
  assert.ok(await bob.locator('#lensBody .rk-tab tbody tr').count() < rows);
  await bob.click('#lensBody [data-rk-clear]');

  // the VPN gateway: compromise of a remote access, then its requirements applied one by one
  await bob.fill('#search', 'vpn-gw');
  await bob.press('#search', 'Enter');
  await bob.click('#det [data-threat="remote-access"]');
  await bob.waitForSelector('#det [data-req]');
  const level = () => bob.locator('#det .kv dd').nth(2).textContent();
  const before = await level();
  const reqs = bob.locator('#det [data-req]'), n = await reqs.count();
  for (let k = 0; k < n; k++) { await reqs.nth(k).selectOption('applied'); await bob.waitForTimeout(150); }
  await bob.waitForTimeout(800);
  assert.notEqual(await level(), before, 'the requirements applied lower the risk');
  const vpn = Object.values((await api('bob', 'GET', 'api/state')).data.assets).find(a => a.site === 'lyon' && a.name === 'vpn-gw');
  assert.equal(Object.values(vpn.risk.threats['remote-access'].reqs).filter(s => s === 'applied').length, n);

  // the 2D plan of the asset lists its requirements by baseline, under the firewall rules
  await bob.click('#det [data-threat-back]');
  await bob.click('#det [data-plan-asset]');
  await bob.waitForSelector('#planView svg');
  assert.match(await bob.locator('#planView svg').textContent(), new RegExp(`REQUIREMENTS FOR VPN-GW · \\d+ · \\d+ APPLIED.*ANSSI`));
  await bob.click('[data-plan="close"]');

  // a click on a plate shows its VLAN alone, the other plates and their assets fade out
  await bob.click('#lensSeg [data-lens="physical"]');
  await bob.click('#viewSeg [data-v="2d"]');
  await bob.waitForSelector('#flatSvg [data-plate]');
  // a point of the first plate with no asset or flow over it
  const spot = await bob.evaluate(() => {
    const r = document.querySelector('#flatSvg [data-plate] rect').getBoundingClientRect();
    for (let y = r.bottom - 4; y > r.top + 4; y -= 6) for (let x = r.left + 4; x < r.right - 4; x += 6) {
      const e = document.elementFromPoint(x, y);
      if (e && e.closest('[data-plate]') && !e.closest('[data-asset],[data-flow],[data-plate-handle]')) return [x, y];
    }
    return null;
  });
  assert.ok(spot, 'no free spot on the plate');
  await bob.mouse.click(...spot);
  await bob.waitForSelector('#focusBar:not([hidden])');
  assert.equal(await bob.locator('#vlans input:checked').count(), 1);
  // a click on an empty space brings every VLAN back
  const empty = await bob.evaluate(() => {
    for (let y = 880; y > 150; y -= 20) for (let x = 1380; x > 320; x -= 20) {
      const e = document.elementFromPoint(x, y);
      if (e && e.closest('#flatSvg') && !e.closest('[data-plate],[data-asset],[data-flow],[data-internet]')) return [x, y];
    }
    return null;
  });
  await bob.mouse.click(...empty);
  await bob.waitForSelector('#focusBar', { state: 'hidden' });
  assert.equal(await bob.locator('#vlans input:not(:checked)').count(), 0);
  await bob.click('#viewSeg [data-v="3d"]');
  await bob.click('#lensSeg [data-lens="risk"]');

  // the settings: one more baseline, saved for every IS
  await bob.click('#lensBody [data-rk-settings]');
  await bob.locator('#det [data-rs-baseline="nist-csf"]').check();
  await bob.waitForFunction(() => /NIST/.test(document.querySelector('#lensBody .lens-head')?.textContent || ''));
  assert.deepEqual((await api('bob', 'GET', 'api/state')).data.risk.baselines, ['anssi', 'nist-csf']);

  // the Baselines tab: overlapping requirements merged, one kept per group
  await bob.click('#lensBody [data-rkv="baselines"]');
  await bob.waitForSelector('#lensBody .ovg');
  await bob.locator('#lensBody [data-ov-on]').check();
  await bob.waitForFunction(() => /merged into another one/.test(document.querySelector('#lensBody .summary')?.textContent || ''));
  assert.equal((await api('bob', 'GET', 'api/state')).data.risk.merge.on, true);

  // the Logs tab: what each asset sends to the SIEM; an asset sheet lists its own
  await bob.click('#lensBody [data-rkv="logs"]');
  await bob.locator('#lensBody [data-goto-logs]').first().click();
  await bob.waitForSelector('#det #logsCap');
  assert.ok(await bob.locator('#det details.lgs').count() > 0);

  // the dashboard for a steering committee: key figures measured from the history of the map
  await bob.click('#ctl [data-act="dashboard"]');
  await bob.waitForSelector('#dash .ktile');
  assert.equal(await bob.locator('#dash .ktile').count(), 7);
  assert.match(await bob.locator('#dash').textContent(), /Internet-facing assets[\s\S]*Scan coverage/);
  await bob.click('#dash [data-dash="close"]');
  assert.deepEqual(errors, [], 'JavaScript errors in the pages');
});

test('plates: all or none, empty VLANs hidden, VLANs imported into chosen zones, arranged on a grid, Internet moved, sign-out', async () => {
  const admin = await signIn('admin');
  if (!(await admin.locator('#siteList [data-site="lyon"]').count())) {
    await admin.click('#empty [data-act="demo"]');
    await admin.waitForFunction(() => document.querySelectorAll('#siteList [data-site]').length === 5);
  }
  await openIs(admin, 'lyon');
  await admin.waitForSelector('#vlans .vrow');
  const boxes = () => admin.locator('#vlans input[type=checkbox]:checked').count();
  const total = await admin.locator('#vlans input[type=checkbox]').count();

  // all / none, for the IS and for one zone
  await admin.click('.vtools [data-vsel="none"]');
  assert.equal(await boxes(), 0);
  await admin.click('.vtools [data-vsel="all"]');
  assert.equal(await boxes(), total);
  const zone = admin.locator('#vlans .zone-h [data-vsel="none"]').first();
  const zoneId = await zone.getAttribute('data-zone');
  const inZone = (await api('admin', 'GET', 'api/state')).data.si.lyon.vlans.filter(v => v.zone === zoneId).length;
  await zone.click();
  assert.equal(await boxes(), total - inZone);
  await admin.click('.vtools [data-vsel="all"]');

  // a CSV of VLANs: two ticked, put in a new zone at once, one in a zone named by the file
  const csv = join(dataDir, 'vlans.csv');
  writeFileSync(csv, 'Numéro;Nom;Réseau;Zone\n300;Lab A;10.30.0.0/24;Labo\n301;Lab B;10.30.1.0/24;Labo\n302;Printers R&D;10.30.2.0/24;\n10;DMZ renamed;;\n');
  await admin.locator('#vlanFile').setInputFiles(csv);
  await admin.waitForSelector('#viBody tr');
  assert.equal(await admin.locator('#viBody tr').count(), 4);
  assert.equal(await admin.locator('#viBody tr').nth(3).locator('[data-vi-on]').isChecked(), false, 'a VLAN already in the IS starts unticked');
  await admin.click('[data-vi="none"]');
  await admin.locator('#viBody tr').nth(1).locator('[data-vi-on]').check();
  await admin.locator('#viBody tr').nth(2).locator('[data-vi-on]').check();
  await admin.selectOption('#viZone', '__new');
  await admin.fill('#viZoneNew', 'Peripherals');
  await admin.click('[data-vi="apply"]');
  await admin.locator('#viBody tr').nth(0).locator('[data-vi-on]').check();
  await admin.click('#frm button[type=submit]');
  await admin.waitForFunction(() => /Lab A/.test(document.querySelector('#vlans')?.textContent || ''));
  const si = (await api('admin', 'GET', 'api/state')).data.si.lyon;
  const zoneOf = num => si.zones.find(z => z.id === si.vlans.find(v => v.num === num).zone).name;
  assert.equal(zoneOf(300), 'Labo');
  assert.equal(zoneOf(301), 'Peripherals');
  assert.equal(zoneOf(302), 'Peripherals');
  assert.equal(si.vlans.find(v => v.num === 10).name, 'DMZ', 'an unticked VLAN is left alone');

  // the three new VLANs are empty: hidden from the model when asked
  await admin.check('#optEmpty');
  await admin.waitForFunction(() => document.querySelectorAll('#vlans .vrow.off').length >= 3);
  await admin.uncheck('#optEmpty');

  // Arrange VLANs: 3 per row at most, saved as plate positions
  await admin.selectOption('#arrCols', '3');
  await admin.click('#arrangeGridBtn');
  await admin.waitForFunction(async () => (await (await fetch('api/state')).json()).si.lyon.vlans.every(v => Array.isArray(v.place)));
  const placed = (await api('admin', 'GET', 'api/state')).data.si.lyon;
  for (const z of placed.zones) {
    const rows = new Set(placed.vlans.filter(v => v.zone === z.id).map(v => v.place[1]));
    const n = placed.vlans.filter(v => v.zone === z.id).length;
    assert.equal(rows.size, Math.ceil(n / 3), `zone ${z.name}: ${n} VLANs on ${rows.size} rows`);
  }

  // the Internet node, dragged in the 2D diagram, keeps its place
  await admin.click('#viewSeg [data-v="2d"]');
  await admin.waitForSelector('#flatSvg [data-internet="internet"] rect');
  const b = await admin.locator('#flatSvg [data-internet="internet"] rect').boundingBox();
  await admin.mouse.move(b.x + b.width / 2, b.y + b.height / 2);
  await admin.mouse.down();
  await admin.mouse.move(b.x + 300, b.y + 200, { steps: 8 });
  await admin.mouse.up();
  await admin.waitForFunction(async () => Array.isArray((await (await fetch('api/state')).json()).si.lyon.cloud2d));
  await admin.click('#cloudReset');
  await admin.waitForFunction(async () => !(await (await fetch('api/state')).json()).si.lyon.cloud2d);

  // Suggest zones: the Internet on top; applied by the admin
  await admin.click('#viewSeg [data-v="3d"]');
  await admin.click('#suggestZonesBtn');
  await admin.waitForSelector('#szBody .sz');
  assert.equal(await admin.locator('#frm button[type=submit]').textContent(), 'Apply');
  await admin.click('#frm button[type=submit]');
  await admin.waitForFunction(async () => { const s = (await (await fetch('api/state')).json()).si.lyon; const top = s.zones[s.zones.length - 1]; return s.vlans.some(v => v.num === 10 && v.zone === top.id); });

  // the 3D view is cheap to draw: a few hundred draw calls, nothing drawn while idle, nothing leaked on a rebuild
  await admin.click('#viewSeg [data-v="3d"]');
  await admin.click('.vtools [data-vsel="all"]');
  await admin.waitForTimeout(1500);
  const rs = () => admin.evaluate(() => window.strataRenderStats());
  const r0 = await rs();
  assert.ok(r0.calls > 20 && r0.calls < 400, `${r0.calls} draw calls for the Lyon model`);
  await admin.click('#gfxSeg [data-gfx="eco"]');
  await admin.waitForTimeout(800);
  assert.equal((await rs()).mode, 'eco');
  const idle0 = (await rs()).frames;
  await admin.waitForTimeout(1500);
  assert.ok((await rs()).frames - idle0 <= 1, 'the model is drawn again while nothing changes');
  // shared geometries (equipment models) go to the GPU the first time they are seen: one cycle warms them up,
  // then rebuilding the model again and again must not add any
  const cycle = async () => { for (const sp of ['wide', 'compact']) { await admin.click(`#spaceSeg [data-space="${sp}"]`); await admin.waitForTimeout(500); } await admin.waitForTimeout(600); return (await rs()).geometries; };
  const geo0 = await cycle(), geos = [await cycle(), await cycle(), await cycle()];
  assert.ok(Math.max(...geos) <= geo0 + 2, `GPU geometries grow on each rebuild (${geo0} → ${geos.join(', ')})`);
  await admin.click('#gfxSeg [data-gfx="quality"]');
  await admin.waitForTimeout(800);
  assert.equal((await rs()).mode, 'quality');
  await admin.click('#gfxSeg [data-gfx="auto"]');

  // sign out: back to the sign-in page, and the session no longer opens the API
  await admin.click('#cart [data-signout]');
  await admin.waitForURL(/\/auth\/login/);
  assert.equal((await admin.request.get(base + 'api/me')).status(), 401);
  assert.deepEqual(errors, [], 'JavaScript errors in the pages');
});
