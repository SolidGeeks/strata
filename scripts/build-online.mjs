// SPDX-License-Identifier: AGPL-3.0-or-later
// Builds dist-online/strata.html: the whole interface in one page that runs without a server, as a Claude
// artifact or any static host. The map lives in the browser (local mode, as when api/me does not answer),
// three.js comes from jsDelivr, the fonts from Google Fonts, and the demo loads on first
// open. The self-hosted version is unchanged: it serves public/ and its vendored copies.
// three.js is imported by absolute URL from jsDelivr's ES module builds (+esm), whose own imports are absolute
// too: no import map, which a host page that has already loaded a module would ignore.
// Run with: npm run build:online
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUB = path.join(ROOT, 'public');
const OUT = path.join(ROOT, 'dist-online');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const THREE = pkg.dependencies.three.replace(/^[^\d]*/, '');
const read = f => fs.readFileSync(path.join(PUB, f), 'utf8');
// A script inlined in the page must not close its own <script> element
const js = s => s.replace(/<\/script/gi, '<\\/script');

const html = read('index.html');
const body = html.slice(html.indexOf('<body>') + 6, html.indexOf('</body>'))
  .replace(/<script src="[^"]+"><\/script>\s*/g, '');
const cdn = `https://cdn.jsdelivr.net/npm/three@${THREE}/`;
let app = read('app.js')
  .replace("import('./vendor/three.module.js')", `import('${cdn}+esm')`)
  .replace("import('./vendor/OrbitControls.js')", `import('${cdn}examples/jsm/controls/OrbitControls.js/+esm')`);
if (!app.includes(cdn + '+esm') || !app.includes('OrbitControls.js/+esm')) throw new Error('app.js no longer imports three.js from ./vendor: check scripts/build-online.mjs');
// Without a server there is no public/vendor to point at: say what failed instead
const why = "The 3D library is missing from <code>public/vendor</code>. Run <code>npm run setup</code>, or rebuild the container with <code>docker compose up -d --build</code>, while the machine can reach the npm registry.";
if (!app.includes(why)) throw new Error('the start-up error message of app.js changed: check scripts/build-online.mjs');
app = app.replace(why, "The 3D library (three.js) could not be loaded from cdn.jsdelivr.net: '+String(e&&e.message||e).replace(/[<&]/g,'')+'. Check the network, then reload.");
// No server behind this page: do not ask for one. Inside a host page the request can stay unanswered,
// and the map would wait for it forever.
const probe = "try{const r=await fetch('api/me',{cache:'no-store',credentials:'same-origin'});if(r.ok)me=await r.json();}catch(e){}";
if (!app.includes(probe)) throw new Error('Store.init no longer asks api/me this way: check scripts/build-online.mjs');
app = app.replace(probe, '');
const page = `<title>Strata</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600&family=Archivo+Narrow:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
${read('app.css')}
</style>
${body}
<script>
// An error at start-up shows on the page, not only in the console
addEventListener('error',e=>{if(document.querySelector('#siteList [data-site]'))return;const m=document.createElement('pre');m.style.cssText='position:fixed;left:16px;right:16px;bottom:16px;z-index:99;white-space:pre-wrap;background:#c4313d;color:#fff;padding:10px;font:12px/1.4 monospace;border-radius:4px';m.textContent='Strata could not start: '+(e.message||e.error)+(e.filename?' ('+e.filename+':'+e.lineno+')':'');document.body.appendChild(m);});
addEventListener('unhandledrejection',e=>dispatchEvent(new ErrorEvent('error',{message:String(e.reason&&e.reason.stack||e.reason)})));
</script>
<script>
${js(read('analysis.js'))}
</script>
<script>
${js(read('incident.js'))}
</script>
<script>
${js(app)}
</script>
<script>
// First open: load the demo, so the page shows a map at once
(function(){let n=0;const t=setInterval(()=>{const b=document.querySelector('#empty:not([hidden]) [data-act="demo"]');if(b){clearInterval(t);b.click();}else if(++n>60||document.querySelector('#siteList [data-site]'))clearInterval(t);},250);})();
</script>
`;
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, 'strata.html'), page);
console.log(`dist-online/strata.html written (${Math.round(page.length / 1024)} KB, three.js ${THREE} from jsDelivr)`);
