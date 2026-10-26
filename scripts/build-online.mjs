// SPDX-License-Identifier: AGPL-3.0-or-later
// Builds dist-online/strata.html: the whole interface in one page that runs without a server, as a Claude
// artifact or any static host. The map lives in the browser (local mode, as when api/me does not answer),
// three.js comes from jsDelivr through an import map, the fonts from Google Fonts, and the demo loads on first
// open. The self-hosted version is unchanged: it serves public/ and its vendored copies.
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
let app = read('app.js')
  .replace("import('./vendor/three.module.js')", "import('three')")
  .replace("import('./vendor/OrbitControls.js')", "import('three/addons/controls/OrbitControls.js')");
if (!/import\('three'\)/.test(app) || !/three\/addons/.test(app)) throw new Error('app.js no longer imports three.js from ./vendor: check scripts/build-online.mjs');

const cdn = `https://cdn.jsdelivr.net/npm/three@${THREE}/`;
const page = `<title>Strata</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600&family=Archivo+Narrow:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
${read('app.css')}
</style>
${body}
<script type="importmap">${JSON.stringify({ imports: { three: cdn + 'build/three.module.js', 'three/addons/': cdn + 'examples/jsm/' } })}</script>
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
