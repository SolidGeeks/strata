// SPDX-License-Identifier: AGPL-3.0-or-later
// Copies the browser libraries and fonts from node_modules into public/vendor,
// so the app runs fully offline (no CDN, no Google Fonts).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NM = path.join(ROOT, 'node_modules');
const OUT = path.join(ROOT, 'public', 'vendor');

function copy(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

fs.rmSync(OUT, { recursive: true, force: true });
// three.js as ES modules: the app imports three.module.js (which imports three.core.js) and the orbit
// controls, whose bare "three" import is pointed at the copy next to it (no import map, no bundler)
copy(path.join(NM, 'three/build/three.module.js'), path.join(OUT, 'three.module.js'));
copy(path.join(NM, 'three/build/three.core.js'), path.join(OUT, 'three.core.js'));
const orbit = fs.readFileSync(path.join(NM, 'three/examples/jsm/controls/OrbitControls.js'), 'utf8');
if (!/from 'three';/.test(orbit)) throw new Error('OrbitControls.js no longer imports from "three": check scripts/vendor.mjs');
fs.writeFileSync(path.join(OUT, 'OrbitControls.js'), orbit.replace(/from 'three';/g, "from './three.module.js';"));
copy(path.join(NM, 'three/LICENSE'), path.join(OUT, 'LICENSE-three.txt'));

const fonts = {
  archivo: ['400', '500', '600'],
  'archivo-narrow': ['500', '600', '700'],
  'ibm-plex-mono': ['400', '500', '600'],
};
for (const [name, weights] of Object.entries(fonts)) {
  const src = path.join(NM, '@fontsource', name);
  const dest = path.join(OUT, 'fonts', name);
  for (const w of weights) {
    const cssFile = path.join(src, `${w}.css`);
    const css = fs.readFileSync(cssFile, 'utf8');
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(path.join(dest, `${w}.css`), css);
    // Copy only the font files this stylesheet references
    for (const m of css.matchAll(/url\(\.\/files\/([^)]+)\)/g)) copy(path.join(src, 'files', m[1]), path.join(dest, 'files', m[1]));
  }
  if (fs.existsSync(path.join(src, 'LICENSE'))) copy(path.join(src, 'LICENSE'), path.join(dest, 'LICENSE'));
}
console.log('Vendor files copied to', OUT);
