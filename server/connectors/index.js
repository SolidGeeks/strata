// SPDX-License-Identifier: AGPL-3.0-or-later
// Connector manager: the modules (modules.js), their settings (data/connectors.json, secrets never sent
// back to browsers), runs (by hand, on a schedule or from an imported file) and their outcome. Each test
// or run happens in a separate process (runner.js). A run never writes the map: it prepares proposals
// that an approver reviews like any other (one per IS, refreshed in place while still open).
import fs from 'node:fs';
import path from 'node:path';
import { ConnectorError } from './sdk.js';
import { discover } from './modules.js';
import { runModule } from './runner.js';

const MASK = '••••••••';
const COMMON = [
  { k: 'enabled', label: 'Enabled', type: 'bool', default: false },
  { k: 'everyHours', label: 'Sync automatically every … hours (0 = by hand only)', type: 'number', default: 0 },
  { k: 'tlsInsecure', label: 'Accept any TLS certificate (self-signed, trusted network only)', type: 'bool', default: false, advanced: true },
  { k: 'tlsCa', label: 'CA certificate (PEM) to trust', type: 'text', placeholder: '-----BEGIN CERTIFICATE-----', advanced: true },
  { k: 'sites', label: 'Limit to these IS (empty = all)', type: 'sites', advanced: true },
];

// A document whose only difference is the connector link (ext) is not worth a review: leave it out
const noExt = o => JSON.stringify(o, (k, v) => (k === 'ext' ? undefined : v));
function dropLinkOnly(changes, state) {
  for (const kind of ['si', 'assets']) for (const [id, doc] of Object.entries(changes[kind] || {})) {
    if (doc && state[kind][id] && noExt(doc) === noExt(state[kind][id])) delete changes[kind][id];
  }
}

// A proposal stays within its IS: that IS's document and the assets that are, or would be, in it.
// Changes to other IS, the links between IS and the common catalogue of services are left out.
function ownSite(changes, siteId, state) {
  const out = { si: {}, assets: {} }, isObj = o => !!o && typeof o === 'object' && !Array.isArray(o);
  if (isObj(changes.si) && Object.hasOwn(changes.si, siteId) && changes.si[siteId] !== null) out.si[siteId] = changes.si[siteId];
  if (isObj(changes.assets)) for (const [aid, doc] of Object.entries(changes.assets)) {
    const now = Object.hasOwn(state.assets, aid) ? state.assets[aid] : null;
    if (now && now.site !== siteId) continue;
    if (doc !== null && !(isObj(doc) && doc.site === siteId)) continue;
    if (doc === null && !now) continue;
    out.assets[aid] = doc;
  }
  return out;
}

// opts: dataDir, providedDir (MODULES_DIR), installedDir (DATA_DIR/modules), strataVersion, timeoutMs,
// and the server's getState, upsertProposal, log, writeJson, broadcast
export function createConnectors({ dataDir, providedDir, installedDir, strataVersion, timeoutMs, getState, upsertProposal, log, writeJson, broadcast }) {
  const FILE = path.join(dataDir, 'connectors.json');
  let store = { connectors: {}, runs: [] };
  try { if (fs.existsSync(FILE)) { const p = JSON.parse(fs.readFileSync(FILE, 'utf8')); store = { connectors: p.connectors || {}, runs: Array.isArray(p.runs) ? p.runs : [] }; } } catch (e) { log('connectors.json unreadable, starting empty:', e.message); }
  let MODULES = new Map(), problems = [];
  function reload() {
    ({ modules: MODULES, problems } = discover({ providedDir, installedDir, strataVersion }));
    for (const p of problems) log(`Connector module ${p.origin}/${p.folder} left out: ${p.error}`);
  }
  reload();
  const known = id => typeof id === 'string' && MODULES.has(id);
  const mod = id => MODULES.get(id);
  const running = new Map(), testing = new Set();
  const save = () => writeJson(FILE, JSON.stringify(store, null, 2)).then(() => { try { fs.chmodSync(FILE, 0o600); } catch { } });
  // the IS filter is common, except for a module that works on one IS it names itself (a "site" setting)
  const fieldsOf = id => { const f = mod(id).fields; return [...f, ...COMMON.filter(c => c.k !== 'sites' || !f.some(x => x.type === 'site'))]; };
  const cfgOf = id => (Object.hasOwn(store.connectors, id) ? store.connectors[id] : (store.connectors[id] = { settings: {}, lastRun: null }));

  // Settings as a module sees them (defaults filled in, TLS options grouped)
  function effective(id, overrides = {}) {
    const c = cfgOf(id), out = {};
    for (const f of fieldsOf(id)) { const v = Object.hasOwn(c.settings, f.k) ? c.settings[f.k] : undefined; out[f.k] = v !== undefined && v !== '' ? v : f.default; }
    Object.assign(out, overrides);
    out.tls = { insecure: !!out.tlsInsecure, ca: out.tlsCa && /BEGIN CERTIFICATE/.test(out.tlsCa) ? out.tlsCa : undefined };
    return out;
  }
  const isConfigured = id => { const s = cfgOf(id).settings; return mod(id).fields.filter(f => f.required).every(f => s[f.k] !== undefined && s[f.k] !== '' && !(Array.isArray(s[f.k]) && !s[f.k].length)); };
  // a sync with the tool (rather than a file import) is possible
  const isLive = id => { const m = mod(id); return m.live !== false && isConfigured(id) && m.live.every(k => cfgOf(id).settings[k]); };
  function publicView(id) {
    const c = cfgOf(id), m = mod(id), settings = {};
    for (const f of fieldsOf(id)) { const v = Object.hasOwn(c.settings, f.k) ? c.settings[f.k] : undefined; settings[f.k] = f.secret ? (v ? MASK : '') : (v === undefined ? (f.default ?? '') : v); }
    return {
      id, name: m.name, what: m.description, badge: m.badge, version: m.version, origin: m.origin, author: m.author, homepage: m.homepage,
      permissions: m.permissions, file: m.file, fields: fieldsOf(id), settings,
      configured: isConfigured(id), live: isLive(id), lastRun: c.lastRun, running: running.has(id) ? running.get(id).info : null,
    };
  }
  function update(id, body) {
    if (!known(id)) throw new ConnectorError('Unknown connector');
    const c = cfgOf(id);
    for (const f of fieldsOf(id)) {
      if (!body || typeof body !== 'object' || !Object.hasOwn(body, f.k)) continue;
      let v = body[f.k];
      if (f.secret) { if (v === MASK) continue; if (v === '' || v == null) { delete c.settings[f.k]; continue; } }
      if (f.type === 'bool') v = !!v;
      else if (f.type === 'number') v = Math.max(0, Math.min(100000, parseFloat(v) || 0));
      else if (f.type === 'multi' || f.type === 'sites') v = Array.isArray(v) ? v.map(String).slice(0, 200) : [];
      else v = String(v ?? '').slice(0, f.type === 'text' || f.type === 'rules' ? 20000 : 2000).trim();
      c.settings[f.k] = v;
    }
    return save();
  }
  // Values of the settings a file import may change for one import (file.fields of the manifest)
  function fileOverrides(id, o) {
    const m = mod(id), out = {}, state = getState();
    if (!m.file || !o || typeof o !== 'object') return out;
    for (const k of m.file.fields) {
      if (!Object.hasOwn(o, k)) continue;
      const f = m.fields.find(x => x.k === k), v = o[k];
      if (f.type === 'site') { if (typeof v === 'string' && Object.hasOwn(state.si, v)) out[k] = v; }
      else if (f.type === 'asset') { if (v === '' || (typeof v === 'string' && Object.hasOwn(state.assets, v))) out[k] = v; }
      else if (f.type === 'select') { if (f.options.some(x => x[0] === v)) out[k] = v; }
      else if (f.type === 'bool') out[k] = !!v;
      else if (f.type === 'number') out[k] = Math.max(0, Math.min(100000, parseFloat(v) || 0));
      else if (f.type === 'multi' || f.type === 'sites') out[k] = Array.isArray(v) ? v.map(String).slice(0, 200) : [];
      else if (typeof v === 'string' || typeof v === 'number') out[k] = String(v).slice(0, 2000).trim();
    }
    return out;
  }
  async function test(id) {
    if (!known(id)) throw new ConnectorError('Unknown connector');
    if (!isLive(id)) throw new ConnectorError(mod(id).live === false ? `${mod(id).name} only imports files.` : 'Fill in its settings first.');
    testing.add(id);
    let r;
    try { r = await runModule(mod(id), 'test', { cfg: effective(id) }, { timeoutMs: Math.min(timeoutMs, 120000), log }); }
    finally { testing.delete(id); }
    return typeof r === 'string' ? r : r && typeof r.message === 'string' ? r.message : 'Connected.';
  }
  // Starts a run; resolves when it is finished. opts: {by, file: {name, text}, overrides}
  async function run(id, opts = {}) {
    if (!known(id)) throw new ConnectorError('Unknown connector');
    const m = mod(id);
    if (running.has(id)) throw new ConnectorError(`${m.name} is already running.`);
    if (opts.file && !m.file) throw new ConnectorError(`${m.name} does not import files.`);
    if (!opts.file && !isLive(id)) throw new ConnectorError(m.live === false ? `${m.name} only imports files.` : 'Fill in its settings first.');
    const started = new Date().toISOString();
    const fileName = opts.file ? String(opts.file.name || 'file').slice(0, 120) : null;
    const info = { startedAt: started, by: opts.by || '', file: fileName };
    running.set(id, { info });
    broadcast('connectors', { id, running: true });
    const rec = { id, at: started, by: opts.by || '', file: fileName, ok: false, summary: '', error: null, proposals: [], ms: 0 };
    const t0 = Date.now();
    try {
      const cfg = effective(id, opts.file ? fileOverrides(id, opts.overrides) : {});
      const state = JSON.parse(JSON.stringify(getState()));
      const res = await runModule(m, 'run', {
        cfg, state: m.permissions.map ? state : null,
        file: opts.file ? { name: fileName, text: String(opts.file.text) } : null,
      }, { timeoutMs, log }) || {};
      if (res.proposals !== undefined && !Array.isArray(res.proposals)) throw new Error('the module answered without a list of proposals');
      const sites = Array.isArray(cfg.sites) && cfg.sites.length ? new Set(cfg.sites) : null, rejected = [];
      for (const p of (res.proposals || []).slice(0, 500)) {
        if (!p || typeof p !== 'object' || typeof p.siteId !== 'string' || !Object.hasOwn(state.si, p.siteId)) continue;
        if (sites && !sites.has(p.siteId)) continue;
        if (!p.changes || typeof p.changes !== 'object') continue;
        const changes = ownSite(p.changes, p.siteId, state);
        dropLinkOnly(changes, state);
        let out;
        try { out = await upsertProposal({ connector: id, connectorName: m.name, by: opts.by, uploadedBy: opts.file ? opts.by : null, siteId: p.siteId, title: String(p.title || `${m.name}: ${state.si[p.siteId].name || p.siteId}`), description: String(p.description || ''), changes }); }
        catch (e) { log(`Connector ${id}: proposal for ${p.siteId} refused: ${e.message}`); rejected.push(`${state.si[p.siteId].name || p.siteId}: ${e.message}`); continue; }
        if (out) rec.proposals.push({ id: out.id, title: out.title, siteId: p.siteId, refreshed: out.refreshed, unchanged: out.unchanged });
      }
      rec.ok = true;
      rec.summary = typeof res.summary === 'string' ? res.summary.slice(0, 2000) : '';
      rec.report = res.report && typeof res.report === 'object' && JSON.stringify(res.report).length <= 64 * 1024 ? res.report : null;
      if (rejected.length) { rec.report = rec.report || {}; rec.report.warnings = [...(Array.isArray(rec.report.warnings) ? rec.report.warnings : []), ...rejected.map(x => 'Proposal refused: ' + x)].slice(0, 40); }
      if (!rec.proposals.length) rec.summary += (rec.summary ? ' ' : '') + 'The map already matches: no proposal.';
      log(`Connector ${id}: ${rec.summary}`);
    } catch (e) {
      rec.error = e instanceof ConnectorError ? e.message : `Unexpected error: ${e.message}`;
      if (!(e instanceof ConnectorError)) log('ERROR connector', id, e.stack || e.message);
      else log(`Connector ${id} failed: ${e.message}`);
    } finally {
      rec.ms = Date.now() - t0;
      running.delete(id);
      cfgOf(id).lastRun = rec;
      store.runs.unshift({ ...rec, report: undefined });
      store.runs = store.runs.slice(0, 60);
      await save();
      broadcast('connectors', { id, running: false });
    }
    return rec;
  }
  // Forgets a module's settings and secrets (when it is uninstalled)
  function forget(id) { delete store.connectors[id]; return save(); }
  // Scheduler: checks once a minute which enabled connector is due
  setInterval(() => {
    const now = Date.now();
    for (const id of MODULES.keys()) {
      const c = cfgOf(id), h = +c.settings.everyHours || 0;
      if (!c.settings.enabled || !h || running.has(id) || !isLive(id)) continue;
      const last = c.lastRun ? Date.parse(c.lastRun.at) : 0;
      if (now - last >= h * 3600000) run(id, { by: 'schedule' }).catch(() => { });
    }
  }, 60000).unref();

  return {
    ids: () => [...MODULES.keys()],
    list: () => ({ connectors: [...MODULES.keys()].map(publicView), runs: store.runs.slice(0, 30), problems }),
    get: id => (known(id) ? publicView(id) : null),
    module: id => (known(id) ? mod(id) : null),
    update, test, run, reload, forget,
    isRunning: id => running.has(id) || testing.has(id),
    exists: known,
  };
}
