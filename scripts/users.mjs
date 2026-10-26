// SPDX-License-Identifier: AGPL-3.0-or-later
// Manage Strata accounts from the command line (works while the server runs).
//   node scripts/users.mjs list
//   node scripts/users.mjs set <name> <viewer|contributor|approver|admin>   (asks for a password, or NEW_PASSWORD=... or NEW_PASSWORD_FILE=...)
//   node scripts/users.mjs role <name> <role>
//   node scripts/users.mjs disable <name> | enable <name> | delete <name>
// With Docker: docker compose exec strata node scripts/users.mjs list
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILE = path.join(path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data')), 'users.json');
const ROLES = ['viewer', 'contributor', 'approver', 'admin'];
// Same rule as the server's USER_RE: account names become object keys, so the names that reach Object.prototype are refused
const USER_RE = /^(?!(?:__proto__|constructor|prototype)$)[A-Za-z0-9_.@-]{1,64}$/;
const load = () => { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')).users || {}; } catch { return {}; } };
const save = u => { fs.mkdirSync(path.dirname(FILE), { recursive: true }); fs.writeFileSync(FILE + '.tmp', JSON.stringify({ users: u }, null, 2), { mode: 0o600 }); fs.renameSync(FILE + '.tmp', FILE); };
const die = m => { console.error(m); process.exit(1); };
async function askPassword() {
  if (process.env.NEW_PASSWORD_FILE) { try { return fs.readFileSync(process.env.NEW_PASSWORD_FILE, 'utf8').replace(/\r?\n$/, ''); } catch (e) { die(`NEW_PASSWORD_FILE: ${e.message}`); } }
  if (process.env.NEW_PASSWORD) return process.env.NEW_PASSWORD;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  rl._writeToOutput = s => { if (/password/i.test(s)) process.stdout.write(s); };
  const p = await new Promise(r => rl.question('New password (10 characters or more): ', r)); rl.close(); process.stdout.write('\n');
  return p;
}
const [cmd, name, role] = process.argv.slice(2);
const users = load();
if (!cmd || cmd === 'list') {
  const rows = Object.entries(users).map(([n, u]) => `${n.padEnd(24)} ${String(u.role).padEnd(12)} ${u.disabled ? 'disabled' : 'active'}`);
  console.log(rows.length ? rows.join('\n') : `No account yet (${FILE}).`);
} else if (cmd === 'set') {
  if (!name || !USER_RE.test(name)) die('Give a name (letters, digits, . _ - @; not __proto__, constructor or prototype).');
  if (!ROLES.includes(role)) die(`Role must be one of: ${ROLES.join(', ')}`);
  const pass = await askPassword();
  if (String(pass).length < 10) die('Use at least 10 characters.');
  const salt = crypto.randomBytes(16).toString('hex');
  users[name] = Object.assign((Object.hasOwn(users, name) && users[name]) || { createdAt: new Date().toISOString() }, { role, salt, hash: crypto.scryptSync(pass, salt, 32).toString('hex'), disabled: false, passwordChangedAt: new Date().toISOString() });
  save(users); console.log(`Account ${name} saved (${role}).`);
} else if (['role', 'disable', 'enable', 'delete'].includes(cmd)) {
  if (!name || !Object.hasOwn(users, name)) die(`No account named ${name}.`);
  if (cmd === 'role') { if (!ROLES.includes(role)) die(`Role must be one of: ${ROLES.join(', ')}`); users[name].role = role; }
  if (cmd === 'disable') users[name].disabled = true;
  if (cmd === 'enable') users[name].disabled = false;
  if (cmd === 'delete') delete users[name];
  save(users); console.log('Done.');
} else die('Unknown command. Use: list | set | role | disable | enable | delete');
