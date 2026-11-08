#!/usr/bin/env bash
exec bash -c "$(tr -d '\r' < "$0" | tail -n +3)" "$0" #
set -Eeuo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; BLD=$'\033[1m'; RST=$'\033[0m'
log(){ printf '%s[*]%s %s\n' "$CYN" "$RST" "$*"; }
ok(){  printf '%s[+]%s %s\n' "$GRN" "$RST" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$YLW" "$RST" "$*"; }
die(){ printf '%s[x]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
trap 'die "installer failed at line $LINENO"' ERR

[[ $EUID -eq 0 ]] || die "run as root: sudo bash $0"
[[ -f /etc/os-release ]] || die "not Ubuntu/Debian"
. /etc/os-release
case "$ID" in ubuntu|debian) ok "OS: $PRETTY_NAME";; *) die "unsupported: $ID";; esac

# ------------------------------------------------------------------
# Repo URL
# ------------------------------------------------------------------
REPO_URL="https://github.com/spideragentai/Panel-.git"

echo
echo "${BLD}=== PRIV L7 HUB — installer ===${RST}"
echo

read -rp "Domain (e.g. tr.dellix.ir): " DOMAIN
[[ -n "$DOMAIN" ]] || die "domain required"
read -rp "Email for Let's Encrypt (blank to skip SSL): " LE_EMAIL || true
read -rp "Admin username [root]: " ADMIN_USER || true
ADMIN_USER="${ADMIN_USER:-root}"
while :; do
  read -rsp "Admin password (min 3 chars): " ADMIN_PASS; echo
  [[ "${#ADMIN_PASS}" -ge 3 ]] && break
  warn "min 3 chars"
done

# ------------------------------------------------------------------
# Telegram bot setup — validate token BEFORE writing hub.env
# ------------------------------------------------------------------
BOT_TOKEN=""
MINI_APP_URL=""
while :; do
  read -rp "Telegram bot token (blank to skip): " BOT_TOKEN || true
  BOT_TOKEN="${BOT_TOKEN:-}"
  [[ -z "$BOT_TOKEN" ]] && break

  log "validating Telegram bot token..."
  TG_RESP="$(curl -s --max-time 8 "https://api.telegram.org/bot$BOT_TOKEN/getMe" || true)"
  if echo "$TG_RESP" | grep -q '"ok":true'; then
    TG_USER="$(echo "$TG_RESP" | jq -r '.result.username // "unknown"' 2>/dev/null || echo unknown)"
    ok "bot token valid — @$TG_USER"
    break
  else
    warn "bot token rejected by Telegram — try again, or press Enter to skip."
    warn "response: $(echo "$TG_RESP" | head -c 160)"
    BOT_TOKEN=""
  fi
done

# Always ask for Mini App URL if we have a domain (so admin can fix it later)
if [[ -n "$BOT_TOKEN" ]]; then
  read -rp "Mini App URL [https://$DOMAIN]: " MINI_APP_URL || true
  MINI_APP_URL="${MINI_APP_URL:-https://$DOMAIN}"
else
  # still remember the default so a later manual edit is easy
  MINI_APP_URL=""
fi

echo
echo "Cloudflare mode: orange / gray / none"
read -rp "Mode [orange]: " CF_MODE || true
CF_MODE="${CF_MODE:-orange}"
case "$CF_MODE" in orange|gray|none) ;; *) CF_MODE="orange";; esac
echo
log "Detecting public IP..."
PUB_IP="$(curl -s --max-time 5 https://api.ipify.org || true)"
if ! [[ "$PUB_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  PUB_IP="$(curl -s --max-time 5 https://ifconfig.me || true)"
fi
[[ -n "$PUB_IP" ]] || PUB_IP="0.0.0.0"
ok "public IP: $PUB_IP"

CFG_DIR="/etc/privhub"
mkdir -p "$CFG_DIR"; chmod 700 "$CFG_DIR"
PATH_FILE="$CFG_DIR/install.path"
if [[ -f "$PATH_FILE" ]] && [[ -d "$(cat "$PATH_FILE")" ]]; then
  PROJECT_DIR="$(cat "$PATH_FILE")"
  ok "reusing $PROJECT_DIR"
else
  PROJECT_DIR="/root/privhub-$(openssl rand -hex 4)"
  mkdir -p "$PROJECT_DIR"; chmod 700 "$PROJECT_DIR"
  echo "$PROJECT_DIR" > "$PATH_FILE"; chmod 600 "$PATH_FILE"
  ok "created $PROJECT_DIR"
fi
HUB_FILE="$PROJECT_DIR/hub.js"

log "apt update..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

log "installing packages..."
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release apt-transport-https \
  git jq openssl rsync build-essential \
  nginx certbot python3-certbot-nginx ufw

if [[ ! -f /etc/nginx/nginx.conf ]]; then
  warn "/etc/nginx/nginx.conf missing — reinstalling"
  apt-get install --reinstall -o Dpkg::Options::="--force-confmiss" -y nginx-common nginx
fi
[[ -f /etc/nginx/nginx.conf ]] || die "cannot restore nginx.conf"

NEED_NODE=0
if ! command -v node >/dev/null 2>&1; then NEED_NODE=1
else
  NODE_MAJ="$(node -v 2>/dev/null | sed 's/^v//;s/\..*//' || echo 0)"
  [[ "$NODE_MAJ" -lt 20 ]] && NEED_NODE=1
fi
if [[ "$NEED_NODE" -eq 1 ]]; then
  log "installing Node.js 20..."
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq
  apt-get install -y -qq nodejs
fi
ok "node $(node -v)"

# ------------------------------------------------------------------
# Clone (never prompt for credentials)
# ------------------------------------------------------------------
cd "$PROJECT_DIR"
if [[ -d "$PROJECT_DIR/.git" ]]; then
  log "pulling repo..."
  GIT_TERMINAL_PROMPT=0 git -C "$PROJECT_DIR" fetch --quiet --depth 1 origin || warn "fetch failed"
  GIT_TERMINAL_PROMPT=0 git -C "$PROJECT_DIR" reset --hard --quiet origin/HEAD 2>/dev/null || true
else
  log "cloning $REPO_URL ..."
  if GIT_TERMINAL_PROMPT=0 git clone --depth 1 \
       -c credential.helper= \
       -c core.askPass=true \
       "$REPO_URL" "$PROJECT_DIR.tmp"
  then
    shopt -s dotglob nullglob
    mv "$PROJECT_DIR.tmp/"* "$PROJECT_DIR/" 2>/dev/null || true
    shopt -u dotglob nullglob
    rm -rf "$PROJECT_DIR.tmp"
    ok "cloned"
  else
    warn "clone failed — place hub.js manually in $PROJECT_DIR"
  fi
fi

if [[ ! -f "$HUB_FILE" ]]; then
  FOUND="$(find "$PROJECT_DIR" -maxdepth 4 -type f -name 'hub.js' 2>/dev/null | head -n1)"
  if [[ -n "$FOUND" ]]; then
    mv "$FOUND" "$HUB_FILE"
    for f in priv.js bypass.js l.js proxy.txt iran.txt; do
      src="$(find "$PROJECT_DIR" -maxdepth 4 -type f -name "$f" 2>/dev/null | head -n1)"
      if [[ -n "$src" && "$src" != "$PROJECT_DIR/$f" ]]; then
        mv "$src" "$PROJECT_DIR/$f"
      fi
    done
    ok "located hub.js (moved to $HUB_FILE)"
  fi
fi
[[ -f "$HUB_FILE" ]] || die "hub.js missing at $HUB_FILE"

for f in priv.js bypass.js l.js; do
  [[ -f "$PROJECT_DIR/$f" ]] && ok "$f present" || warn "$f missing"
done
for f in proxy.txt iran.txt; do
  [[ -f "$PROJECT_DIR/$f" ]] && ok "$f present" || warn "$f missing"
done

# ------------------------------------------------------------------
# npm deps — bare names, no version pins, installed into $PROJECT_DIR.
# ------------------------------------------------------------------
log "installing npm deps into $PROJECT_DIR ..."
(
  cd "$PROJECT_DIR"
  npm install --no-audit --no-fund --no-package-lock --prefix "$PROJECT_DIR" \
    express express-session express-rate-limit helmet bcryptjs \
    node-telegram-bot-api axios colors hpack node-bash-title
) || die "npm install failed"

REQUIRED_MODULES=(express express-session express-rate-limit helmet bcryptjs node-telegram-bot-api axios colors hpack node-bash-title)
for m in "${REQUIRED_MODULES[@]}"; do
  [[ -d "$PROJECT_DIR/node_modules/$m" ]] || die "module missing after install: $m"
done
ok "npm deps installed in $PROJECT_DIR/node_modules"

# ------------------------------------------------------------------
# ufw
# ------------------------------------------------------------------
log "configuring ufw..."
ufw --force default deny incoming  >/dev/null
ufw --force default allow outgoing >/dev/null
ufw allow 22/tcp  >/dev/null
ufw allow 80/tcp  >/dev/null
ufw allow 443/tcp >/dev/null

if [[ "$CF_MODE" == "orange" ]]; then
  log "restricting 80/443 to Cloudflare..."
  ufw --force delete allow 80/tcp  >/dev/null 2>&1 || true
  ufw --force delete allow 443/tcp >/dev/null 2>&1 || true
  CF_RANGES=(
    173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
    141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
    197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
    104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
  )
  for r in "${CF_RANGES[@]}"; do
    ufw allow from "$r" to any port 80 proto tcp  >/dev/null
    ufw allow from "$r" to any port 443 proto tcp >/dev/null
  done
fi

ufw --force enable >/dev/null
ok "ufw: $(ufw status | head -1 | awk '{print $2}')"

# ------------------------------------------------------------------
# certbot
# ------------------------------------------------------------------
CERT_PATH=""; KEY_PATH=""
if [[ -n "$LE_EMAIL" ]]; then
  log "obtaining SSL for $DOMAIN..."
  systemctl stop nginx 2>/dev/null || true
  if certbot certonly --standalone --non-interactive --agree-tos --email "$LE_EMAIL" -d "$DOMAIN" --keep-until-expiring; then
    CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    ok "cert: $CERT_PATH"
  else
    warn "certbot failed — continuing without SSL"
  fi
fi

# ------------------------------------------------------------------
# config
# ------------------------------------------------------------------
log "writing /etc/privhub/config.json..."
CFG_FILE="$CFG_DIR/config.json"
ENV_FILE="$CFG_DIR/hub.env"

if ! (cd "$PROJECT_DIR" && node -e "require('bcryptjs'); process.exit(0)" >/dev/null 2>&1); then
  die "bcryptjs not usable from $PROJECT_DIR"
fi
ADMIN_HASH="$(cd "$PROJECT_DIR" && node -e "const b=require('bcryptjs');b.hash(process.argv[1],12).then(h=>process.stdout.write(h));" "$ADMIN_PASS")"
[[ -n "$ADMIN_HASH" ]] || die "hash failed"
SESSION_SECRET="$(openssl rand -hex 32)"
cookie_secure=false
[[ -n "$CERT_PATH" ]] && cookie_secure=true
[[ "$CF_MODE" == "orange" ]] && cookie_secure=true
CF_REAL_IP_TRUSTED=false
[[ "$CF_MODE" == "orange" ]] && CF_REAL_IP_TRUSTED=true

jq -n \
  --arg host "127.0.0.1" --argjson port 3000 \
  --arg domain "$DOMAIN" --arg email "$LE_EMAIL" \
  --arg botToken "$BOT_TOKEN" --arg miniAppUrl "$MINI_APP_URL" \
  --arg adminUsername "$ADMIN_USER" --arg adminPasswordHash "$ADMIN_HASH" \
  --arg sessionSecret "$SESSION_SECRET" --argjson cookieSecure "$cookie_secure" \
  --arg cfMode "$CF_MODE" --argjson cfRealIpTrusted "$CF_REAL_IP_TRUSTED" \
  --arg sslCertPath "$CERT_PATH" --arg sslKeyPath "$KEY_PATH" \
  --arg serverPublicIp "$PUB_IP" \
  '{createdAt:(now|todate),host:$host,port:$port,domain:$domain,email:$email,botToken:$botToken,miniAppUrl:$miniAppUrl,adminUsername:$adminUsername,adminPasswordHash:$adminPasswordHash,sessionSecret:$sessionSecret,cookieSecure:$cookieSecure,cfMode:$cfMode,cfRealIpTrusted:$cfRealIpTrusted,sslCertPath:$sslCertPath,sslKeyPath:$sslKeyPath,serverPublicIp:$serverPublicIp}' > "$CFG_FILE"
chmod 600 "$CFG_FILE"

cat > "$ENV_FILE" <<ENV
SESSION_SECRET=$SESSION_SECRET
ADMIN_USERNAME=$ADMIN_USER
ADMIN_PASSWORD_HASH=$ADMIN_HASH
BOT_TOKEN=$BOT_TOKEN
MINI_APP_URL=$MINI_APP_URL
HUB_HOST=127.0.0.1
PORT=3000
HUB_DOMAIN=$DOMAIN
CF_MODE=$CF_MODE
HUB_EMAIL=$LE_EMAIL
HUB_SSL_CERT=$CERT_PATH
HUB_SSL_KEY=$KEY_PATH
HUB_PUBLIC_IP=$PUB_IP
ENV
chmod 600 "$ENV_FILE"
ok "config written"

# ------------------------------------------------------------------
# nginx site
# ------------------------------------------------------------------
log "writing site config..."
NGINX_VER="$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9.]*\).*#\1#p')"
HTTP2_STYLE="none"
if [[ -n "$NGINX_VER" ]]; then
  MAJ="${NGINX_VER%%.*}"; rest="${NGINX_VER#*.}"; MIN="${rest%%.*}"
  if (( MAJ > 1 )) || { (( MAJ == 1 )) && (( MIN >= 25 )); }; then HTTP2_STYLE="modern"
  elif (( MAJ == 1 )) && (( MIN >= 9 )); then HTTP2_STYLE="legacy"; fi
fi

CF_REAL_IP=""
if [[ "$CF_MODE" == "orange" ]]; then
  CF_REAL_IP="$(cat <<'CFIP'
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    real_ip_header CF-Connecting-IP;
    real_ip_recursive on;
CFIP
)"
fi

LISTEN_443=""
TLS_BLOCK=""
if [[ -n "$CERT_PATH" ]]; then
  case "$HTTP2_STYLE" in
    modern) LISTEN_443=$'    listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;';;
    legacy) LISTEN_443=$'    listen 443 ssl http2;\n    listen [::]:443 ssl http2;';;
    *) LISTEN_443=$'    listen 443 ssl;\n    listen [::]:443 ssl;';;
  esac
  TLS_BLOCK="$(cat <<TLSEOF
$LISTEN_443
    ssl_certificate     $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
$CF_REAL_IP
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
TLSEOF
)"
fi

PLAIN_BLOCK="$(cat <<'PLAIN'
    client_max_body_size 64k;

    location /api/ {
        proxy_pass http://privhub_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
    }

    location / {
        proxy_pass http://privhub_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
    }
PLAIN
)"

PORT80_BODY="$PLAIN_BLOCK"
[[ -n "$CERT_PATH" ]] && PORT80_BODY='    return 301 https://$host$request_uri;'

TLS_SERVER=""
if [[ -n "$CERT_PATH" ]]; then
  TLS_SERVER="$(cat <<TLSERVER

server {
$TLS_BLOCK
    client_max_body_size 64k;

    location = /favicon.ico { access_log off; return 204; }
    location = /robots.txt  { access_log off; return 200 "User-agent: *\nDisallow: /\n"; add_header Content-Type text/plain; }

    location /api/ {
        proxy_pass http://privhub_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
    }

    location / {
        proxy_pass http://privhub_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
    }
}
TLSERVER
)"
fi

cat > /etc/nginx/sites-available/privhub.conf <<NGINX
upstream privhub_backend {
    server 127.0.0.1:3000;
    keepalive 64;
    keepalive_requests 500;
    keepalive_timeout 30s;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN _;

$PORT80_BODY
}
$TLS_SERVER
NGINX

ln -sf /etc/nginx/sites-available/privhub.conf /etc/nginx/sites-enabled/privhub.conf
rm -f /etc/nginx/sites-enabled/default

if ! nginx -t 2>&1 | tee /tmp/ngx-test.log | grep -q 'test is successful'; then
  cat /tmp/ngx-test.log >&2
  die "nginx site config invalid"
fi
ok "nginx site valid"

# ------------------------------------------------------------------
# systemd unit
# ------------------------------------------------------------------
log "writing systemd unit..."
NODE_BIN="$(command -v node)"
cat > /etc/systemd/system/privhub.service <<UNIT
[Unit]
Description=PrivHub L7 Hub
After=network-online.target nginx.service
Wants=nginx.service

[Service]
Type=simple
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$ENV_FILE
ExecStart=$NODE_BIN $HUB_FILE
Restart=always
RestartSec=3
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=10
Environment=NODE_ENV=production
Environment=UV_THREADPOOL_SIZE=64

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable privhub >/dev/null
ok "systemd installed"

# ------------------------------------------------------------------
# start
# ------------------------------------------------------------------
free_ports(){
  local pids
  pids="$(ss -ltnp 2>/dev/null | awk '/:80 |:443 |:3000 / {print $NF}' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"
  [[ -z "$pids" ]] && return 0
  for pid in $pids; do
    local comm; comm="$(ps -p "$pid" -o comm= 2>/dev/null || true)"
    [[ "$comm" == "nginx" ]] && continue
    warn "port held by pid=$pid ($comm) — killing"
    kill -9 "$pid" 2>/dev/null || true
  done
  sleep 1
}
free_ports || true

log "starting nginx..."
systemctl enable nginx >/dev/null 2>&1 || true
systemctl reset-failed nginx 2>/dev/null || true
NGINX_OK=0
for i in 1 2 3; do
  if systemctl restart nginx 2>/dev/null; then sleep 1; systemctl is-active --quiet nginx && { NGINX_OK=1; break; }; fi
  warn "nginx attempt $i failed — cleaning"
  systemctl stop nginx 2>/dev/null || true
  pkill -9 nginx 2>/dev/null || true
  sleep 1
  free_ports || true
done
[[ "$NGINX_OK" -eq 1 ]] || { journalctl -u nginx -n 40 --no-pager >&2 || true; die "nginx failed to start"; }
ok "nginx: $(systemctl is-active nginx)"

log "starting privhub..."
systemctl reset-failed privhub 2>/dev/null || true
systemctl restart privhub || true
sleep 3
systemctl is-active --quiet privhub || { journalctl -u privhub -n 40 --no-pager >&2 || true; die "privhub failed"; }
ok "privhub: $(systemctl is-active privhub)"

# ------------------------------------------------------------------
# self test
# ------------------------------------------------------------------
echo
log "self test..."
sleep 1
HUB_CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/health || echo 000)"
NGX_HTTP="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" http://127.0.0.1/ || echo 000)"
NGX_HTTPS="(no TLS)"
[[ -n "$CERT_PATH" ]] && NGX_HTTPS="$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" https://127.0.0.1/api/health || echo 000)"
LISTEN="$(ss -ltnp 2>/dev/null | grep -E ':80|:443|:3000' | awk '{print $4}' | sort -u | tr '\n' ' ')"
echo
echo "${BLD}=== SELF-TEST ===${RST}"
printf '  hub  /api/health : %s\n' "$HUB_CODE"
printf '  nginx http       : %s\n' "$NGX_HTTP"
printf '  nginx https      : %s\n' "$NGX_HTTPS"
printf '  listeners        : %s\n' "$LISTEN"
echo
echo "${GRN}${BLD}=========================${RST}"
echo "${GRN}${BLD} PRIV L7 HUB — READY${RST}"
echo "${GRN}${BLD}=========================${RST}"
echo
echo "  Domain  : https://$DOMAIN"
echo "  Public  : http://$PUB_IP"
echo "  Admin   : $ADMIN_USER"
echo "  Project : $PROJECT_DIR"
echo "  Bot     : ${BOT_TOKEN:+enabled (Mini App: $MINI_APP_URL)}${BOT_TOKEN:-disabled}"
echo "  Service : sudo systemctl {status|restart} privhub"
echo "  Logs    : sudo journalctl -u privhub -f"
echo
if [[ "$CF_MODE" == "orange" ]]; then
  echo "  ${YLW}CF mode = orange — set DNS in Cloudflare to proxied${RST}"
elif [[ "$CF_MODE" == "gray" ]]; then
  echo "  ${YLW}CF mode = gray — DNS A record for $DOMAIN → $PUB_IP, DNS-only${RST}"
fi
if [[ -n "$BOT_TOKEN" ]]; then
  echo
  echo "  ${YLW}IMPORTANT: Register the Mini App URL in BotFather:${RST}"
  echo "    /newapp  →  pick your bot  →  Web App URL: $MINI_APP_URL"
  echo "    Without this step the Open Hub button will silently fail."
fi
echo
echo "  Open https://$DOMAIN and sign in as $ADMIN_USER"
echo
