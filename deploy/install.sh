#!/usr/bin/env bash
# tg-ws-proxy-server — quick installer for Debian/Ubuntu.
#
#   sudo bash deploy/install.sh
#
# Steps: venv + package install, dedicated user, config generation,
# systemd unit, enable & start. Safe to re-run (keeps existing config).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=${APP_DIR:-/opt/tg-ws-proxy-server}
CONF_DIR=${CONF_DIR:-/etc/tgws-server}
LOG_DIR=${LOG_DIR:-/var/log/tgws-server}
SERVICE_USER=${SERVICE_USER:-tgws}
FTLS_DOMAIN=${FTLS_DOMAIN:-cloudflare.com}

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo/root"; exit 1; }

echo "==> Installing dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip openssl >/dev/null

echo "==> Deploying to $APP_DIR"
mkdir -p "$APP_DIR" "$CONF_DIR" "$LOG_DIR"
rsync -a --delete \
    --exclude '.git' --exclude '.pytest_cache' --exclude '__pycache__' \
    --exclude 'tgws-server.yaml' \
    "$REPO_DIR"/ "$APP_DIR"/

echo "==> Creating service user '$SERVICE_USER'"
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"

echo "==> Python venv"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -e "$APP_DIR"

echo "==> Config"
if [ ! -f "$CONF_DIR/tgws-server.yaml" ]; then
    sudo -u "$SERVICE_USER" "$APP_DIR/.venv/bin/tgws-server" gen \
        -o "$CONF_DIR/tgws-server.yaml" \
        --secrets 2 --domain "$FTLS_DOMAIN" \
        --log-file "$LOG_DIR/proxy.log" --force
else
    echo "    existing config kept: $CONF_DIR/tgws-server.yaml"
fi

echo "==> systemd unit"
cp "$APP_DIR/deploy/systemd/tgws-server.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tgws-server

echo
echo "============================================================"
echo " Installed. Useful next commands:"
echo "   $APP_DIR/.venv/bin/tgws-server links -c $CONF_DIR/tgws-server.yaml"
echo "   $APP_DIR/.venv/bin/tgws-server doctor -c $CONF_DIR/tgws-server.yaml"
echo "   journalctl -u tgws-server -f"
echo "============================================================"
