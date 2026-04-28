#!/usr/bin/env bash
# PMT-DFC VPS tunnel-node installer.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/easyfast2008/PMT-DFC/main/deploy/install-vps.sh | bash -s -- <auth_key>
#
# Or manually:
#   bash deploy/install-vps.sh <auth_key> [port]
#
# This script:
#   1. Downloads the latest pmt-server binary (or builds from source if Go is available).
#   2. Creates a systemd service that runs pmt-server on the specified port.
#   3. Opens the port in ufw/firewalld if detected.
#
# Requirements: Linux, root/sudo, curl or wget.
set -euo pipefail

AUTH_KEY="${1:-}"
PORT="${2:-8080}"

if [ -z "$AUTH_KEY" ] || [ ${#AUTH_KEY} -lt 16 ]; then
  echo "Usage: $0 <auth_key> [port]"
  echo "  auth_key must be at least 16 characters."
  exit 1
fi

INSTALL_DIR="/opt/pmt-dfc"
BIN="$INSTALL_DIR/pmt-server"
SERVICE="pmt-server"

echo "==> Installing PMT-DFC tunnel-node"
echo "    Port:     $PORT"
echo "    Install:  $INSTALL_DIR"

# Create install directory.
sudo mkdir -p "$INSTALL_DIR"

# Try to download prebuilt binary; fall back to building from source.
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  GOARCH="amd64" ;;
  aarch64) GOARCH="arm64" ;;
  *)       GOARCH="" ;;
esac

built=false
if command -v go &>/dev/null; then
  echo "==> Go found, building from source..."
  TMPDIR=$(mktemp -d)
  git clone --depth 1 https://github.com/easyfast2008/PMT-DFC.git "$TMPDIR/src" 2>/dev/null || true
  if [ -d "$TMPDIR/src" ]; then
    cd "$TMPDIR/src"
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/server
    built=true
    cd /
    rm -rf "$TMPDIR"
  fi
fi

if [ "$built" = false ]; then
  echo "==> Go not found. Please build pmt-server manually and copy to $BIN"
  echo "    On a build machine: go build -o pmt-server ./cmd/server"
  echo "    Then: scp pmt-server root@this-vps:$BIN"
  exit 1
fi

sudo chmod +x "$BIN"

# Create systemd service.
sudo tee /etc/systemd/system/${SERVICE}.service > /dev/null <<EOF
[Unit]
Description=PMT-DFC Tunnel Node
After=network.target

[Service]
Type=simple
Environment=PMT_AUTH_KEY=${AUTH_KEY}
Environment=PORT=${PORT}
ExecStart=${BIN}
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE"
sudo systemctl restart "$SERVICE"

# Open firewall port if ufw or firewalld is active.
if command -v ufw &>/dev/null && sudo ufw status | grep -q "active"; then
  sudo ufw allow "$PORT/tcp" || true
  echo "==> Opened port $PORT in ufw"
fi
if command -v firewall-cmd &>/dev/null && sudo firewall-cmd --state 2>/dev/null | grep -q "running"; then
  sudo firewall-cmd --permanent --add-port="${PORT}/tcp" || true
  sudo firewall-cmd --reload || true
  echo "==> Opened port $PORT in firewalld"
fi

echo ""
echo "==> PMT-DFC tunnel-node installed and running!"
echo "    Status:  sudo systemctl status $SERVICE"
echo "    Logs:    sudo journalctl -u $SERVICE -f"
echo "    Port:    $PORT"
echo ""
echo "Next steps:"
echo "  1. Deploy the Apps Script relay (see relay/apps-script/Code.gs)"
echo "     Set TUNNEL_SERVER_URL = \"http://$(curl -s ifconfig.me):${PORT}\""
echo "  2. OR deploy the Cloudflare Worker relay (see relay/cloudflare-worker/)"
echo "  3. Configure your client with the relay details and auth_key."
