#!/usr/bin/env bash
# ============================================================
# pritunl-portfwd — Installation Script
# Tested on: Ubuntu 20.04, 22.04, 24.04 / Debian 11, 12
# Must be run as root.
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

INSTALL_DIR="/opt/pritunl-portfwd"
CONFIG_DIR="/etc/pritunl-portfwd"
LOG_DIR="/var/log"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_USER="portfwd"

# ── Root check ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "This script must be run as root. Try: sudo bash install.sh"
fi

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Pritunl Port Forward Manager — Installer   ${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Detect OS ──────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
  PKG_MGR="apt-get"
elif command -v dnf &>/dev/null; then
  PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
  PKG_MGR="yum"
else
  err "Unsupported package manager. Install manually."
fi

# ── Dependencies ───────────────────────────────────────────
log "Installing system dependencies…"
if [[ $PKG_MGR == "apt-get" ]]; then
  apt-get update -qq
  apt-get install -y -qq python3 python3-pip python3-venv iptables iptables-persistent || \
    apt-get install -y -qq python3 python3-pip python3-venv iptables
else
  $PKG_MGR install -y python3 python3-pip iptables
fi

# ── Create service user ────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
  log "Creating system user '$SERVICE_USER'…"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
  info "User '$SERVICE_USER' already exists."
fi

# ── Directories ────────────────────────────────────────────
log "Creating directories…"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# ── Copy files ─────────────────────────────────────────────
log "Installing application files to $INSTALL_DIR…"
# install.sh lives in <repo>/scripts/, app.py/daemon.py/templates live in <repo>/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ ! -f "$REPO_ROOT/app.py" ]] || [[ ! -f "$REPO_ROOT/common.py" ]]; then
  err "Could not find app.py/common.py at $REPO_ROOT — run this script from inside the cloned repo (e.g. 'sudo bash scripts/install.sh')"
fi

cp -r "$REPO_ROOT"/app.py "$REPO_ROOT"/daemon.py "$REPO_ROOT"/common.py "$REPO_ROOT"/templates "$INSTALL_DIR"/

# ── Python venv ────────────────────────────────────────────
log "Creating Python virtual environment…"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet flask pymongo

# ── Config dir ownership ───────────────────────────────────
chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR"
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# ── Default config ─────────────────────────────────────────
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
  echo '{}' > "$CONFIG_DIR/config.json"
  chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/config.json"
fi

if [[ ! -f "$CONFIG_DIR/rules.json" ]]; then
  echo '[]' > "$CONFIG_DIR/rules.json"
  chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/rules.json"
fi

# ── Log file permissions ───────────────────────────────────
touch "$LOG_DIR/pritunl-portfwd.log" "$LOG_DIR/pritunl-portfwd-daemon.log"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR/pritunl-portfwd.log"
chown root:root "$LOG_DIR/pritunl-portfwd-daemon.log"

# ── systemd: Web UI service ────────────────────────────────
log "Installing systemd service: pritunl-portfwd-ui…"
cat > /etc/systemd/system/pritunl-portfwd-ui.service <<EOF
[Unit]
Description=Pritunl Port Forward Manager – Web UI
After=network.target pritunl.service
Wants=pritunl.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/pritunl-portfwd.log
StandardError=append:$LOG_DIR/pritunl-portfwd.log

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$CONFIG_DIR $LOG_DIR
EnvironmentFile=-$CONFIG_DIR/env

[Install]
WantedBy=multi-user.target
EOF

# ── systemd: Daemon service ────────────────────────────────
log "Installing systemd service: pritunl-portfwd-daemon…"
cat > /etc/systemd/system/pritunl-portfwd-daemon.service <<EOF
[Unit]
Description=Pritunl Port Forward Manager – iptables Daemon
After=network.target pritunl.service
Wants=pritunl.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/daemon.py
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/pritunl-portfwd-daemon.log
StandardError=append:$LOG_DIR/pritunl-portfwd-daemon.log
EnvironmentFile=-$CONFIG_DIR/env

[Install]
WantedBy=multi-user.target
EOF

# ── env file ───────────────────────────────────────────────
if [[ ! -f "$CONFIG_DIR/env" ]]; then
  cat > "$CONFIG_DIR/env" <<EOF
# pritunl-portfwd environment config
# Edit as needed, then restart both services.

RULES_FILE=$CONFIG_DIR/rules.json
STATUS_FILE=$CONFIG_DIR/status.json
CONFIG_FILE=$CONFIG_DIR/config.json
MONGO_URI=mongodb://localhost:27017/
MONGO_DB=pritunl
LISTEN_HOST=127.0.0.1
LISTEN_PORT=8181
POLL_SECS=10
# How often (in poll cycles) to refresh StrongSwan/IPsec tunnel status.
# Each swanctl/ipsec call spawns a subprocess, so this is checked less
# often than the main sync loop. Only relevant if you use IPsec-type rules.
IPSEC_POLL_EVERY=3
EOF
  chown root:root "$CONFIG_DIR/env"
  chmod 640 "$CONFIG_DIR/env"
fi

# ── Enable and start ───────────────────────────────────────
log "Enabling and starting services…"
systemctl daemon-reload
systemctl enable pritunl-portfwd-ui pritunl-portfwd-daemon
systemctl restart pritunl-portfwd-ui pritunl-portfwd-daemon

# ── Status check ───────────────────────────────────────────
sleep 2
UI_STATUS=$(systemctl is-active pritunl-portfwd-ui 2>/dev/null || echo "failed")
DM_STATUS=$(systemctl is-active pritunl-portfwd-daemon 2>/dev/null || echo "failed")

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Installation Complete${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Web UI service  : $([ "$UI_STATUS" == "active" ] && echo "${GREEN}running${NC}" || echo "${RED}$UI_STATUS${NC}")"
echo -e "  Daemon service  : $([ "$DM_STATUS" == "active" ] && echo "${GREEN}running${NC}" || echo "${RED}$DM_STATUS${NC}")"
echo ""
echo -e "  Web UI URL      : ${BOLD}http://127.0.0.1:8181${NC}"
echo -e "  Config dir      : $CONFIG_DIR"
echo -e "  Logs            : $LOG_DIR/pritunl-portfwd*.log"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo -e "  1. Visit the Web UI to set your admin password."
echo -e "  2. (Recommended) Set up nginx reverse proxy — see docs/nginx.md"
echo -e "  3. Ensure IP forwarding is enabled:"
echo -e "     ${BOLD}echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p${NC}"
echo ""
