#!/usr/bin/env bash
# pritunl-portfwd — Uninstall Script
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Must be run as root.${NC}"; exit 1
fi

echo ""
echo -e "${BOLD}Pritunl Port Forward Manager — Uninstall${NC}"
echo ""
read -rp "This will remove all services and application files. Continue? [y/N] " confirm
[[ "${confirm,,}" != "y" ]] && echo "Cancelled." && exit 0

echo -e "${GREEN}[+]${NC} Stopping and disabling services…"
systemctl stop  pritunl-portfwd-ui pritunl-portfwd-daemon 2>/dev/null || true
systemctl disable pritunl-portfwd-ui pritunl-portfwd-daemon 2>/dev/null || true

echo -e "${GREEN}[+]${NC} Flushing iptables rules…"
python3 /opt/pritunl-portfwd/daemon.py --flush 2>/dev/null || true

echo -e "${GREEN}[+]${NC} Removing files…"
rm -f /etc/systemd/system/pritunl-portfwd-ui.service
rm -f /etc/systemd/system/pritunl-portfwd-daemon.service
rm -rf /opt/pritunl-portfwd
systemctl daemon-reload

read -rp "Remove config and rules from /etc/pritunl-portfwd? [y/N] " rmcfg
if [[ "${rmcfg,,}" == "y" ]]; then
  rm -rf /etc/pritunl-portfwd
  echo -e "${GREEN}[+]${NC} Config removed."
else
  echo -e "${YELLOW}[!]${NC} Config retained at /etc/pritunl-portfwd"
fi

echo ""
echo -e "${BOLD}Uninstall complete.${NC}"
