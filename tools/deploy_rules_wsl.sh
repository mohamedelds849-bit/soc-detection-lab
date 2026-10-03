#!/usr/bin/env bash
# Deploy the lab's custom Wazuh rules into the local Wazuh manager (Ubuntu / WSL2).
# Run inside Ubuntu:  sudo bash /mnt/c/Users/VIET/cyber-portfolio/soc-detection-lab/tools/deploy_rules_wsl.sh
# Safe: backs up the current local_rules.xml, validates the config, and restores the backup on failure.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/rules/wazuh/local_rules.xml"
DST="/var/ossec/etc/rules/local_rules.xml"
BACKUP="$DST.bak.$(date +%Y%m%d-%H%M%S)"

if [[ $EUID -ne 0 ]]; then echo "Run with sudo."; exit 1; fi
[[ -f "$SRC" ]] || { echo "Rules file not found: $SRC"; exit 1; }
[[ -d /var/ossec/etc/rules ]] || { echo "Wazuh manager not installed (no /var/ossec/etc/rules)."; exit 1; }

echo "[1/4] Backup  $DST -> $BACKUP"
cp -p "$DST" "$BACKUP"

echo "[2/4] Install $SRC"
cp "$SRC" "$DST"
chown wazuh:wazuh "$DST"
chmod 660 "$DST"

echo "[3/4] Validate configuration (wazuh-analysisd -t)"
if ! /var/ossec/bin/wazuh-analysisd -t; then
  echo "!! Validation FAILED -> restoring backup, manager not restarted."
  cp -p "$BACKUP" "$DST"
  exit 2
fi

echo "[4/4] Restart wazuh-manager"
systemctl restart wazuh-manager
sleep 3
systemctl is-active --quiet wazuh-manager && echo "OK: wazuh-manager active, custom rules loaded." \
  || { echo "!! wazuh-manager not active: check  journalctl -u wazuh-manager -n 50"; exit 3; }
echo "Next: sudo /var/ossec/bin/wazuh-logtest  and follow docs/WAZUH-VALIDATION.md"
