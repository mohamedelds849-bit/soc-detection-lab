#!/usr/bin/env bash
# Copy rules/wazuh/local_rules.xml into the running container, validate, restart. Restores backup on failure.
set -euo pipefail
NAME="wazuh-manager"; REPO="$(cd "$(dirname "$0")/.." && pwd)"
DST="/var/ossec/etc/rules/local_rules.xml"
docker exec "$NAME" cp -p "$DST" "$DST.bak"
docker cp "$REPO/rules/wazuh/local_rules.xml" "$NAME:$DST"
docker exec "$NAME" chown wazuh:wazuh "$DST"
if ! docker exec "$NAME" /var/ossec/bin/wazuh-analysisd -t; then
  echo "!! Rules invalid -> restoring backup"; docker exec "$NAME" cp -p "$DST.bak" "$DST"; exit 2
fi
docker exec "$NAME" /var/ossec/bin/wazuh-control restart >/dev/null
echo "OK: lab rules loaded. Next: bash lab/run_all.sh"
