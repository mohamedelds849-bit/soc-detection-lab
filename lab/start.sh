#!/usr/bin/env bash
# Start a Wazuh manager (4.9.2) in Docker and load the lab rules. Run from the repo root in Codespaces:
#   bash lab/start.sh
set -euo pipefail
IMG="wazuh/wazuh-manager:4.9.2"; NAME="wazuh-manager"
if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "[1/3] Pulling and starting $IMG (first time: a few minutes)"
  docker run -d --name "$NAME" --hostname "$NAME" "$IMG" >/dev/null
fi
echo "[2/3] Waiting for wazuh-analysisd ..."
for i in $(seq 1 60); do
  if docker exec "$NAME" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"; then break; fi
  sleep 5
  [[ $i -eq 60 ]] && { echo "Manager did not start: docker logs $NAME | tail -50"; exit 1; }
done
docker exec "$NAME" /var/ossec/bin/wazuh-control info | head -3
echo "[3/3] Deploying lab rules"
bash "$(dirname "$0")/deploy_rules.sh"
