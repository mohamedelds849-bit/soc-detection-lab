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
ready=0
for i in $(seq 1 60); do
  st="$(docker exec "$NAME" /var/ossec/bin/wazuh-control status 2>&1 || true)"
  if echo "$st" | grep -qiE "analysisd.*(is )?running"; then ready=1; break; fi
  sleep 5
done
if [[ $ready -ne 1 ]]; then
  echo "!! Manager not ready. wazuh-control status:"; echo "$st"
  echo "!! docker ps -a:"; docker ps -a
  echo "!! docker logs (last 80 lines):"; docker logs "$NAME" 2>&1 | tail -80
  exit 1
fi
docker exec "$NAME" /var/ossec/bin/wazuh-control info | head -3
echo "[3/3] Deploying lab rules"
bash "$(dirname "$0")/deploy_rules.sh"
