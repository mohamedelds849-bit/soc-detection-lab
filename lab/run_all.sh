#!/usr/bin/env bash
# Replay every datasets/wazuh_logtest/*.log through wazuh-logtest (one session per file, so correlation works)
# and save the full output in lab/results/. Prints, per file, which rule IDs fired.
# Compare with the "expected" column of docs/WAZUH-VALIDATION.md and fill in OK / KO.
set -uo pipefail
NAME="wazuh-manager"; REPO="$(cd "$(dirname "$0")/.." && pwd)"; OUT="$REPO/lab/results"
mkdir -p "$OUT"
bash "$REPO/lab/windows_mode.sh" on >/dev/null
printf "%-58s %s\n" "FILE" "RULE IDs FIRED (custom 1001xx in last position = your rule)"
for f in "$REPO"/datasets/wazuh_logtest/*.log; do
  n="$(basename "$f" .log)"
  docker exec -i "$NAME" /var/ossec/bin/wazuh-logtest < "$f" > "$OUT/$n.txt" 2>&1
  ids="$(grep -oE "id: '[0-9]+'" "$OUT/$n.txt" | grep -oE "[0-9]+" | tr '\n' ' ')"
  printf "%-58s %s\n" "$n" "${ids:-<none>}"
done
bash "$REPO/lab/windows_mode.sh" off >/dev/null
echo; echo "Full outputs: lab/results/*.txt  (screenshot the terminal for docs/screenshots/)"
echo; echo "=== Automatic check against lab/expected.json ==="
python3 "$REPO/lab/check_results.py"
