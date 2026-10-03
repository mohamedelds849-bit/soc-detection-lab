#!/usr/bin/env bash
# wazuh-logtest decodes pasted Windows JSON with the generic `json` decoder, but root rule 60000 requires
# `windows_eventchannel`. For TESTING ONLY, temporarily switch 60000 to `json` (same trick as Wazuh's own
# ruleset/testing/runtests.py). Usage: bash lab/windows_mode.sh on|off
set -euo pipefail
NAME="wazuh-manager"; F="/var/ossec/ruleset/rules/0575-win-base_rules.xml"
case "${1:-}" in
  on)  docker exec "$NAME" sh -c "[ -f $F.orig ] || cp -p $F $F.orig; sed -i 's#<decoded_as>windows_eventchannel</decoded_as>#<decoded_as>json</decoded_as>#' $F" ;;
  off) docker exec "$NAME" sh -c "[ -f $F.orig ] && cp -p $F.orig $F" ;;
  *) echo "usage: $0 on|off"; exit 1 ;;
esac
docker exec "$NAME" /var/ossec/bin/wazuh-control restart >/dev/null
echo "Windows test mode: $1"
