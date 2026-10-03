#!/usr/bin/env bash
# wazuh-logtest decodes pasted Windows JSON with the generic `json` decoder, but root rule 60000 requires
# `windows_eventchannel` + category `ossec`. For TESTING ONLY, apply the same change as Wazuh's own
# ruleset/testing/runtests.py: in rule 60000, decode as json and drop <category>ossec</category>.
# Usage: bash lab/windows_mode.sh on|off
set -euo pipefail
NAME="wazuh-manager"; F="/var/ossec/ruleset/rules/0575-win-base_rules.xml"
SED='/<rule id="60000"/,/<\/rule>/{s#<decoded_as>windows_eventchannel</decoded_as>#<decoded_as>json</decoded_as>#;/<category>ossec<\/category>/d}'
case "${1:-}" in
  on)
    docker exec "$NAME" sh -c "[ -f $F.orig ] || cp -p $F $F.orig"
    docker exec "$NAME" sed -i "$SED" "$F"
    docker exec "$NAME" grep -A4 'rule id="60000"' "$F" ;;
  off)
    docker exec "$NAME" sh -c "[ -f $F.orig ] && cp -p $F.orig $F" ;;
  *) echo "usage: $0 on|off"; exit 1 ;;
esac
docker exec "$NAME" /var/ossec/bin/wazuh-control restart >/dev/null
echo "Windows test mode: $1"
