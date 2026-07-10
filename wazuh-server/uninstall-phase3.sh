#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
DESTINATION_RULE="$WAZUH_HOME/etc/rules/edge_navigation_rules.xml"
ANALYSISD="$WAZUH_HOME/bin/wazuh-analysisd"

if [[ "$EUID" -ne 0 ]]; then
  echo "Run this uninstaller as root." >&2
  exit 1
fi

if [[ ! -f "$DESTINATION_RULE" ]]; then
  echo "Phase 3 rule is already absent: $DESTINATION_RULE"
  exit 0
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$DESTINATION_RULE.$timestamp.removed.bak"
cp -a -- "$DESTINATION_RULE" "$backup"
rm -f -- "$DESTINATION_RULE"

if ! "$ANALYSISD" -t; then
  cp -a -- "$backup" "$DESTINATION_RULE"
  echo "Rule removal made the ruleset invalid; the Phase 3 rule was restored." >&2
  exit 1
fi

if ! systemctl restart wazuh-manager || ! systemctl is-active --quiet wazuh-manager; then
  cp -a -- "$backup" "$DESTINATION_RULE"
  systemctl restart wazuh-manager || true
  echo "Manager restart failed; the Phase 3 rule was restored." >&2
  exit 1
fi

echo "Phase 3 navigation rule removed."
echo "Removed-rule backup: $backup"
