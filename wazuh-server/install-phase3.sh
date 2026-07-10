#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_RULE="$SCRIPT_DIR/rules/edge_navigation_rules.xml"
RULE_DIRECTORY="$WAZUH_HOME/etc/rules"
DESTINATION_RULE="$RULE_DIRECTORY/edge_navigation_rules.xml"
ANALYSISD="$WAZUH_HOME/bin/wazuh-analysisd"
LOGTEST="$WAZUH_HOME/bin/wazuh-logtest"
RULE_ID="100100"

if [[ "$EUID" -ne 0 ]]; then
  echo "Run this installer as root (for example, sudo ./install-phase3.sh)." >&2
  exit 1
fi

for required in "$SOURCE_RULE" "$ANALYSISD" "$LOGTEST"; do
  if [[ ! -e "$required" ]]; then
    echo "Required file not found: $required" >&2
    exit 1
  fi
done

mkdir -p "$RULE_DIRECTORY"

# Refuse to silently introduce a duplicate ID in another custom rule file.
conflicts="$(grep -RIl --include='*.xml' "<rule id=\"$RULE_ID\"" "$RULE_DIRECTORY" 2>/dev/null || true)"
if [[ -n "$conflicts" ]]; then
  while IFS= read -r conflict; do
    if [[ "$conflict" != "$DESTINATION_RULE" ]]; then
      echo "Rule ID $RULE_ID already exists in $conflict. Choose a free custom rule ID before installing." >&2
      exit 1
    fi
  done <<< "$conflicts"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup=""
had_previous=0
if [[ -f "$DESTINATION_RULE" ]]; then
  had_previous=1
  backup="$DESTINATION_RULE.$timestamp.bak"
  cp -a -- "$DESTINATION_RULE" "$backup"
fi

rollback_rule() {
  if [[ "$had_previous" -eq 1 ]]; then
    cp -a -- "$backup" "$DESTINATION_RULE"
  else
    rm -f -- "$DESTINATION_RULE"
  fi
}

install -o root -g wazuh -m 0640 -- "$SOURCE_RULE" "$DESTINATION_RULE"

if ! "$ANALYSISD" -t; then
  rollback_rule
  echo "Wazuh rule validation failed. The previous rule state was restored." >&2
  exit 1
fi

sample_event='{"schema_version":1,"event_type":"browser_navigation","event_id":"phase3-logtest-event","timestamp":"2026-07-10T10:00:29.005Z","browser":"edge","url":"https://example.test/phase3","tab_id":1,"document_id":"PHASE3","navigation_kind":"committed","transition_type":"typed","transition_qualifiers":[],"source":"edge_extension"}'
if ! printf '%s\n' "$sample_event" | "$LOGTEST" -q -U "$RULE_ID:3:json"; then
  rollback_rule
  echo "The sample JSON event did not match rule $RULE_ID with decoder json. The previous rule state was restored." >&2
  exit 1
fi

if ! systemctl restart wazuh-manager; then
  rollback_rule
  "$ANALYSISD" -t || true
  systemctl restart wazuh-manager || true
  echo "Wazuh manager restart failed. The previous rule state was restored." >&2
  exit 1
fi

if ! systemctl is-active --quiet wazuh-manager; then
  rollback_rule
  systemctl restart wazuh-manager || true
  echo "Wazuh manager is not active after installation. The previous rule state was restored." >&2
  exit 1
fi

echo "Phase 3 rule installed: $DESTINATION_RULE"
[[ -n "$backup" ]] && echo "Previous rule backup: $backup"
echo "Rule $RULE_ID passed wazuh-analysisd and wazuh-logtest validation."
echo "Wazuh manager is active. Open a fresh URL in Edge, copy its event_id, then run:"
echo "  sudo $SCRIPT_DIR/verify-phase3.sh --event-id EVENT_ID --wait 60"
