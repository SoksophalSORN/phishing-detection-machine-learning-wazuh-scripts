#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
RULE_ID="100100"
RULE_LEVEL="3"
RULE_FILE="$WAZUH_HOME/etc/rules/edge_navigation_rules.xml"
POLICY_FILE="$WAZUH_HOME/etc/edge-phishing-rule-policy.json"
ALERTS_FILE="$WAZUH_HOME/logs/alerts/alerts.json"
ARCHIVES_FILE="$WAZUH_HOME/logs/archives/archives.json"
ANALYSISD="$WAZUH_HOME/bin/wazuh-analysisd"
LOGTEST="$WAZUH_HOME/bin/wazuh-logtest"
event_id=""
wait_seconds=0

usage() {
  cat <<'USAGE'
Usage:
  sudo ./verification/verify-navigation-ingestion.sh
  sudo ./verification/verify-navigation-ingestion.sh --event-id EVENT_ID [--wait SECONDS]

Without an event ID, the script validates the service, ruleset, and sample rule
match. With an event ID, it also waits for and locates the real Edge alert.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --event-id)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      event_id="$2"
      shift 2
      ;;
    --wait)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      wait_seconds="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$wait_seconds" =~ ^[0-9]+$ ]]; then
  echo "--wait must be a non-negative whole number of seconds." >&2
  exit 2
fi

failures=0
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*" >&2; failures=$((failures + 1)); }

if [[ -f "$POLICY_FILE" ]]; then
  policy_values="$(python3 - "$POLICY_FILE" <<'PY'
import json
import sys
from pathlib import Path
value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(int(value["navigation_rule_id"]), int(value["navigation_level"]))
PY
)" || { echo "Installed rule policy is invalid: $POLICY_FILE" >&2; exit 1; }
  read -r RULE_ID RULE_LEVEL <<< "$policy_values"
  RULE_FILE="$WAZUH_HOME/etc/rules/edge_phishing_pipeline_rules.xml"
fi

if systemctl is-active --quiet wazuh-manager; then
  pass "wazuh-manager is active."
else
  fail "wazuh-manager is not active."
fi

if [[ -f "$RULE_FILE" ]]; then
  pass "Phase 3 rule file exists."
else
  fail "Phase 3 rule file is missing: $RULE_FILE"
fi

if "$ANALYSISD" -t >/dev/null 2>&1; then
  pass "wazuh-analysisd accepts the manager rules and configuration."
else
  fail "wazuh-analysisd configuration validation failed."
fi

sample_event='{"schema_version":1,"event_type":"browser_navigation","event_id":"phase3-verification-event","timestamp":"2026-07-10T10:00:29.005Z","browser":"edge","url":"https://example.test/phase3","tab_id":1,"document_id":"PHASE3","navigation_kind":"committed","transition_type":"typed","transition_qualifiers":[],"source":"edge_extension"}'
if printf '%s\n' "$sample_event" | "$LOGTEST" -q -U "$RULE_ID:$RULE_LEVEL:json"; then
  pass "Sample Edge JSON matches rule $RULE_ID through decoder json."
else
  fail "Sample Edge JSON does not match rule $RULE_ID."
fi

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

if [[ -z "$event_id" ]]; then
  echo "Static Phase 3 checks passed. Open a fresh URL in Edge and rerun with --event-id."
  exit 0
fi
if [[ ! "$event_id" =~ ^[0-9A-Za-z._:-]{1,128}$ ]]; then
  echo "The event ID contains unexpected characters or exceeds 128 characters." >&2
  exit 2
fi

deadline=$((SECONDS + wait_seconds))
while true; do
  if [[ -f "$ALERTS_FILE" ]] && grep -Fq -- "$event_id" "$ALERTS_FILE"; then
    pass "Event $event_id reached the manager and generated rule $RULE_ID alert data."
    match="$(grep -F -- "$event_id" "$ALERTS_FILE" | tail -n 1)"
    if command -v jq >/dev/null 2>&1; then
      printf '%s\n' "$match" | jq '{timestamp, agent, rule, data}'
    else
      printf '%s\n' "$match"
    fi
    exit 0
  fi

  if (( SECONDS >= deadline )); then
    break
  fi
  sleep 1
done

echo "Event $event_id was not found in $ALERTS_FILE." >&2
if [[ -f "$ARCHIVES_FILE" ]] && grep -Fq -- "$event_id" "$ARCHIVES_FILE"; then
  echo "It is present in archives.json, so transport succeeded but rule matching/alerting needs investigation." >&2
else
  echo "It was not found in archives.json either (archives may be disabled). Check agent connectivity and manager ossec.log." >&2
fi
exit 1
