#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
event_id=""
wait_seconds=0

usage() {
  echo "Usage: verify-phase4.sh --source-event-id EVENT_ID [--wait SECONDS]"
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-event-id) event_id="${2:-}"; shift 2 ;;
    --wait) wait_seconds="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$event_id" && "$wait_seconds" =~ ^[0-9]+$ ]] || { usage >&2; exit 2; }

systemctl is-active --quiet wazuh-manager || { echo "[FAIL] wazuh-manager is inactive" >&2; exit 1; }
echo "[PASS] wazuh-manager is active."
"$WAZUH_HOME/bin/wazuh-analysisd" -t >/dev/null
echo "[PASS] Wazuh configuration is valid."

alerts="$WAZUH_HOME/logs/alerts/alerts.json"
deadline=$((SECONDS + wait_seconds))
while true; do
  if [[ -f "$alerts" ]] && grep -F '"integration":"edge-phishing-classifier"' "$alerts" | grep -Fq -- "$event_id"; then
    echo "[PASS] Classification result found for source event $event_id."
    match="$(grep -F '"integration":"edge-phishing-classifier"' "$alerts" | grep -F -- "$event_id" | tail -n 1)"
    if command -v jq >/dev/null 2>&1; then
      printf '%s\n' "$match" | jq '{timestamp,agent,rule,data}'
    else
      printf '%s\n' "$match"
    fi
    exit 0
  fi
  (( SECONDS >= deadline )) && break
  sleep 1
done

echo "[FAIL] No classification alert found for $event_id." >&2
echo "Inspect $WAZUH_HOME/logs/integrations.log and $WAZUH_HOME/logs/ossec.log." >&2
exit 1
