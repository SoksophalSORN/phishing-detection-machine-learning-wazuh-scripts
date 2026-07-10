#!/usr/bin/env bash
set -u

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"

echo "== Original custom rules (100002-100004) =="
grep -RInE --include='*.xml' '<rule id="10000[234]"' "$WAZUH_HOME/etc/rules" 2>/dev/null || echo "No original rule IDs found."

echo
echo "== Original integration configuration references =="
grep -nEi 'custom-phishing|phishtank|100002' "$WAZUH_HOME/etc/ossec.conf" 2>/dev/null || echo "No matching ossec.conf references found."

echo
echo "== Original integration files and model artifacts =="
find "$WAZUH_HOME/integrations" -maxdepth 1 -type f \
  \( -iname '*phish*' -o -name 'model.joblib' -o -name 'scaler.joblib' \) \
  -printf '%M %u:%g %p\n' 2>/dev/null || true

echo
echo "This script is read-only. Follow cleanup-original-implementation.md after reviewing these results."
