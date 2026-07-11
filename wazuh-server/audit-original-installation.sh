#!/usr/bin/env bash
set -u

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"

echo "== Legacy custom rule IDs =="
WAZUH_RULES="$WAZUH_HOME/etc/rules" python3 - <<'PY'
import os
import re
from pathlib import Path

root = Path(os.environ["WAZUH_RULES"])
legacy = {100002, 100003, 100004, 100300, 100301, 100302, 100303, 100309, 100310}
rule_re = re.compile(r'<rule\s+id=["\'](\d+)["\']')
comment_re = re.compile(r'<!--.*?-->', re.DOTALL)
found = False
for path in sorted(root.glob("*.xml")) if root.is_dir() else []:
    text = path.read_text(encoding="utf-8", errors="replace")
    active = {int(value) for value in rule_re.findall(comment_re.sub("", text))}
    all_ids = {int(value) for value in rule_re.findall(text)}
    for rule_id in sorted(all_ids & legacy):
        if path.name == "edge_phishing_pipeline_rules.xml":
            state = "CURRENT MANAGED POLICY"
        elif rule_id in active:
            state = "ACTIVE"
        else:
            state = "COMMENTED"
        print(f"{state:22} rule {rule_id} in {path}")
        found = True
if not found:
    print("No known legacy rule IDs found.")
PY

echo
echo "== Original integration configuration references =="
grep -nEi 'custom-phishing|phishtank|100002|10030[239]|100310' "$WAZUH_HOME/etc/ossec.conf" 2>/dev/null || echo "No matching ossec.conf references found."

echo
echo "== Original integration files and model artifacts =="
find "$WAZUH_HOME/integrations" -maxdepth 1 -type f \
  \( -iname '*phish*' -o -name 'model.joblib' -o -name 'scaler.joblib' \) \
  -printf '%M %u:%g %p\n' 2>/dev/null || true

echo
echo "This script is read-only. Follow cleanup-original-implementation.md after reviewing these results."
