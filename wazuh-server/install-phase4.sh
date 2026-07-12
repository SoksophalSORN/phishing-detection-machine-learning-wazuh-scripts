#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/phase4"
RULE_DEST="$WAZUH_HOME/etc/rules/edge_phishing_classification_rules.xml"
PIPELINE_RULES="$WAZUH_HOME/etc/rules/edge_phishing_pipeline_rules.xml"
POLICY_MANIFEST="$WAZUH_HOME/etc/edge-phishing-rule-policy.json"
WRAPPER_DEST="$WAZUH_HOME/integrations/custom-edge-phishing-classifier"
PYTHON_WRAPPER_DEST="$WAZUH_HOME/integrations/custom-edge-phishing-classifier.py"
MODULE_DEST="$WAZUH_HOME/integrations/edge_phishing_classifier.py"
ML_MODULE_DEST="$WAZUH_HOME/integrations/url_ml.py"
LEGACY_ML_MODULE_DEST="$WAZUH_HOME/integrations/legacy_url_ml.py"
WEB_RISK_MODULE_DEST="$WAZUH_HOME/integrations/google_web_risk.py"
CONFIG_DEST="$WAZUH_HOME/etc/edge-phishing-classifier.json"
CACHE_DIR="$WAZUH_HOME/var/edge-phishing-classifier"
OSSEC_CONFIG="$WAZUH_HOME/etc/ossec.conf"
ANALYSISD="$WAZUH_HOME/bin/wazuh-analysisd"
LOGTEST="$WAZUH_HOME/bin/wazuh-logtest"
MARKER_BEGIN='<!-- BEGIN EDGE PHISHING CLASSIFIER -->'
MARKER_END='<!-- END EDGE PHISHING CLASSIFIER -->'
verbose=0
config_source=""
prompt_api_key=0
temporary_config=""
unified_policy=0

usage() {
  cat <<'USAGE'
Usage: install-phase4.sh [OPTIONS]

Install the structured Edge phishing-reputation classification integration.

Options:
  -v, --verbose       Show detailed validation and wazuh-logtest output.
  -c, --config FILE   Install the specified classifier JSON configuration.
      --api-key-prompt Prompt securely for a PhishTank API key and update the
                       installed configuration without exposing it in history.
  -h, --help          Show help without changing the system.

If --config is omitted, an existing installed configuration is preserved. On
first installation, phase4/config.json is used.
USAGE
}

log_verbose() { [[ "$verbose" -eq 1 ]] && printf '[VERBOSE] %s\n' "$*" || true; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) verbose=1; shift ;;
    -c|--config) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; config_source="$2"; shift 2 ;;
    --api-key-prompt) prompt_api_key=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$EUID" -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

required=(
  "$SOURCE/custom-edge-phishing-classifier"
  "$SOURCE/custom-edge-phishing-classifier-launcher"
  "$SOURCE/edge_phishing_classifier.py"
  "$SOURCE/url_ml.py"
  "$SOURCE/legacy_url_ml.py"
  "$SOURCE/google_web_risk.py"
  "$OSSEC_CONFIG" "$ANALYSISD" "$LOGTEST"
)
if [[ -e "$PIPELINE_RULES" || -e "$POLICY_MANIFEST" ]]; then
  [[ -f "$PIPELINE_RULES" && -f "$POLICY_MANIFEST" ]] || {
    echo "The unified rule policy is incomplete; expected both $PIPELINE_RULES and $POLICY_MANIFEST" >&2
    exit 1
  }
  unified_policy=1
  required+=("$PIPELINE_RULES" "$POLICY_MANIFEST")
else
  required+=("$SOURCE/edge_phishing_classification_rules.xml" "$WAZUH_HOME/etc/rules/edge_navigation_rules.xml")
fi
for path in "${required[@]}"; do
  [[ -e "$path" ]] || { echo "Required file not found: $path" >&2; exit 1; }
  log_verbose "Found $path"
done

if [[ -n "$config_source" ]]; then
  [[ -f "$config_source" ]] || { echo "Configuration not found: $config_source" >&2; exit 1; }
elif [[ ! -f "$CONFIG_DEST" ]]; then
  config_source="$SOURCE/config.json"
fi

if [[ "$prompt_api_key" -eq 1 ]]; then
  base_config="$config_source"
  [[ -n "$base_config" ]] || base_config="$CONFIG_DEST"
  [[ -f "$base_config" ]] || { echo "No classifier configuration is available." >&2; exit 1; }
  read -r -s -p "PhishTank API key: " phishtank_api_key
  echo
  [[ -n "$phishtank_api_key" ]] || { echo "API key cannot be empty." >&2; exit 1; }
  temporary_config="$(mktemp)"
  trap '[[ -n "$temporary_config" ]] && rm -f -- "$temporary_config"' EXIT
  BASE_CONFIG="$base_config" OUTPUT_CONFIG="$temporary_config" PHISHTANK_API_KEY="$phishtank_api_key" python3 - <<'PY'
import json
import os
from pathlib import Path
source = Path(os.environ["BASE_CONFIG"])
output = Path(os.environ["OUTPUT_CONFIG"])
value = json.loads(source.read_text(encoding="utf-8"))
value["api_key"] = os.environ["PHISHTANK_API_KEY"]
output.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
PY
  unset phishtank_api_key PHISHTANK_API_KEY
  config_source="$temporary_config"
fi

echo "[1/6] Validating classifier source files..."
python3 - "$SOURCE/edge_phishing_classifier.py" "$SOURCE/url_ml.py" "$SOURCE/legacy_url_ml.py" "$SOURCE/google_web_risk.py" <<'PY'
import ast
import sys
from pathlib import Path
for value in sys.argv[1:]:
    path = Path(value)
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
PY
if [[ -n "$config_source" ]]; then
  python3 -m json.tool "$config_source" >/dev/null
  PYTHONPATH="$SOURCE" python3 - "$config_source" <<'PY'
import sys
from pathlib import Path
from edge_phishing_classifier import load_settings
from google_web_risk import read_api_key
settings = load_settings(Path(sys.argv[1]))
if settings.reputation_provider == "google_webrisk":
    read_api_key(settings.web_risk_api_key_file)
PY
fi

if [[ "$unified_policy" -eq 0 ]]; then
  for rule_id in 100110 100111 100112 100113 100114 100115; do
    conflicts="$(grep -RIl --include='*.xml' "<rule id=\"$rule_id\"" "$WAZUH_HOME/etc/rules" 2>/dev/null || true)"
    while IFS= read -r conflict; do
      [[ -z "$conflict" || "$conflict" == "$RULE_DEST" ]] && continue
      echo "Rule ID $rule_id conflicts with $conflict" >&2
      exit 1
    done <<< "$conflicts"
  done
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="$WAZUH_HOME/backup/edge-phase4-$timestamp"
mkdir -p "$backup_dir"
managed=("$WRAPPER_DEST" "$PYTHON_WRAPPER_DEST" "$MODULE_DEST" "$ML_MODULE_DEST" "$LEGACY_ML_MODULE_DEST" "$WEB_RISK_MODULE_DEST" "$CONFIG_DEST")
[[ "$unified_policy" -eq 0 ]] && managed+=("$RULE_DEST")
for path in "${managed[@]}"; do
  [[ -e "$path" ]] && cp -a -- "$path" "$backup_dir/"
done
cp -a -- "$OSSEC_CONFIG" "$backup_dir/ossec.conf"

rollback() {
  echo "Rolling Phase 4 back from $backup_dir" >&2
  rm -f -- "${managed[@]}"
  for path in "${managed[@]}"; do
    name="$(basename -- "$path")"
    [[ -e "$backup_dir/$name" ]] && cp -a -- "$backup_dir/$name" "$path"
  done
  cp -a -- "$backup_dir/ossec.conf" "$OSSEC_CONFIG"
  systemctl restart wazuh-manager || true
}

transaction_active=1
handle_install_error() {
  status=$?
  trap - ERR
  if [[ "$transaction_active" -eq 1 ]]; then
    transaction_active=0
    rollback || true
  fi
  exit "$status"
}
trap handle_install_error ERR

echo "[2/6] Installing integration files and rules..."
install -o root -g wazuh -m 0750 "$SOURCE/custom-edge-phishing-classifier-launcher" "$WRAPPER_DEST"
install -o root -g wazuh -m 0640 "$SOURCE/custom-edge-phishing-classifier" "$PYTHON_WRAPPER_DEST"
install -o root -g wazuh -m 0640 "$SOURCE/edge_phishing_classifier.py" "$MODULE_DEST"
install -o root -g wazuh -m 0640 "$SOURCE/url_ml.py" "$ML_MODULE_DEST"
install -o root -g wazuh -m 0640 "$SOURCE/legacy_url_ml.py" "$LEGACY_ML_MODULE_DEST"
install -o root -g wazuh -m 0640 "$SOURCE/google_web_risk.py" "$WEB_RISK_MODULE_DEST"
if [[ "$unified_policy" -eq 0 ]]; then
  install -o root -g wazuh -m 0640 "$SOURCE/edge_phishing_classification_rules.xml" "$RULE_DEST"
else
  log_verbose "Preserved unified rule policy $PIPELINE_RULES"
fi
install -d -o root -g wazuh -m 0770 "$CACHE_DIR"
if [[ -n "$config_source" ]]; then
  install -o root -g wazuh -m 0640 "$config_source" "$CONFIG_DEST"
  log_verbose "Installed classifier config from $config_source"
else
  log_verbose "Preserved existing classifier config $CONFIG_DEST"
fi

PYTHONPATH="$WAZUH_HOME/integrations" python3 - "$CONFIG_DEST" <<'PY'
import sys
from pathlib import Path
from edge_phishing_classifier import load_settings
from google_web_risk import read_api_key
settings = load_settings(Path(sys.argv[1]))
if settings.reputation_provider == "google_webrisk":
    read_api_key(settings.web_risk_api_key_file)
PY

if [[ "$unified_policy" -eq 1 ]]; then
  CONFIG_DEST="$CONFIG_DEST" POLICY_MANIFEST="$POLICY_MANIFEST" python3 - <<'PY'
import json
import os
from pathlib import Path

config_path = Path(os.environ["CONFIG_DEST"])
policy_path = Path(os.environ["POLICY_MANIFEST"])
config = json.loads(config_path.read_text(encoding="utf-8"))
policy = json.loads(policy_path.read_text(encoding="utf-8"))
configured_provider = config.get("reputation", {}).get("provider", "phishtank").replace("-", "_")
policy_provider = policy.get("reputation_provider", "phishtank").replace("-", "_")
if configured_provider != policy_provider:
    raise SystemExit(
        f"classifier provider {configured_provider} does not match rule provider {policy_provider}"
    )
config["navigation_rule_id"] = str(int(policy["navigation_rule_id"]))
config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY
  log_verbose "Synchronized classifier trigger with the unified rule policy"
fi

navigation_rule_id="$(CONFIG_DEST="$CONFIG_DEST" python3 - <<'PY'
import json
import os
from pathlib import Path

value = json.loads(Path(os.environ["CONFIG_DEST"]).read_text(encoding="utf-8"))
rule_id = str(value.get("navigation_rule_id", "100100"))
if not rule_id.isdigit() or not 100000 <= int(rule_id) <= 120000:
    raise SystemExit("navigation_rule_id must be a Wazuh custom rule ID (100000-120000)")
print(rule_id)
PY
)"
log_verbose "Classifier will trigger from navigation rule $navigation_rule_id"

reputation_provider="$(CONFIG_DEST="$CONFIG_DEST" python3 - <<'PY'
import json
import os
from pathlib import Path
value = json.loads(Path(os.environ["CONFIG_DEST"]).read_text(encoding="utf-8"))
provider = value.get("reputation", {}).get("provider", "phishtank").replace("-", "_")
if provider not in {"phishtank", "google_webrisk"}:
    raise SystemExit("reputation.provider must be phishtank or google_webrisk")
print(provider)
PY
)"
log_verbose "Classifier reputation provider is $reputation_provider"

echo "[3/6] Registering custom integration in ossec.conf..."
OSSEC_CONFIG="$OSSEC_CONFIG" MARKER_BEGIN="$MARKER_BEGIN" MARKER_END="$MARKER_END" NAVIGATION_RULE_ID="$navigation_rule_id" python3 - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["OSSEC_CONFIG"])
begin = os.environ["MARKER_BEGIN"]
end = os.environ["MARKER_END"]
navigation_rule_id = os.environ["NAVIGATION_RULE_ID"]
block = f"""  {begin}
  <integration>
    <name>custom-edge-phishing-classifier</name>
    <rule_id>{navigation_rule_id}</rule_id>
    <alert_format>json</alert_format>
  </integration>
  {end}"""
text = path.read_text(encoding="utf-8")
if (begin in text) != (end in text):
    raise SystemExit("Incomplete Phase 4 marker block in ossec.conf")
if begin in text:
    start = text.index(begin)
    line_start = text.rfind("\n", 0, start) + 1
    finish = text.index(end, start) + len(end)
    text = text[:line_start] + block + text[finish:]
else:
    closing = text.lower().rfind("</ossec_config>")
    if closing < 0:
        raise SystemExit("No closing </ossec_config> found")
    text = text[:closing].rstrip() + "\n\n" + block + "\n" + text[closing:]
path.write_text(text, encoding="utf-8")
PY

echo "[4/6] Validating manager configuration and classification rules..."
if ! "$ANALYSISD" -t; then
  transaction_active=0
  rollback
  echo "wazuh-analysisd rejected Phase 4; previous state restored." >&2
  exit 1
fi

echo "[5/6] Restarting wazuh-manager with the validated configuration..."
if ! systemctl restart wazuh-manager || ! systemctl is-active --quiet wazuh-manager; then
  transaction_active=0
  rollback
  echo "Manager restart failed; previous state restored." >&2
  exit 1
fi

sample="{\"integration\":\"edge-phishing-classifier\",\"schema_version\":1,\"classification\":{\"status\":\"malicious\",\"malicious\":true,\"source\":\"$reputation_provider\",\"threat_types\":[\"SOCIAL_ENGINEERING\"],\"url\":\"https://example.test/phish\",\"url_host\":\"example.test\",\"source_event_id\":\"phase4-test\"}}"
phishtank_expectation='100111:10:json'
if [[ "$unified_policy" -eq 1 ]]; then
  phishtank_expectation="$(POLICY_MANIFEST="$POLICY_MANIFEST" python3 - <<'PY'
import json
import os
from pathlib import Path
policy = json.loads(Path(os.environ["POLICY_MANIFEST"]).read_text(encoding="utf-8"))
print(f'{int(policy["phishtank_rule_id"])}:{int(policy["phishtank_level"])}:json')
PY
)"
fi
options=(-U "$phishtank_expectation")
[[ "$verbose" -eq 1 ]] && options=(-v "${options[@]}") || options=(-q "${options[@]}")
echo "[6/6] Testing a confirmed-phishing result through the analysisd session manager..."
if ! printf '%s\n' "$sample" | "$LOGTEST" "${options[@]}"; then
  [[ "$verbose" -eq 0 ]] && printf '%s\n' "$sample" | "$LOGTEST" -v || true
  transaction_active=0
  rollback
  echo "wazuh-logtest could not verify $phishtank_expectation; previous state restored." >&2
  echo "If the output says it cannot connect with wazuh-analysisd, inspect the manager service and the <rule_test> section in ossec.conf." >&2
  exit 1
fi

transaction_active=0
trap - ERR

echo "Phase 4 reputation integration installed successfully (provider: $reputation_provider)."
echo "Backup: $backup_dir"
if [[ "$unified_policy" -eq 1 ]]; then
  echo "Routine negative alerts are suppressed. Use the verification script for the selected provider when a live lookup is required."
else
  echo "Open a fresh Edge URL and verify its source event ID with verification/verify-classification-event.sh."
fi
