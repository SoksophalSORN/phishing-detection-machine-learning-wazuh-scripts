#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/phase4"
RULE_DEST="$WAZUH_HOME/etc/rules/edge_phishing_classification_rules.xml"
WRAPPER_DEST="$WAZUH_HOME/integrations/custom-edge-phishing-classifier"
MODULE_DEST="$WAZUH_HOME/integrations/edge_phishing_classifier.py"
CONFIG_DEST="$WAZUH_HOME/etc/edge-phishing-classifier.json"
CACHE_DIR="$WAZUH_HOME/var/edge-phishing-classifier"
OSSEC_CONFIG="$WAZUH_HOME/etc/ossec.conf"
ANALYSISD="$WAZUH_HOME/bin/wazuh-analysisd"
LOGTEST="$WAZUH_HOME/bin/wazuh-logtest"
MARKER_BEGIN='<!-- BEGIN EDGE PHISHING CLASSIFIER -->'
MARKER_END='<!-- END EDGE PHISHING CLASSIFIER -->'
verbose=0
config_source=""

usage() {
  cat <<'USAGE'
Usage: install-phase4.sh [OPTIONS]

Install the structured Edge-to-PhishTank Wazuh classification integration.

Options:
  -v, --verbose       Show detailed validation and wazuh-logtest output.
  -c, --config FILE   Install the specified classifier JSON configuration.
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
  "$SOURCE/edge_phishing_classifier.py"
  "$SOURCE/edge_phishing_classification_rules.xml"
  "$SOURCE/test_edge_phishing_classifier.py"
  "$OSSEC_CONFIG" "$ANALYSISD" "$LOGTEST"
  "$WAZUH_HOME/etc/rules/edge_navigation_rules.xml"
)
for path in "${required[@]}"; do
  [[ -e "$path" ]] || { echo "Required file not found: $path" >&2; exit 1; }
  log_verbose "Found $path"
done

if [[ -n "$config_source" ]]; then
  [[ -f "$config_source" ]] || { echo "Configuration not found: $config_source" >&2; exit 1; }
elif [[ ! -f "$CONFIG_DEST" ]]; then
  config_source="$SOURCE/config.json"
fi

echo "[1/6] Running classifier unit tests..."
(cd "$SOURCE" && python3 -m unittest -v test_edge_phishing_classifier.py)
if [[ -n "$config_source" ]]; then
  python3 -m json.tool "$config_source" >/dev/null
fi

for rule_id in 100110 100111 100112 100113; do
  conflicts="$(grep -RIl --include='*.xml' "<rule id=\"$rule_id\"" "$WAZUH_HOME/etc/rules" 2>/dev/null || true)"
  while IFS= read -r conflict; do
    [[ -z "$conflict" || "$conflict" == "$RULE_DEST" ]] && continue
    echo "Rule ID $rule_id conflicts with $conflict" >&2
    exit 1
  done <<< "$conflicts"
done

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="$WAZUH_HOME/backup/edge-phase4-$timestamp"
mkdir -p "$backup_dir"
managed=("$RULE_DEST" "$WRAPPER_DEST" "$MODULE_DEST" "$CONFIG_DEST")
for path in "${managed[@]}"; do
  [[ -e "$path" ]] && cp -a -- "$path" "$backup_dir/"
done
cp -a -- "$OSSEC_CONFIG" "$backup_dir/ossec.conf"

rollback() {
  echo "Rolling Phase 4 back from $backup_dir" >&2
  rm -f -- "$RULE_DEST" "$WRAPPER_DEST" "$MODULE_DEST" "$CONFIG_DEST"
  for path in "$RULE_DEST" "$WRAPPER_DEST" "$MODULE_DEST" "$CONFIG_DEST"; do
    name="$(basename -- "$path")"
    [[ -e "$backup_dir/$name" ]] && cp -a -- "$backup_dir/$name" "$path"
  done
  cp -a -- "$backup_dir/ossec.conf" "$OSSEC_CONFIG"
}

echo "[2/6] Installing integration files and rules..."
install -o root -g wazuh -m 0750 "$SOURCE/custom-edge-phishing-classifier" "$WRAPPER_DEST"
install -o root -g wazuh -m 0640 "$SOURCE/edge_phishing_classifier.py" "$MODULE_DEST"
install -o root -g wazuh -m 0640 "$SOURCE/edge_phishing_classification_rules.xml" "$RULE_DEST"
install -d -o root -g wazuh -m 0770 "$CACHE_DIR"
if [[ -n "$config_source" ]]; then
  install -o root -g wazuh -m 0640 "$config_source" "$CONFIG_DEST"
  log_verbose "Installed classifier config from $config_source"
else
  log_verbose "Preserved existing classifier config $CONFIG_DEST"
fi

echo "[3/6] Registering custom integration in ossec.conf..."
OSSEC_CONFIG="$OSSEC_CONFIG" MARKER_BEGIN="$MARKER_BEGIN" MARKER_END="$MARKER_END" python3 - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["OSSEC_CONFIG"])
begin = os.environ["MARKER_BEGIN"]
end = os.environ["MARKER_END"]
block = f"""  {begin}
  <integration>
    <name>custom-edge-phishing-classifier</name>
    <rule_id>100100</rule_id>
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
  rollback
  echo "wazuh-analysisd rejected Phase 4; previous state restored." >&2
  exit 1
fi

sample='{"integration":"edge-phishing-classifier","schema_version":1,"classification":{"status":"malicious","malicious":true,"source":"phishtank","url":"https://example.test/phish","source_event_id":"phase4-test"}}'
options=(-U '100111:12:json')
[[ "$verbose" -eq 1 ]] && options=(-v "${options[@]}") || options=(-q "${options[@]}")
echo "[5/6] Testing a confirmed-phishing result..."
if ! printf '%s\n' "$sample" | "$LOGTEST" "${options[@]}"; then
  [[ "$verbose" -eq 0 ]] && printf '%s\n' "$sample" | "$LOGTEST" -v || true
  rollback
  echo "Phase 4 result did not match rule 100111; previous state restored." >&2
  exit 1
fi

echo "[6/6] Restarting wazuh-manager..."
if ! systemctl restart wazuh-manager || ! systemctl is-active --quiet wazuh-manager; then
  rollback
  systemctl restart wazuh-manager || true
  echo "Manager restart failed; previous state restored." >&2
  exit 1
fi

echo "Phase 4 PhishTank integration installed successfully."
echo "Backup: $backup_dir"
echo "Open a fresh Edge URL and verify its source event ID with verify-phase4.sh."
