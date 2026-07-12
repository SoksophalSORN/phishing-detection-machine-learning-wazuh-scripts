#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

model=""
legacy_scaler=""
config=""
threshold=""
review_threshold=""
test_url="https://example.test/login"
environment="production"
api_key_prompt=0
web_risk_key_prompt=0
web_risk_key_file=""
web_risk_monthly_limit=""
web_risk_negative_cache_seconds=""
reputation_provider=""
web_risk_threat_types=()
wizard=0
verbose=0
legacy_network_features=0
transaction_active=0
backup_dir=""
rule_args=()

usage() {
  cat <<'USAGE'
Usage: install-wazuh-server.sh [OPTIONS]

Install the complete Edge-navigation, phishing-reputation, and ML integration
on a Wazuh manager. The repository's model.joblib and scaler.joblib are used
automatically when --model is omitted and both files exist.

Core options:
  --model FILE                    Trusted modern bundle or original model.joblib.
  --legacy-scaler FILE            Original scaler.joblib (selects legacy mode).
  --threshold NUMBER              ML decision threshold (0..1).
  --review-threshold NUMBER       Lower ML review threshold (default: 0.07).
  --config FILE                   Classifier JSON configuration.
  --api-key-prompt                Securely prompt for an optional PhishTank key.
  --reputation-provider NAME      phishtank or google-webrisk. Existing installs
                                  retain their provider when this is omitted.
  --web-risk-key-prompt           Securely prompt for a Google Web Risk API key.
  --web-risk-key-file FILE        Read a Web Risk key from a protected file.
  --web-risk-threat-type TYPE     Repeat for SOCIAL_ENGINEERING, MALWARE, or
                                  UNWANTED_SOFTWARE (default: SOCIAL_ENGINEERING).
  --web-risk-monthly-limit NUMBER Application call ceiling (default: 90000).
  --web-risk-negative-cache-seconds NUMBER
                                  Empty-result cache TTL (default: 300).
  --enable-legacy-network-features
                                  Enable guarded WHOIS/page-derived features.
                                  Disabled by default for server safety.
  --test-url URL                  Controlled offline ML validation URL.
  --environment NAME              Deployment profile: production or staging.
                                  Production suppresses routine negatives;
                                  staging alerts on them at level 3.
  --wizard                        Prompt for all Wazuh rule IDs and levels.
  -v, --verbose                   Show detailed child-installer diagnostics.
  -h, --help                      Show help without changing Wazuh.

Rule policy options (all optional):
  --group-name NAME
  --preferred-start ID
  --navigation-rule-id ID         --navigation-level LEVEL
  --classification-base-rule-id ID --classification-base-level LEVEL
  --phishtank-rule-id ID          --phishtank-level LEVEL
  --reputation-rule-id ID         --reputation-level LEVEL (provider-neutral aliases)
  --ml-rule-id ID                 --ml-level LEVEL
  --review-rule-id ID             --review-level LEVEL
  --error-rule-id ID              --error-level LEVEL
  --negative-rule-id ID           --negative-level LEVEL

Environment:
  WAZUH_HOME                      Wazuh installation directory (/var/ossec).

Examples:
  sudo bash wazuh-server/install-wazuh-server.sh --environment production -v
  sudo bash wazuh-server/install-wazuh-server.sh --environment staging --wizard -v
  sudo bash wazuh-server/install-wazuh-server.sh \
    --model /secure/model.joblib --legacy-scaler /secure/scaler.joblib \
    --threshold 0.5 -v
USAGE
}

log_verbose() {
  [[ "$verbose" -eq 1 ]] && printf '[VERBOSE] %s\n' "$*" || true
}

need_value() {
  [[ $# -ge 2 && -n "$2" ]] || { echo "$1 requires a value." >&2; usage >&2; exit 2; }
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model) need_value "$@"; model="$2"; shift 2 ;;
    --legacy-scaler) need_value "$@"; legacy_scaler="$2"; shift 2 ;;
    --threshold) need_value "$@"; threshold="$2"; shift 2 ;;
    --review-threshold) need_value "$@"; review_threshold="$2"; shift 2 ;;
    --config) need_value "$@"; config="$2"; shift 2 ;;
    --test-url) need_value "$@"; test_url="$2"; shift 2 ;;
    --environment) need_value "$@"; environment="${2,,}"; shift 2 ;;
    --api-key-prompt) api_key_prompt=1; shift ;;
    --reputation-provider) need_value "$@"; reputation_provider="${2,,}"; shift 2 ;;
    --web-risk-key-prompt) web_risk_key_prompt=1; shift ;;
    --web-risk-key-file) need_value "$@"; web_risk_key_file="$2"; shift 2 ;;
    --web-risk-threat-type) need_value "$@"; web_risk_threat_types+=("${2^^}"); shift 2 ;;
    --web-risk-monthly-limit) need_value "$@"; web_risk_monthly_limit="$2"; shift 2 ;;
    --web-risk-negative-cache-seconds) need_value "$@"; web_risk_negative_cache_seconds="$2"; shift 2 ;;
    --enable-legacy-network-features) legacy_network_features=1; shift ;;
    --wizard) wizard=1; shift ;;
    -v|--verbose) verbose=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --group-name|--preferred-start|--navigation-rule-id|--navigation-level|\
    --classification-base-rule-id|--classification-base-level|\
    --phishtank-rule-id|--phishtank-level|--reputation-rule-id|--reputation-level|--ml-rule-id|--ml-level|\
    --review-rule-id|--review-level|\
    --error-rule-id|--error-level|--negative-rule-id|--negative-level)
      need_value "$@"
      rule_args+=("$1" "$2")
      shift 2
      ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$environment" != "production" && "$environment" != "staging" ]]; then
  echo "--environment must be production or staging." >&2
  exit 2
fi
if [[ -n "$review_threshold" ]] && ! python3 - "$review_threshold" <<'PY'
import sys
try:
    value = float(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if 0.0 <= value <= 1.0 else 1)
PY
then
  echo "--review-threshold must be between 0 and 1." >&2
  exit 2
fi

if [[ -n "$reputation_provider" && "$reputation_provider" != "phishtank" && "$reputation_provider" != "google-webrisk" ]]; then
  echo "--reputation-provider must be phishtank or google-webrisk." >&2
  exit 2
fi
if [[ "$web_risk_key_prompt" -eq 1 && ( "$api_key_prompt" -eq 1 || -n "$web_risk_key_file" ) ]]; then
  echo "Select only one provider key prompt." >&2
  exit 2
fi
if [[ -n "$web_risk_key_file" && "$api_key_prompt" -eq 1 ]]; then
  echo "A Web Risk key cannot be combined with --api-key-prompt." >&2
  exit 2
fi
if [[ -n "$web_risk_monthly_limit" && ( ! "$web_risk_monthly_limit" =~ ^[0-9]+$ || "$web_risk_monthly_limit" -lt 1 || "$web_risk_monthly_limit" -gt 10000000 ) ]]; then
  echo "--web-risk-monthly-limit must be between 1 and 10000000." >&2; exit 2
fi
if [[ -n "$web_risk_negative_cache_seconds" && ( ! "$web_risk_negative_cache_seconds" =~ ^[0-9]+$ || "$web_risk_negative_cache_seconds" -gt 86400 ) ]]; then
  echo "--web-risk-negative-cache-seconds must be between 0 and 86400." >&2; exit 2
fi
for threat_type in "${web_risk_threat_types[@]}"; do
  case "$threat_type" in SOCIAL_ENGINEERING|MALWARE|UNWANTED_SOFTWARE) ;; *)
    echo "Unsupported Web Risk threat type: $threat_type" >&2; exit 2 ;;
  esac
done

# Profile defaults are appended before any explicit rule arguments so the
# user's later value wins when argparse processes a repeated option.
if [[ "$environment" == "staging" ]]; then
  rule_args=(--negative-level 3 "${rule_args[@]}")
else
  rule_args=(--negative-level 0 "${rule_args[@]}")
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

if [[ -z "$model" ]]; then
  if [[ -f "$REPOSITORY_ROOT/model.joblib" && -f "$REPOSITORY_ROOT/scaler.joblib" ]]; then
    model="$REPOSITORY_ROOT/model.joblib"
    [[ -n "$legacy_scaler" ]] || legacy_scaler="$REPOSITORY_ROOT/scaler.joblib"
    log_verbose "Automatically selected the repository's original model and scaler."
  else
    echo "No model was supplied and model.joblib/scaler.joblib were not both found at $REPOSITORY_ROOT." >&2
    echo "Supply --model and, for the original model, --legacy-scaler." >&2
    exit 1
  fi
fi

[[ -f "$model" ]] || { echo "Model not found: $model" >&2; exit 1; }
if [[ -n "$legacy_scaler" ]]; then
  [[ -f "$legacy_scaler" ]] || { echo "Legacy scaler not found: $legacy_scaler" >&2; exit 1; }
fi
if [[ -n "$config" ]]; then
  [[ -f "$config" ]] || { echo "Classifier configuration not found: $config" >&2; exit 1; }
  python3 -m json.tool "$config" >/dev/null
fi

required=(
  "$SCRIPT_DIR/configure-rules.py"
  "$SCRIPT_DIR/install-phase4.sh"
  "$SCRIPT_DIR/install-ml-model.py"
  "$SCRIPT_DIR/verification/verify-ml-integration.py"
  "$WAZUH_HOME/etc/ossec.conf"
  "$WAZUH_HOME/bin/wazuh-analysisd"
  "$WAZUH_HOME/bin/wazuh-logtest"
)
for path in "${required[@]}"; do
  [[ -e "$path" ]] || { echo "Required file not found: $path" >&2; exit 1; }
  log_verbose "Found $path"
done
getent group wazuh >/dev/null || { echo "Required Wazuh group 'wazuh' was not found." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemctl is required." >&2; exit 1; }

managed=(
  "$WAZUH_HOME/etc/ossec.conf"
  "$WAZUH_HOME/etc/rules/edge_navigation_rules.xml"
  "$WAZUH_HOME/etc/rules/edge_phishing_classification_rules.xml"
  "$WAZUH_HOME/etc/rules/edge_phishing_pipeline_rules.xml"
  "$WAZUH_HOME/etc/edge-phishing-rule-policy.json"
  "$WAZUH_HOME/etc/edge-phishing-classifier.json"
  "$WAZUH_HOME/etc/edge-phishing-deployment.json"
  "$WAZUH_HOME/etc/edge-google-web-risk.key"
  "$WAZUH_HOME/var/edge-phishing-classifier/cache.sqlite3"
  "$WAZUH_HOME/etc/edge-url-model.joblib"
  "$WAZUH_HOME/etc/edge-legacy-model.joblib"
  "$WAZUH_HOME/etc/edge-legacy-scaler.joblib"
  "$WAZUH_HOME/integrations/custom-edge-phishing-classifier"
  "$WAZUH_HOME/integrations/custom-edge-phishing-classifier.py"
  "$WAZUH_HOME/integrations/edge_phishing_classifier.py"
  "$WAZUH_HOME/integrations/url_ml.py"
  "$WAZUH_HOME/integrations/legacy_url_ml.py"
  "$WAZUH_HOME/integrations/google_web_risk.py"
)

installed_provider=""
if [[ -f "$WAZUH_HOME/etc/edge-phishing-classifier.json" ]]; then
  installed_provider="$(python3 - "$WAZUH_HOME/etc/edge-phishing-classifier.json" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
    print(value.get("reputation", {}).get("provider", "phishtank").replace("_", "-"))
except Exception:
    print("")
PY
)"
fi
[[ -n "$reputation_provider" ]] || reputation_provider="${installed_provider:-phishtank}"
if [[ "$reputation_provider" == "google-webrisk" && "$api_key_prompt" -eq 1 ]]; then
  echo "--api-key-prompt is for PhishTank; use --web-risk-key-prompt." >&2
  exit 2
fi
if [[ "$reputation_provider" == "phishtank" && ( "$web_risk_key_prompt" -eq 1 || -n "$web_risk_key_file" || ${#web_risk_threat_types[@]} -gt 0 || -n "$web_risk_monthly_limit" || -n "$web_risk_negative_cache_seconds" ) ]]; then
  echo "Web Risk options require --reputation-provider google-webrisk." >&2
  exit 2
fi
if [[ "$reputation_provider" == "google-webrisk" ]]; then
  unmanaged="$(python3 - "$WAZUH_HOME/etc/rules" "$WAZUH_HOME/etc/ossec.conf" <<'PY'
import re, sys
from pathlib import Path
managed={"edge_navigation_rules.xml","edge_phishing_classification_rules.xml","edge_phishing_pipeline_rules.xml"}
for path in Path(sys.argv[1]).glob("*.xml"):
    if path.name in managed: continue
    text=re.sub(r"<!--.*?-->", "", path.read_text(encoding="utf-8", errors="replace"), flags=re.S)
    if re.search(r"phishtank|custom-phishtank", text, re.I): print(path)
ossec=Path(sys.argv[2])
text=re.sub(r"<!--.*?-->", "", ossec.read_text(encoding="utf-8", errors="replace"), flags=re.S)
if re.search(r"<name>[^<]*phishtank[^<]*</name>", text, re.I): print(f"{ossec} (unmanaged PhishTank integration)")
PY
)"
  if [[ -n "$unmanaged" ]]; then
    echo "Active unmanaged PhishTank rules must be disabled before Google Web Risk can be installed:" >&2
    echo "$unmanaged" >&2
    exit 1
  fi
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="$WAZUH_HOME/backup/edge-complete-install-$timestamp"
mkdir -p "$backup_dir/files"
chmod 0750 "$backup_dir" "$backup_dir/files"
for index in "${!managed[@]}"; do
  path="${managed[$index]}"
  if [[ -e "$path" ]]; then
    cp -a -- "$path" "$backup_dir/files/$index"
    printf '%s\t%s\n' "$index" "$path" >> "$backup_dir/manifest.tsv"
  fi
done
log_verbose "Pre-installation snapshot stored at $backup_dir"

rollback() {
  local index path
  echo "Rolling the complete Wazuh-server installation back from $backup_dir" >&2
  for index in "${!managed[@]}"; do
    path="${managed[$index]}"
    rm -f -- "$path"
    if [[ -e "$backup_dir/files/$index" ]]; then
      mkdir -p -- "$(dirname -- "$path")"
      cp -a -- "$backup_dir/files/$index" "$path"
    fi
  done
  "$WAZUH_HOME/bin/wazuh-analysisd" -t || true
  systemctl restart wazuh-manager || true
}

handle_error() {
  local status=$?
  trap - ERR INT TERM
  if [[ "$transaction_active" -eq 1 ]]; then
    transaction_active=0
    rollback || true
  fi
  echo "Complete Wazuh-server installation failed." >&2
  exit "$status"
}
trap handle_error ERR INT TERM
transaction_active=1

if [[ -n "$installed_provider" && "$installed_provider" != "$reputation_provider" ]]; then
  echo "[0/5] Disabling the managed $installed_provider provider before switching providers..."
  rm -f -- "$WAZUH_HOME/etc/rules/edge_navigation_rules.xml" \
    "$WAZUH_HOME/etc/rules/edge_phishing_classification_rules.xml" \
    "$WAZUH_HOME/etc/rules/edge_phishing_pipeline_rules.xml" \
    "$WAZUH_HOME/etc/edge-phishing-rule-policy.json"
  OSSEC_CONFIG="$WAZUH_HOME/etc/ossec.conf" python3 - <<'PY'
import os
from pathlib import Path
path=Path(os.environ["OSSEC_CONFIG"]); text=path.read_text(encoding="utf-8")
begin="<!-- BEGIN EDGE PHISHING CLASSIFIER -->"; end="<!-- END EDGE PHISHING CLASSIFIER -->"
if (begin in text) != (end in text): raise SystemExit("Incomplete managed integration marker")
if begin in text:
    start=text.rfind("\n", 0, text.index(begin))+1
    finish=text.index(end, start)+len(end)
    text=text[:start]+text[finish:].lstrip("\n")
    path.write_text(text, encoding="utf-8")
PY
  "$WAZUH_HOME/bin/wazuh-analysisd" -t
  systemctl restart wazuh-manager
  systemctl is-active --quiet wazuh-manager
fi

effective_config="$(mktemp)"
base_config="$config"
[[ -n "$base_config" ]] || base_config="$WAZUH_HOME/etc/edge-phishing-classifier.json"
[[ -f "$base_config" ]] || base_config="$SCRIPT_DIR/phase4/config.json"
if [[ "$reputation_provider" == "google-webrisk" ]]; then
  key_path="$WAZUH_HOME/etc/edge-google-web-risk.key"
  if [[ "$web_risk_key_prompt" -eq 1 ]]; then
    read -r -s -p "Google Web Risk API key: " web_risk_api_key
    echo
    [[ "$web_risk_api_key" =~ ^[^[:space:]]{20,256}$ ]] || { echo "The Web Risk key is empty or invalid." >&2; false; }
    key_temp="$(mktemp "$WAZUH_HOME/etc/.edge-google-web-risk.key.XXXXXX")"
    printf '%s\n' "$web_risk_api_key" > "$key_temp"
    install -o root -g wazuh -m 0640 "$key_temp" "$key_temp.installed"
    mv -f -- "$key_temp.installed" "$key_path"
    rm -f -- "$key_temp"
    unset web_risk_api_key
  elif [[ -n "$web_risk_key_file" ]]; then
    [[ -f "$web_risk_key_file" ]] || { echo "Web Risk key file not found: $web_risk_key_file" >&2; false; }
    key_temp="$(mktemp "$WAZUH_HOME/etc/.edge-google-web-risk.key.XXXXXX")"
    install -o root -g wazuh -m 0640 "$web_risk_key_file" "$key_temp"
    mv -f -- "$key_temp" "$key_path"
  fi
  [[ -f "$key_path" ]] || { echo "No Web Risk key exists at $key_path; use --web-risk-key-prompt." >&2; false; }
  PYTHONPATH="$SCRIPT_DIR/phase4" python3 - "$key_path" <<'PY'
import sys
from google_web_risk import read_api_key
read_api_key(sys.argv[1])
PY
fi
BASE_CONFIG="$base_config" OUTPUT_CONFIG="$effective_config" PROVIDER="$reputation_provider" \
WEB_RISK_KEY_FILE="$WAZUH_HOME/etc/edge-google-web-risk.key" \
WEB_RISK_THREAT_TYPES="$(IFS=,; echo "${web_risk_threat_types[*]-}")" \
WEB_RISK_MONTHLY_LIMIT="$web_risk_monthly_limit" \
WEB_RISK_NEGATIVE_CACHE_SECONDS="$web_risk_negative_cache_seconds" python3 - <<'PY'
import json, os
from pathlib import Path
value=json.loads(Path(os.environ["BASE_CONFIG"]).read_text(encoding="utf-8"))
provider=os.environ["PROVIDER"]
if provider == "google-webrisk":
    reputation=value.get("reputation", {})
    if not isinstance(reputation, dict): reputation={}
    supplied=[x for x in os.environ["WEB_RISK_THREAT_TYPES"].split(",") if x]
    reputation.update({
        "provider":"google_webrisk",
        "endpoint":"https://webrisk.googleapis.com/v1/uris:search",
        "api_key_file":os.environ["WEB_RISK_KEY_FILE"],
        "threat_types":supplied or reputation.get("threat_types", ["SOCIAL_ENGINEERING"]),
    })
    reputation.setdefault("timeout_seconds", 8)
    reputation.setdefault("negative_cache_seconds", 300)
    reputation.setdefault("maximum_response_bytes", 65536)
    reputation.setdefault("monthly_request_limit", 90000)
    reputation.setdefault("retry_count", 1)
    reputation.setdefault("circuit_breaker_seconds", 300)
    if os.environ["WEB_RISK_MONTHLY_LIMIT"]:
        reputation["monthly_request_limit"]=int(os.environ["WEB_RISK_MONTHLY_LIMIT"])
    if os.environ["WEB_RISK_NEGATIVE_CACHE_SECONDS"]:
        reputation["negative_cache_seconds"]=int(os.environ["WEB_RISK_NEGATIVE_CACHE_SECONDS"])
    value["reputation"]=reputation
else:
    value["reputation"]={"provider":"phishtank","timeout_seconds":8,"negative_cache_seconds":900}
Path(os.environ["OUTPUT_CONFIG"]).write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")
PY

echo "[1/5] Installing the configurable Edge navigation and classification rules..."
configure_command=(python3 "$SCRIPT_DIR/configure-rules.py" --install --wazuh-home "$WAZUH_HOME" --reputation-provider "$reputation_provider")
[[ "$wizard" -eq 1 ]] && configure_command+=(--wizard)
[[ "$verbose" -eq 1 ]] && configure_command+=(-v)
configure_command+=("${rule_args[@]}")
"${configure_command[@]}"

echo "[2/5] Installing the structured phishing-reputation integration..."
phase4_command=(bash "$SCRIPT_DIR/install-phase4.sh")
[[ "$verbose" -eq 1 ]] && phase4_command+=(-v)
phase4_command+=(--config "$effective_config")
[[ "$api_key_prompt" -eq 1 ]] && phase4_command+=(--api-key-prompt)
WAZUH_HOME="$WAZUH_HOME" "${phase4_command[@]}"

echo "[3/5] Installing and enabling the ML model..."
model_command=(python3 "$SCRIPT_DIR/install-ml-model.py" --wazuh-home "$WAZUH_HOME" --model "$model" --test-url "$test_url")
[[ -n "$legacy_scaler" ]] && model_command+=(--legacy-scaler "$legacy_scaler")
[[ -n "$threshold" ]] && model_command+=(--threshold "$threshold")
[[ -n "$review_threshold" ]] && model_command+=(--review-threshold "$review_threshold")
if [[ -n "$legacy_scaler" && "$legacy_network_features" -eq 0 ]]; then
  model_command+=(--disable-legacy-network-features)
fi
[[ "$verbose" -eq 1 ]] && model_command+=(-v)
"${model_command[@]}"

echo "[4/5] Verifying the installed ML fallback and selected Wazuh rule..."
ml_test_command=(python3 "$SCRIPT_DIR/verification/verify-ml-integration.py" --wazuh-home "$WAZUH_HOME" --url "$test_url")
[[ "$verbose" -eq 1 ]] && ml_test_command+=(-v)
"${ml_test_command[@]}"

echo "[5/5] Performing final manager validation..."
"$WAZUH_HOME/bin/wazuh-analysisd" -t
systemctl is-active --quiet wazuh-manager

RULE_POLICY="$WAZUH_HOME/etc/edge-phishing-rule-policy.json" \
CLASSIFIER_CONFIG="$WAZUH_HOME/etc/edge-phishing-classifier.json" \
PIPELINE_RULES="$WAZUH_HOME/etc/rules/edge_phishing_pipeline_rules.xml" \
EXPECTED_PROVIDER="$reputation_provider" python3 - <<'PY'
import json, os, re
from pathlib import Path
expected=os.environ["EXPECTED_PROVIDER"].replace("-", "_")
config=json.loads(Path(os.environ["CLASSIFIER_CONFIG"]).read_text(encoding="utf-8"))
policy=json.loads(Path(os.environ["RULE_POLICY"]).read_text(encoding="utf-8"))
rules=Path(os.environ["PIPELINE_RULES"]).read_text(encoding="utf-8")
configured=config.get("reputation", {}).get("provider", "phishtank").replace("-", "_")
selected=policy.get("reputation_provider", "phishtank").replace("-", "_")
if configured != expected or selected != expected:
    raise SystemExit("post-install provider audit found inconsistent configuration")
sources=set(re.findall(r'<field name="classification.source" type="pcre2">\^([^$]+)\$</field>', rules))
providers=sources & {"phishtank", "google_webrisk"}
if providers != {expected}:
    raise SystemExit(f"post-install provider audit expected only {expected}, found {sorted(providers)}")
PY

policy="$WAZUH_HOME/etc/edge-phishing-rule-policy.json"
config_path="$WAZUH_HOME/etc/edge-phishing-classifier.json"
deployment_manifest="$WAZUH_HOME/etc/edge-phishing-deployment.json"
DEPLOYMENT_ENVIRONMENT="$environment" DEPLOYMENT_MANIFEST="$deployment_manifest" \
REPUTATION_PROVIDER="$reputation_provider" RULE_POLICY="$policy" CLASSIFIER_CONFIG="$config_path" python3 - <<'PY'
import json
import os
import time
from pathlib import Path

path = Path(os.environ["DEPLOYMENT_MANIFEST"])
config = json.loads(Path(os.environ["CLASSIFIER_CONFIG"]).read_text(encoding="utf-8"))
reputation = config.get("reputation", {})
value = {
    "schema_version": 1,
    "deployment_environment": os.environ["DEPLOYMENT_ENVIRONMENT"],
    "reputation_provider": os.environ["REPUTATION_PROVIDER"],
    "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "rule_policy": os.environ["RULE_POLICY"],
    "classifier_config": os.environ["CLASSIFIER_CONFIG"],
    "reputation_threat_types": reputation.get("threat_types", []),
    "reputation_monthly_request_limit": reputation.get("monthly_request_limit"),
}
path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
PY
chown root:wazuh "$deployment_manifest"
chmod 0640 "$deployment_manifest"

transaction_active=0
trap - ERR INT TERM
rm -f -- "$effective_config"

echo
echo "Complete Wazuh-server phishing pipeline installed successfully."
echo "Pre-installation snapshot: $backup_dir"
echo "Rule policy: $policy"
echo "Classifier configuration: $config_path"
echo "Deployment manifest: $deployment_manifest"
echo "Deployment environment: $environment"
echo "Reputation provider: $reputation_provider"
if [[ -n "$legacy_scaler" ]]; then
  echo "Legacy network features: $([[ "$legacy_network_features" -eq 1 ]] && echo enabled || echo disabled)"
else
  echo "Legacy network features: not applicable (modern model mode)"
fi
echo
echo "The installer validated navigation, reputation, and ML rule structures and ran ML offline."
echo "It did not require a live reputation lookup; external API availability is operational state."
echo "Next, open a fresh Edge URL, copy its event_id, and run:"
echo "  sudo bash $SCRIPT_DIR/verification/verify-navigation-ingestion.sh --event-id EVENT_ID --wait 60"
