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
test_url="https://example.test/login"
environment="production"
api_key_prompt=0
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
  --config FILE                   Classifier JSON configuration.
  --api-key-prompt                Securely prompt for an optional PhishTank key.
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
  --ml-rule-id ID                 --ml-level LEVEL
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
    --config) need_value "$@"; config="$2"; shift 2 ;;
    --test-url) need_value "$@"; test_url="$2"; shift 2 ;;
    --environment) need_value "$@"; environment="${2,,}"; shift 2 ;;
    --api-key-prompt) api_key_prompt=1; shift ;;
    --enable-legacy-network-features) legacy_network_features=1; shift ;;
    --wizard) wizard=1; shift ;;
    -v|--verbose) verbose=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --group-name|--preferred-start|--navigation-rule-id|--navigation-level|\
    --classification-base-rule-id|--classification-base-level|\
    --phishtank-rule-id|--phishtank-level|--ml-rule-id|--ml-level|\
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
  "$WAZUH_HOME/etc/edge-url-model.joblib"
  "$WAZUH_HOME/etc/edge-legacy-model.joblib"
  "$WAZUH_HOME/etc/edge-legacy-scaler.joblib"
  "$WAZUH_HOME/integrations/custom-edge-phishing-classifier"
  "$WAZUH_HOME/integrations/custom-edge-phishing-classifier.py"
  "$WAZUH_HOME/integrations/edge_phishing_classifier.py"
  "$WAZUH_HOME/integrations/url_ml.py"
  "$WAZUH_HOME/integrations/legacy_url_ml.py"
)

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

echo "[1/5] Installing the configurable Edge navigation and classification rules..."
configure_command=(python3 "$SCRIPT_DIR/configure-rules.py" --install --wazuh-home "$WAZUH_HOME")
[[ "$wizard" -eq 1 ]] && configure_command+=(--wizard)
[[ "$verbose" -eq 1 ]] && configure_command+=(-v)
configure_command+=("${rule_args[@]}")
"${configure_command[@]}"

echo "[2/5] Installing the structured phishing-reputation integration..."
phase4_command=(bash "$SCRIPT_DIR/install-phase4.sh")
[[ "$verbose" -eq 1 ]] && phase4_command+=(-v)
[[ -n "$config" ]] && phase4_command+=(--config "$config")
[[ "$api_key_prompt" -eq 1 ]] && phase4_command+=(--api-key-prompt)
WAZUH_HOME="$WAZUH_HOME" "${phase4_command[@]}"

echo "[3/5] Installing and enabling the ML model..."
model_command=(python3 "$SCRIPT_DIR/install-ml-model.py" --wazuh-home "$WAZUH_HOME" --model "$model" --test-url "$test_url")
[[ -n "$legacy_scaler" ]] && model_command+=(--legacy-scaler "$legacy_scaler")
[[ -n "$threshold" ]] && model_command+=(--threshold "$threshold")
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

policy="$WAZUH_HOME/etc/edge-phishing-rule-policy.json"
config_path="$WAZUH_HOME/etc/edge-phishing-classifier.json"
deployment_manifest="$WAZUH_HOME/etc/edge-phishing-deployment.json"
DEPLOYMENT_ENVIRONMENT="$environment" DEPLOYMENT_MANIFEST="$deployment_manifest" \
RULE_POLICY="$policy" CLASSIFIER_CONFIG="$config_path" python3 - <<'PY'
import json
import os
import time
from pathlib import Path

path = Path(os.environ["DEPLOYMENT_MANIFEST"])
value = {
    "schema_version": 1,
    "deployment_environment": os.environ["DEPLOYMENT_ENVIRONMENT"],
    "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "rule_policy": os.environ["RULE_POLICY"],
    "classifier_config": os.environ["CLASSIFIER_CONFIG"],
}
path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
PY
chown root:wazuh "$deployment_manifest"
chmod 0640 "$deployment_manifest"

transaction_active=0
trap - ERR INT TERM

echo
echo "Complete Wazuh-server phishing pipeline installed successfully."
echo "Pre-installation snapshot: $backup_dir"
echo "Rule policy: $policy"
echo "Classifier configuration: $config_path"
echo "Deployment manifest: $deployment_manifest"
echo "Deployment environment: $environment"
if [[ -n "$legacy_scaler" ]]; then
  echo "Legacy network features: $([[ "$legacy_network_features" -eq 1 ]] && echo enabled || echo disabled)"
else
  echo "Legacy network features: not applicable (modern model mode)"
fi
echo
echo "The installer validated navigation, reputation, and ML rule structures and ran ML offline."
echo "It did not require a live PhishTank response; external API availability is operational state."
echo "Next, open a fresh Edge URL, copy its event_id, and run:"
echo "  sudo bash $SCRIPT_DIR/verification/verify-navigation-ingestion.sh --event-id EVENT_ID --wait 60"
