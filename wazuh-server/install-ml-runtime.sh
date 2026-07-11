#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
VENV_DIR="$WAZUH_HOME/var/edge-phishing-classifier/venv"
wheelhouse=""
verbose=0

usage() {
  cat <<'USAGE'
Usage: install-ml-runtime.sh [OPTIONS]

Create a dedicated full-Python runtime for the legacy ML compatibility layer.

Options:
  --python PATH       Full system Python used to create the venv.
  --wheelhouse DIR    Install only from an offline wheel directory.
  -v, --verbose       Show pip and validation details.
  -h, --help          Show this help.

Environment:
  WAZUH_HOME          Wazuh installation root (default: /var/ossec).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; PYTHON_BIN="$2"; shift 2 ;;
    --wheelhouse) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; wheelhouse="$2"; shift 2 ;;
    -v|--verbose) verbose=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$EUID" -eq 0 ]] || { echo "Run this installer as root." >&2; exit 1; }
[[ -x "$PYTHON_BIN" ]] || { echo "Python is not executable: $PYTHON_BIN" >&2; exit 1; }
if [[ -n "$wheelhouse" && ! -d "$wheelhouse" ]]; then
  echo "Wheelhouse directory not found: $wheelhouse" >&2
  exit 1
fi

parent="$(dirname -- "$VENV_DIR")"
mkdir -p "$parent"
temporary="$parent/.venv.new.$$"
backup=""
trap 'rm -rf -- "$temporary"' EXIT

echo "[1/4] Creating ML virtual environment with $PYTHON_BIN..."
"$PYTHON_BIN" -c 'import _posixshmem' || {
  echo "$PYTHON_BIN is also missing _posixshmem; choose a full Ubuntu Python." >&2
  exit 1
}
"$PYTHON_BIN" -m venv "$temporary"

pip_options=()
if [[ -n "$wheelhouse" ]]; then
  pip_options=(--no-index --find-links "$wheelhouse")
fi
[[ "$verbose" -eq 1 ]] || pip_options+=(--quiet)

echo "[2/4] Installing legacy model runtime dependencies..."
"$temporary/bin/python3" -m pip install "${pip_options[@]}" --upgrade pip
"$temporary/bin/python3" -m pip install "${pip_options[@]}" \
  'numpy<2' 'joblib<2' 'scikit-learn==1.0.2' python-whois

echo "[3/4] Validating the runtime..."
"$temporary/bin/python3" -c \
  'import _posixshmem, joblib, sklearn, numpy, whois; print(sklearn.__version__)'

if [[ -e "$VENV_DIR" ]]; then
  backup="$parent/venv.before.$(date -u +%Y%m%dT%H%M%SZ)"
  mv -- "$VENV_DIR" "$backup"
fi
mv -- "$temporary" "$VENV_DIR"
chown -R root:wazuh "$VENV_DIR"
chmod -R o-rwx "$VENV_DIR"

echo "[4/4] Restarting wazuh-manager..."
if ! systemctl restart wazuh-manager || ! systemctl is-active --quiet wazuh-manager; then
  rm -rf -- "$VENV_DIR"
  [[ -n "$backup" ]] && mv -- "$backup" "$VENV_DIR"
  systemctl restart wazuh-manager || true
  echo "Manager restart failed; the previous runtime was restored." >&2
  exit 1
fi

echo "ML runtime installed: $VENV_DIR/bin/python3"
[[ -n "$backup" ]] && echo "Previous runtime backup: $backup"
