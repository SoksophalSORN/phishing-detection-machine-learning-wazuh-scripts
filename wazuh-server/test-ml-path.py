#!/usr/bin/env python3
"""Test the installed ML fallback and its Wazuh rule without network access."""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
import uuid
from pathlib import Path
from types import ModuleType


RUNTIME_MARKER = "EDGE_ML_WAZUH_PYTHON"
RUNTIME_PROBE = (
    "import sys,types;"
    "m=types.ModuleType('_posixshmem');"
    "m.shm_unlink=lambda *a,**k:None;"
    "m.shm_open=lambda *a,**k:None;"
    "sys.modules.setdefault('_posixshmem',m);"
    "import joblib,sklearn,numpy"
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--url", required=True, help="controlled HTTP/HTTPS URL to score; it is not opened")
    parser.add_argument("--expect", choices=("suspicious", "unlikely"))
    parser.add_argument("--wazuh-home", default="/var/ossec")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Python module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def expected_rule(home: Path, status: str) -> tuple[int, int]:
    manifest = home / "etc" / "edge-phishing-rule-policy.json"
    if manifest.exists():
        policy = json.loads(manifest.read_text(encoding="utf-8"))
        if status == "suspicious":
            return int(policy["ml_rule_id"]), int(policy["ml_level"])
        return int(policy["negative_rule_id"]), int(policy["negative_level"])
    return (100114, 9) if status == "suspicious" else (100113, 3)


def use_wazuh_python(home: Path) -> None:
    if os.environ.get(RUNTIME_MARKER) == "1":
        return
    candidates = [
        home / "var" / "edge-phishing-classifier" / "venv" / "bin" / "python3",
        home / "framework" / "python" / "bin" / "python3",
    ]
    for candidate in candidates:
        if not candidate.is_file() or Path(sys.executable).resolve() == candidate.resolve():
            continue
        compatible = subprocess.run(
            [str(candidate), "-c", RUNTIME_PROBE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if compatible.returncode == 0:
            environment = os.environ.copy()
            environment[RUNTIME_MARKER] = "1"
            os.execve(
                str(candidate),
                [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]],
                environment,
            )


def main() -> int:
    args = arguments()
    home = Path(args.wazuh_home)
    use_wazuh_python(home)
    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("--url must be an HTTP/HTTPS URL with a hostname")
    if parsed.username or parsed.password:
        raise SystemExit("--url must not contain embedded credentials")

    integrations = home / "integrations"
    sys.path.insert(0, str(integrations))
    classifier = load_module(integrations / "edge_phishing_classifier.py", "installed_edge_classifier")
    settings = classifier.load_settings(home / "etc" / "edge-phishing-classifier.json")
    if not settings.ml_enabled:
        raise SystemExit("ML is disabled in edge-phishing-classifier.json")
    if settings.ml_mode == "legacy_svr":
        settings = dataclasses.replace(settings, legacy_network_features=False)

    source_event_id = f"safe-ml-test-{uuid.uuid4()}"
    navigation = {
        "url": args.url,
        "url_host": parsed.hostname.lower(),
        "source_event_id": source_event_id,
        "source_alert_id": f"synthetic-{uuid.uuid4()}",
        "source_rule_id": settings.navigation_rule_id,
        "agent": {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1"},
    }

    def forced_not_found(_url, _settings):
        return {
            "status": "not_found", "malicious": False, "in_database": False,
            "verified": False, "valid": False,
        }

    with tempfile.TemporaryDirectory() as directory:
        cache = classifier.ResultCache(Path(directory) / "cache.sqlite3")
        try:
            event = classifier.classify_navigation(
                navigation, settings, cache, query=forced_not_found
            )
        finally:
            cache.close()

    classification = event["classification"]
    status = classification["status"]
    print("The target URL was not opened and no network request was made.")
    print(json.dumps({"source_event_id": source_event_id, "classification": classification}, indent=2))
    if args.expect and status != args.expect:
        print(f"[FAIL] Expected {args.expect}, got {status}.", file=sys.stderr)
        return 1

    rule_id, level = expected_rule(home, status)
    analysisd = home / "bin" / "wazuh-analysisd"
    logtest = home / "bin" / "wazuh-logtest"
    subprocess.run([str(analysisd), "-t"], check=True)
    completed = subprocess.run(
        [str(logtest), "-v" if args.verbose else "-q", "-U", f"{rule_id}:{level}:json"],
        input=json.dumps(event, separators=(",", ":")) + "\n", text=True, check=False,
    )
    if completed.returncode != 0:
        print(f"[FAIL] Wazuh rule {rule_id} level {level} did not match.", file=sys.stderr)
        return 1
    print(f"[PASS] ML fallback returned {status} and matched Wazuh rule {rule_id} at level {level}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
