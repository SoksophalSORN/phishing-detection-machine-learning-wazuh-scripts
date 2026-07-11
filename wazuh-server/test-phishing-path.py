#!/usr/bin/env python3
"""Safely exercise the installed classifier without opening a phishing URL."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="verified PhishTank URL to submit; it is never opened")
    parser.add_argument("--wazuh-home", default="/var/ossec")
    parser.add_argument("--wait", type=int, default=60)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise SystemExit("--url must be an HTTP/HTTPS URL without embedded credentials")
    if not 0 <= args.wait <= 600:
        raise SystemExit("--wait must be between 0 and 600 seconds")

    home = Path(args.wazuh_home)
    integration = home / "integrations" / "custom-edge-phishing-classifier"
    config_path = home / "etc" / "edge-phishing-classifier.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    navigation_rule = str(config.get("navigation_rule_id", "100100"))
    source_event_id = f"safe-phish-test-{uuid.uuid4()}"
    alert = {
        "id": f"synthetic-{uuid.uuid4()}",
        "rule": {"id": navigation_rule},
        "agent": {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1"},
        "data": {
            "schema_version": "1",
            "event_type": "browser_navigation",
            "event_id": source_event_id,
            "browser": "edge",
            "url": args.url,
            "url_host": parsed.hostname.lower(),
            "source": "edge_extension",
        },
    }

    print("The URL will be submitted to the local classifier; the target will not be opened or downloaded.")
    print(f"Synthetic source_event_id: {source_event_id}")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
        json.dump(alert, handle)
        handle.flush()
        completed = subprocess.run([str(integration), handle.name], check=False)
    if completed.returncode != 0:
        print(f"Integration exited with status {completed.returncode}")
        return 1

    alerts_path = home / "logs" / "alerts" / "alerts.json"
    deadline = time.monotonic() + args.wait
    while True:
        if alerts_path.exists():
            with alerts_path.open("r", encoding="utf-8", errors="replace") as alerts:
                for line in alerts:
                    if source_event_id not in line or "edge-phishing-classifier" not in line:
                        continue
                    event = json.loads(line)
                    print(json.dumps({
                        "rule": event.get("rule"),
                        "data": event.get("data"),
                    }, indent=2))
                    status = event.get("data", {}).get("classification", {}).get("status")
                    return 0 if status == "malicious" else 1
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    print("No classification result appeared before the timeout.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
