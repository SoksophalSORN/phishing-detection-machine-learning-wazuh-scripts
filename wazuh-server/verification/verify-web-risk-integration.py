#!/usr/bin/env python3
"""Perform one explicit live Google Web Risk lookup through the Wazuh integration."""

from __future__ import annotations

import argparse
import json
import subprocess
import sqlite3
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="URL to submit to Web Risk; it is never opened")
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
    config = json.loads((home / "etc" / "edge-phishing-classifier.json").read_text(encoding="utf-8"))
    provider = config.get("reputation", {}).get("provider", "phishtank").replace("-", "_")
    if provider != "google_webrisk":
        raise SystemExit(f"Google Web Risk is not active (configured provider: {provider})")
    navigation_rule = str(config.get("navigation_rule_id", "100100"))
    source_event_id = f"safe-web-risk-test-{uuid.uuid4()}"
    alert = {
        "id": f"synthetic-{uuid.uuid4()}",
        "rule": {"id": navigation_rule},
        "agent": {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1"},
        "data": {
            "schema_version": "1", "event_type": "browser_navigation",
            "event_id": source_event_id, "browser": "edge", "url": args.url,
            "url_host": parsed.hostname.lower(), "source": "edge_extension",
        },
    }
    print("This performs one explicit Web Risk lookup; the target URL is not opened or downloaded.")
    print(f"Synthetic source_event_id: {source_event_id}")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
        json.dump(alert, handle); handle.flush()
        completed = subprocess.run(
            [str(home / "integrations" / "custom-edge-phishing-classifier"), handle.name],
            check=False,
        )
    if completed.returncode != 0:
        print(f"Integration exited with status {completed.returncode}")
        return 1

    deadline = time.monotonic() + args.wait
    alerts_path = home / "logs" / "alerts" / "alerts.json"
    while True:
        if alerts_path.exists():
            with alerts_path.open("r", encoding="utf-8", errors="replace") as alerts:
                for line in alerts:
                    if source_event_id not in line or "edge-phishing-classifier" not in line:
                        continue
                    event = json.loads(line)
                    classification = event.get("data", {}).get("classification", {})
                    print(json.dumps({"rule": event.get("rule"), "data": event.get("data")}, indent=2))
                    cache_path = home / "var" / "edge-phishing-classifier" / "cache.sqlite3"
                    try:
                        with sqlite3.connect(cache_path) as database:
                            row = database.execute(
                                "SELECT request_count FROM reputation_usage "
                                "WHERE provider='google_webrisk' AND calendar_month=strftime('%Y-%m','now')"
                            ).fetchone()
                        print(f"Recorded Web Risk requests this UTC month: {0 if row is None else row[0]}")
                    except (OSError, sqlite3.Error):
                        print("Web Risk request counter was unavailable.")
                    if classification.get("status") == "error":
                        return 1
                    if classification.get("source") == "google_webrisk":
                        return 0
                    # A clean no-match may legitimately advance to ML.
                    return 0 if classification.get("reputation_provider", "google_webrisk") == "google_webrisk" else 1
        if time.monotonic() >= deadline:
            print("No classification result appeared before the timeout.")
            return 1
        time.sleep(1)


if __name__ == "__main__":
    raise SystemExit(main())
