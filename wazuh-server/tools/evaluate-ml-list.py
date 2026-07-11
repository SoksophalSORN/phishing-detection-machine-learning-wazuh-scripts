#!/usr/bin/env python3
"""Evaluate ML against a local suspected-phishing URL list without network access."""

from __future__ import annotations

import argparse
import csv
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
from typing import Any, Iterable


RUNTIME_MARKER = "EDGE_ML_WAZUH_PYTHON"
RUNTIME_PROBE = (
    "import sys,types;"
    "m=types.ModuleType('_posixshmem');"
    "m.shm_unlink=lambda *a,**k:None;"
    "m.shm_open=lambda *a,**k:None;"
    "sys.modules.setdefault('_posixshmem',m);"
    "import joblib,sklearn,numpy"
)
UNVERIFIED_VALUES = {"0", "false", "n", "no", "u", "unverified"}
VERIFIED_VALUES = {"1", "true", "y", "yes", "verified"}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--input", required=True, type=Path, help="local CSV, JSON, JSONL, or text file")
    parser.add_argument("--output", required=True, type=Path, help="JSONL result file (created mode 0600)")
    parser.add_argument("--format", choices=("auto", "csv", "json", "jsonl", "text"), default="auto")
    parser.add_argument("--url-column", default="url", help="URL field name in CSV/JSON records")
    parser.add_argument("--id-column", default="phish_id", help="optional sample ID field name")
    parser.add_argument("--verified-column", default="verified", help="verification field name")
    parser.add_argument(
        "--include-verified", action="store_true",
        help="score verified rows too; normally they are excluded from an unverified test",
    )
    parser.add_argument("--limit", type=int, default=1000, help="maximum unique accepted URLs")
    parser.add_argument("--wazuh-home", default="/var/ossec")
    parser.add_argument("--fail-under", type=float, help="fail if suspicious fraction is below this value (0..1)")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def detect_format(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix == ".json":
        return "json"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    return "text"


def records_from_file(path: Path, input_format: str, url_column: str) -> tuple[list[dict[str, Any]], bool]:
    if input_format == "csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or url_column not in reader.fieldnames:
                raise ValueError(f"CSV must contain a {url_column!r} column")
            return list(reader), True
    if input_format == "json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            for key in ("results", "entries", "urls"):
                if isinstance(value.get(key), list):
                    value = value[key]
                    break
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError("JSON input must be an array of objects")
        return value, True
    if input_format == "jsonl":
        records: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"JSONL line {line_number} is not an object")
                records.append(value)
        return records, True
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if value and not value.startswith("#"):
                records.append({url_column: value})
    return records, False


def verification_state(value: Any) -> bool | None:
    normalized = str(value).strip().lower()
    if normalized in UNVERIFIED_VALUES:
        return False
    if normalized in VERIFIED_VALUES:
        return True
    return None


def valid_url(value: Any) -> tuple[str, str]:
    raw_url = str(value).strip()
    if len(raw_url) > 8192:
        raise ValueError("URL exceeds 8192 characters")
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL is not HTTP/HTTPS with a hostname")
    if parsed.username or parsed.password:
        raise ValueError("URL contains embedded credentials")
    return raw_url, parsed.hostname.lower()


def select_samples(
    records: Iterable[dict[str, Any]], url_column: str, id_column: str,
    verified_column: str, include_verified: bool, limit: int,
) -> tuple[list[dict[str, str]], dict[str, int], bool]:
    selected: list[dict[str, str]] = []
    seen: set[str] = set()
    counts = {"rows": 0, "invalid": 0, "verified_skipped": 0, "duplicates": 0}
    verification_field_seen = False
    for record in records:
        counts["rows"] += 1
        if verified_column in record:
            verification_field_seen = True
            state = verification_state(record.get(verified_column))
            if not include_verified and state is not False:
                counts["verified_skipped"] += 1
                continue
        try:
            raw_url, hostname = valid_url(record.get(url_column, ""))
        except (TypeError, ValueError):
            counts["invalid"] += 1
            continue
        if raw_url in seen:
            counts["duplicates"] += 1
            continue
        seen.add(raw_url)
        selected.append({
            "sample_id": str(record.get(id_column, "")),
            "url": raw_url,
            "url_host": hostname,
        })
        if len(selected) >= limit:
            break
    return selected, counts, verification_field_seen


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Python module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


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
            [str(candidate), "-c", RUNTIME_PROBE], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False,
        )
        if compatible.returncode == 0:
            environment = os.environ.copy()
            environment[RUNTIME_MARKER] = "1"
            os.execve(str(candidate), [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]], environment)


def forced_not_found(_url: str, _settings: Any) -> dict[str, Any]:
    return {
        "status": "not_found", "malicious": False, "in_database": False,
        "verified": False, "valid": False,
    }


def secure_jsonl(path: Path, results: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
    os.chmod(path, 0o600)


def main() -> int:
    args = arguments()
    if args.limit < 1 or args.limit > 100000:
        raise SystemExit("--limit must be between 1 and 100000")
    if args.fail_under is not None and not 0 <= args.fail_under <= 1:
        raise SystemExit("--fail-under must be between 0 and 1")
    if args.input.resolve() == args.output.resolve():
        raise SystemExit("--input and --output must be different files")

    home = Path(args.wazuh_home)
    use_wazuh_python(home)
    input_format = detect_format(args.input, args.format)
    try:
        records, structured = records_from_file(args.input, input_format, args.url_column)
        samples, counts, verification_seen = select_samples(
            records, args.url_column, args.id_column, args.verified_column,
            args.include_verified, args.limit,
        )
    except (OSError, ValueError, json.JSONDecodeError, csv.Error) as exc:
        raise SystemExit(f"Cannot read input: {exc}") from exc

    if structured and not verification_seen and not args.include_verified:
        print(
            f"[WARN] No {args.verified_column!r} field was found; treating the supplied records "
            "as an operator-curated unverified list.", file=sys.stderr,
        )
    if not samples:
        detail = " All rows were verified or had an unknown verification value." if verification_seen else ""
        raise SystemExit(f"No valid unverified URLs were selected.{detail}")

    integrations = home / "integrations"
    sys.path.insert(0, str(integrations))
    classifier = load_module(integrations / "edge_phishing_classifier.py", "installed_edge_classifier_batch")
    settings = classifier.load_settings(home / "etc" / "edge-phishing-classifier.json")
    if not settings.ml_enabled:
        raise SystemExit("ML is disabled in edge-phishing-classifier.json")
    if settings.ml_mode == "legacy_svr":
        settings = dataclasses.replace(settings, legacy_network_features=False)

    print(f"Scoring {len(samples)} unique URL(s); no URL, WHOIS, DNS, or PhishTank request will be made.")
    results: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    with tempfile.TemporaryDirectory() as directory:
        cache = classifier.ResultCache(Path(directory) / "cache.sqlite3")
        try:
            for index, sample in enumerate(samples, 1):
                navigation = {
                    **sample,
                    "source_event_id": f"offline-ml-list-{uuid.uuid4()}",
                    "source_alert_id": "offline-batch",
                    "source_rule_id": settings.navigation_rule_id,
                    "agent": {"id": "000", "name": "offline-batch", "ip": "127.0.0.1"},
                }
                try:
                    event = classifier.classify_navigation(navigation, settings, cache, query=forced_not_found)
                    classification = event["classification"]
                    status = str(classification["status"])
                    result = {
                        **sample,
                        "status": status,
                        "score": classification.get("score"),
                        "threshold": classification.get("threshold"),
                        "model_kind": classification.get("model_kind"),
                        "model_version": classification.get("model_version"),
                        "calibrated": classification.get("calibrated"),
                    }
                except Exception as exc:  # preserve failures per sample and finish the evaluation
                    status = "error"
                    result = {**sample, "status": status, "error_type": type(exc).__name__, "error": str(exc)}
                results.append(result)
                status_counts[status] = status_counts.get(status, 0) + 1
                if args.verbose and (index % 25 == 0 or index == len(samples)):
                    print(f"[VERBOSE] Scored {index}/{len(samples)}")
        finally:
            cache.close()

    secure_jsonl(args.output, results)
    suspicious = status_counts.get("suspicious", 0)
    evaluated = suspicious + status_counts.get("unlikely", 0)
    fraction = suspicious / evaluated if evaluated else 0.0
    summary = {
        **counts,
        "selected": len(samples),
        "evaluated": evaluated,
        "suspicious": suspicious,
        "unlikely": status_counts.get("unlikely", 0),
        "errors": status_counts.get("error", 0),
        "suspicious_fraction": round(fraction, 6),
        "output": str(args.output),
    }
    print(json.dumps(summary, indent=2))
    print("These are model screening results for unverified candidates, not measured accuracy or confirmed phishing labels.")
    if args.fail_under is not None and fraction < args.fail_under:
        print(f"[FAIL] Suspicious fraction {fraction:.4f} is below {args.fail_under:.4f}.", file=sys.stderr)
        return 1
    return 1 if status_counts.get("error", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
