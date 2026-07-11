"""Deterministic URL-only features and optional probabilistic model inference."""

from __future__ import annotations

import ipaddress
import math
import re
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any


FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "digit_ratio", "special_character_count", "subdomain_count", "path_depth",
    "hostname_is_ip", "contains_at", "contains_punycode", "hostname_has_dash",
    "character_entropy", "suspicious_token_count", "known_shortener",
    "uses_https", "explicit_port", "query_parameter_count",
]
SUSPICIOUS_TOKENS = re.compile(
    r"(?i)(account|auth|confirm|credential|invoice|login|password|payment|recover|secure|signin|support|suspend|update|verify|wallet)"
)
SHORTENERS = {
    "bit.ly", "buff.ly", "cutt.ly", "is.gd", "lnkd.in", "ow.ly", "rebrand.ly",
    "shorturl.at", "t.co", "tiny.cc", "tinyurl.com", "v.gd",
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(raw_url: str) -> list[float]:
    parsed = urllib.parse.urlsplit(raw_url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValueError("URL must be HTTP or HTTPS with a hostname")
    try:
        ipaddress.ip_address(hostname)
        hostname_is_ip = 1.0
    except ValueError:
        hostname_is_ip = 0.0
    digits = sum(character.isdigit() for character in raw_url)
    specials = sum(not character.isalnum() for character in raw_url)
    labels = [label for label in hostname.split(".") if label]
    tokens = SUSPICIOUS_TOKENS.findall(raw_url)
    try:
        explicit_port = 1.0 if parsed.port is not None else 0.0
    except ValueError:
        explicit_port = 1.0
    values = [
        len(raw_url), len(hostname), len(parsed.path), len(parsed.query),
        digits / max(len(raw_url), 1), specials, max(len(labels) - 2, 0),
        len([part for part in parsed.path.split("/") if part]), hostname_is_ip,
        1.0 if "@" in raw_url else 0.0, 1.0 if "xn--" in hostname else 0.0,
        1.0 if "-" in hostname else 0.0, _entropy(raw_url), len(tokens),
        1.0 if hostname in SHORTENERS else 0.0, 1.0 if parsed.scheme == "https" else 0.0,
        explicit_port, len(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)),
    ]
    return [float(value) for value in values]


def score_url(raw_url: str, model_path: str, threshold_override: float | None = None) -> dict[str, Any]:
    try:
        import joblib  # type: ignore
    except ImportError as exc:
        raise RuntimeError("ML is enabled but joblib is not installed") from exc
    bundle = joblib.load(Path(model_path))
    if not isinstance(bundle, dict) or bundle.get("format") != "wazuh-url-model-v1":
        raise RuntimeError("unsupported ML model bundle")
    if bundle.get("feature_names") != FEATURE_NAMES:
        raise RuntimeError("ML feature schema does not match this classifier")
    model_version = bundle.get("model_version")
    if not isinstance(model_version, str) or not model_version.strip():
        raise RuntimeError("ML model bundle has no version")
    model = bundle.get("model")
    if not hasattr(model, "predict_proba"):
        raise RuntimeError("ML model does not provide predict_proba")
    probability = float(model.predict_proba([extract_features(raw_url)])[0][1])
    threshold = float(bundle.get("threshold", 0.8) if threshold_override is None else threshold_override)
    if not 0.0 <= probability <= 1.0 or not 0.0 <= threshold <= 1.0:
        raise RuntimeError("ML probability or threshold is outside 0..1")
    return {
        "score": probability,
        "score_percent": round(probability * 100, 2),
        "threshold": threshold,
        "model_version": model_version,
        "model_kind": "calibrated_url_classifier",
        "calibrated": True,
        "compatibility_mode": False,
    }
