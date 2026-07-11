"""Compatibility inference for the project's original scaler and RBF SVR."""

from __future__ import annotations

import ipaddress
import multiprocessing
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any


SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|"
    r"is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|"
    r"su\.pr|twurl\.nl|snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|"
    r"just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|"
    r"kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|"
    r"adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|"
    r"u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
    r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
    r"link\.zip\.net",
    re.IGNORECASE,
)
LEGACY_FEATURE_NAMES = [
    "have_ip", "have_at", "url_length", "url_depth", "redirection",
    "https_domain", "tiny_url", "prefix_suffix", "dns_record", "domain_age",
    "domain_end", "iframe", "mouse_over", "right_click", "web_forwards",
]


def lexical_features(raw_url: str) -> list[float]:
    parsed = urllib.parse.urlsplit(raw_url)
    hostname = parsed.hostname or ""
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValueError("URL must be HTTP or HTTPS with a hostname")
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain embedded credentials")
    depth = len([part for part in parsed.path.split("/") if part])
    redirect_position = raw_url.rfind("//")
    redirection = 1 if redirect_position > 7 else 0
    return [
        0.0,  # The original training/integration IP feature was effectively constant.
        float("@" in raw_url),
        float(len(raw_url) >= 54),
        float(depth),
        float(redirection),
        float("https" in parsed.netloc),
        float(bool(SHORTENING_SERVICES.search(raw_url))),
        float("-" in parsed.netloc),
    ]


def _date_value(value: Any) -> datetime | None:
    if isinstance(value, list):
        value = next((item for item in value if isinstance(item, datetime)), None)
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        for pattern in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value[:19], pattern)
            except ValueError:
                continue
    return None


def _whois_worker(hostname: str, output) -> None:
    try:
        import whois  # type: ignore

        record = whois.whois(hostname)
        creation = _date_value(record.creation_date)
        expiration = _date_value(record.expiration_date)
        if creation is None or expiration is None:
            output.put((1.0, 1.0, 1.0))
            return
        age_months = abs((expiration - creation).days) / 30
        remaining_months = abs((expiration - datetime.now()).days) / 30
        output.put((0.0, float(age_months < 6), float(remaining_months >= 6)))
    except Exception:
        output.put((1.0, 1.0, 1.0))


def whois_features(hostname: str, timeout_seconds: float) -> list[float]:
    context = multiprocessing.get_context("fork")
    output = context.Queue(maxsize=1)
    process = context.Process(target=_whois_worker, args=(hostname, output), daemon=True)
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(1)
        return [1.0, 1.0, 1.0]
    try:
        return list(output.get(timeout=0.2))
    except Exception:
        return [1.0, 1.0, 1.0]


def ensure_public_target(raw_url: str) -> None:
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("legacy page feature URL is invalid")
    if parsed.username or parsed.password:
        raise ValueError("legacy page feature URL contains credentials")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    if not addresses:
        raise ValueError("legacy page feature hostname did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError("legacy page features refuse non-public destinations")


class GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, maximum_redirects: int):
        super().__init__()
        self.maximum_redirects = maximum_redirects
        self.redirects = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirects += 1
        if self.redirects > self.maximum_redirects:
            raise urllib.error.HTTPError(newurl, code, "too many redirects", headers, fp)
        ensure_public_target(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def page_features(
    raw_url: str, timeout_seconds: float, maximum_response_bytes: int,
    maximum_redirects: int,
) -> list[float]:
    try:
        ensure_public_target(raw_url)
        redirect_handler = GuardedRedirectHandler(maximum_redirects)
        opener = urllib.request.build_opener(redirect_handler)
        request = urllib.request.Request(raw_url, headers={"User-Agent": "wazuh-legacy-url-ml/1"})
        with opener.open(request, timeout=timeout_seconds) as response:
            body = response.read(maximum_response_bytes + 1)
        if len(body) > maximum_response_bytes:
            raise ValueError("legacy page response exceeded size limit")
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return [1.0, 1.0, 1.0, 1.0]

    iframe = 0.0 if re.findall(r"[<iframe>|<frameBorder>]", text) else 1.0
    mouse_over = 1.0 if re.findall(r"<script>.+onmouseover.+</script>", text) else 0.0
    right_click = 0.0 if re.findall(r"event.button ?== ?2", text) else 1.0
    forwards = 0.0 if redirect_handler.redirects <= 2 else 1.0
    return [iframe, mouse_over, right_click, forwards]


def extract_legacy_features(
    raw_url: str, network_features: bool = True, timeout_seconds: float = 5.0,
    maximum_response_bytes: int = 1024 * 1024, maximum_redirects: int = 4,
) -> list[float]:
    features = lexical_features(raw_url)
    if network_features:
        parsed = urllib.parse.urlsplit(raw_url)
        try:
            ensure_public_target(raw_url)
            features.extend(whois_features(parsed.hostname or "", timeout_seconds))
            features.extend(page_features(raw_url, timeout_seconds, maximum_response_bytes, maximum_redirects))
        except Exception:
            features.extend([1.0] * 7)
    else:
        features.extend([1.0] * 7)
    if len(features) != len(LEGACY_FEATURE_NAMES):
        raise RuntimeError("legacy feature schema length is invalid")
    return features


def score_legacy_url(
    raw_url: str, model_path: str, scaler_path: str, threshold: float | None = None,
    network_features: bool = True, timeout_seconds: float = 5.0,
    maximum_response_bytes: int = 1024 * 1024, maximum_redirects: int = 4,
) -> dict[str, Any]:
    try:
        import joblib  # type: ignore
    except ImportError as exc:
        raise RuntimeError("legacy ML is enabled but joblib/scikit-learn is not installed") from exc
    scaler = joblib.load(Path(scaler_path))
    model = joblib.load(Path(model_path))
    if not hasattr(scaler, "transform") or not hasattr(model, "predict"):
        raise RuntimeError("legacy scaler or model has an unsupported interface")
    features = extract_legacy_features(
        raw_url, network_features, timeout_seconds, maximum_response_bytes, maximum_redirects
    )
    expected = getattr(scaler, "n_features_in_", len(features))
    if int(expected) != len(features):
        raise RuntimeError(f"legacy scaler expects {expected} features, adapter produced {len(features)}")
    transformed = scaler.transform([features])
    raw_score = abs(float(model.predict(transformed)[0]))
    effective_threshold = 0.5 if threshold is None else float(threshold)
    return {
        "score": raw_score,
        "threshold": effective_threshold,
        "model_version": "original-sklearn-1.0.2-svr",
        "model_kind": "legacy_svr",
        "calibrated": False,
        "compatibility_mode": True,
        "legacy_network_features": network_features,
    }
