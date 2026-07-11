"""Structured PhishTank and optional URL-only ML classification for Wazuh."""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


MAX_RESPONSE_BYTES = 1024 * 1024


class ClassificationError(Exception):
    """A safe-to-report classification failure."""


@dataclass(frozen=True)
class Settings:
    endpoint: str = "https://checkurl.phishtank.com/checkurl/"
    api_key: str = ""
    user_agent: str = "phishtank/wazuh-edge-phishing-pilot"
    timeout_seconds: float = 8.0
    positive_cache_seconds: int = 21600
    negative_cache_seconds: int = 900
    navigation_rule_id: str = "100100"
    ml_enabled: bool = False
    ml_mode: str = "modern"
    ml_model_path: str = "/var/ossec/etc/edge-url-model.joblib"
    ml_scaler_path: str = ""
    ml_threshold: float | None = None
    legacy_network_features: bool = True
    legacy_timeout_seconds: float = 5.0
    legacy_max_response_bytes: int = 1024 * 1024
    legacy_max_redirects: int = 4

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "Settings":
        endpoint = str(value.get("endpoint", cls.endpoint))
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ClassificationError("PhishTank endpoint must be an HTTPS URL")
        ml = value.get("ml", {})
        if not isinstance(ml, dict):
            raise ClassificationError("ml configuration must be an object")
        ml_enabled = ml.get("enabled", False)
        if not isinstance(ml_enabled, bool):
            raise ClassificationError("ml.enabled must be true or false")
        ml_mode = str(ml.get("mode", "modern"))
        if ml_mode not in {"modern", "legacy_svr"}:
            raise ClassificationError("ml.mode must be modern or legacy_svr")
        threshold_value = ml.get("threshold")
        try:
            threshold = None if threshold_value is None else float(threshold_value)
        except (TypeError, ValueError) as exc:
            raise ClassificationError("ml.threshold must be a number or null") from exc
        if threshold is not None and not 0.0 <= threshold <= 1.0:
            raise ClassificationError("ml.threshold must be between 0 and 1")
        model_path = str(ml.get("model_path", cls.ml_model_path))
        if ml_enabled and not Path(model_path).is_absolute():
            raise ClassificationError("ml.model_path must be absolute when ML is enabled")
        scaler_path = str(ml.get("scaler_path", ""))
        if ml_enabled and ml_mode == "legacy_svr" and not Path(scaler_path).is_absolute():
            raise ClassificationError("ml.scaler_path must be absolute in legacy_svr mode")
        legacy_network_features = ml.get("legacy_network_features", True)
        if not isinstance(legacy_network_features, bool):
            raise ClassificationError("ml.legacy_network_features must be true or false")
        legacy_timeout_seconds = float(ml.get("legacy_timeout_seconds", 5.0))
        legacy_max_response_bytes = int(ml.get("legacy_max_response_bytes", 1024 * 1024))
        legacy_max_redirects = int(ml.get("legacy_max_redirects", 4))
        if not 0.1 <= legacy_timeout_seconds <= 30:
            raise ClassificationError("ml.legacy_timeout_seconds must be between 0.1 and 30")
        if not 1024 <= legacy_max_response_bytes <= 10 * 1024 * 1024:
            raise ClassificationError("ml.legacy_max_response_bytes must be between 1024 and 10485760")
        if not 0 <= legacy_max_redirects <= 10:
            raise ClassificationError("ml.legacy_max_redirects must be between 0 and 10")
        navigation_rule_id = str(value.get("navigation_rule_id", cls.navigation_rule_id))
        if not navigation_rule_id.isdigit() or not 100000 <= int(navigation_rule_id) <= 120000:
            raise ClassificationError("navigation_rule_id must be between 100000 and 120000")
        return cls(
            endpoint=endpoint,
            api_key=str(value.get("api_key", "")),
            user_agent=str(value.get("user_agent", cls.user_agent)),
            timeout_seconds=float(value.get("timeout_seconds", cls.timeout_seconds)),
            positive_cache_seconds=int(value.get("positive_cache_seconds", cls.positive_cache_seconds)),
            negative_cache_seconds=int(value.get("negative_cache_seconds", cls.negative_cache_seconds)),
            navigation_rule_id=navigation_rule_id,
            ml_enabled=ml_enabled,
            ml_mode=ml_mode,
            ml_model_path=model_path,
            ml_scaler_path=scaler_path,
            ml_threshold=threshold,
            legacy_network_features=legacy_network_features,
            legacy_timeout_seconds=legacy_timeout_seconds,
            legacy_max_response_bytes=legacy_max_response_bytes,
            legacy_max_redirects=legacy_max_redirects,
        )


def load_settings(path: Path) -> Settings:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise ClassificationError(f"configuration file is missing: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ClassificationError("configuration file cannot be read") from exc
    if not isinstance(value, dict):
        raise ClassificationError("configuration root must be a JSON object")
    return Settings.from_mapping(value)


def validate_navigation_alert(alert: dict[str, Any], navigation_rule_id: str = "100100") -> dict[str, Any]:
    try:
        rule_id = str(alert["rule"]["id"])
        data = alert["data"]
        agent = alert["agent"]
    except (KeyError, TypeError) as exc:
        raise ClassificationError("alert is missing required Wazuh fields") from exc

    if rule_id != navigation_rule_id:
        raise ClassificationError(f"alert did not originate from navigation rule {navigation_rule_id}")
    if not isinstance(data, dict) or data.get("event_type") != "browser_navigation":
        raise ClassificationError("alert is not a browser_navigation event")
    if data.get("source") != "edge_extension" or data.get("browser") != "edge":
        raise ClassificationError("alert has an unexpected navigation source")

    raw_url = data.get("url")
    if not isinstance(raw_url, str) or len(raw_url) > 8192:
        raise ClassificationError("alert URL is missing or too long")
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ClassificationError("alert URL is not HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise ClassificationError("alert URL contains credentials")

    event_id = data.get("event_id")
    if not isinstance(event_id, str) or not event_id or len(event_id) > 128:
        raise ClassificationError("alert event_id is invalid")

    return {
        "url": raw_url,
        "url_host": parsed.hostname.lower(),
        "source_event_id": event_id,
        "source_alert_id": str(alert.get("id", "")),
        "source_rule_id": rule_id,
        "agent": {
            "id": str(agent.get("id", "")),
            "name": str(agent.get("name", "")),
            "ip": str(agent.get("ip", "any")),
        },
    }


class ResultCache:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=5)
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS phishtank_cache "
            "(url TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, result TEXT NOT NULL)"
        )
        self.connection.commit()

    def get(self, url: str, now: int | None = None) -> dict[str, Any] | None:
        timestamp = int(time.time()) if now is None else now
        row = self.connection.execute(
            "SELECT result FROM phishtank_cache WHERE url = ? AND expires_at > ?",
            (url, timestamp),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
        except json.JSONDecodeError:
            self.connection.execute("DELETE FROM phishtank_cache WHERE url = ?", (url,))
            self.connection.commit()
            return None
        return value if isinstance(value, dict) else None

    def put(self, url: str, result: dict[str, Any], ttl_seconds: int, now: int | None = None) -> None:
        timestamp = int(time.time()) if now is None else now
        self.connection.execute(
            "INSERT OR REPLACE INTO phishtank_cache(url, expires_at, result) VALUES (?, ?, ?)",
            (url, timestamp + ttl_seconds, json.dumps(result, separators=(",", ":"), sort_keys=True)),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    return isinstance(value, str) and value.lower() in {"true", "yes", "y", "1"}


def normalize_phishtank_result(payload: dict[str, Any]) -> dict[str, Any]:
    results = payload.get("results")
    if not isinstance(results, dict):
        raise ClassificationError("PhishTank response is missing results")

    in_database = _truthy(results.get("in_database"))
    verified = _truthy(results.get("verified"))
    valid = _truthy(results.get("valid"))
    malicious = in_database and verified and valid

    if malicious:
        status = "malicious"
    elif in_database:
        status = "listed_inactive"
    else:
        status = "not_found"

    normalized: dict[str, Any] = {
        "status": status,
        "malicious": malicious,
        "in_database": in_database,
        "verified": verified,
        "valid": valid,
    }
    if results.get("phish_id") is not None:
        normalized["phish_id"] = str(results["phish_id"])
    if isinstance(results.get("phish_detail_page"), str):
        normalized["detail_url"] = results["phish_detail_page"]
    return normalized


def query_phishtank(
    url: str,
    settings: Settings,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    fields = {"url": url, "format": "json"}
    if settings.api_key:
        fields["app_key"] = settings.api_key
    request = urllib.request.Request(
        settings.endpoint,
        data=urllib.parse.urlencode(fields).encode("ascii"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": settings.user_agent,
        },
        method="POST",
    )
    try:
        with opener(request, timeout=settings.timeout_seconds) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 509:
            raise ClassificationError("PhishTank rate limit exceeded") from exc
        raise ClassificationError(f"PhishTank HTTP error {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ClassificationError("PhishTank request failed") from exc

    if len(payload) > MAX_RESPONSE_BYTES:
        raise ClassificationError("PhishTank response exceeded size limit")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClassificationError("PhishTank returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise ClassificationError("PhishTank response root is not an object")
    return normalize_phishtank_result(decoded)


def classify_navigation(
    navigation: dict[str, Any],
    settings: Settings,
    cache: ResultCache,
    query: Callable[[str, Settings], dict[str, Any]] = query_phishtank,
    ml_scorer: Callable[[str, str, float | None], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    cached = cache.get(navigation["url"])
    if cached is None:
        reputation = query(navigation["url"], settings)
        ttl = settings.positive_cache_seconds if reputation["in_database"] else settings.negative_cache_seconds
        cache.put(navigation["url"], reputation, ttl)
        cache_hit = False
    else:
        reputation = cached
        cache_hit = True

    classification_source = "phishtank"
    if not reputation["malicious"] and settings.ml_enabled:
        if ml_scorer is None:
            if settings.ml_mode == "legacy_svr":
                from legacy_url_ml import score_legacy_url

                ml_result = score_legacy_url(
                    navigation["url"], settings.ml_model_path, settings.ml_scaler_path,
                    settings.ml_threshold, settings.legacy_network_features,
                    settings.legacy_timeout_seconds, settings.legacy_max_response_bytes,
                    settings.legacy_max_redirects,
                )
            else:
                from url_ml import score_url

                ml_result = score_url(
                    navigation["url"], settings.ml_model_path, settings.ml_threshold
                )
        else:
            ml_result = ml_scorer(
                navigation["url"], settings.ml_model_path, settings.ml_threshold
            )
        reputation.update(ml_result)
        reputation["status"] = "suspicious" if ml_result["score"] >= ml_result["threshold"] else "unlikely"
        reputation["malicious"] = reputation["status"] == "suspicious"
        classification_source = "ml"

    return {
        "integration": "edge-phishing-classifier",
        "schema_version": 1,
        "classification": {
            **reputation,
            "source": classification_source,
            "url": navigation["url"],
            "url_host": navigation["url_host"],
            "source_event_id": navigation["source_event_id"],
            "source_alert_id": navigation["source_alert_id"],
            "source_rule_id": navigation["source_rule_id"],
            "cache_hit": cache_hit,
            "latency_ms": round((time.monotonic() - started) * 1000),
        },
    }


def error_result(navigation: dict[str, Any] | None, error: Exception) -> dict[str, Any]:
    return {
        "integration": "edge-phishing-classifier",
        "schema_version": 1,
        "classification": {
            "status": "error",
            "malicious": False,
            "source": "classifier",
            "error_type": type(error).__name__,
            "error": str(error),
            "url": "" if navigation is None else navigation.get("url", ""),
            "url_host": "" if navigation is None else navigation.get("url_host", ""),
            "source_event_id": "" if navigation is None else navigation.get("source_event_id", ""),
            "source_alert_id": "" if navigation is None else navigation.get("source_alert_id", ""),
            "source_rule_id": "" if navigation is None else navigation.get("source_rule_id", ""),
        },
    }
