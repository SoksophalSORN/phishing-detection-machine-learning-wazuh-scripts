"""Mutually exclusive reputation providers and optional ML classification."""

from __future__ import annotations

import json
import hashlib
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
    reputation_provider: str = "phishtank"
    endpoint: str = "https://checkurl.phishtank.com/checkurl/"
    api_key: str = ""
    user_agent: str = "phishtank/wazuh-edge-phishing-pilot"
    timeout_seconds: float = 8.0
    positive_cache_seconds: int = 21600
    negative_cache_seconds: int = 900
    web_risk_endpoint: str = "https://webrisk.googleapis.com/v1/uris:search"
    web_risk_api_key_file: str = "/var/ossec/etc/edge-google-web-risk.key"
    web_risk_threat_types: tuple[str, ...] = ("SOCIAL_ENGINEERING",)
    web_risk_maximum_response_bytes: int = 65536
    web_risk_monthly_request_limit: int = 90000
    web_risk_retry_count: int = 1
    web_risk_circuit_breaker_seconds: int = 300
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
        reputation = value.get("reputation")
        if reputation is None:
            reputation = {}
        if not isinstance(reputation, dict):
            raise ClassificationError("reputation configuration must be an object")
        provider = str(reputation.get("provider", "phishtank")).replace("-", "_")
        if provider not in {"phishtank", "google_webrisk", "disabled"}:
            raise ClassificationError("reputation.provider must be phishtank, google_webrisk, or disabled")
        endpoint = str(value.get("endpoint", cls.endpoint))
        parsed = urllib.parse.urlsplit(endpoint)
        if provider == "phishtank" and (parsed.scheme != "https" or not parsed.hostname):
            raise ClassificationError("PhishTank endpoint must be an HTTPS URL")
        web_risk_endpoint = str(reputation.get("endpoint", cls.web_risk_endpoint))
        web_risk_key_file = str(reputation.get("api_key_file", cls.web_risk_api_key_file))
        try:
            from google_web_risk import validate_endpoint, validate_threat_types

            if provider == "google_webrisk":
                validate_endpoint(web_risk_endpoint)
                if not Path(web_risk_key_file).is_absolute():
                    raise ValueError("Web Risk api_key_file must be absolute")
            threat_types = validate_threat_types(
                reputation.get("threat_types", list(cls.web_risk_threat_types))
            )
        except ValueError as exc:
            raise ClassificationError(str(exc)) from exc
        timeout_seconds = float(reputation.get("timeout_seconds", value.get("timeout_seconds", cls.timeout_seconds)))
        negative_cache_seconds = int(
            reputation.get("negative_cache_seconds", value.get("negative_cache_seconds", cls.negative_cache_seconds))
        )
        maximum_response_bytes = int(reputation.get("maximum_response_bytes", cls.web_risk_maximum_response_bytes))
        monthly_request_limit = int(reputation.get("monthly_request_limit", cls.web_risk_monthly_request_limit))
        retry_count = int(reputation.get("retry_count", cls.web_risk_retry_count))
        circuit_seconds = int(reputation.get("circuit_breaker_seconds", cls.web_risk_circuit_breaker_seconds))
        if not 0.1 <= timeout_seconds <= 30:
            raise ClassificationError("reputation.timeout_seconds must be between 0.1 and 30")
        if not 0 <= negative_cache_seconds <= 86400:
            raise ClassificationError("reputation.negative_cache_seconds must be between 0 and 86400")
        if not 1024 <= maximum_response_bytes <= 1024 * 1024:
            raise ClassificationError("reputation.maximum_response_bytes must be between 1024 and 1048576")
        if not 1 <= monthly_request_limit <= 10000000:
            raise ClassificationError("reputation.monthly_request_limit must be between 1 and 10000000")
        if not 0 <= retry_count <= 3:
            raise ClassificationError("reputation.retry_count must be between 0 and 3")
        if not 1 <= circuit_seconds <= 3600:
            raise ClassificationError("reputation.circuit_breaker_seconds must be between 1 and 3600")
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
            reputation_provider=provider,
            endpoint=endpoint,
            api_key=str(value.get("api_key", "")),
            user_agent=str(value.get("user_agent", cls.user_agent)),
            timeout_seconds=timeout_seconds,
            positive_cache_seconds=int(value.get("positive_cache_seconds", cls.positive_cache_seconds)),
            negative_cache_seconds=negative_cache_seconds,
            web_risk_endpoint=web_risk_endpoint,
            web_risk_api_key_file=web_risk_key_file,
            web_risk_threat_types=threat_types,
            web_risk_maximum_response_bytes=maximum_response_bytes,
            web_risk_monthly_request_limit=monthly_request_limit,
            web_risk_retry_count=retry_count,
            web_risk_circuit_breaker_seconds=circuit_seconds,
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
            "CREATE TABLE IF NOT EXISTS reputation_cache "
            "(provider TEXT NOT NULL, url_key TEXT NOT NULL, expires_at INTEGER NOT NULL, "
            "result TEXT NOT NULL, PRIMARY KEY(provider, url_key))"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS reputation_usage "
            "(provider TEXT NOT NULL, calendar_month TEXT NOT NULL, request_count INTEGER NOT NULL, "
            "error_count INTEGER NOT NULL, PRIMARY KEY(provider, calendar_month))"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS reputation_state "
            "(provider TEXT PRIMARY KEY, consecutive_failures INTEGER NOT NULL, circuit_open_until INTEGER NOT NULL)"
        )
        self.connection.commit()

    @staticmethod
    def url_key(url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def get(self, url: str, provider: str = "phishtank", now: int | None = None) -> dict[str, Any] | None:
        timestamp = int(time.time()) if now is None else now
        row = self.connection.execute(
            "SELECT result FROM reputation_cache WHERE provider = ? AND url_key = ? AND expires_at > ?",
            (provider, self.url_key(url), timestamp),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
        except json.JSONDecodeError:
            self.connection.execute(
                "DELETE FROM reputation_cache WHERE provider = ? AND url_key = ?",
                (provider, self.url_key(url)),
            )
            self.connection.commit()
            return None
        return value if isinstance(value, dict) else None

    def put(
        self, url: str, result: dict[str, Any], ttl_seconds: int,
        provider: str = "phishtank", now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        self.connection.execute(
            "INSERT OR REPLACE INTO reputation_cache(provider, url_key, expires_at, result) VALUES (?, ?, ?, ?)",
            (
                provider, self.url_key(url), timestamp + max(0, ttl_seconds),
                json.dumps(result, separators=(",", ":"), sort_keys=True),
            ),
        )
        self.connection.commit()

    def reserve_request(self, provider: str, limit: int, now: int | None = None) -> bool:
        timestamp = int(time.time()) if now is None else now
        month = time.strftime("%Y-%m", time.gmtime(timestamp))
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT request_count FROM reputation_usage WHERE provider = ? AND calendar_month = ?",
                (provider, month),
            ).fetchone()
            count = 0 if row is None else int(row[0])
            if count >= limit:
                self.connection.rollback()
                return False
            self.connection.execute(
                "INSERT INTO reputation_usage(provider, calendar_month, request_count, error_count) "
                "VALUES (?, ?, 1, 0) ON CONFLICT(provider, calendar_month) DO UPDATE SET request_count=request_count+1",
                (provider, month),
            )
            self.connection.commit()
            return True
        except Exception:
            self.connection.rollback()
            raise

    def record_error(self, provider: str, circuit_seconds: int, now: int | None = None) -> None:
        timestamp = int(time.time()) if now is None else now
        month = time.strftime("%Y-%m", time.gmtime(timestamp))
        self.connection.execute(
            "INSERT INTO reputation_usage(provider, calendar_month, request_count, error_count) "
            "VALUES (?, ?, 0, 1) ON CONFLICT(provider, calendar_month) DO UPDATE SET error_count=error_count+1",
            (provider, month),
        )
        self.connection.execute(
            "INSERT INTO reputation_state(provider, consecutive_failures, circuit_open_until) VALUES (?, 1, ?) "
            "ON CONFLICT(provider) DO UPDATE SET consecutive_failures=consecutive_failures+1, circuit_open_until=excluded.circuit_open_until",
            (provider, timestamp + circuit_seconds),
        )
        self.connection.commit()

    def record_success(self, provider: str) -> None:
        self.connection.execute(
            "INSERT INTO reputation_state(provider, consecutive_failures, circuit_open_until) VALUES (?, 0, 0) "
            "ON CONFLICT(provider) DO UPDATE SET consecutive_failures=0, circuit_open_until=0",
            (provider,),
        )
        self.connection.commit()

    def circuit_open(self, provider: str, now: int | None = None) -> bool:
        timestamp = int(time.time()) if now is None else now
        row = self.connection.execute(
            "SELECT circuit_open_until FROM reputation_state WHERE provider = ?", (provider,)
        ).fetchone()
        return row is not None and int(row[0]) > timestamp

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
        "provider": "phishtank",
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


def query_reputation(url: str, settings: Settings) -> dict[str, Any]:
    if settings.reputation_provider == "phishtank":
        return query_phishtank(url, settings)
    if settings.reputation_provider == "google_webrisk":
        from google_web_risk import WebRiskError, query_url

        try:
            return query_url(
                url,
                endpoint=settings.web_risk_endpoint,
                api_key_file=settings.web_risk_api_key_file,
                threat_types=settings.web_risk_threat_types,
                timeout_seconds=settings.timeout_seconds,
                maximum_response_bytes=settings.web_risk_maximum_response_bytes,
                retry_count=settings.web_risk_retry_count,
            )
        except WebRiskError as exc:
            raise ClassificationError(str(exc)) from exc
    raise ClassificationError("reputation provider is disabled")


def classify_navigation(
    navigation: dict[str, Any],
    settings: Settings,
    cache: ResultCache,
    query: Callable[[str, Settings], dict[str, Any]] | None = None,
    ml_scorer: Callable[[str, str, float | None], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    provider = settings.reputation_provider

    def score_with_ml() -> dict[str, Any]:
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
            result = ml_scorer(
                navigation["url"], settings.ml_model_path, settings.ml_threshold
            )
            return result
        return ml_result

    cached = cache.get(navigation["url"], provider=provider)
    cache_hit = cached is not None
    reputation_error: str | None = None
    reputation_failure_status = "error"
    if cached is not None:
        reputation = cached
    else:
        if provider == "google_webrisk" and cache.circuit_open(provider):
            reputation_error = "Google Web Risk circuit breaker is open"
            reputation_failure_status = "circuit_open"
            reputation = {}
        elif provider == "google_webrisk" and not cache.reserve_request(
            provider, settings.web_risk_monthly_request_limit
        ):
            reputation_error = "Google Web Risk monthly request guard reached"
            reputation_failure_status = "quota_guard"
            reputation = {}
        else:
            try:
                reputation = (query or query_reputation)(navigation["url"], settings)
            except ClassificationError as exc:
                reputation_error = str(exc)
                reputation = {}
                if provider == "google_webrisk":
                    cache.record_error(provider, settings.web_risk_circuit_breaker_seconds)
            else:
                if provider == "google_webrisk":
                    cache.record_success(provider)
                reputation.setdefault("provider", provider)
                if provider == "google_webrisk" and reputation.get("malicious"):
                    expire_at = int(reputation.pop("expire_at", int(time.time()) + 1))
                    ttl = max(1, expire_at - int(time.time()))
                else:
                    ttl = settings.positive_cache_seconds if reputation.get("in_database") else settings.negative_cache_seconds
                if ttl > 0:
                    cache.put(navigation["url"], reputation, ttl, provider=provider)

    if reputation_error is not None:
        if not settings.ml_enabled:
            raise ClassificationError(reputation_error)
        ml_result = score_with_ml()
        ml_status = "suspicious" if ml_result["score"] >= ml_result["threshold"] else "unlikely"
        if ml_status == "suspicious":
            reputation = {
                **ml_result,
                "status": "suspicious",
                "malicious": True,
                "source": "ml",
                "degraded": True,
                "reputation_provider": provider,
                "reputation_status": reputation_failure_status,
                "reputation_error": reputation_error,
            }
        else:
            reputation = {
                **ml_result,
                "status": "error",
                "ml_status": "unlikely",
                "malicious": False,
                "source": "classifier",
                "degraded": True,
                "reputation_provider": provider,
                "reputation_status": reputation_failure_status,
                "error": reputation_error,
            }
        classification_source = reputation["source"]
    else:
        classification_source = str(reputation.get("provider", provider))
        if not reputation.get("malicious", False) and settings.ml_enabled:
            ml_result = score_with_ml()
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
            "reputation_provider": provider,
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
