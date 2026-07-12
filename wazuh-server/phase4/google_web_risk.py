"""Bounded Google Web Risk Lookup API client for the Wazuh integration."""

from __future__ import annotations

import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


WEB_RISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"
ALLOWED_THREAT_TYPES = {"SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"}


class WebRiskError(Exception):
    """A key-safe error suitable for classification diagnostics."""

    def __init__(self, message: str, *, retryable: bool = False, status_code: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


def validate_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "webrisk.googleapis.com"
        or parsed.port not in (None, 443)
        or parsed.path != "/v1/uris:search"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Web Risk endpoint must be exactly https://webrisk.googleapis.com/v1/uris:search")
    return endpoint


def validate_threat_types(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list) or not values:
        raise ValueError("Web Risk threat_types must be a non-empty array")
    normalized: list[str] = []
    for value in values:
        threat_type = str(value).strip().upper()
        if threat_type not in ALLOWED_THREAT_TYPES:
            raise ValueError(f"unsupported Web Risk threat type: {threat_type}")
        if threat_type not in normalized:
            normalized.append(threat_type)
    return tuple(normalized)


def read_api_key(path_value: str, *, required_owner: int | None = 0) -> str:
    path = Path(path_value)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WebRiskError("Google Web Risk API key file cannot be read") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise WebRiskError("Google Web Risk API key path must be a regular non-symlink file")
    if required_owner is not None and metadata.st_uid != required_owner:
        raise WebRiskError("Google Web Risk API key file must be owned by root")
    if stat.S_IMODE(metadata.st_mode) & 0o027:
        raise WebRiskError("Google Web Risk API key file must not be group-writable or accessible by others")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise WebRiskError("Google Web Risk API key file cannot be read") from exc
    if not 20 <= len(value) <= 256 or any(character.isspace() for character in value):
        raise WebRiskError("Google Web Risk API key file contains an invalid key")
    return value


def parse_expire_time(value: Any, *, now: float | None = None) -> int:
    if not isinstance(value, str) or not value:
        raise WebRiskError("Google Web Risk match has no expireTime")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WebRiskError("Google Web Risk match has an invalid expireTime") from exc
    if parsed.tzinfo is None:
        raise WebRiskError("Google Web Risk expireTime must include a timezone")
    timestamp = int(parsed.timestamp())
    current = int(time.time() if now is None else now)
    if timestamp <= current:
        raise WebRiskError("Google Web Risk match expireTime is not in the future")
    return timestamp


def normalize_response(
    payload: dict[str, Any], configured_types: tuple[str, ...], *, now: float | None = None
) -> dict[str, Any]:
    if not payload:
        return {
            "status": "not_found",
            "malicious": False,
            "in_database": False,
            "verified": False,
            "valid": False,
            "provider": "google_webrisk",
            "threat_types": [],
        }
    threat = payload.get("threat")
    if not isinstance(threat, dict):
        raise WebRiskError("Google Web Risk response is missing threat")
    raw_types = threat.get("threatTypes")
    if not isinstance(raw_types, list) or not raw_types:
        raise WebRiskError("Google Web Risk threat has no threatTypes")
    returned_types: list[str] = []
    for value in raw_types:
        threat_type = str(value).strip().upper()
        if threat_type not in ALLOWED_THREAT_TYPES or threat_type not in configured_types:
            raise WebRiskError("Google Web Risk returned an unexpected threat type")
        if threat_type not in returned_types:
            returned_types.append(threat_type)
    expire_at = parse_expire_time(threat.get("expireTime"), now=now)
    return {
        "status": "malicious",
        "malicious": True,
        "in_database": True,
        "verified": True,
        "valid": True,
        "provider": "google_webrisk",
        "threat_types": returned_types,
        "expire_time": threat["expireTime"],
        "expire_at": expire_at,
    }


def query_url(
    raw_url: str,
    *,
    endpoint: str,
    api_key_file: str,
    threat_types: tuple[str, ...],
    timeout_seconds: float,
    maximum_response_bytes: int,
    retry_count: int,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleeper: Callable[[float], None] = time.sleep,
    required_key_owner: int | None = 0,
) -> dict[str, Any]:
    validate_endpoint(endpoint)
    key = read_api_key(api_key_file, required_owner=required_key_owner)
    query = urllib.parse.urlencode(
        [("threatTypes", value) for value in threat_types]
        + [("uri", raw_url), ("key", key)]
    )
    request = urllib.request.Request(
        endpoint + "?" + query,
        headers={"Accept": "application/json", "User-Agent": "wazuh-edge-phishing/1"},
        method="GET",
    )
    key = ""

    attempts = retry_count + 1
    for attempt in range(attempts):
        try:
            with opener(request, timeout=timeout_seconds) as response:
                payload = response.read(maximum_response_bytes + 1)
            if len(payload) > maximum_response_bytes:
                raise WebRiskError("Google Web Risk response exceeded size limit")
            try:
                decoded = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise WebRiskError("Google Web Risk returned invalid JSON") from exc
            if not isinstance(decoded, dict):
                raise WebRiskError("Google Web Risk response root is not an object")
            return normalize_response(decoded, threat_types)
        except urllib.error.HTTPError as exc:
            retryable = exc.code in {500, 503, 504}
            error = WebRiskError(
                f"Google Web Risk HTTP error {exc.code}", retryable=retryable,
                status_code=exc.code,
            )
            exc.close()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = WebRiskError("Google Web Risk request failed", retryable=True)
        if not error.retryable or attempt + 1 >= attempts:
            raise error
        sleeper(min(0.25 * (2 ** attempt), 1.0))
    raise WebRiskError("Google Web Risk request failed")
