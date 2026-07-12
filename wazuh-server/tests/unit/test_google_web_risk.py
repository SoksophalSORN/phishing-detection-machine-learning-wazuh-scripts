import json
import os
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "phase4"))

from google_web_risk import (
    WebRiskError,
    normalize_response,
    query_url,
    read_api_key,
    validate_endpoint,
    validate_threat_types,
)


class Response:
    def __init__(self, value):
        self.payload = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _maximum):
        return self.payload


class GoogleWebRiskTests(unittest.TestCase):
    def future(self):
        return (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def key_file(self, directory):
        path = Path(directory) / "key"
        path.write_text("A" * 39, encoding="utf-8")
        path.chmod(0o640)
        return path

    def test_endpoint_is_fixed(self):
        self.assertEqual(
            validate_endpoint("https://webrisk.googleapis.com/v1/uris:search"),
            "https://webrisk.googleapis.com/v1/uris:search",
        )
        with self.assertRaises(ValueError):
            validate_endpoint("https://example.test/v1/uris:search")

    def test_threat_type_allowlist(self):
        self.assertEqual(validate_threat_types(["social_engineering"]), ("SOCIAL_ENGINEERING",))
        with self.assertRaises(ValueError):
            validate_threat_types(["UNKNOWN"])

    def test_empty_response_is_not_found_not_safe(self):
        result = normalize_response({}, ("SOCIAL_ENGINEERING",))
        self.assertEqual(result["status"], "not_found")
        self.assertFalse(result["malicious"])

    def test_match_is_normalized_with_expiry(self):
        result = normalize_response(
            {"threat": {"threatTypes": ["SOCIAL_ENGINEERING"], "expireTime": self.future()}},
            ("SOCIAL_ENGINEERING",),
        )
        self.assertEqual(result["status"], "malicious")
        self.assertEqual(result["provider"], "google_webrisk")
        self.assertGreater(result["expire_at"], 0)

    def test_key_permissions_reject_other_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.key_file(directory)
            path.chmod(0o644)
            with self.assertRaises(WebRiskError):
                read_api_key(str(path), required_owner=os.getuid())

    def test_key_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.key_file(directory)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(WebRiskError):
                read_api_key(str(link), required_owner=os.getuid())

    def test_malformed_match_is_rejected(self):
        with self.assertRaises(WebRiskError):
            normalize_response({"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}}, ("SOCIAL_ENGINEERING",))

    def test_query_encodes_url_and_never_returns_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.key_file(directory)
            requests = []

            def opener(request, timeout):
                requests.append((request, timeout))
                return Response({})

            result = query_url(
                "https://example.test/login?a=1&b=2", endpoint="https://webrisk.googleapis.com/v1/uris:search",
                api_key_file=str(path), threat_types=("SOCIAL_ENGINEERING",), timeout_seconds=2,
                maximum_response_bytes=65536, retry_count=0, opener=opener,
                required_key_owner=os.getuid(),
            )
        self.assertEqual(result["status"], "not_found")
        self.assertIn("uri=https%3A%2F%2Fexample.test%2Flogin%3Fa%3D1%26b%3D2", requests[0][0].full_url)
        self.assertNotIn("A" * 39, json.dumps(result))

    def test_403_is_not_retried_and_error_has_no_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.key_file(directory)
            calls = []

            def opener(request, timeout):
                calls.append(request)
                raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)

            with self.assertRaises(WebRiskError) as raised:
                query_url(
                    "https://example.test/", endpoint="https://webrisk.googleapis.com/v1/uris:search",
                    api_key_file=str(path), threat_types=("SOCIAL_ENGINEERING",), timeout_seconds=2,
                    maximum_response_bytes=65536, retry_count=1, opener=opener,
                    required_key_owner=os.getuid(),
                )
        self.assertEqual(len(calls), 1)
        self.assertEqual(raised.exception.status_code, 403)
        self.assertNotIn("A" * 39, str(raised.exception))

    def test_503_is_retried_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.key_file(directory)
            calls = []

            def opener(request, timeout):
                calls.append(request)
                if len(calls) == 1:
                    raise urllib.error.HTTPError(request.full_url, 503, "Unavailable", {}, None)
                return Response({})

            result = query_url(
                "https://example.test/", endpoint="https://webrisk.googleapis.com/v1/uris:search",
                api_key_file=str(path), threat_types=("SOCIAL_ENGINEERING",), timeout_seconds=2,
                maximum_response_bytes=65536, retry_count=1, opener=opener, sleeper=lambda _seconds: None,
                required_key_owner=os.getuid(),
            )
        self.assertEqual(result["status"], "not_found")
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
