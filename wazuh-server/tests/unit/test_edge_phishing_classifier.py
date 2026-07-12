import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "phase4"))

from edge_phishing_classifier import (
    ClassificationError,
    ResultCache,
    Settings,
    classify_navigation,
    normalize_phishtank_result,
    validate_navigation_alert,
)


class ClassifierTests(unittest.TestCase):
    def navigation_alert(self):
        return {
            "id": "wazuh-alert-1",
            "rule": {"id": "100100"},
            "agent": {"id": "002", "name": "Windows-10", "ip": "192.0.2.10"},
            "data": {
                "event_type": "browser_navigation",
                "source": "edge_extension",
                "browser": "edge",
                "event_id": "event-1",
                "url": "https://example.test/login",
            },
        }

    def test_validates_structured_navigation_alert(self):
        parsed = validate_navigation_alert(self.navigation_alert())
        self.assertEqual(parsed["source_event_id"], "event-1")
        self.assertEqual(parsed["agent"]["id"], "002")
        self.assertEqual(parsed["url_host"], "example.test")

    def test_accepts_configured_navigation_rule(self):
        alert = self.navigation_alert()
        alert["rule"]["id"] = "100300"
        parsed = validate_navigation_alert(alert, "100300")
        self.assertEqual(parsed["source_rule_id"], "100300")

    def test_rejects_wrong_rule(self):
        alert = self.navigation_alert()
        alert["rule"]["id"] = "100999"
        with self.assertRaises(ClassificationError):
            validate_navigation_alert(alert)

    def test_rejects_ambiguous_ml_enabled_value(self):
        with self.assertRaises(ClassificationError):
            Settings.from_mapping({"ml": {"enabled": "false"}})

    def test_rejects_relative_enabled_model_path(self):
        with self.assertRaises(ClassificationError):
            Settings.from_mapping({"ml": {"enabled": True, "model_path": "model.joblib"}})

    def test_accepts_legacy_model_and_scaler_paths(self):
        settings = Settings.from_mapping({
            "ml": {
                "enabled": True,
                "mode": "legacy_svr",
                "model_path": "/var/ossec/etc/model.joblib",
                "scaler_path": "/var/ossec/etc/scaler.joblib",
                "threshold": 0.5,
            }
        })
        self.assertEqual(settings.ml_mode, "legacy_svr")
        self.assertEqual(settings.ml_scaler_path, "/var/ossec/etc/scaler.joblib")

    def test_accepts_google_web_risk_settings(self):
        settings = Settings.from_mapping({
            "reputation": {
                "provider": "google-webrisk",
                "api_key_file": "/var/ossec/etc/key",
                "threat_types": ["SOCIAL_ENGINEERING", "MALWARE"],
            }
        })
        self.assertEqual(settings.reputation_provider, "google_webrisk")
        self.assertEqual(settings.web_risk_threat_types, ("SOCIAL_ENGINEERING", "MALWARE"))

    def test_normalizes_confirmed_phish(self):
        result = normalize_phishtank_result({
            "results": {
                "in_database": True,
                "verified": "y",
                "valid": "y",
                "phish_id": 123,
                "phish_detail_page": "https://phishtank.test/123",
            }
        })
        self.assertEqual(result["status"], "malicious")
        self.assertTrue(result["malicious"])
        self.assertEqual(result["phish_id"], "123")

    def test_negative_result_is_cached(self):
        navigation = validate_navigation_alert(self.navigation_alert())
        settings = Settings()
        calls = []

        def query(url, _settings):
            calls.append(url)
            return {
                "status": "not_found",
                "malicious": False,
                "in_database": False,
                "verified": False,
                "valid": False,
            }

        with tempfile.TemporaryDirectory() as directory:
            cache = ResultCache(Path(directory) / "cache.sqlite3")
            try:
                first = classify_navigation(navigation, settings, cache, query=query)
                second = classify_navigation(navigation, settings, cache, query=query)
            finally:
                cache.close()

        self.assertEqual(len(calls), 1)
        self.assertFalse(first["classification"]["cache_hit"])
        self.assertTrue(second["classification"]["cache_hit"])

    def test_ml_scores_unconfirmed_phishtank_result(self):
        navigation = validate_navigation_alert(self.navigation_alert())
        settings = Settings(ml_enabled=True)
        ml_calls = []

        def query(_url, _settings):
            return {
                "status": "not_found", "malicious": False,
                "in_database": False, "verified": False, "valid": False,
            }

        def score(url, model_path, threshold):
            ml_calls.append((url, model_path, threshold))
            return {
                "score": 0.91, "score_percent": 91.0,
                "threshold": 0.8, "model_version": "test-v1",
            }

        with tempfile.TemporaryDirectory() as directory:
            cache = ResultCache(Path(directory) / "cache.sqlite3")
            try:
                result = classify_navigation(navigation, settings, cache, query=query, ml_scorer=score)
            finally:
                cache.close()

        self.assertEqual(len(ml_calls), 1)
        self.assertEqual(result["classification"]["status"], "suspicious")
        self.assertEqual(result["classification"]["source"], "ml")
        self.assertEqual(result["classification"]["model_version"], "test-v1")

    def test_ml_does_not_override_confirmed_phishtank_result(self):
        navigation = validate_navigation_alert(self.navigation_alert())
        settings = Settings(ml_enabled=True)

        def query(_url, _settings):
            return {
                "status": "malicious", "malicious": True,
                "in_database": True, "verified": True, "valid": True,
            }

        def unexpected_score(_url, _model_path, _threshold):
            self.fail("ML must not run for a confirmed PhishTank result")

        with tempfile.TemporaryDirectory() as directory:
            cache = ResultCache(Path(directory) / "cache.sqlite3")
            try:
                result = classify_navigation(
                    navigation, settings, cache, query=query, ml_scorer=unexpected_score
                )
            finally:
                cache.close()

        self.assertEqual(result["classification"]["status"], "malicious")
        self.assertEqual(result["classification"]["source"], "phishtank")

    def test_web_risk_cache_is_isolated_from_phishtank(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = ResultCache(Path(directory) / "cache.sqlite3")
            try:
                cache.put("https://example.test/", {"status": "not_found"}, 60, provider="phishtank")
                self.assertIsNone(cache.get("https://example.test/", provider="google_webrisk"))
            finally:
                cache.close()

    def test_web_risk_monthly_guard_and_circuit_state(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = ResultCache(Path(directory) / "cache.sqlite3")
            try:
                self.assertTrue(cache.reserve_request("google_webrisk", 1, now=1_700_000_000))
                self.assertFalse(cache.reserve_request("google_webrisk", 1, now=1_700_000_001))
                cache.record_error("google_webrisk", 60, now=1_700_000_000)
                self.assertTrue(cache.circuit_open("google_webrisk", now=1_700_000_001))
                self.assertFalse(cache.circuit_open("google_webrisk", now=1_700_000_061))
            finally:
                cache.close()

    def test_web_risk_failure_uses_ml_as_degraded_fallback(self):
        navigation = validate_navigation_alert(self.navigation_alert())
        settings = Settings(reputation_provider="google_webrisk", ml_enabled=True)

        def failed_query(_url, _settings):
            raise ClassificationError("Google Web Risk HTTP error 403")

        def score(_url, _model_path, _threshold):
            return {"score": 0.9, "threshold": 0.5, "model_kind": "test", "calibrated": False}

        with tempfile.TemporaryDirectory() as directory:
            cache = ResultCache(Path(directory) / "cache.sqlite3")
            try:
                result = classify_navigation(navigation, settings, cache, query=failed_query, ml_scorer=score)
            finally:
                cache.close()
        classification = result["classification"]
        self.assertEqual(classification["status"], "suspicious")
        self.assertTrue(classification["degraded"])
        self.assertEqual(classification["reputation_provider"], "google_webrisk")

    def test_web_risk_match_prevents_ml_and_keeps_provider_source(self):
        navigation = validate_navigation_alert(self.navigation_alert())
        settings = Settings(reputation_provider="google_webrisk", ml_enabled=True)

        def query(_url, _settings):
            return {
                "status": "malicious", "malicious": True, "in_database": True,
                "verified": True, "valid": True, "provider": "google_webrisk",
                "threat_types": ["SOCIAL_ENGINEERING"], "expire_at": 4_000_000_000,
            }

        def unexpected_score(*_args):
            self.fail("ML must not override a Web Risk match")

        with tempfile.TemporaryDirectory() as directory:
            cache = ResultCache(Path(directory) / "cache.sqlite3")
            try:
                result = classify_navigation(navigation, settings, cache, query=query, ml_scorer=unexpected_score)
            finally:
                cache.close()
        self.assertEqual(result["classification"]["source"], "google_webrisk")
        self.assertEqual(result["classification"]["status"], "malicious")


if __name__ == "__main__":
    unittest.main()
