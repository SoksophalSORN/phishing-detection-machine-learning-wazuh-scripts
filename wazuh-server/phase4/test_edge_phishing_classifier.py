import json
import tempfile
import unittest
from pathlib import Path

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

    def test_rejects_wrong_rule(self):
        alert = self.navigation_alert()
        alert["rule"]["id"] = "100999"
        with self.assertRaises(ClassificationError):
            validate_navigation_alert(alert)

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


if __name__ == "__main__":
    unittest.main()
