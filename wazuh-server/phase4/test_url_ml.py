import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from url_ml import FEATURE_NAMES, extract_features, score_url


class URLFeatureTests(unittest.TestCase):
    def test_feature_schema_is_stable(self):
        values = extract_features("https://secure-login.example.test/account/verify?id=42")
        self.assertEqual(len(values), len(FEATURE_NAMES))
        self.assertEqual(values, extract_features("https://secure-login.example.test/account/verify?id=42"))

    def test_detects_structural_indicators(self):
        values = dict(zip(
            FEATURE_NAMES,
            extract_features("http://192.0.2.10:8080/login@example?token=1"),
        ))
        self.assertEqual(values["hostname_is_ip"], 1.0)
        self.assertEqual(values["explicit_port"], 1.0)
        self.assertEqual(values["contains_at"], 1.0)
        self.assertEqual(values["uses_https"], 0.0)

    def test_rejects_non_web_url(self):
        with self.assertRaises(ValueError):
            extract_features("file:///tmp/example")

    def test_scores_versioned_probability_bundle(self):
        class Model:
            def predict_proba(self, _features):
                return [[0.09, 0.91]]

        bundle = {
            "format": "wazuh-url-model-v1",
            "feature_names": FEATURE_NAMES,
            "model_version": "unit-v1",
            "threshold": 0.8,
            "model": Model(),
        }
        fake_joblib = SimpleNamespace(load=lambda _path: bundle)
        with patch.dict(sys.modules, {"joblib": fake_joblib}):
            result = score_url("https://example.test/login", "/trusted/model.joblib")
        self.assertEqual(result["score"], 0.91)
        self.assertEqual(result["score_percent"], 91.0)
        self.assertEqual(result["threshold"], 0.8)
        self.assertEqual(result["model_version"], "unit-v1")


if __name__ == "__main__":
    unittest.main()
