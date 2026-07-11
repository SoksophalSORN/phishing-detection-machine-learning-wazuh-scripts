import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "phase4"))

from legacy_url_ml import (
    LEGACY_FEATURE_NAMES,
    ensure_public_target,
    extract_legacy_features,
    score_legacy_url,
)


class LegacyURLMLTests(unittest.TestCase):
    def test_offline_adapter_produces_original_15_feature_shape(self):
        features = extract_legacy_features(
            "https://secure-login.example.test/account/verify?id=42",
            network_features=False,
        )
        self.assertEqual(len(features), len(LEGACY_FEATURE_NAMES))
        self.assertEqual(features[-7:], [1.0] * 7)

    def test_private_destination_is_refused(self):
        with self.assertRaisesRegex(ValueError, "non-public"):
            ensure_public_target("http://127.0.0.1/private")

    def test_original_scaler_and_svr_interfaces_are_adapted(self):
        class Scaler:
            n_features_in_ = 15

            def transform(self, values):
                return values

        class Model:
            def predict(self, _values):
                return [-0.73]

        fake_joblib = SimpleNamespace(
            load=lambda path: Scaler() if "scaler" in str(path) else Model()
        )
        with patch.dict(sys.modules, {"joblib": fake_joblib}):
            result = score_legacy_url(
                "https://example.test/login", "model.joblib", "scaler.joblib",
                threshold=0.5, network_features=False,
            )
        self.assertEqual(result["score"], 0.73)
        self.assertEqual(result["threshold"], 0.5)
        self.assertEqual(result["model_kind"], "legacy_svr")
        self.assertFalse(result["calibrated"])


if __name__ == "__main__":
    unittest.main()
