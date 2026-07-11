import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


INSTALLER = load("install_ml_model", ROOT / "install-ml-model.py")
VERIFIER = load("test_ml_path", ROOT / "test-ml-path.py")


class MLDeploymentTests(unittest.TestCase):
    def test_enables_model_without_discarding_other_config(self):
        original = {"endpoint": "https://example.test/api", "ml": {"enabled": False}}
        updated = INSTALLER.updated_config(original, Path("/var/ossec/etc/model.joblib"), None)
        self.assertEqual(updated["endpoint"], original["endpoint"])
        self.assertTrue(updated["ml"]["enabled"])
        self.assertEqual(updated["ml"]["threshold"], None)

    def test_configures_original_model_and_scaler_compatibility_mode(self):
        updated = INSTALLER.updated_config(
            {}, Path("/var/ossec/etc/edge-legacy-model.joblib"), 0.5,
            mode="legacy_svr",
            scaler_path=Path("/var/ossec/etc/edge-legacy-scaler.joblib"),
            legacy_network_features=True,
        )
        self.assertEqual(updated["ml"]["mode"], "legacy_svr")
        self.assertEqual(
            updated["ml"]["scaler_path"], "/var/ossec/etc/edge-legacy-scaler.joblib"
        )
        self.assertTrue(updated["ml"]["legacy_network_features"])

    def test_formats_legacy_score_without_claiming_a_percentage(self):
        message = INSTALLER.validation_score_message(
            {"score": 0.09, "calibrated": False}, "https://example.test/"
        )
        self.assertEqual(
            message, "Validation raw score: 0.09 for https://example.test/"
        )

    def test_uses_configured_policy_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy = home / "etc" / "edge-phishing-rule-policy.json"
            policy.parent.mkdir(parents=True)
            policy.write_text(
                '{"ml_rule_id":100312,"ml_level":9,"negative_rule_id":100314,"negative_level":0}',
                encoding="utf-8",
            )
            self.assertEqual(VERIFIER.expected_rule(home, "suspicious"), (100312, 9))
            self.assertEqual(VERIFIER.expected_rule(home, "unlikely"), (100314, 0))


if __name__ == "__main__":
    unittest.main()
