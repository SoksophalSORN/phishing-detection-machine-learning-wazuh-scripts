import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "verification" / "verify-web-risk-integration.py"
SPEC = importlib.util.spec_from_file_location("verify_web_risk_integration", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class WebRiskVerifierTests(unittest.TestCase):
    def event(self, source_event_id):
        return {
            "rule": {"id": "100302"},
            "data": {
                "integration": "edge-phishing-classifier",
                "classification": {
                    "source_event_id": source_event_id,
                    "status": "not_found",
                    "source": "google_webrisk",
                },
            },
        }

    def test_incomplete_matching_final_record_is_retried(self):
        source_event_id = "safe-web-risk-test-race"
        serialized = json.dumps(self.event(source_event_id))
        with tempfile.TemporaryDirectory() as directory:
            alerts_path = Path(directory) / "alerts.json"
            alerts_path.write_text(serialized[:-8], encoding="utf-8")
            self.assertIsNone(MODULE.find_classification_event(alerts_path, source_event_id))

            alerts_path.write_text(serialized + "\n", encoding="utf-8")
            found = MODULE.find_classification_event(alerts_path, source_event_id)

        self.assertIsNotNone(found)
        self.assertEqual(found["data"]["classification"]["source_event_id"], source_event_id)

    def test_malformed_complete_matching_line_does_not_crash(self):
        source_event_id = "safe-web-risk-test-malformed"
        with tempfile.TemporaryDirectory() as directory:
            alerts_path = Path(directory) / "alerts.json"
            alerts_path.write_text(
                '{"integration":"edge-phishing-classifier","source_event_id":"'
                + source_event_id + '" broken}\n',
                encoding="utf-8",
            )
            self.assertIsNone(MODULE.find_classification_event(alerts_path, source_event_id))


if __name__ == "__main__":
    unittest.main()
