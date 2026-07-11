import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("test_ml_list_script", ROOT / "test-ml-list.py")
SCRIPT = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(SCRIPT)


class MLListTests(unittest.TestCase):
    def test_csv_selects_only_explicitly_unverified_unique_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.csv"
            path.write_text(
                "phish_id,url,verified\n"
                "1,https://unverified.example/login,no\n"
                "2,https://verified.example/,yes\n"
                "3,https://unknown.example/,\n"
                "4,https://unverified.example/login,no\n",
                encoding="utf-8",
            )
            records, structured = SCRIPT.records_from_file(path, "csv", "url")
            selected, counts, verification_seen = SCRIPT.select_samples(
                records, "url", "phish_id", "verified", False, 100
            )
        self.assertTrue(structured)
        self.assertTrue(verification_seen)
        self.assertEqual([item["sample_id"] for item in selected], ["1"])
        self.assertEqual(counts["verified_skipped"], 2)
        self.assertEqual(counts["duplicates"], 1)

    def test_plain_text_is_accepted_as_operator_curated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.txt"
            path.write_text("# comment\nhttps://candidate.example/path\n", encoding="utf-8")
            records, structured = SCRIPT.records_from_file(path, "text", "url")
            selected, _, verification_seen = SCRIPT.select_samples(
                records, "url", "phish_id", "verified", False, 100
            )
        self.assertFalse(structured)
        self.assertFalse(verification_seen)
        self.assertEqual(selected[0]["url_host"], "candidate.example")

    def test_rejects_credentials_and_non_web_urls(self):
        records = [
            {"url": "https://user:secret@example.test/", "verified": "no"},
            {"url": "file:///tmp/test", "verified": "no"},
        ]
        selected, counts, _ = SCRIPT.select_samples(
            records, "url", "phish_id", "verified", False, 100
        )
        self.assertEqual(selected, [])
        self.assertEqual(counts["invalid"], 2)


if __name__ == "__main__":
    unittest.main()
