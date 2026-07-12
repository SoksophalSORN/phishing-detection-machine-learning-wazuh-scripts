import subprocess
import unittest
from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = SERVER_ROOT / "install-wazuh-server.sh"


class CompleteInstallerTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(INSTALLER)], check=True)

    def test_help_documents_complete_and_custom_installations(self):
        completed = subprocess.run(
            ["bash", str(INSTALLER), "--help"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        self.assertIn("--legacy-scaler", completed.stdout)
        self.assertIn("--wizard", completed.stdout)
        self.assertIn("--navigation-rule-id", completed.stdout)
        self.assertIn("--api-key-prompt", completed.stdout)
        self.assertIn("--enable-legacy-network-features", completed.stdout)
        self.assertIn("--environment", completed.stdout)
        self.assertIn("--reputation-provider", completed.stdout)
        self.assertIn("--web-risk-key-prompt", completed.stdout)
        self.assertIn("--web-risk-key-file", completed.stdout)
        self.assertIn("--web-risk-threat-type", completed.stdout)
        self.assertIn("--web-risk-monthly-limit", completed.stdout)
        self.assertIn("--web-risk-negative-cache-seconds", completed.stdout)
        self.assertIn("--review-threshold", completed.stdout)
        self.assertIn("--review-rule-id", completed.stdout)
        self.assertIn("--review-level", completed.stdout)

    def test_unknown_option_is_rejected_without_installing(self):
        completed = subprocess.run(
            ["bash", str(INSTALLER), "--not-an-option"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Unknown option", completed.stderr)

    def test_unknown_environment_is_rejected_without_installing(self):
        completed = subprocess.run(
            ["bash", str(INSTALLER), "--environment", "qa"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("production or staging", completed.stderr)


if __name__ == "__main__":
    unittest.main()
