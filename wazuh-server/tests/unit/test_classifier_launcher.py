import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parents[2]
    / "phase4"
    / "custom-edge-phishing-classifier-launcher"
)
UBUNTU_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")


class ClassifierLauncherTests(unittest.TestCase):
    def make_home(self, directory: str) -> Path:
        home = Path(directory) / "ossec"
        integrations = home / "integrations"
        python_dir = home / "framework" / "python" / "bin"
        integrations.mkdir(parents=True)
        python_dir.mkdir(parents=True)
        launcher = integrations / "custom-edge-phishing-classifier"
        shutil.copy2(SOURCE, launcher)
        launcher.chmod(0o750)
        fake_python = python_dir / "python3"
        fake_python.write_text(
            '#!/bin/sh\nprintf "%s" "${SSL_CERT_FILE:-}"\n', encoding="utf-8"
        )
        fake_python.chmod(0o750)
        return launcher

    @unittest.skipUnless(UBUNTU_CA_BUNDLE.is_file(), "Ubuntu CA bundle is unavailable")
    def test_selects_ubuntu_ca_bundle_for_wazuh_python(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = self.make_home(directory)
            environment = os.environ.copy()
            environment.pop("SSL_CERT_FILE", None)
            completed = subprocess.run(
                [str(launcher)], env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
        self.assertEqual(completed.stdout, str(UBUNTU_CA_BUNDLE))

    def test_preserves_administrator_ca_bundle_override(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = self.make_home(directory)
            environment = os.environ.copy()
            environment["SSL_CERT_FILE"] = "/approved/custom-ca.pem"
            completed = subprocess.run(
                [str(launcher)], env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
        self.assertEqual(completed.stdout, "/approved/custom-ca.pem")


if __name__ == "__main__":
    unittest.main()
