#!/usr/bin/env python3
"""Validate, install, and enable a modern model or the original SVR for Phase 4."""

from __future__ import annotations

import argparse
import grp
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import ModuleType


RUNTIME_MARKER = "EDGE_ML_WAZUH_PYTHON"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--model", required=True, type=Path,
        help="trusted modern model bundle or the original model.joblib",
    )
    parser.add_argument(
        "--legacy-scaler", type=Path,
        help="original scaler.joblib; supplying this enables legacy_svr compatibility mode",
    )
    parser.add_argument(
        "--disable-legacy-network-features", action="store_true",
        help="use the original failure defaults instead of guarded WHOIS/page features",
    )
    parser.add_argument("--wazuh-home", default="/var/ossec")
    parser.add_argument("--threshold", type=float, help="override the artifact threshold; omit to use the artifact")
    parser.add_argument("--test-url", default="https://example.test/login")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Python module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def updated_config(
    config: dict, model_path: Path, threshold: float | None, mode: str = "modern",
    scaler_path: Path | None = None, legacy_network_features: bool = True,
) -> dict:
    result = dict(config)
    ml = dict(result.get("ml", {}))
    ml.update({
        "enabled": True,
        "mode": mode,
        "model_path": str(model_path),
        "scaler_path": "" if scaler_path is None else str(scaler_path),
        "threshold": threshold,
        "legacy_network_features": legacy_network_features,
    })
    result["ml"] = ml
    return result


def atomic_json_write(path: Path, value: dict, uid: int, gid: int, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def use_wazuh_python(home: Path) -> None:
    embedded = home / "framework" / "python" / "bin" / "python3"
    if os.environ.get(RUNTIME_MARKER) == "1" or not embedded.is_file():
        return
    environment = os.environ.copy()
    environment[RUNTIME_MARKER] = "1"
    os.execve(
        str(embedded),
        [str(embedded), str(Path(__file__).resolve()), *sys.argv[1:]],
        environment,
    )


def main() -> int:
    args = arguments()
    home = Path(args.wazuh_home)
    use_wazuh_python(home)
    if os.geteuid() != 0:
        raise SystemExit("Run this installer as root.")
    if args.threshold is not None and not 0.0 <= args.threshold <= 1.0:
        raise SystemExit("--threshold must be between 0 and 1")

    model_source = args.model.resolve(strict=True)
    if not model_source.is_file():
        raise SystemExit("--model must name a regular file")
    scaler_source = args.legacy_scaler.resolve(strict=True) if args.legacy_scaler else None
    if scaler_source is not None and not scaler_source.is_file():
        raise SystemExit("--legacy-scaler must name a regular file")
    legacy_mode = scaler_source is not None
    modern_module_path = home / "integrations" / "url_ml.py"
    legacy_module_path = home / "integrations" / "legacy_url_ml.py"
    config_path = home / "etc" / "edge-phishing-classifier.json"
    model_destination = home / "etc" / (
        "edge-legacy-model.joblib" if legacy_mode else "edge-url-model.joblib"
    )
    scaler_destination = home / "etc" / "edge-legacy-scaler.joblib" if legacy_mode else None
    required_paths = [config_path, legacy_module_path if legacy_mode else modern_module_path]
    for required in required_paths:
        if not required.is_file():
            raise SystemExit(f"Required Phase 4 file is missing: {required}")

    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise SystemExit("Classifier configuration root must be an object")
    ml_module = load_module(
        legacy_module_path if legacy_mode else modern_module_path,
        "installed_edge_legacy_url_ml" if legacy_mode else "installed_edge_url_ml",
    )
    try:
        if legacy_mode:
            validation = ml_module.score_legacy_url(
                args.test_url, str(model_source), str(scaler_source), args.threshold,
                False,
            )
        else:
            validation = ml_module.score_url(args.test_url, str(model_source), args.threshold)
    except Exception as exc:
        raise SystemExit(
            "Model validation failed. Ensure this Python runtime has the same joblib/scikit-learn "
            f"versions used for training. Details: {type(exc).__name__}: {exc}"
        ) from exc

    wazuh_gid = grp.getgrnam("wazuh").gr_gid
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = home / "backup" / f"edge-ml-model-{stamp}"
    backup.mkdir(parents=True)
    managed_artifacts = [model_destination]
    if scaler_destination is not None:
        managed_artifacts.append(scaler_destination)
    for path in (*managed_artifacts, config_path):
        if path.exists():
            shutil.copy2(path, backup / path.name)
    previously_existed = {path: path.exists() for path in managed_artifacts}

    try:
        artifact_pairs = [(model_source, model_destination)]
        if scaler_source is not None and scaler_destination is not None:
            artifact_pairs.append((scaler_source, scaler_destination))
        for artifact_source, artifact_destination in artifact_pairs:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{artifact_destination.name}.", dir=artifact_destination.parent
            )
            os.close(descriptor)
            temporary_artifact = Path(temporary_name)
            try:
                shutil.copyfile(artifact_source, temporary_artifact)
                os.chown(temporary_artifact, 0, wazuh_gid)
                os.chmod(temporary_artifact, 0o640)
                os.replace(temporary_artifact, artifact_destination)
            finally:
                if temporary_artifact.exists():
                    temporary_artifact.unlink()

        configured = updated_config(
            config, model_destination, args.threshold,
            "legacy_svr" if legacy_mode else "modern", scaler_destination,
            not args.disable_legacy_network_features,
        )
        atomic_json_write(config_path, configured, 0, wazuh_gid, 0o640)

        if legacy_mode:
            installed_validation = ml_module.score_legacy_url(
                args.test_url, str(model_destination), str(scaler_destination),
                args.threshold, False,
            )
        else:
            installed_validation = ml_module.score_url(
                args.test_url, str(model_destination), args.threshold
            )
        subprocess.run(["systemctl", "restart", "wazuh-manager"], check=True)
        subprocess.run(["systemctl", "is-active", "--quiet", "wazuh-manager"], check=True)
    except Exception:
        for artifact in managed_artifacts:
            if previously_existed[artifact]:
                shutil.copy2(backup / artifact.name, artifact)
            elif artifact.exists():
                artifact.unlink()
        shutil.copy2(backup / config_path.name, config_path)
        subprocess.run(["systemctl", "restart", "wazuh-manager"], check=False)
        raise

    print("ML model installed and enabled.")
    print(f"Mode: {'legacy_svr' if legacy_mode else 'modern'}")
    print(f"Model: {model_destination}")
    if scaler_destination is not None:
        print(f"Scaler: {scaler_destination}")
    print(f"Model version: {installed_validation['model_version']}")
    print(f"Effective threshold: {validation['threshold']}")
    print(f"Validation score: {installed_validation['score_percent']}% for {args.test_url}")
    print(f"Backup: {backup}")
    print("Next: run test-ml-path.py with a controlled URL.")
    if args.verbose:
        print(f"Python runtime: {sys.executable}")
        print(json.dumps(installed_validation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
