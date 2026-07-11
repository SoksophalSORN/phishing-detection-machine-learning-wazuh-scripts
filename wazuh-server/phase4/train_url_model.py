#!/usr/bin/env python3
"""Train a calibrated URL-only phishing classifier from a labeled CSV."""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import time
from pathlib import Path

from url_ml import FEATURE_NAMES, extract_features


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="CSV with url and label columns")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--threshold", type=float, default=0.8)
    args = parser.parse_args()
    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0 and 1")

    try:
        import joblib
        import sklearn
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import classification_report, roc_auc_score
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise SystemExit("Install joblib and scikit-learn to train the model") from exc

    labeled_urls: dict[str, int] = {}
    conflicting_urls: set[str] = set()
    with args.input.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                label = int(row[args.label_column])
                if label not in {0, 1}:
                    continue
                url = row[args.url_column].strip()
                extract_features(url)
            except (KeyError, TypeError, ValueError):
                continue
            if url in labeled_urls and labeled_urls[url] != label:
                conflicting_urls.add(url)
                labeled_urls.pop(url, None)
            elif url not in conflicting_urls:
                labeled_urls[url] = label

    features = [extract_features(url) for url in labeled_urls]
    labels = list(labeled_urls.values())
    class_counts = collections.Counter(labels)
    if len(features) < 100 or min(class_counts.values(), default=0) < 10:
        raise SystemExit("At least 100 valid rows and 10 rows from each label are required")

    train_x, test_x, train_y, test_y = train_test_split(
        features, labels, test_size=0.2, random_state=42, stratify=labels
    )
    base = Pipeline([
        ("scale", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)),
    ])
    model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    model.fit(train_x, train_y)
    probabilities = model.predict_proba(test_x)[:, 1]
    predictions = (probabilities >= args.threshold).astype(int)
    metrics = {
        "roc_auc": float(roc_auc_score(test_y, probabilities)),
        "classification_report": classification_report(test_y, predictions, output_dict=True),
        "test_rows": len(test_y),
    }
    bundle = {
        "format": "wazuh-url-model-v1",
        "model_version": args.model_version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sklearn_version": sklearn.__version__,
        "dataset_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
        "random_state": 42,
        "feature_names": FEATURE_NAMES,
        "threshold": args.threshold,
        "metrics": metrics,
        "training_rows": len(features),
        "class_counts": {str(key): value for key, value in sorted(class_counts.items())},
        "conflicting_urls_excluded": len(conflicting_urls),
        "model": model,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.output)
    print(json.dumps({key: value for key, value in bundle.items() if key != "model"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
