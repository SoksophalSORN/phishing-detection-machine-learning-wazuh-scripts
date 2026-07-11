# Offline Evaluation Tools

`evaluate-ml-list.py` evaluates a local CSV, JSON, JSONL, or text URL list with
the installed model. It forces the reputation-negative path, disables legacy
network-derived features, does not contact candidate URLs, and does not inject
Wazuh alerts. Its output is model evaluation data rather than deployment
verification.
