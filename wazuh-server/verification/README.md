# Installed-System Verification

These commands inspect or safely exercise a configured Wazuh manager:

- `verify-navigation-ingestion.sh` validates the navigation rule and optionally
  locates a real extension event by `event_id`.
- `verify-classification-event.sh` locates a classification event produced for
  a real navigation.
- `verify-ml-integration.py` forces a reputation-negative result, scores a
  controlled URL offline, and validates the selected Wazuh rule.
- `verify-phishtank-integration.py` submits a URL to the configured PhishTank
  lookup without opening or downloading the target. It requires the external
  service to be reachable.
- `verify-web-risk-integration.py` performs one explicit lookup through the
  configured Google Web Risk provider without opening or downloading the
  target. It may consume API quota. A match or a clean no-match pipeline result
  succeeds; provider/authentication errors fail.

Each live provider verifier refuses to run when its provider is not selected.

These are acceptance and operational diagnostics, not development unit tests.
