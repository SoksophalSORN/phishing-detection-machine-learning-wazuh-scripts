# Ubuntu Wazuh Server Phishing Pipeline

This directory installs the manager side of the Microsoft Edge navigation
pipeline. It receives structured events forwarded by a Windows Wazuh agent,
checks each URL with one selected reputation provider, optionally runs ML, and
emits provider-specific Wazuh alerts.

Use `install-wazuh-server.sh` for staging and production. The individual Phase
3 and Phase 4 scripts remain available for historical migration and component
diagnostics, but they are not the recommended deployment workflow.

## Supported Scope

- Ubuntu Wazuh manager installed under `/var/ossec` by default.
- Windows 10 x64 endpoint running the project’s Microsoft Edge extension,
  native host, and enrolled Wazuh agent.
- Google Web Risk or PhishTank as mutually exclusive reputation providers.
- The included original scaler/SVR through legacy compatibility mode, or an
  optional trusted modern model bundle.

Linux is supported here as the Wazuh server. Linux browser/endpoint capture and
Chrome, Brave, and Firefox support are not implemented by this repository.

## Prerequisites

- `wazuh-manager` is installed and running.
- The Windows agent is enrolled and connected.
- The Edge native host is writing valid JSONL events and the Windows agent is
  collecting them.
- This repository is present on the manager.
- `model.joblib` and `scaler.joblib` are present in the repository root unless
  another trusted model is supplied explicitly.
- For Google Web Risk, create a restricted key using the
  [demo setup](../docs/google-web-risk-demo-setup.md). Do not store the key in
  `.env`, Git, command arguments, or shell history.

Check the manager before installation:

```bash
sudo systemctl is-active wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t
```

If the original fork’s Sysmon/browser-command-line implementation is installed,
run the read-only audit and follow the cleanup guide first:

```bash
sudo bash ./wazuh-server/audit-original-installation.sh
```

[Original implementation cleanup](cleanup-original-implementation.md)

## Recommended Staging Installation

Staging raises routine negative or unlikely results to level 3 so the complete
fallback path is visible during acceptance. Start there before production.

### Google Web Risk

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment staging \
  --reputation-provider google-webrisk \
  --web-risk-key-prompt \
  -v
```

The key is entered without echo and installed at:

```text
/var/ossec/etc/edge-google-web-risk.key
```

It is stored as `root:wazuh`, mode `0640`, separately from the JSON
configuration. For automation, `--web-risk-key-file /protected/key` copies a
pre-staged secret; the key itself must never be passed as an argument.

`SOCIAL_ENGINEERING` is requested by default. Optional categories can be
selected by repeating the option:

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment staging \
  --reputation-provider google-webrisk \
  --web-risk-key-prompt \
  --web-risk-threat-type SOCIAL_ENGINEERING \
  --web-risk-threat-type MALWARE \
  -v
```

Supported Web Risk categories are `SOCIAL_ENGINEERING`, `MALWARE`, and
`UNWANTED_SOFTWARE`. Optional application controls include:

```text
--web-risk-monthly-limit NUMBER
--web-risk-negative-cache-seconds NUMBER
```

Defaults are a 90,000-call monthly application limit and a 300-second negative cache.
Positive matches are cached until Google’s returned `expireTime`.

### PhishTank Alternative

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment staging \
  --reputation-provider phishtank \
  -v
```

Anonymous operation remains possible. Add `--api-key-prompt` only when a
PhishTank application key is available.

PhishTank and Google Web Risk are never active together. On an explicit
provider change, the complete installer backs up the current deployment,
removes the managed integration and provider rule, validates and restarts Wazuh
in the provider-disabled state, and only then installs the new provider. It
aborts when unmanaged active PhishTank rules or integrations would conflict.

## What the Complete Installer Does

The installer:

1. Detects or explicitly selects one reputation provider.
2. Scans active Wazuh rules and allocates a free custom-rule range.
3. Installs the unified navigation and classification rule policy.
4. Installs and registers the provider-neutral classifier.
5. Installs the Web Risk client and system-CA handling regardless of which
   provider is selected, leaving only the selected provider active.
6. Validates and installs the trusted model and scaler.
7. Exercises reputation-negative ML fallback without a network request.
8. Validates the final provider configuration and active rule source.
9. Restarts Wazuh and records the deployment manifest.

Before making changes, it snapshots managed rules, configuration, integration
modules, model files, provider key, and cache state under `/var/ossec/backup`.
Failure restores the pre-installation state and restarts the manager.

The installer makes no live Web Risk or PhishTank request. External provider
availability is tested separately after local configuration succeeds.

## ML Runtime and Included Model

When `model.joblib` and `scaler.joblib` are present in the repository root, the
complete installer selects them automatically and enables `legacy_svr` mode.
The compatibility adapter:

- Preserves the original 15-feature ordering.
- Applies the original `StandardScaler` before the RBF SVR.
- Treats the SVR output as an uncalibrated raw score, not a probability.
- Uses a default suspicious threshold of `0.5` unless overridden.
- Sends scores from the default `0.07` review threshold up to (but not
  including) the suspicious threshold to a level-7 review rule.
- Labels output with `model_kind: legacy_svr`, `calibrated: false`, and
  `compatibility_mode: true`.

Set the two bands independently with `--review-threshold` and `--threshold`.
The review threshold must be lower than the suspicious threshold. A review
result is not declared malicious; it is an intermediate alert for analyst
triage.

The complete installer disables legacy WHOIS and page-derived network features
by default. This avoids arbitrary manager-side retrieval. Enable the guarded
compatibility implementation only when that risk is explicitly accepted:

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment staging \
  --reputation-provider google-webrisk \
  --web-risk-key-prompt \
  --enable-legacy-network-features \
  -v
```

If model validation reports that joblib/scikit-learn is unavailable, create a
dedicated runtime from a complete Python 3.10 interpreter:

```bash
sudo bash ./wazuh-server/install-ml-runtime.sh \
  --python /usr/bin/python3.10 \
  -v
```

Use the actual Python 3.10 path on the server. An offline wheel directory can
be supplied with `--wheelhouse /path/to/wheels`. The original artifact was
serialized by scikit-learn 1.0.2; Python 3.14 is not a compatible replacement
runtime for that artifact.

The Wazuh embedded Python can omit `_posixshmem`; the compatibility adapter
provides only the narrow shim required for serial loading and prediction. The
launcher also keeps TLS verification enabled while selecting the operating
system CA bundle when embedded Python points at a missing `/usr/local/ssl`
trust store.

## Default Wazuh Rule Policy

With no conflicts, the complete installer allocates:

| Purpose | Rule ID | Staging level | Production level |
| --- | ---: | ---: | ---: |
| Edge URL observed | `100300` | 5 | 5 |
| Classification parent | `100301` | 0 | 0 |
| Confirmed selected-provider match | `100302` | 10 | 10 |
| ML-suspicious result | `100303` | 9 | 9 |
| Classifier/provider error | `100304` | 5 | 5 |
| Negative or unlikely result | `100305` | 3 | 0 |
| ML review-band result | `100306` | 7 | 7 |

If those IDs are already active, the configurator selects the first free
contiguous range in Wazuh’s custom interval. Explicit collisions are rejected.

Use the integrated wizard when IDs, levels, or groups must be chosen manually:

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment staging \
  --reputation-provider google-webrisk \
  --web-risk-key-prompt \
  --wizard \
  -v
```

Non-interactive policy options include:

```text
--group-name NAME
--preferred-start ID
--navigation-rule-id ID          --navigation-level LEVEL
--classification-base-rule-id ID --classification-base-level LEVEL
--reputation-rule-id ID          --reputation-level LEVEL
--ml-rule-id ID                  --ml-level LEVEL
--review-rule-id ID              --review-level LEVEL
--error-rule-id ID               --error-level LEVEL
--negative-rule-id ID            --negative-level LEVEL
```

The older `--phishtank-rule-id` and `--phishtank-level` spellings remain as
manifest-compatibility aliases. Use the provider-neutral names for new
deployments.

Preview a rule policy without changing Wazuh:

```bash
python3 ./wazuh-server/configure-rules.py \
  --reputation-provider google-webrisk \
  --output /tmp/edge-phishing-policy.xml
```

## Verification

Installed-system checks are under `wazuh-server/verification`; development unit
tests are separate under `wazuh-server/tests`.

### 1. Safe live Google Web Risk check

This explicit command can consume one API call. It sends the URL string only to
Google and does not open or download the target:

```bash
sudo python3 ./wazuh-server/verification/verify-web-risk-integration.py \
  --url 'http://testsafebrowsing.appspot.com/s/phishing.html' \
  --wait 60
```

A confirmed test match should reach the configured level-10 reputation rule
with `classification.source: google_webrisk`. A repeated lookup before its
expiry should report `cache_hit: true` without increasing the monthly counter.

Never open a real phishing URL in Edge to test this system.

### 2. PhishTank live check

Run this only when PhishTank is the selected provider and with an
administrator-approved URL:

```bash
sudo python3 ./wazuh-server/verification/verify-phishtank-integration.py \
  --url 'https://approved-test.example/path' \
  --wait 60
```

Each live verifier refuses to run when its provider is not selected.

### 3. Offline ML check

This forces a local reputation no-match and makes no request to the provider or
target URL:

```bash
sudo python3 ./wazuh-server/verification/verify-ml-integration.py \
  --url 'https://controlled-test.example/login' \
  -v
```

After observing the installed model’s result, add `--expect suspicious`,
`--expect review`, or `--expect unlikely` for repeatable acceptance.

### 4. Real harmless Edge event

Copy a fresh `event_id` from the Windows JSONL log, then verify transport:

```bash
sudo bash ./wazuh-server/verification/verify-navigation-ingestion.sh \
  --event-id 'PASTE_EVENT_ID' \
  --wait 60
```

Verify classification for the same event:

```bash
sudo bash ./wazuh-server/verification/verify-classification-event.sh \
  --source-event-id 'PASTE_EVENT_ID' \
  --wait 60
```

The result must retain the Windows agent identity and source event ID. A
provider no-match means only “not found”; it is not proof that a URL is safe.

## Production Promotion

After staging acceptance and observation, preserve the selected provider and
change the manager profile:

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment production \
  --reputation-provider google-webrisk \
  -v
```

For PhishTank, select `--reputation-provider phishtank`. An installed Web Risk
key is retained when no key prompt/file option is supplied. Production changes
only routine negative/unknown visibility to level 0; confirmed reputation,
ML-suspicious, ML-review (level 7), and error levels remain active.

The deployment profile and selected provider are recorded in:

```text
/var/ossec/etc/edge-phishing-deployment.json
```

## Runtime Files and Operations

Primary installed paths are:

```text
/var/ossec/etc/edge-phishing-classifier.json
/var/ossec/etc/edge-phishing-rule-policy.json
/var/ossec/etc/edge-phishing-deployment.json
/var/ossec/etc/rules/edge_phishing_pipeline_rules.xml
/var/ossec/integrations/custom-edge-phishing-classifier
/var/ossec/var/edge-phishing-classifier/cache.sqlite3
```

Web Risk request counts and circuit state can be inspected without exposing the
key:

```bash
sudo sqlite3 /var/ossec/var/edge-phishing-classifier/cache.sqlite3 \
  'SELECT * FROM reputation_usage; SELECT * FROM reputation_state;'
```

Integration diagnostics are written to:

```text
/var/ossec/logs/integrations.log
```

Provider failures never become `not_found`. If ML is enabled, a provider outage
can produce a degraded ML result; otherwise it produces the configured level-5
error. Google Web Risk uses bounded retries and a temporary circuit breaker.

## Offline Evaluation and Optional Models

Evaluate a local CSV, JSON, JSONL, or text list without contacting reputation
providers or candidate hosts:

```bash
sudo python3 ./wazuh-server/tools/evaluate-ml-list.py \
  --input /path/to/operator-reviewed-urls.csv \
  --output /tmp/ml-results.jsonl \
  --limit 500 \
  -v
```

Structured inputs with a `verified` field accept explicit unverified values by
default; verified rows are skipped unless `--include-verified` is supplied.
Output is mode `0600`. The suspicious fraction is a model baseline, not recall
or accuracy unless the input is a properly labeled evaluation dataset.

An optional calibrated URL-only model interface remains available through
`phase4/train_url_model.py` and `install-ml-model.py`. The repository does not
ship a replacement training dataset. Training/retraining is outside the
required deployment path; only trusted, reviewed joblib artifacts should be
loaded.

## Privacy and Limitations

- The extension and native host remove fragments and embedded credentials and
  redact common sensitive query values and search terms.
- Rule descriptions use `url_host`, but the normalized complete URL remains in
  structured Wazuh data because classification requires it.
- Endpoint JSONL rotates at 10 MiB and retains three rotated files. Wazuh index
  and archive retention must be configured separately.
- Google Web Risk and PhishTank have quotas, outages, authentication failures,
  and coverage gaps.
- The original SVR score is uncalibrated and must not be presented as a phishing
  percentage. Its quality limitations cannot be corrected without retraining.
- This pipeline detects and alerts after committed navigation; it does not block
  or close browser pages.

Production key ownership, quota/budget controls, privacy review, and rollout
guidance are covered in the
[Google Web Risk preparation guide](../docs/google-web-risk-preparation-guide.md)
and [integration plan](../docs/google-web-risk-integration-plan.md).

## Historical Component Scripts

These scripts are retained for migration, troubleshooting, and reproducing the
development phases:

```text
install-phase3.sh
uninstall-phase3.sh
install-phase4.sh
configure-rules.py
install-ml-model.py
```

They should not be layered manually on a new staging or production deployment.
Use `install-wazuh-server.sh`, which coordinates their responsibilities,
provider exclusivity, complete backup, validation, and rollback.

Development tests:

```bash
python3 -m unittest discover -s wazuh-server/tests/unit -p 'test_*.py'
```

See [development tests](tests/README.md), [offline tools](tools/README.md), and
[installed verification](verification/README.md) for their narrower scopes.
