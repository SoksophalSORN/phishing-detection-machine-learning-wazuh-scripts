# Wazuh Server Phishing Pipeline

This directory covers Phase 3 transport verification, Phase 4 classification,
and the final configurable rule policy.

## Phase 3: Server Receipt and Pilot Alert

Phase 3 proves that the Edge navigation event crosses the complete transport boundary:

```text
Edge -> native host -> JSONL -> Windows Wazuh agent -> Ubuntu Wazuh manager -> alert
```

It installs a temporary level-3 rule for every valid navigation. This deliberate pilot noise makes transport easy to verify. Phase 4 should replace or lower this rule so ordinary browsing does not remain a security alert.

## Prerequisites

- Phase 1 writes valid navigation JSONL records.
- Phase 2 reports that the Windows Wazuh agent analyzes the JSONL file.
- The Windows agent is enrolled and connected to this Ubuntu manager.
- This `wazuh-server` directory is available on the Ubuntu server.

## Install

On the Ubuntu Wazuh server:

```bash
cd /path/to/phishing-detection-machine-learning-wazuh-scripts
chmod +x wazuh-server/*.sh
sudo ./wazuh-server/install-phase3.sh
```

For full diagnostics, including the sample event and verbose `wazuh-logtest` output:

```bash
sudo ./wazuh-server/install-phase3.sh -v
```

Display help without installing anything:

```bash
bash ./wazuh-server/install-phase3.sh -h
```

The installer:

- Rejects rule ID `100100` if another custom file already uses it.
- Backs up an existing Phase 3 rule.
- Installs `/var/ossec/etc/rules/edge_navigation_rules.xml` as `root:wazuh`, mode `0640`.
- Runs `wazuh-analysisd -t`.
- Uses `wazuh-logtest -U 100100:3:json` against a representative event.
- Restarts `wazuh-manager` and rolls back if validation or restart fails.

Rule `100100` is a narrowly filtered child of built-in rule `86600`. Wazuh's built-in JSON rules route records containing `timestamp` and `event_type` through that tree; the child additionally requires this pilot's schema, source, browser, and URL fields.

Wazuh recommends IDs `100000` through `120000` for custom rules and recommends placing larger custom rule sets under `/var/ossec/etc/rules/`.

## Verify a Real Edge Event

After installation:

1. Open a fresh URL in Edge.
2. Open the last JSONL line on Windows and copy its `event_id`.
3. On Ubuntu, run:

```bash
sudo ./wazuh-server/verify-phase3.sh \
  --event-id "PASTE_EVENT_ID" \
  --wait 60
```

Successful output includes:

```text
[PASS] wazuh-manager is active.
[PASS] Phase 3 rule file exists.
[PASS] wazuh-analysisd accepts the manager rules and configuration.
[PASS] Sample Edge JSON matches rule 100100 through decoder json.
[PASS] Event ... reached the manager and generated rule 100100 alert data.
```

The matching alert is stored in:

```text
/var/ossec/logs/alerts/alerts.json
```

In the dashboard, search for either:

```text
rule.id: 100100
```

or the copied event ID. Exact dashboard field syntax can vary by Wazuh dashboard/index-template version; the server-side verification script is the authoritative pilot check.

If the event appears in `archives.json` but not `alerts.json`, transport succeeded and rule matching needs investigation. Archives are not necessarily enabled, so an absent archive file alone is not proof of transport failure.

## Remove the Phase 3 Rule

```bash
sudo ./wazuh-server/uninstall-phase3.sh
```

The script retains a timestamped copy next to the removed rule and restores it automatically if the manager cannot restart.

## Original Implementation Cleanup

Before Phase 4, disable the old Chrome/Sysmon command-line integration so a browser event is not processed twice. Follow:

[Cleanup of the Original Sysmon/Command-Line Implementation](cleanup-original-implementation.md)

Start with the read-only audit:

```bash
sudo ./wazuh-server/audit-original-installation.sh
```

## Proceed to Phase 4

After a real event passes `verify-phase3.sh`, install the structured PhishTank classifier:

```bash
sudo bash ./wazuh-server/install-phase4.sh -v
```

An API key is optional but strongly recommended because PhishTank applies a
lower request limit without one. The safest installation path prompts without
putting the key in shell history:

```bash
sudo bash ./wazuh-server/install-phase4.sh -v --api-key-prompt
```

Alternatively, copy and edit the provided configuration:

```bash
cp wazuh-server/phase4/config.json /tmp/edge-phishing-classifier.json
nano /tmp/edge-phishing-classifier.json
sudo bash ./wazuh-server/install-phase4.sh -v \
  --config /tmp/edge-phishing-classifier.json
```

Open a fresh URL in Edge, copy its navigation `event_id`, and verify the classification result:

```bash
sudo bash ./wazuh-server/verify-phase4.sh \
  --source-event-id "PASTE_EVENT_ID" \
  --wait 60
```

The compatibility Phase 4 rules use level `10` for confirmed PhishTank URLs,
level `9` for ML suspicion, level `5` for processing errors, and a temporary
level `3` for negative/unknown pilot results. Run the configurable policy
installer below to move to the final rule range and suppress those routine
negative alerts at level `0`.

## Install the Final Configurable Rule Policy

The configurator scans active XML rules in `/var/ossec/etc/rules` and
`/var/ossec/ruleset/rules`. XML comments do not reserve IDs. With no conflicts,
the default policy is:

| Purpose | Rule ID | Level |
|---|---:|---:|
| Edge URL observed | `100300` | `5` |
| Classification base | `100301` | `0` |
| Verified PhishTank URL | `100302` | `10` |
| ML-suspicious URL | `100303` | `9` |
| Classifier error | `100304` | `5` |
| Negative/unknown result | `100305` | `0` |

These levels preserve the original project's navigation, PhishTank, and ML
severities while suppressing routine negative-result alerts. If any default ID
is active elsewhere, the tool selects the first free contiguous range. It
rejects collisions for explicitly supplied IDs.

Preview generated XML without changing Wazuh:

```bash
python3 ./wazuh-server/configure-rules.py > /tmp/edge-phishing-policy.xml
```

Run the interactive wizard and install atomically:

```bash
sudo python3 ./wazuh-server/configure-rules.py --wizard --install -v
```

The wizard asks for the group/block name and every rule ID and alert level. A
group may be a single Wazuh name or a comma-separated list such as
`gmail,phishing`; each component may contain letters, digits, `_`, `.`, or `-`.
The default is `browser_navigation,phishing_detection`. Press Enter at a prompt
to accept the scanned default.

The same policy can be installed non-interactively. For example:

```bash
sudo python3 ./wazuh-server/configure-rules.py --install -v \
  --group-name browser_navigation,phishing \
  --preferred-start 100300 \
  --navigation-rule-id 100300 --navigation-level 5 \
  --classification-base-rule-id 100301 --classification-base-level 0 \
  --phishtank-rule-id 100302 --phishtank-level 10 \
  --ml-rule-id 100303 --ml-level 9 \
  --error-rule-id 100304 --error-level 5 \
  --negative-rule-id 100305 --negative-level 0
```

Installation writes a unified rule file and a JSON policy manifest, backs up
the managed Phase 3/4 rules and configuration, updates both the classifier's
source rule and the `<integration>` trigger, validates the configuration,
restarts the manager, and then runs three rule tests against the refreshed
analysisd session manager. A failed validation, restart, or rule test restores
the backup and restarts the restored configuration.

## Safely Test a Confirmed-Phishing Alert

Choose a URL that PhishTank currently marks as verified and active. Do not open
it in Edge. Submit it directly to the installed classifier:

```bash
sudo python3 ./wazuh-server/test-phishing-path.py \
  --url 'https://verified-test-url.example/path' --wait 60
```

The script creates a unique synthetic source event, sends the URL only to the
classifier/PhishTank flow, and succeeds only when the resulting classification
status is `malicious`. A `not_found` response is not proof that a URL is safe.

## Original Model Compatibility Mode

The original root-level `model.joblib` and `scaler.joblib` can be connected to
the modern Edge event pipeline without retraining. The compatibility adapter:

- Recreates the original 15-feature order.
- Applies the original `StandardScaler` before the original RBF SVR.
- Treats the absolute SVR regression output as an uncalibrated raw score.
- Defaults to a raw-score threshold of `0.5`.
- Marks every result as `model_kind: legacy_svr`, `calibrated: false`, and
  `compatibility_mode: true`.
- Preserves the configured level-9 ML Wazuh rule.

The original model was serialized by scikit-learn 1.0.2. The Python runtime
used by the Wazuh integration must have compatible NumPy, joblib and
scikit-learn packages. Some Wazuh embedded Python builds omit `_posixshmem`,
which prevents joblib from importing even when it was installed successfully.
The legacy adapter installs a narrow import shim for serial model loading and
prediction. Shared-memory and parallel joblib operations remain unavailable;
the classifier does not use them. Rerun Phase 4 to install the adapter and the
launcher before enabling the model:

```bash
sudo bash ./wazuh-server/install-phase4.sh -v
```

The model installer automatically selects the Wazuh interpreter when joblib,
scikit-learn and NumPy can import through that compatibility layer.

Alternatively, a dedicated virtual environment can be used, but it must be
built from a complete Python 3.10 interpreter. Python 3.14 cannot install the
NumPy/scikit-learn versions required by this artifact:

```bash
sudo bash ./wazuh-server/install-ml-runtime.sh \
  --python /path/to/python3.10 -v
```

An offline wheel directory can additionally be supplied with
`--wheelhouse /path/to/wheels`.

After Phase 4 is updated, install the two original artifacts together:

```bash
sudo python3 ./wazuh-server/install-ml-model.py \
  --model ./model.joblib \
  --legacy-scaler ./scaler.joblib \
  --threshold 0.5 -v
```

Installation validates both artifacts before changing Wazuh, copies them to
root-controlled files under `/var/ossec/etc`, enables `legacy_svr` mode,
restarts the manager, and rolls back on failure.

Refresh the unified ML rule description while preserving the IDs and levels
already stored in the installed policy manifest:

```bash
sudo python3 ./wazuh-server/configure-rules.py --install -v
```

When a policy manifest exists, omitted options reuse its values. Supplying
`--preferred-start` explicitly requests a fresh automatic allocation instead.

By default the adapter attempts the original WHOIS and page-derived features.
It restricts page requests to public HTTP/HTTPS destinations, rejects embedded
credentials and non-public IP addresses, rechecks redirects, limits redirects
and response size, and enforces timeouts. These controls reduce but do not
eliminate the risks of manager-side URL retrieval.

To avoid all WHOIS/page requests and use the original extractor's failure
defaults for those seven features, install with:

```bash
sudo python3 ./wazuh-server/install-ml-model.py \
  --model ./model.joblib \
  --legacy-scaler ./scaler.joblib \
  --threshold 0.5 \
  --disable-legacy-network-features -v
```

Test the installed scaler, SVR, forced PhishTank-negative fallback, and chosen
Wazuh rule without opening the target or making a network request:

```bash
sudo python3 ./wazuh-server/test-ml-path.py \
  --url 'https://controlled-test.example/login' -v
```

The first run reports whether the raw score is `suspicious` or `unlikely`.
After observing the expected result, add `--expect suspicious` or
`--expect unlikely` for repeatable acceptance testing.

The score must not be interpreted as a percentage or calibrated probability.
The original training extractor made its IP-address feature effectively
constant, and unavailable WHOIS/page features fall back to suspicious defaults;
these limitations cannot be corrected without retraining.

## Alternative Modern URL-Only ML Model

The repository also supports a new calibrated URL-only model that performs no
page download, DNS lookup, WHOIS lookup, or arbitrary outbound request. This is
optional and is not required when using the original compatibility mode.

The repository intentionally does not contain a replacement training dataset.
To use the optional modern mode, prepare a reviewed
CSV containing `url,label` columns (`0` benign, `1` phishing), for example:

```csv
url,label
https://known-benign.example/,0
https://reviewed-phishing.example/login,1
```

Train in an environment whose joblib and scikit-learn versions are also
available to the `python3` runtime used by the Wazuh integration:

```bash
python3 -m venv /tmp/edge-url-ml-venv
/tmp/edge-url-ml-venv/bin/pip install joblib scikit-learn
/tmp/edge-url-ml-venv/bin/python \
  ./wazuh-server/phase4/train_url_model.py \
  --input /path/to/reviewed-urls.csv \
  --output /tmp/edge-url-model.joblib \
  --model-version pilot-2026-01 --threshold 0.80
```

Install `joblib` and the matching scikit-learn runtime for the Python used by
the Wazuh integration. Only load a trusted, root-controlled model artifact;
joblib model files are executable deserialization formats. The model installer
loads the artifact with that runtime, checks its format, feature schema,
version, probability and threshold, installs it as `root:wazuh` mode `0640`,
enables ML atomically, restarts Wazuh, and rolls back on failure:

```bash
sudo python3 ./wazuh-server/install-ml-model.py \
  --model /tmp/edge-url-model.joblib -v
```

To override the trained threshold, add `--threshold 0.85`. Omitting the option
stores `null` in `/var/ossec/etc/edge-phishing-classifier.json` and uses the
threshold bundled with the model:

```json
"ml": {
  "enabled": true,
  "model_path": "/var/ossec/etc/edge-url-model.joblib",
  "threshold": null
}
```

`null` uses the threshold stored with the trained artifact. ML runs only when
PhishTank has not confirmed the URL as active phishing. It emits `suspicious`
or `unlikely`; it never changes a confirmed PhishTank result.

Test the installed modern artifact, forced PhishTank-negative fallback, and
the configured Wazuh ML/negative rule without opening the target or making any
network request:

```bash
sudo python3 ./wazuh-server/test-ml-path.py \
  --url 'https://controlled-test.example/login' -v
```

The command reports the actual model score and status. After observing it, use
`--expect suspicious` or `--expect unlikely` in repeatable acceptance tests.
This isolated test proves the fallback and rule; a subsequent controlled Edge
navigation proves the complete browser-to-ML path.

## Privacy, Retention, and Legacy Cleanup

The extension and native host remove fragments and embedded credentials,
redact common secret query parameters, and redact search terms on common
search-engine hosts. Rule descriptions contain `url_host`, not the complete
URL. The normalized URL remains in structured event data because both
PhishTank and the URL-only model require it.

The endpoint JSONL rotates at 10 MiB and retains three rotated files. Wazuh
server/index retention is controlled separately by the deployment's indexer
and archival policies; set that retention according to the pilot's privacy and
incident-response requirements.

After the configurable pipeline passes the real and synthetic tests, run the
read-only legacy audit and follow the cleanup guide:

```bash
sudo bash ./wazuh-server/audit-original-installation.sh
```

[Cleanup of the Original Sysmon/Command-Line Implementation](cleanup-original-implementation.md)
