# Microsoft Edge Phishing Detection with Wazuh

This project records top-level HTTP/HTTPS navigation from Microsoft Edge on a
Windows endpoint, forwards the structured events through a Wazuh agent, and
classifies the URLs on an Ubuntu Wazuh manager.

Google Web Risk and PhishTank are supported as alternative reputation
providers. When a URL is not confirmed by the selected provider, the manager
can pass it to the included legacy machine-learning compatibility layer. Wazuh
then produces separate alerts for confirmed reputation matches, ML suspicion,
level-7 ML review results, and processing failures.

This is a detection and demonstration system. It reports navigation after it
occurs; it does not block a page from loading.

## Supported Pilot

| Component | Supported implementation |
| --- | --- |
| Endpoint operating system | Windows 10 x64 |
| Browser | Microsoft Edge with a sideloaded Manifest V3 extension |
| Endpoint collector | Enrolled Windows Wazuh agent |
| Manager | Ubuntu Wazuh manager under `/var/ossec` |
| Reputation | Google Web Risk or PhishTank, exactly one at a time |
| ML | Included original scaler and SVR through legacy compatibility mode |

The server-side Ubuntu deployment is supported. “Linux is unsupported” below
refers to browser/endpoint collection: this repository does not provide a Linux
browser extension installation, native-messaging host, or endpoint installer.

## Architecture

```text
Microsoft Edge extension
  -> Windows native-messaging host
  -> C:\ProgramData\PhishingDetection\browser-navigation.json
  -> Windows Wazuh agent
  -> Ubuntu Wazuh manager
  -> Google Web Risk OR PhishTank
  -> optional ML fallback
  -> Wazuh rules, alerts, and dashboard
```

Only committed top-level HTTP/HTTPS navigation is collected. Page contents,
form values, cookies, authorization headers, iframe navigation, `edge://`
pages, and `file://` URLs are not collected.

## Prerequisites

Before beginning, prepare:

- A Windows 10 x64 pilot endpoint with Microsoft Edge.
- A Windows Wazuh agent that is already installed, enrolled, and connected to
  the intended manager.
- An Ubuntu Wazuh manager that is running and accessible with `sudo`.
- A copy of this repository on both systems.
- The included `model.joblib` and `scaler.joblib` in the repository root on the
  manager.
- For Google Web Risk, a restricted API key created with the
  [console-only demo setup](docs/google-web-risk-demo-setup.md). Do not save the
  key in `.env`, Git, or shell history.

Use staging first. It makes routine negative results visible at Wazuh level 3;
production suppresses them at level 0.

The ML fallback uses two thresholds. Scores at or above the suspicious
threshold are suspicious; scores from `0.07` up to that threshold generate a
level-7 review alert; lower scores remain unlikely. The review band is meant
for analyst triage and does not claim that the URL is malicious.

## Part 1: Install the Windows Endpoint

Run these steps from the Windows copy of the repository.

### 1. Load the Edge extension

1. Open `edge://extensions` in Microsoft Edge.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Select the repository's `edge-extension` directory.
5. Copy the 32-character extension ID displayed by Edge.

The extension is intentionally sideloaded for the pilot; it does not need to be
published in the Microsoft Edge Add-ons store.

### 2. Install the native-messaging host

Open PowerShell as Administrator, move to the repository root, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\native-host\install-host.ps1 `
  -ExtensionId "PASTE_THE_EDGE_EXTENSION_ID"
```

The repository includes the Windows x64 pilot executable at
`native-host\dist\navigation-host.exe`. To rebuild it instead, install Go and
run `native-host\build-host.ps1` first.

Return to `edge://extensions` and select **Reload** for the extension, or fully
restart Edge.

### 3. Confirm local navigation logging

Open a harmless HTTPS URL in Edge, then inspect the log in PowerShell:

```powershell
Get-Content "$env:ProgramData\PhishingDetection\browser-navigation.json" -Tail 3
```

Each line must be one JSON object containing fields such as `event_type`,
`event_id`, `browser`, `url`, `url_host`, and `source`.

Also test a cold start: close Edge completely and click an HTTP/HTTPS link from
a messaging application. The first committed URL should be recorded.

### 4. Configure the Windows Wazuh agent

Still in Administrator PowerShell, run:

```powershell
.\wazuh-agent\install-wazuh-agent.ps1 -Environment Staging
```

The installer backs up `ossec.conf`, adds an idempotent JSON `localfile` block,
restarts the Wazuh agent, and rolls back automatically if the service cannot
restart.

Verify it:

```powershell
.\wazuh-agent\verification\verify-wazuh-agent.ps1 `
  -ExpectedEnvironment Staging
```

Expected output confirms that the Wazuh service is running, the JSON collection
block is installed, recent records are valid, and logcollector recognizes
`browser-navigation.json`.

For non-default Wazuh paths, see the detailed
[Windows Wazuh-agent guide](wazuh-agent/README.md).

## Part 2: Install the Ubuntu Wazuh Server

Run these steps from the repository root on the Wazuh manager.

### 1. Check the manager and legacy installation state

```bash
sudo systemctl is-active wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t
```

If this server previously used the fork's Sysmon/Chrome command-line
implementation, follow the
[original implementation cleanup](wazuh-server/cleanup-original-implementation.md)
before continuing. A new server can skip that cleanup.

### 2. Choose one reputation provider

Google Web Risk is the recommended demonstration path because it has a
controlled test URL and uses a direct per-URL lookup. Complete the
[Google Cloud console setup](docs/google-web-risk-demo-setup.md) first.

PhishTank remains available as an alternative. The installer never enables
both providers together and performs a validated disabled transition when
switching an existing installation.

### 3. Run the complete staging installer

For Google Web Risk:

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment staging \
  --reputation-provider google-webrisk \
  --web-risk-key-prompt \
  -v
```

Enter the API key only at the hidden prompt. It is installed at
`/var/ossec/etc/edge-google-web-risk.key` with `root:wazuh` ownership and mode
`0640`.

For PhishTank instead:

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment staging \
  --reputation-provider phishtank \
  -v
```

Add `--api-key-prompt` only when you have a PhishTank application key.

The complete installer:

1. Scans active Wazuh rules and selects a free custom-rule range.
2. Installs the Edge navigation and classification rules.
3. Installs and registers the reputation classifier.
4. Validates and installs the included model and scaler.
5. Exercises the ML fallback offline.
6. Validates and restarts the manager.
7. Restores its pre-installation snapshot if a stage fails.

If model validation says that joblib/scikit-learn is unavailable, install a
complete Python 3.10 runtime for the original artifact, then rerun the complete
installer:

```bash
sudo bash ./wazuh-server/install-ml-runtime.sh \
  --python /usr/bin/python3.10 \
  -v
```

Use an actual full Python 3.10 path on the server. The runtime installer rejects
incompatible versions rather than retraining or silently changing the supplied
model.

### 4. Verify Google Web Risk safely

This explicit test consumes a Lookup API call but does not open or download the
target URL:

```bash
sudo python3 ./wazuh-server/verification/verify-web-risk-integration.py \
  --url 'http://testsafebrowsing.appspot.com/s/phishing.html' \
  --wait 60
```

Success produces the configured confirmed-reputation rule at level 10 with
`classification.source: google_webrisk` and threat type
`SOCIAL_ENGINEERING`. Never open a real phishing URL in Edge merely to test the
system.

For PhishTank, use the provider-specific verifier described in the
[server guide](wazuh-server/README.md) with an administrator-approved URL.

### 5. Verify a real, harmless Edge event end to end

Open a harmless new URL in Edge. On Windows, copy its event ID:

```powershell
(Get-Content "$env:ProgramData\PhishingDetection\browser-navigation.json" `
  -Tail 1 | ConvertFrom-Json).event_id
```

On the Ubuntu manager, verify transport:

```bash
sudo bash ./wazuh-server/verification/verify-navigation-ingestion.sh \
  --event-id 'PASTE_EVENT_ID' \
  --wait 60
```

Then verify its classification result:

```bash
sudo bash ./wazuh-server/verification/verify-classification-event.sh \
  --source-event-id 'PASTE_EVENT_ID' \
  --wait 60
```

A reputation no-match is not a declaration that the URL is safe. It proceeds
to ML and normally appears as `unlikely` or `suspicious` according to the
configured threshold.

### 6. Promote the validated pilot to production

After staging observation, update the endpoint profile in Administrator
PowerShell:

```powershell
.\wazuh-agent\install-wazuh-agent.ps1 -Environment Production
```

Then update the manager while retaining its installed Web Risk key:

```bash
sudo bash ./wazuh-server/install-wazuh-server.sh \
  --environment production \
  --reputation-provider google-webrisk \
  -v
```

For a PhishTank deployment, select `--reputation-provider phishtank` instead.

The default rule policy is:

| Result | Default level |
| --- | ---: |
| Edge navigation observed | 5 |
| Confirmed reputation match | 10 |
| ML-suspicious URL | 9 |
| Classifier/provider error | 5 |
| Negative or unlikely result in staging | 3 |
| Negative or unlikely result in production | 0 |

Rule IDs, levels, groups, cache controls, provider switching, rollback, and
production security guidance are documented in the full
[Wazuh server guide](wazuh-server/README.md).

## Current Limitations

- **Microsoft Edge only:** Chrome, Brave, and Firefox have not been implemented
  or tested. They need browser-specific extension packaging, permissions,
  native-messaging registration, installation, and acceptance tests. Do not
  assume Chromium compatibility makes the current Edge installer portable.
- **No Linux endpoint implementation:** Linux browser capture, native-host
  registration, log paths, permissions, and Wazuh-agent deployment are not
  provided. Ubuntu is supported only as the Wazuh server.
- **Windows 10 x64 pilot:** Windows 11, Windows Server, ARM, multi-user hosts,
  domain policy deployment, and centrally managed extension rollout have not
  been validated by this project.
- **Sideloaded extension:** The extension is not published in a browser store.
  Developer mode is suitable for a pilot but is not an enterprise deployment
  mechanism.
- **Detection, not prevention:** The extension observes committed navigation.
  It does not block, redirect, or close a malicious page.
- **URL visibility:** Credentials, fragments, common sensitive query values,
  and common search terms are redacted, but the normalized full URL remains in
  structured endpoint and Wazuh data. Review retention and access controls.
- **External reputation limitations:** Web Risk and PhishTank can have outages,
  quotas, authentication failures, and coverage gaps. An empty lookup response
  means only “not found,” not “safe.”
- **Legacy ML limitations:** The supplied model is an original scikit-learn
  1.0.2 scaler/SVR artifact. Its output is an uncalibrated raw score, not a
  phishing probability. Accuracy limitations remain, and retraining is outside
  this integration's scope. Network-derived legacy features are disabled by
  default.
- **Pilot log permissions:** The installing Edge user can modify the local data
  directory so the native host can append and rotate logs. Stronger endpoint
  tamper resistance would require a dedicated Windows service or equivalent
  hardening.

## Detailed Documentation

- [Extension installation and tests](edge-extension/README.md)
- [Windows native-messaging host](native-host/README.md)
- [Windows Wazuh-agent collection](wazuh-agent/README.md)
- [Ubuntu Wazuh-server pipeline](wazuh-server/README.md)
- [Overall extension–Wazuh integration plan](docs/extension-wazuh-integration-plan.md)
- [Google Web Risk integration plan](docs/google-web-risk-integration-plan.md)
- [Simple Google Web Risk API-key setup](docs/google-web-risk-demo-setup.md)
- [Production Web Risk preparation](docs/google-web-risk-preparation-guide.md)
- [Development tests](wazuh-server/tests/README.md)
- [Installed-system verification](wazuh-server/verification/README.md)
- [Legacy original implementation](legacy/original-implementation/README.md)

Development tests are separated from staging/production installers. Server
unit tests can be run with:

```bash
python3 -m unittest discover -s wazuh-server/tests/unit -p 'test_*.py'
```

## Contributors

- [@Spades0](https://github.com/Spades0), co-author.
- [@xrisbarney](https://github.com/xrisbarney), co-author.
- [@kahlflekzy](https://github.com/kahlflekzy), model and URL-feature work.
- Nadezhda.
- Ahmed.

The modern implementation uses Microsoft Edge, Wazuh, Google Web Risk or
PhishTank, and the original project model through a compatibility adapter. The
former Sysmon/browser-command-line workflow is retained only under `legacy/`
for historical reference.
