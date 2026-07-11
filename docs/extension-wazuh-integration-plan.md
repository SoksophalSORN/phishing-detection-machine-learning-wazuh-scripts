# Edge Extension–Wazuh Integration Plan

## Purpose

Modernize the project so it detects URLs opened inside an already-running browser, including links opened in new tabs. The pilot targets Microsoft Edge on Windows and replaces URL discovery from Sysmon process command lines with structured browser-navigation events.

The pilot is an alerting system, not a pre-navigation blocking system. A navigation is observed after Edge commits it, and Wazuh then classifies and alerts on the URL.

## Target Architecture

```text
Microsoft Edge
  -> pilot browser extension
  -> Edge Native Messaging
  -> Windows native host
  -> local JSONL navigation log
  -> Wazuh agent
  -> Wazuh server decoder and rules
  -> PhishTank and ML integration
  -> Wazuh phishing alert
```

### Component Responsibilities

| Component | Responsibility |
| --- | --- |
| Edge extension | Observe top-level HTTP/HTTPS navigation and submit structured events. |
| Native host | Authenticate the extension origin, validate messages, and append JSONL records safely. |
| Wazuh agent | Collect the endpoint JSONL file and forward records to the Wazuh server. |
| Wazuh server | Decode events, match rules, invoke classification, and generate alerts. |
| PhishTank client | Check known phishing URLs with bounded network behavior. |
| ML classifier | Score URLs not conclusively identified by reputation data. |

## Event Contract

All components should use a versioned event contract. One complete JSON object must be written per line.

```json
{
  "schema_version": 1,
  "event_type": "browser_navigation",
  "event_id": "generated-unique-id",
  "timestamp": "2026-07-10T08:14:22.491Z",
  "browser": "edge",
  "url": "https://example.test/login",
  "tab_id": 42,
  "transition_type": "link",
  "transition_qualifiers": [],
  "source": "edge_extension"
}
```

Only `http` and `https` URLs are accepted. The extension and native host must reject unsupported schemes, malformed records, and oversized messages. URL fragments and sensitive query parameters should be handled according to an agreed privacy policy.

## Delivery Phases

### Pilot Completion Status

The initial implementation phases are complete for the pilot:

- Phase 1 captured committed Edge navigation, including new-tab and cold-start
  browser scenarios, through the extension and native host.
- Phase 2 forwarded the JSONL navigation log through the Windows Wazuh agent.
- Phase 3 received structured events on the manager and matched the navigation
  rule while retaining the endpoint agent and event ID.
- Phase 4 produced structured confirmed-PhishTank, negative-reputation, ML,
  and error results and matched their configurable Wazuh rules.
- The original scaler and SVR run through an explicitly identified legacy
  compatibility adapter without retraining. Its raw score is uncalibrated and
  its observed detection quality remains a documented model limitation.

A previously successful live PhishTank result and the synthetic classification
tests establish the integration contract. Subsequent Cloudflare challenges or
registration availability are external service-operability issues and do not
invalidate the completed Wazuh integration. Production hardening may retain
PhishTank when supported access is available or select another supported
reputation solution.

New Wazuh servers should use `wazuh-server/install-wazuh-server.sh`. It installs
the final rule policy, classifier, and trusted ML artifacts in one workflow,
runs offline ML and Wazuh rule verification, and restores a complete
pre-installation snapshot if any stage fails.

The per-URL Google Web Risk Lookup API is planned as another supported solution
beside PhishTank, not as its removal from the project. Only one reputation
provider may be active on a Wazuh manager. PhishTank integration and
PhishTank-specific rules must be disabled and Wazuh validated before Web Risk
configuration is installed. The Web Risk implementation will not download a
local threat database. See the
[Google Web Risk–Wazuh integration plan](google-web-risk-integration-plan.md).

### Phase 1: Capture Edge Navigation Locally

Build and sideload a Manifest V3 extension. It observes committed, top-level navigation and sends events to a Windows native-messaging host. The host appends validated events to:

```text
C:\ProgramData\PhishingDetection\browser-navigation.json
```

Test these navigation cases:

- Normal link click.
- Middle-click and **Open link in new tab**.
- Foreground and background tabs.
- Address-bar navigation.
- HTTP redirects and URL shorteners.
- Back and forward navigation.
- Browser session restoration.
- Single-page application URL changes, if history-state tracking is enabled.
- Multiple Edge windows and profiles.

Acceptance criteria:

- A supported navigation produces a valid JSONL record within approximately one second of commit.
- Top-level navigation is captured without logging iframe activity.
- Internal browser pages and unsupported URL schemes are ignored.
- Duplicate events are bounded and explainable.
- Edge and native-host restarts do not corrupt the log.
- Malformed extension messages do not crash the host.

### Phase 2: Collect Events with the Wazuh Agent

Configure the Windows agent to monitor the JSONL file:

```xml
<localfile>
  <location>C:\ProgramData\PhishingDetection\browser-navigation.json</location>
  <log_format>json</log_format>
  <only-future-events>no</only-future-events>
</localfile>
```

The pilot uses `no` so records produced during a Wazuh-agent outage can be collected after the agent restarts. This also means that the first installation can forward existing records in the file.

The native host's user must have append access, while the Wazuh service must have read access. File rotation must preserve those permissions.

Acceptance criteria:

- The Wazuh agent starts monitoring the file without permission or parsing errors.
- New events are forwarded shortly after being appended.
- Agent restart, native-host restart, and log rotation do not stop collection.
- Invalid test lines are rejected or surfaced without preventing later valid records from being collected.

### Phase 3: Decode and Alert on the Wazuh Server

First verify transport independently of phishing classification. Add a low-severity rule for valid navigation events:

```xml
<group name="browser_navigation,phishing_detection,pilot,">
  <rule id="100100" level="3">
    <if_sid>86600</if_sid>
    <field name="schema_version" type="pcre2">^1$</field>
    <field name="event_type" type="pcre2">^browser_navigation$</field>
    <field name="source" type="pcre2">^edge_extension$</field>
    <field name="browser" type="pcre2">^edge$</field>
    <url type="pcre2">^https?://</url>
    <description>Edge browser navigation observed: $(url) [event_id=$(event_id)]</description>
  </rule>
</group>
```

Rule `100100` avoids the original implementation's `100002`–`100004` IDs. It inherits from built-in rule `86600` because that rule claims JSON records containing `timestamp` and `event_type`; the additional PCRE2 fields restrict this child to the Edge navigation contract. It is a temporary level-3 pilot rule for transport verification and must be lowered or replaced during Phase 4 so normal navigation does not remain alert noise.

Acceptance criteria:

- Events appear in Wazuh archives with their structured fields.
- The event is associated with the correct endpoint agent.
- The navigation rule matches and produces a searchable pilot alert.
- Normal browser volume does not overwhelm the manager or dashboard.

### Phase 4: Integrate Phishing Classification

Modify the existing integration to consume the structured URL field instead of extracting a URL from a Sysmon command line. Separate parsing, reputation lookup, feature extraction, model inference, and Wazuh output into testable units.

Required corrections include:

- Remove reliance on the stale global `json_alert` variable.
- Create nested output fields before assigning to them.
- Handle missing and malformed URLs without regex exceptions.
- Correct the IP-address feature, which is currently hard-coded in the integration.
- Add connection and read timeouts, error handling, caching, and rate-limit handling.
- Use the configured PhishTank endpoint instead of an unrelated hard-coded value.
- Treat a class label as a label, not as a percentage.
- Add an explicit ML threshold and a calibrated probability if percentage output is required.
- Avoid unrestricted server-side retrieval of arbitrary URLs; isolate or remove HTML retrieval to prevent SSRF.

Classification output should be structured and versioned:

```json
{
  "schema_version": 1,
  "event_type": "phishing_classification",
  "event_id": "classification-unique-id",
  "source_event_id": "navigation-event-id",
  "url": "https://example.test/login",
  "malicious": true,
  "classification_source": "phishtank",
  "score": 1.0,
  "model_version": "pilot-1",
  "timestamp": "2026-07-10T08:14:23.120Z"
}
```

Create distinct Wazuh rules for:

- Browser navigation observed.
- Confirmed PhishTank match.
- ML score above the alert threshold.
- Classification timeout or internal failure.

Acceptance criteria:

- A known test phishing URL produces a PhishTank classification event when available.
- A controlled URL not found in PhishTank reaches the ML path.
- Benign, malicious, timeout, and malformed-input paths produce predictable results.
- Classification failures are visible but do not interrupt later events.
- The final alert retains the endpoint agent and source navigation event identifiers.

## Security and Privacy Requirements

- Collect only the fields required for detection.
- Document whether query strings and fragments are retained, redacted, or hashed.
- Never collect page contents, form values, cookies, credentials, or authorization headers in the pilot.
- Restrict the native host to the expected extension ID through `allowed_origins`.
- Restrict log-directory permissions and prevent arbitrary output paths.
- Enforce URL, field-length, event-size, and message-rate limits.
- Rotate and retain logs according to a defined policy.
- Keep native-host diagnostic logs separate from navigation data.
- Use controlled benign and phishing test URLs; do not expose users or production systems to live malicious content.

## Observability and Failure Handling

Measure at least:

- Events observed by the extension.
- Events accepted and rejected by the native host.
- File-write failures and queue depth.
- Events collected by the Wazuh agent.
- Events decoded and matched by the manager.
- Classification success, timeout, error, and latency.
- Duplicate and dropped event counts.

The extension should queue a small bounded number of events when the native host is temporarily unavailable. The host should acknowledge accepted messages. Both components must fail without blocking normal browsing.

## Rollout and Exit Criteria

Use a dedicated Windows pilot endpoint and test Edge profile. Complete each phase before enabling the next one.

The pilot is successful when:

- All required Edge navigation scenarios are captured consistently.
- At least one hundred controlled navigation events complete the end-to-end path without unexplained loss.
- Wazuh can distinguish navigation, malicious classification, and processing-failure events.
- Performance impact is not noticeable during normal browsing.
- Security and privacy review approves the collected fields and retention behavior.
- Installation, rollback, and troubleshooting steps are documented and repeatable.

Rollback consists of disabling/removing the extension, unregistering the native host, removing the Wazuh `localfile` entry and pilot rules, and archiving or deleting pilot logs according to the retention policy.

## Post-Phase-4 Hardening and ML Plan

The initial four phases prove browser capture, endpoint forwarding, manager receipt, and PhishTank classification. The following work converts that successful pilot into a maintainable phishing-detection pipeline.

### 1. Safely Validate the Confirmed-Phishing Path

Provide a synthetic event injector that submits a user-supplied, currently verified PhishTank URL through the installed integration without opening that URL in a browser. The test must preserve a unique source event ID and verify the confirmed-phishing rule at its configured alert level.

### 2. Reduce Pilot Noise

Successful negative reputation lookups should default to rule level `0` after transport testing. Browser-navigation observability remains configurable; its default level is `5` to preserve the original project policy. Verified PhishTank detections default to level `10`, and ML detections default to level `9`.

### 3. Minimize URL Data Exposure

- Add a dedicated `url_host` field for descriptions and dashboards.
- Keep complete URLs out of human-readable rule descriptions.
- Remove fragments and embedded credentials.
- Redact common authentication secrets.
- Redact search terms on known search-engine hosts.
- Retain the normalized URL in structured data only where classification requires it.
- Document local and server-side retention separately.

### 4. Configure Authenticated PhishTank Access

Support an optional PhishTank application key stored in a root-controlled configuration file. The installer should offer a hidden interactive prompt so the key is not exposed in shell history. Anonymous operation remains supported for low-volume testing.

### 5. Retire the Legacy Command-Line Path

Audit and remove the original Edge/Chrome Sysmon command-line rules and legacy classification result rules after the modern pipeline passes validation. Preserve Sysmon when other endpoint detections use it, and preserve the old model/scaler as historical artifacts until the ML replacement is accepted.

### 6. Add a Modern ML Fallback

Replace the legacy scikit-learn 1.0.2 SVR with a versioned, URL-only probabilistic classifier:

- Use deterministic lexical and hostname features that require no page retrieval, DNS, WHOIS, or arbitrary manager-side HTTP requests.
- Train from labeled URL data through a reproducible command.
- Produce a calibrated `predict_proba()` score.
- Store the feature schema, training metadata, model version, and decision threshold with the artifact.
- Invoke ML only when PhishTank does not confirm active phishing.
- Default the suspicious threshold from the trained artifact, while allowing an administrator override.
- Emit distinct structured results for confirmed reputation, ML suspicion, benign/unknown, and processing failure.
- Validate and install only a trusted, versioned model through an atomic installer with rollback.
- Provide an offline fallback test that forces a PhishTank-negative result, exercises the installed model, and validates the selected Wazuh rule without opening or requesting the target URL.

If retraining is outside the deployment scope, support the original scikit-learn 1.0.2 scaler and RBF SVR through an explicitly labeled compatibility mode. The adapter must preserve the original 15-feature ordering and treat its regression output as an uncalibrated raw score rather than a percentage. Original WHOIS/page-derived features may be enabled only with timeouts, response and redirect limits, credential rejection, and non-public destination blocking; an offline failure-default mode must also be available.

### Configurable Wazuh Rule Policy

The rule installer must support both CLI and wizard modes. Administrators can configure:

- Rule group/block name, defaulting to `browser_navigation,phishing_detection` and validated as one or more comma-separated Wazuh group names. Each name must match `^[A-Za-z0-9_.-]+$`.
- Preferred starting ID, defaulting to `100300`.
- Navigation-observed rule ID and level, default level `5`.
- Classification base rule ID, default level `0`.
- Verified PhishTank rule ID and level, default level `10`.
- ML-detection rule ID and level, default level `9`.
- Classification-error rule ID and level, default level `5`.
- Negative-result rule ID and level, default level `0`.

When an ID is not supplied, the installer scans `/var/ossec/etc/rules` and `/var/ossec/ruleset/rules`, prefers a free contiguous range beginning at `100300`, and otherwise selects the first free range inside Wazuh's custom-rule interval `100000`–`120000`. Explicit IDs must be rejected on collision rather than silently overwritten.
