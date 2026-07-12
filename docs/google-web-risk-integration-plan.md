# Google Web Risk–Wazuh Integration Plan

## Implementation Status

The implementation-ready pilot was completed on 2026-07-12. The finalized server installer supports
`--reputation-provider google-webrisk`, secure interactive key installation,
provider-specific level-10 rules, provider-separated caching, a monthly request
guard, bounded retries and circuit state, ML degraded fallback, transactional
provider switching, and an explicit live verification command. PhishTank
remains available through `--reputation-provider phishtank`; the installer does
not activate both providers together.

The repository-side implementation and offline validation are complete. The
environment-specific staging and production rollout phases later in this plan
remain operator acceptance work: run the explicit live verifier, compare usage
with Google Cloud metrics, and observe the selected pilot environment before a
wider rollout.

The policy manifest retains `phishtank_rule_id` and `phishtank_level` for
backward compatibility. New deployments can use the provider-neutral
`--reputation-rule-id` and `--reputation-level` aliases.

## Purpose

Add Google Web Risk's per-URL Lookup API as an alternative reputation solution
beside the existing PhishTank solution while preserving the Edge extension,
Wazuh event transport, configurable rule policy, and ML fallback.

Both implementations remain supported in the repository, but they are mutually
exclusive at runtime. A Wazuh manager may have either the PhishTank reputation
integration or the Google Web Risk reputation integration enabled, never both.

This integration will use only `v1/uris:search`. It will not use the Update API,
download Google's threat lists, maintain a hash-prefix database, submit URLs for
analysis, or use the preview Evaluate API.

## Decision Summary

- Use the Google Web Risk Lookup API because it is the lowest-complexity API and
  checks one URL per request.
- Require an explicit provider selection; do not silently replace an installed
  PhishTank deployment.
- Disable the active PhishTank integration and PhishTank-specific rules before
  writing any Google Web Risk configuration, key, integration, or rules.
- Request `SOCIAL_ENGINEERING` by default because Web Risk categorizes phishing
  under that threat type.
- Optionally allow `MALWARE` and `UNWANTED_SOFTWARE` in the same request without
  changing the phishing default.
- Preserve ML as the fallback when Web Risk returns an empty response.
- Never treat an empty Web Risk response as proof that a URL is safe; it means
  only that the URL was not present on the requested threat lists at lookup
  time.
- Keep a small SQLite verdict/cache and usage database. This is not a downloaded
  Web Risk threat database.
- Cache positive Web Risk matches until their returned `expireTime`, as required
  by Google's caching guidance.
- Use a short, configurable application-level negative cache to control repeated
  lookups for common browser URLs. Default to five minutes in staging and
  production, with `0` available to disable it.
- Restrict the API key to Web Risk and, where the manager has stable egress, to
  the Wazuh server's public IP.
- Set an application-side monthly request ceiling below the free-tier boundary
  and configure Google Cloud quota/budget monitoring as a second control.

Google currently documents up to 100,000 Lookup API `uris.search` calls per
month at no charge. Calls above that tier are billed, and prices and quotas can
change, so deployment must verify the current values rather than hard-code a
permanent pricing assumption. See [Web Risk pricing](https://cloud.google.com/web-risk/pricing)
and [Web Risk quotas](https://docs.cloud.google.com/web-risk/quotas).

## Target Architecture

```text
Microsoft Edge extension
  -> native host JSONL
  -> Windows Wazuh agent
  -> Wazuh manager navigation rule
  -> edge-phishing-classifier
       -> local verdict/cache and usage check
       -> Google Web Risk Lookup API (uris.search)
            -> SOCIAL_ENGINEERING match: confirmed reputation alert
            -> empty response: legacy/modern ML fallback
            -> API failure: degraded classification policy
  -> Wazuh classification rules and dashboard
```

The URL is sent only to Google's Lookup API. The integration must not open the
URL, resolve its host as part of Web Risk lookup, or download content from the
target website.

## Provider Exclusivity and Switch Prerequisite

PhishTank and Google Web Risk are separate supported solutions. Their provider
code, tests, and installer templates may coexist in the repository, but their
active Wazuh integrations and provider-specific rules must not coexist on a
manager. Running both would duplicate lookups, classifications, and alerts for
the same navigation event and make quota/cost accounting unreliable.

Before Google Web Risk configuration is installed, the installer must complete
this sequence:

1. Detect the currently active reputation provider from the classifier
   configuration, managed `<integration>` block, deployment manifest, and
   active custom rules.
2. Create a complete transactional backup of the PhishTank configuration,
   integration modules, integration registration, rules, cache, and policy
   manifest.
3. Disable the managed PhishTank `<integration>` registration so no new
   navigation event can invoke it.
4. Disable or remove the active PhishTank-specific confirmed-reputation rule
   and any legacy PhishTank result rules from Wazuh's active rule directories.
   Files may be archived in the backup, but cannot remain active.
5. Validate and restart Wazuh in the provider-disabled transitional state.
6. Only after those steps succeed, install the Web Risk key, configuration,
   client, integration registration, and Web Risk-specific rules.
7. Validate, restart, and run synthetic Web Risk rule tests before declaring the
   switch complete.

If the Web Risk stage fails, the complete transaction may restore the previous
PhishTank state. Restoration is rollback, not simultaneous activation.

The Web Risk installer must abort rather than proceed when it finds an active
PhishTank integration or rule outside its managed migration scope. It must name
the conflicting file or marker and require administrative cleanup. It must also
reject a configuration that enables both providers or attempts runtime fallback
from Web Risk to PhishTank. The only runtime fallback for an inconclusive or
unavailable selected reputation provider is ML under the policy defined below.

Switching back to PhishTank follows the reverse process: disable and validate
removal of Web Risk integration/rules first, then restore or install PhishTank.

## Google Cloud Prerequisites

For a small experiment, use the console-only
[Google Web Risk demo setup](google-web-risk-demo-setup.md). It covers only the
project, billing, API enablement, restricted key, and optional one-call test.

Use the step-by-step [Google Web Risk preparation guide](google-web-risk-preparation-guide.md)
to create the staging project, enable billing/API access, restrict and test the
key, establish cost controls, and prepare the Wazuh manager.

An administrator must complete these steps outside the Wazuh installer:

1. Create or select a dedicated Google Cloud project.
2. Enable billing for that project, even when expected usage remains within the
   free tier.
3. Enable `webrisk.googleapis.com`.
4. Create a separate API key for each production/staging trust boundary.
5. Apply an API restriction allowing only the Web Risk API.
6. When the manager uses stable public egress, apply a server/IP restriction for
   that IPv4 address, IPv6 address, or CIDR range.
7. Configure Google Cloud quota monitoring, billing budgets, and alerts.
8. Record the project owner, key owner, rotation date, and incident procedure.

Google recommends both client and API restrictions for API keys. Server key
restrictions support public IP addresses and CIDR ranges. See
[Google API key restrictions](https://docs.cloud.google.com/api-keys/docs/add-restrictions-api-keys).

The Wazuh server does not need the Google Cloud CLI at runtime. The classifier
will call the HTTPS REST endpoint using Python's standard HTTP library.

## Request and Response Contract

### Request

Use an HTTPS `GET` request:

```text
https://webrisk.googleapis.com/v1/uris:search
  ?threatTypes=SOCIAL_ENGINEERING
  &uri=<percent-encoded normalized URL>
  &key=<API key>
```

The Lookup API accepts one URL per request and permits multiple `threatTypes`
parameters in the same request. The URI must be encoded as a query parameter.
Google performs the lookup-side canonicalization, so this project should send
the privacy-normalized URL produced by the existing extension/native-host
contract rather than implement the Update API's hash canonicalization. See
[Using the Lookup API](https://docs.cloud.google.com/web-risk/docs/lookup-api).

### Match response

```json
{
  "threat": {
    "threatTypes": ["SOCIAL_ENGINEERING"],
    "expireTime": "2026-07-12T12:34:56Z"
  }
}
```

A non-empty supported `threatTypes` array is a reputation match. The match must
be cached and considered unsafe until `expireTime`.

### No-match response

```json
{}
```

An empty response means the URL is not on the requested lists. It advances to
ML and must be labeled `not_found`, not `safe` or `benign`.

### Normalized internal result

```json
{
  "status": "malicious",
  "malicious": true,
  "provider": "google_webrisk",
  "threat_types": ["SOCIAL_ENGINEERING"],
  "expire_time": "2026-07-12T12:34:56Z",
  "cache_hit": false
}
```

The final Wazuh classification event retains the current `source_event_id`,
`source_alert_id`, `source_rule_id`, agent, normalized URL, and `url_host`.

## Configuration Contract

Replace provider-specific top-level PhishTank fields with a provider object:

```json
{
  "navigation_rule_id": "100300",
  "reputation": {
    "provider": "google_webrisk",
    "endpoint": "https://webrisk.googleapis.com/v1/uris:search",
    "api_key_file": "/var/ossec/etc/edge-google-web-risk.key",
    "threat_types": ["SOCIAL_ENGINEERING"],
    "timeout_seconds": 8,
    "maximum_response_bytes": 65536,
    "negative_cache_seconds": 300,
    "monthly_request_limit": 90000,
    "retry_count": 1,
    "circuit_breaker_seconds": 300
  },
  "ml": {
    "enabled": true,
    "mode": "legacy_svr"
  }
}
```

Requirements:

- Permit only the exact HTTPS Web Risk hostname and `/v1/uris:search` path.
- Do not allow arbitrary provider endpoints in production configuration.
- Validate threat types against a fixed allowlist.
- Store the key in a dedicated `root:wazuh` mode-`0640` file, not inline in the
  JSON configuration, shell history, command arguments, Wazuh events, or logs.
- Reject symlinked, non-regular, incorrectly owned, or overly permissive key
  files.
- Keep separate keys and usage limits for staging and production.
- Make the monthly application ceiling configurable. Default to `90000`,
  leaving headroom below the currently documented 100,000-call free tier.

## Caching and Call Control

Extend the existing SQLite cache into provider-neutral tables:

```text
reputation_cache
  provider
  url_key                   (SHA-256 of the normalized URL)
  result_json
  expires_at

reputation_usage
  provider
  calendar_month_utc
  request_count
  error_count

reputation_state
  provider
  consecutive_failures
  circuit_open_until
```

Behavior:

1. Consult an unexpired cache entry before every lookup.
   Use a SHA-256 URL key so the cache index does not duplicate complete URLs.
2. Cache positive matches exactly until Google's `expireTime`.
3. Cache empty responses for the configured short negative TTL. This is a local
   cost/latency policy, not a claim that Google supplied a negative expiry.
4. Deduplicate identical normalized URLs and prevent concurrent cache misses
   from creating a request stampede.
5. Count actual outbound requests atomically by UTC calendar month.
6. Refuse additional outbound calls after the application ceiling, mark the
   reputation result `quota_guard`, and use the degraded policy below.
7. Expose request count, positive/negative cache hits, errors, circuit state,
   and remaining application budget in diagnostics.
8. Never cache malformed responses or authentication/configuration failures.

Google's Lookup caching guidance requires retaining returned threat matches
until `expireTime`; see [Web Risk caching](https://docs.cloud.google.com/web-risk/docs/caching).

## Failure and ML Fallback Policy

HTTP and transport outcomes must be distinguished:

| Outcome | Behavior |
| --- | --- |
| `200` with threat | Emit confirmed reputation classification; do not run ML. |
| `200` with `{}` | Mark reputation `not_found`; run ML. |
| `400` | Configuration/request error; do not retry. |
| `403` | Authentication/restriction error; open circuit and alert. |
| `429` | Quota/rate error; honor `Retry-After` when present and open circuit. |
| `500`, `503`, `504` | Retry once with bounded jitter, then open circuit. |
| DNS/TLS/timeout | Retry once when safe, then open circuit. |
| Application ceiling | Do not call Google; mark `quota_guard`. |

Google requires clients receiving any non-`200` response to enter backoff mode.
See [Web Risk HTTP status codes](https://docs.cloud.google.com/web-risk/docs/status-codes).

Degraded behavior:

- A reputation failure must never be converted into `not_found`.
- Run ML when reputation is unavailable if ML is enabled.
- If degraded ML is suspicious, emit the existing level-9 ML alert and include
  `reputation_status` and `degraded: true`.
- If degraded ML is unlikely, emit the level-5 classification/provider error
  instead of a routine level-0 negative event; do not imply that the URL is
  safe.
- If both reputation and ML fail, emit the level-5 classifier error.
- A later event must attempt normal processing after the circuit cooldown.

## Wazuh Rule Policy Changes

Generalize the shared rule-policy role without allowing both provider rules to
remain active:

- Rename the logical role `phishtank_rule_id` to `reputation_rule_id`.
- Continue accepting `phishtank_rule_id` as a migration alias when reading an
  existing policy manifest.
- Add `--reputation-rule-id` and `--reputation-level` installer options while
  retaining deprecated aliases for one release.
- Keep the default confirmed-reputation severity at level `10`.
- Generate a Google Web Risk confirmed-reputation rule that matches only
  `^google_webrisk$`. Do not use a combined
  `^(google_webrisk|phishtank)$` source expression.
- Archive or remove the prior PhishTank confirmed-reputation rule before the
  Web Risk rule is activated. Reusing its configured ID is allowed only after
  the PhishTank rule is no longer active.
- Use provider-neutral descriptions, for example:

```text
A URL opened by a user on example.test matched Google Web Risk threat type SOCIAL_ENGINEERING.
```

- Keep complete URLs out of rule descriptions; retain them only in structured
  event data according to the established privacy policy.
- Match degraded results separately so provider outages are visible even when
  ML still produces a score.

## Installer Changes

Extend `wazuh-server/install-wazuh-server.sh` with:

```text
--reputation-provider google-webrisk|phishtank|disabled
--web-risk-key-prompt
--web-risk-key-file FILE
--web-risk-threat-type TYPE       (repeatable)
--web-risk-monthly-limit NUMBER
--web-risk-negative-cache-seconds NUMBER
```

Installation requirements:

1. Keep PhishTank and Google Web Risk as explicit alternative selections. Do
   not change the current provider unless the administrator supplies
   `--reputation-provider`.
2. Require `--reputation-provider google-webrisk` for a switch to Web Risk and
   print that PhishTank will be disabled before requesting confirmation or
   proceeding in non-interactive mode.
3. Preserve the installed provider during idempotent upgrades unless the
   administrator explicitly changes it.
4. Run the provider-disable sequence above before installing any Web Risk
   configuration or secret.
5. Prompt for the key without echo and never expose it in process arguments.
6. Install the key atomically with `root:wazuh` ownership and mode `0640`.
7. Back up and restore the provider configuration and secret as part of the
   complete installer transaction.
8. Validate configuration, key-file permissions, endpoint allowlisting, and
   Wazuh rules without making a billable request.
9. Provide a separate opt-in live verification command that clearly states it
   consumes a Lookup API call.
10. Record the single active provider, threat types, and configured application
   ceiling in
   `/var/ossec/etc/edge-phishing-deployment.json`, but never record the key.

## Implementation Phases

### Phase A: Provider Abstraction

- Introduce a provider-neutral `ReputationResult` contract.
- Move current PhishTank normalization and query code behind a provider
  interface without changing current behavior.
- Rename the cache schema without losing existing data; provider must be part
  of every cache key.
- Preserve the existing classifier event contract during refactoring.

Acceptance criteria:

- Existing unit tests continue to pass.
- PhishTank mock results still normalize identically.
- Cache entries from one provider cannot satisfy another provider's lookup.

### Phase B: Google Web Risk Client

- Implement `uris.search` using the standard Python HTTP library.
- Encode repeated threat types, URI, and key correctly.
- Enforce endpoint, timeout, response-size, JSON-shape, threat-type, and
  `expireTime` validation.
- Redact the key from exceptions and diagnostics.
- Implement status-specific retry/backoff and circuit-breaker behavior.

Acceptance criteria:

- Mocked matches, empty responses, malformed responses, timeouts, and every
  supported HTTP failure follow the defined policy.
- No test contacts Google or a candidate URL unless explicitly marked live.

### Phase C: Classifier and Rules

- Insert Web Risk before ML.
- Implement degraded ML behavior.
- Generalize confirmed-reputation and provider-error rules.
- Retain agent attribution and source event identifiers.

Acceptance criteria:

- Web Risk match produces the configured level-10 reputation alert.
- Empty response reaches ML.
- Provider failure plus suspicious ML produces level 9 with degraded context.
- Provider failure plus unlikely ML produces the level-5 provider error.
- Confirmed reputation is never overridden by ML.

### Phase D: Installer and Verification

- Add secure key installation and provider options.
- Add a read-only provider-conflict audit covering `ossec.conf`, active rule
  directories, classifier configuration, and the deployment manifest.
- Implement and test the transactional PhishTank-disable step before any Web
  Risk configuration is written.
- Add a mock/synthetic rule verifier that consumes no API call.
- Add `verification/verify-web-risk-integration.py` for an explicit live lookup.
- Display the request count and warn that the command consumes quota.
- Extend rollback tests to include provider configuration, key, and cache state.

Acceptance criteria:

- Fresh production and staging installation succeed without a live call.
- A Web Risk installation refuses to run while unmanaged active PhishTank rules
  or integrations remain.
- During a managed switch, PhishTank is disabled and Wazuh validates before Web
  Risk configuration is installed.
- At no point after a successful switch are both providers active.
- A failed installation restores the prior provider and key.
- Rerunning without provider options preserves the current provider.
- Logs and command output contain no API key.

### Phase E: Staging Pilot

- Use a dedicated staging Google Cloud project/key when practical.
- Start with `SOCIAL_ENGINEERING` only.
- Generate controlled benign navigation and use a Google-documented or
  administrator-approved threat test URL without opening it.
- Compare Wazuh request counters with Google Cloud metrics.
- Measure unique lookups, cache-hit ratio, latency, error rate, ML fallback
  rate, and projected monthly calls.
- Exercise invalid-key, quota-guard, timeout, and circuit-breaker paths.

Acceptance criteria:

- No API key appears in Wazuh events, integration logs, process listings, or
  installer output.
- Projected monthly calls remain below the configured ceiling with headroom.
- A known Web Risk match triggers the confirmed-reputation rule.
- Common repeat navigations are served from cache.
- Provider outages remain visible and later events recover after cooldown.

### Phase F: Production Rollout

- Create a production-specific restricted key.
- Confirm billing budget alerts and application ceiling before installation.
- Deploy through `--environment production` to one pilot manager/endpoint.
- Observe for at least one normal business cycle before wider rollout.
- Keep the alternative PhishTank provider code disabled but available as a
  separately selectable solution and rollback target.
- Rotate the Web Risk key after deployment validation or according to the
  organization's credential policy.

## Testing Matrix

Unit tests:

- Settings validation and endpoint allowlist.
- API-key file ownership, mode, symlink, and missing-file cases.
- Correct request encoding without exposing the key.
- Provider-conflict discovery and rejection.
- Transactional disabling of PhishTank integration and rules before Web Risk
  configuration is written.
- Rollback restoration of PhishTank after a failed Web Risk switch.
- `SOCIAL_ENGINEERING`, multiple-threat, and empty responses.
- Missing/invalid `threat`, `threatTypes`, and `expireTime` fields.
- Oversized, non-JSON, and truncated responses.
- Positive cache expiration and negative-cache policy.
- Duplicate/concurrent lookup suppression.
- UTC monthly counter rollover and application ceiling.
- `400`, `403`, `429`, `500`, `503`, `504`, DNS, TLS, and timeout paths.
- Circuit opening, cooldown, and recovery.
- ML fallback, degraded status, and confirmed-match precedence.
- Key redaction from every error and diagnostic path.

Wazuh rule tests:

- Confirmed Google Web Risk social-engineering result.
- Confirmed malware result when that optional threat type is enabled.
- Normal no-match plus unlikely ML.
- No-match plus suspicious ML.
- Provider error plus suspicious ML.
- Provider error plus unlikely ML.
- Quota guard and classifier failure.

Live tests:

- Must be explicit and never run during unit tests or installation.
- Must state that one Lookup API call will be consumed unless served by cache.
- Must submit the URL only to Google Web Risk and never open/download it.
- Must use a unique source event ID and verify the configured Wazuh rule.

## Privacy and Security Review

- Google receives the normalized full URL supplied to `uris.search`. Review this
  data transfer against organizational privacy and data-processing policy.
- Continue stripping fragments, embedded credentials, search terms, and common
  secret query parameters before the URL reaches Wazuh.
- Do not send cookies, page contents, referrers, form data, authorization
  headers, or endpoint user identity to Web Risk.
- Do not log the complete outbound request URI because the API key is a query
  parameter.
- Keep human-readable Wazuh descriptions host-only.
- Retain cache records only as long as operationally necessary and apply the
  existing Wazuh/index retention policy to structured URL data.
- Treat an untrusted joblib artifact separately from Web Risk credentials; both
  remain root-controlled deployment inputs.

## Observability and Cost Controls

Record without including the API key:

- Lookup requests, matches, empty responses, and errors.
- Positive and negative cache hits.
- Request latency.
- Threat types returned.
- Application monthly count and configured ceiling.
- Circuit-breaker state and last successful lookup time.
- ML fallback and degraded-classification counts.

Alert thresholds should include:

- 75% of the application monthly ceiling: informational warning.
- 90%: operational warning.
- 100%: stop outbound calls and enter `quota_guard` until reset or explicit
  administrative override.
- Sustained provider error/circuit-open state: level-5 Wazuh operational alert.

Use a dedicated Google Cloud project where possible so project-level quota and
billing metrics correspond to this integration. Google currently documents a
`SearchUris` quota of 6,000 requests per minute per project, shared across its
applications and IP addresses; the application should operate far below that
ceiling.

## Rollback

Rollback must:

1. Restore the prior classifier configuration, rules, integration modules, and
   deployment manifest from the complete installer snapshot.
2. Restore or remove the Web Risk key file according to its pre-install state.
3. Restart and validate `wazuh-manager`.
4. Preserve diagnostic logs and usage counters for incident review.
5. Disable or delete the Google API key in Google Cloud if compromise is
   suspected; local file removal alone does not revoke it.
6. Ensure Web Risk integration and rules are disabled before restoring
   PhishTank.
7. Return to the previous provider or provider-disabled plus ML-only mode as
   explicitly selected by the administrator; never leave both active.

## Completion Criteria

The Google Web Risk integration is complete when:

- The provider abstraction and Web Risk client pass the full unit matrix.
- The provider switch proves PhishTank integration/rules are inactive before
  Web Risk configuration is applied.
- Post-install audit proves exactly one reputation provider is active.
- Synthetic rule verification consumes no external API call.
- A controlled live match reaches the configured level-10 Wazuh rule.
- Empty lookup results reach ML without being labeled safe.
- Provider failures remain visible and degraded ML behavior is deterministic.
- API key restrictions, file permissions, redaction, rotation, and rollback are
  verified.
- Staging measurements demonstrate projected usage below the application and
  Google Cloud cost controls.
- Production installation and rollback are documented and repeatable.

## Official References

- [Detect malicious URLs with Web Risk](https://docs.cloud.google.com/web-risk/docs/detect-malicious-urls)
- [Using the Lookup API](https://docs.cloud.google.com/web-risk/docs/lookup-api)
- [Caching](https://docs.cloud.google.com/web-risk/docs/caching)
- [HTTP status codes](https://docs.cloud.google.com/web-risk/docs/status-codes)
- [Quotas and limits](https://docs.cloud.google.com/web-risk/quotas)
- [Pricing](https://cloud.google.com/web-risk/pricing)
- [Restricting Google API keys](https://docs.cloud.google.com/api-keys/docs/add-restrictions-api-keys)
