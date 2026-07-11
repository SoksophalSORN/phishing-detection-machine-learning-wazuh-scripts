# Microsoft Edge Pilot Extension Implementation Plan

## Objective

Create a sideloaded Microsoft Edge extension and Windows native-messaging host that capture supported browser navigation in near real time and write validated JSONL events for later collection by the Wazuh agent.

This plan covers the extension-to-local-log boundary. Wazuh agent and server work is defined in the companion [Edge Extension–Wazuh Integration Plan](./extension-wazuh-integration-plan.md).

## Pilot Scope

Included:

- Microsoft Edge Stable on a dedicated Windows pilot endpoint.
- Manifest V3 extension loaded through `edge://extensions`.
- Top-level `http` and `https` navigation.
- New foreground and background tabs.
- A local Windows native-messaging host.
- A single-line JSON output file suitable for Wazuh.
- Installation, verification, diagnostics, and removal scripts or instructions.

Excluded from the initial pilot:

- Edge Add-ons publication.
- Enterprise force installation and automatic extension updates.
- Navigation blocking or warning interstitials.
- Page content, form data, cookies, or request-body inspection.
- Chrome and Firefox packaging.
- PhishTank and ML classification.

## Proposed Repository Layout

```text
edge-extension/
  manifest.json
  service-worker.js
  README.md
  icons/
    icon-16.png
    icon-32.png
    icon-48.png
    icon-128.png

native-host/
  src/
    host implementation
  host-manifest.template.json
  install-host.ps1
  uninstall-host.ps1
  README.md

tests/
  extension/
  native-host/
  fixtures/
```

The pilot host should ultimately be a self-contained Windows executable. A script-based host is acceptable for early development if the runtime path and dependencies are controlled, but it should not be the final deployment artifact.

## Extension Design

### Manifest

Use Manifest V3 with the least permissions needed:

```json
{
  "manifest_version": 3,
  "name": "Wazuh Browser Navigation Pilot",
  "version": "0.1.0",
  "description": "Captures top-level Edge navigation for a controlled Wazuh pilot.",
  "permissions": [
    "webNavigation",
    "nativeMessaging",
    "storage"
  ],
  "background": {
    "service_worker": "service-worker.js"
  }
}
```

The `storage` permission is only needed if the pilot implements a bounded retry queue or local counters. Do not request content-script, cookie, history, or broad page-modification permissions unless a later requirement justifies them.

### Navigation Events

Register `chrome.webNavigation.onCommitted`. Accept an event only when:

- `frameId === 0`.
- The URL parses successfully.
- The URL scheme is `http:` or `https:`.
- The document is not a duplicate already handled for the same tab.

`onCommitted` is the primary event because it represents a navigation Edge has accepted. It captures ordinary navigation and navigation into a new tab without depending on a new browser process.

Optionally add `onHistoryStateUpdated` after the base flow works. Treat it as a separate transition so single-page application updates can be distinguished and deduplicated.

### Event Creation

Create a new event object rather than forwarding the raw browser event. Include only approved fields:

```json
{
  "schema_version": 1,
  "event_type": "browser_navigation",
  "event_id": "uuid",
  "timestamp": "ISO-8601 UTC timestamp",
  "browser": "edge",
  "url": "https://example.test/path",
  "tab_id": 42,
  "document_id": "browser document identifier when available",
  "transition_type": "link",
  "transition_qualifiers": [],
  "source": "edge_extension"
}
```

Do not include page titles initially because titles may contain sensitive document or user information and are unnecessary for URL phishing classification.

### URL Privacy Policy

Choose and document one policy before implementation:

1. Preserve the normalized path and non-sensitive query structure for path-level phishing detection, while removing fragments, credentials, secret-like parameters, and search terms.
2. Remove fragments, because they are not sent to servers and can contain sensitive application state.
3. Redact configured query parameters such as `token`, `code`, `key`, `password`, `session`, and `auth`.

For the pilot, the recommended default is to remove fragments and redact known sensitive query values while retaining parameter names.

### Native Connection and Retry

Use `chrome.runtime.connectNative()` for a long-lived connection to:

```text
com.phishing_detection.navigation
```

The service worker should:

- Connect lazily when the first event is ready.
- Send one JSON event per native message.
- Wait for a positive acknowledgement.
- Reconnect with bounded exponential backoff after disconnection.
- Store only a small bounded retry queue.
- Drop the oldest event when the queue limit is reached and increment a dropped-event counter.
- Never delay, redirect, or block the user's navigation.

Suggested pilot limits:

| Setting | Initial value |
| --- | ---: |
| Maximum queued events | 500 |
| Maximum serialized event | 16 KiB |
| Initial reconnect delay | 1 second |
| Maximum reconnect delay | 60 seconds |
| Duplicate window | 2 seconds |

These are starting values and should be adjusted from pilot observations.

## Native Host Design

### Native Messaging Protocol

The host reads messages from standard input using Edge's native-messaging framing:

1. Read a four-byte unsigned message length in native byte order.
2. Reject a zero, incomplete, or excessive length.
3. Read exactly that number of UTF-8 bytes.
4. Decode and parse one JSON object.
5. Validate it against the event contract.
6. Append a normalized JSON object followed by a newline.
7. Flush the file and return a framed acknowledgement on standard output.

Standard output must contain only protocol messages. Diagnostics go to a separate file or standard error.

Example acknowledgement:

```json
{
  "accepted": true,
  "event_id": "the-submitted-event-id"
}
```

### Validation

Validate all of the following before writing:

- The message is a JSON object, not an array or scalar.
- `schema_version` and `event_type` are supported.
- `event_id` is valid and within its length limit.
- `timestamp` is a valid UTC timestamp.
- `url` is within its maximum length and uses HTTP or HTTPS.
- Hostname is present.
- String and array fields meet size and item-count limits.
- Unknown fields are removed or rejected consistently.

The host must reconstruct the normalized record from validated fields. It must never directly append arbitrary input bytes.

### Output and Permissions

Use:

```text
C:\ProgramData\PhishingDetection\browser-navigation.json
```

Requirements:

- Create the directory during native-host installation, not from untrusted message data.
- Allow the interactive user or native host identity to append.
- Allow the Wazuh service to read.
- Deny ordinary users permission to replace host binaries or manifests.
- Keep a separate diagnostic log with bounded retention.
- Rotate navigation logs by size without producing partial JSON lines.

For the pilot, use a conservative maximum file size and retain only a small number of rotated files. Wazuh rotation behavior must be tested before finalizing the mechanism.

### Host Manifest

Use a template that is completed after Edge assigns the sideloaded extension ID:

```json
{
  "name": "com.phishing_detection.navigation",
  "description": "Native host for the Wazuh Edge navigation pilot",
  "path": "C:\\Program Files\\PhishingDetection\\navigation-host.exe",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://EXTENSION_ID/"
  ]
}
```

The installer registers the manifest under the Microsoft Edge native-messaging registry location. It must verify that the manifest path, executable path, and extension ID are correct before reporting success.

## Implementation Sequence

### Milestone 1: Extension Console Prototype

- Add the Manifest V3 files.
- Listen to `onCommitted`.
- Filter top-level HTTP/HTTPS events.
- Normalize and print approved events to the service-worker console.
- Sideload with **Developer mode** and **Load unpacked**.
- Test normal and new-tab navigation.

Exit condition: required navigation cases appear once in the extension console with the expected fields.

### Milestone 2: Native Host Protocol

- Implement framed input and output.
- Add schema validation and normalized JSONL writing.
- Add acknowledgements and diagnostic logging.
- Add unit tests for framing, partial input, invalid JSON, excessive sizes, invalid URLs, and write failures.

Exit condition: recorded test messages produce exact JSONL fixtures and invalid messages do not alter the navigation log.

### Milestone 3: Edge Native Messaging

- Add `nativeMessaging` permission and connection management.
- Package/install the host executable.
- Load the extension and record its ID.
- Generate the host manifest with that ID in `allowed_origins`.
- Register the native host for Microsoft Edge.
- Send navigation events and verify acknowledgements.

Exit condition: an Edge navigation creates a corresponding JSONL record without manual copying or polling.

### Milestone 4: Reliability and Privacy Controls

- Add bounded retry and reconnection.
- Add deduplication.
- Implement URL fragment removal and query-value redaction.
- Add file rotation and permission checks.
- Add extension and host counters for accepted, rejected, queued, retried, and dropped events.

Exit condition: controlled restarts and invalid inputs do not corrupt the log or noticeably affect browsing.

### Milestone 5: Pilot Packaging and Documentation

- Provide host install and uninstall automation.
- Document sideloading, extension-ID retrieval, host registration, verification, updates, and removal.
- Document diagnostic locations and common errors.
- Record tested Edge and Windows versions.
- Produce a repeatable clean-machine test.

Exit condition: a tester can install and remove the pilot on a clean Windows endpoint using only the documented steps.

## Test Matrix

| Scenario | Expected result |
| --- | --- |
| Left-click HTTP/HTTPS link | One top-level navigation event. |
| Middle-click link | Event is recorded even if the new tab remains in the background. |
| Context menu: open in new tab | One event for the destination. |
| Address-bar navigation | One committed navigation event. |
| Server redirect | Final committed URL is recorded; redirect qualifier is preserved when available. |
| Back/forward | Event recorded with transition information. |
| Iframe navigation | Ignored. |
| `edge://`, `file://`, or extension page | Ignored. |
| URL with fragment | Fragment removed under the pilot policy. |
| Sensitive query value | Value redacted under the pilot policy. |
| Native host unavailable | Event queued up to the limit; browsing continues. |
| Host becomes available | Queued events retry without uncontrolled duplication. |
| Invalid native message | Rejected, diagnosed, and not written. |
| Edge restart | New events continue after reconnecting. |
| Edge fully closed; link clicked in a messaging app | Edge starts and the first committed URL is logged exactly once. |
| Cold Edge start with a slow native host | The first URL is persisted in the extension queue and delivered after connection. |
| Concurrent windows/tabs | Events remain individually valid and attributable. |

## Verification Procedure

For every test navigation, correlate these identifiers and timestamps:

1. Extension service-worker observation.
2. Native-host acknowledgement or rejection.
3. JSONL output record.

Record observed latency from `onCommitted` to the flushed JSONL line. Run a batch of at least one hundred controlled navigations and account for every accepted, rejected, duplicated, and dropped event.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Sensitive URL data is collected | Minimize fields, redact sensitive query values, remove fragments, and restrict access. |
| Extension ID changes | Preserve the extension package/key and regenerate the host manifest when necessary. |
| Native host output breaks protocol | Reserve stdout for framed JSON acknowledgements and test framing thoroughly. |
| Service worker suspends | Persist a bounded queue and reconnect when new events wake the worker. |
| Navigation volume grows rapidly | Filter frames/schemes, deduplicate, rate-limit diagnostics, and rotate logs. |
| Host becomes a local attack surface | Restrict `allowed_origins`, validate every field, limit sizes, and protect the binary and registry settings. |
| Log file becomes unreadable by Wazuh | Define ACLs during installation and verify them under the actual Wazuh service identity. |

## Definition of Done

The custom extension portion of the pilot is complete when:

- It captures all agreed Edge navigation scenarios, including background new tabs.
- It ignores unsupported schemes and iframe navigation.
- It sends events only to the registered native host.
- The host validates and writes one complete JSON record per line.
- The extension tolerates host restarts using bounded retry behavior.
- One hundred controlled test navigations have no unexplained event loss.
- Installation, diagnostics, updating, and complete removal are documented.
- The JSONL output is ready for the Wazuh agent integration phase.
