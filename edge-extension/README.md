# Wazuh Browser Navigation Pilot Extension

This unpacked Manifest V3 extension captures top-level HTTP/HTTPS navigation in Microsoft Edge and sends versioned events to the `com.phishing_detection.navigation` native host.

## Supported Scope

This pilot is implemented and tested for Microsoft Edge on Windows 10 x64.
Chrome, Brave, Firefox, Windows 11, and Linux endpoints are not currently
supported or tested. The extension is sideloaded through Developer mode and is
not published in the Microsoft Edge Add-ons store. It detects committed
navigation but does not block a page from loading.

## Install for the Pilot

1. Build the native host, or use the supplied Windows x64 pilot executable, as described in [`../native-host/README.md`](../native-host/README.md).
2. Open `edge://extensions` in Microsoft Edge.
3. Enable **Developer mode**.
4. Select **Load unpacked** and choose this `edge-extension` directory.
5. Copy the extension ID shown by Edge.
6. Run the native-host installer as Administrator with that extension ID.
7. Select **Reload** for the extension or restart Edge.

The native host must be installed after the extension ID is known. Its manifest authorizes that exact ID.

## Inspect the Pilot

On `edge://extensions`, select the extension's **service worker** link to open DevTools. Navigation and native-host connection failures appear in its console.

Pending events and counters are stored in `chrome.storage.local` under:

- `pending_navigation_events`
- `navigation_counters`

The host output is:

```text
C:\ProgramData\PhishingDetection\browser-navigation.json
```

Each line is one complete JSON event. The extension removes URL fragments and
embedded credentials, redacts values for common sensitive query parameters,
redacts search terms on common search-engine hosts, and adds a separate
`url_host` field for privacy-safe descriptions and dashboards.

After pulling an extension update, select **Reload** on `edge://extensions`.
When the native host is also updated, rerun `install-host.ps1` as Administrator
so the rebuilt executable is copied into `C:\Program Files\PhishingDetection`.

## Required Manual Tests

- Open a link normally.
- Open a link in a foreground and background new tab.
- Navigate from the address bar.
- Follow a redirect.
- Close Edge completely, then click an HTTP/HTTPS link in a messaging application. Confirm the first committed URL is logged exactly once.
- Stop/unregister the native host temporarily, navigate, restore the host, and confirm queued delivery.
- Confirm iframe, `edge://`, and `file://` navigation is not logged.

## Development Test

```bash
npm test
```

No npm packages are required; tests use the Node.js built-in test runner.
