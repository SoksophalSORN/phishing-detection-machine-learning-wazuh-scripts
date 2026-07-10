# Microsoft Edge Native Messaging Host

This self-contained Go program receives framed JSON messages from the pilot Edge extension, validates and normalizes them, and appends one event per line to:

```text
C:\ProgramData\PhishingDetection\browser-navigation.json
```

It acknowledges an event only after the log record has been flushed to disk. It rotates at 10 MiB and retains three rotated files.

## Build on Windows

The repository includes `dist\navigation-host.exe` for the Windows x64 pilot. To reproduce it from source, install Go and run PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build-host.ps1
```

This runs the Go tests and creates `dist\navigation-host.exe`.

## Install

First load the unpacked extension in Edge and copy its 32-character extension ID from `edge://extensions`. Then open PowerShell as Administrator:

```powershell
.\install-host.ps1 -ExtensionId "replace_with_the_edge_extension_id"
```

The installer:

- Copies the executable under `C:\Program Files\PhishingDetection`.
- Creates an Edge native-host manifest authorizing the supplied extension ID.
- Registers the host under `HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts`.
- Creates the navigation log under `C:\ProgramData\PhishingDetection`.
- Grants the installing user modify access and LocalSystem read/full access for Wazuh.

Reload the extension or restart Edge after installation.

## Uninstall

Run PowerShell as Administrator:

```powershell
.\uninstall-host.ps1
```

Logs are preserved by default. Delete them explicitly with:

```powershell
.\uninstall-host.ps1 -RemoveLogs
```

## Local Development

```bash
go test ./...
go build ./...
```

Set `PHISHING_DETECTION_LOG_FILE` to redirect output during controlled tests. The production installer does not set this variable.

## Security Notes

- The host manifest accepts messages only from the configured extension ID.
- The host independently validates the event schema, field sizes, timestamp, source, and HTTP/HTTPS URL.
- URL credentials and fragments are removed, and common sensitive query values are redacted again by the host.
- Standard output is reserved exclusively for Edge native-messaging acknowledgements.
- The pilot grants the installing Edge user modify access to the data directory so the host can rotate files. Production hardening should move writes into a dedicated Windows service if protection from the interactive user is required.
