# Windows Wazuh Agent Collection

This directory configures an enrolled Windows Wazuh agent to collect the JSONL
navigation file produced by the Microsoft Edge native-messaging host:

```text
C:\ProgramData\PhishingDetection\browser-navigation.json
```

The agent only forwards records. Decoding, reputation lookup, ML fallback,
rules, and alerts run on the Ubuntu Wazuh manager.

## Supported Scope

This pilot targets Windows 10 x64 and Microsoft Edge. Linux endpoints and
Chrome, Brave, Firefox, Windows 11, and other platforms are not implemented or
tested. The Windows Wazuh agent must already be installed, enrolled, connected,
and running.

## Prerequisites

- The Edge extension and native host are installed.
- At least one valid navigation event exists in
  `browser-navigation.json`.
- PowerShell is running as Administrator from the repository root.

Default Wazuh paths are:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
C:\Program Files (x86)\ossec-agent\ossec.log
```

## Staging Installation (Recommended First)

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\wazuh-agent\install-wazuh-agent.ps1 -Environment Staging
```

The installer:

1. Confirms that the Wazuh service, configuration, and navigation log exist.
2. Validates the latest JSON navigation event.
3. Backs up `ossec.conf`.
4. Adds or updates a marker-delimited `<localfile>` block.
5. Restarts the Wazuh service.
6. Restores the backup automatically if the service cannot restart.
7. Checks `ossec.log` for logcollector's monitoring entry.

The managed block is:

```xml
<localfile>
  <location>C:\ProgramData\PhishingDetection\browser-navigation.json</location>
  <log_format>json</log_format>
  <only-future-events>no</only-future-events>
</localfile>
```

`only-future-events` is `no`, so eligible records written while the agent is
stopped can be collected when it returns. Existing records may be forwarded on
the first installation.

For a non-default Wazuh installation:

```powershell
.\wazuh-agent\install-wazuh-agent.ps1 -Environment Staging `
  -ConfigPath "D:\Wazuh\ossec.conf" `
  -AgentLog "D:\Wazuh\ossec.log"
```

## Verify the Endpoint

```powershell
.\wazuh-agent\verification\verify-wazuh-agent.ps1 `
  -ExpectedEnvironment Staging
```

Expected checks confirm:

- The Wazuh service is running.
- The managed JSON collection block is present.
- Recent navigation records satisfy the event contract.
- `ossec.log` reports that logcollector is analyzing the JSONL file.

After these checks pass, open a harmless new URL in Edge and copy its
`event_id`. Prove that it crossed the agent-to-manager boundary on Ubuntu:

```bash
sudo bash ./wazuh-server/verification/verify-navigation-ingestion.sh \
  --event-id 'PASTE_EVENT_ID' --wait 60
```

If collection is not recognized, inspect recent agent messages:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100
```

Look for configuration errors, file-access failures, a full agent buffer, or a
lost manager connection.

## Production Promotion

After the complete endpoint-to-manager path passes staging acceptance:

```powershell
.\wazuh-agent\install-wazuh-agent.ps1 -Environment Production

.\wazuh-agent\verification\verify-wazuh-agent.ps1 `
  -ExpectedEnvironment Production
```

Staging and production collect the same event contract. The selected profile is
stored as a comment in the managed block; server-side profiles control routine
negative-alert visibility.

## Remove or Roll Back

Remove only the managed collection block with:

```powershell
.\wazuh-agent\uninstall-wazuh-agent.ps1
```

The uninstaller backs up `ossec.conf`, removes the marked block, and restarts
Wazuh. It does not remove the Edge extension, native host, or navigation logs.

Acceptance is complete when the service is running, the file is monitored,
recent events remain valid, no relevant logcollector errors appear, and a new
event is found by the manager verification script.
