# Phase 2: Wazuh Agent Collection

This directory configures a Windows Wazuh agent to collect the JSONL navigation file produced by the Microsoft Edge native host.

The Wazuh agent collects and forwards the records. Decoding, rule matching, and alert generation occur on the Wazuh server in Phase 3.

## Prerequisites

- Phase 1 is installed and writing valid events to `C:\ProgramData\PhishingDetection\browser-navigation.json`.
- The Windows endpoint has an enrolled, connected Wazuh agent.
- The commands below are run from Windows PowerShell as Administrator.

The default Wazuh paths are:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
C:\Program Files (x86)\ossec-agent\ossec.log
```

## Install

From the repository root on the Windows endpoint:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\wazuh-agent\install-log-collection.ps1
```

The installer:

1. Confirms that the Wazuh service, configuration, and navigation log exist.
2. Validates the latest navigation event.
3. Creates a timestamped backup of `ossec.conf`.
4. Adds or updates an idempotent, marker-delimited `<localfile>` block.
5. Restarts the Wazuh service.
6. Automatically restores the backup if the service cannot restart.
7. Looks for Wazuh logcollector's monitoring entry in `ossec.log`.

The installed block is:

```xml
<localfile>
  <location>C:\ProgramData\PhishingDetection\browser-navigation.json</location>
  <log_format>json</log_format>
  <only-future-events>no</only-future-events>
</localfile>
```

`only-future-events` is set to `no` so records written while the agent is stopped remain eligible for collection when the agent returns. On the first installation, existing records in the file may consequently be forwarded.

If Wazuh was installed in a non-default directory, pass its configuration and internal log paths explicitly:

```powershell
.\wazuh-agent\install-log-collection.ps1 `
  -ConfigPath "D:\Wazuh\ossec.conf" `
  -AgentLog "D:\Wazuh\ossec.log"
```

## Verify the Endpoint

Run:

```powershell
.\wazuh-agent\verify-log-collection.ps1
```

Expected checks:

- The Wazuh service is running.
- The marked JSON collection block is present.
- Recent navigation lines satisfy the event contract.
- `ossec.log` contains an entry similar to:

```text
wazuh-logcollector: INFO: (1950): Analyzing file: 'C:\ProgramData\PhishingDetection\browser-navigation.json'.
```

After the checks pass, open a new URL in Edge. The Windows agent does not maintain a separate human-readable copy of every forwarded event. Definitive proof that the record crossed the agent-to-manager boundary is obtained from the manager archives or a temporary Phase 3 rule.

If collection is not recognized, inspect recent agent messages:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100
```

Check particularly for configuration errors, file-access failures, a full agent buffer, or a lost manager connection.

## Remove or Roll Back

To remove only the Wazuh collection block:

```powershell
.\wazuh-agent\uninstall-log-collection.ps1
```

The script backs up `ossec.conf`, removes the marked block, and restarts Wazuh. It does not remove the extension, native host, or navigation logs.

Timestamped backups are created next to `ossec.conf`. They can be restored manually if necessary.

## Phase 2 Acceptance Criteria

- The Wazuh service returns to `Running` after configuration.
- The agent reports that it is analyzing `browser-navigation.json`.
- No relevant logcollector, permissions, buffer, or manager-connection errors are present.
- Valid events continue to be appended while Wazuh monitors the file.
- Events created during a controlled Wazuh-agent stop are eligible for collection after restart.
- Phase 3 confirms that an event generated after installation reaches the manager.
