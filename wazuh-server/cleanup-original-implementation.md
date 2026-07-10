# Cleanup of the Original Sysmon/Command-Line Implementation

Perform this cleanup only after backing up the endpoint and manager configuration. The new Edge pilot does not require the original Chrome command-line rule or its custom integration.

The cleanup is divided into required and optional actions. Sysmon and the existing model artifacts can be useful outside the old URL-capture path, so they are not automatically removed.

## 1. Inventory Before Changing Anything

On the Ubuntu Wazuh server, copy this repository or at least the `wazuh-server` directory and run:

```bash
sudo ./wazuh-server/audit-original-installation.sh
```

Also create backups:

```bash
sudo cp -a /var/ossec/etc/ossec.conf \
  /var/ossec/etc/ossec.conf.before-edge-cleanup.$(date -u +%Y%m%dT%H%M%SZ)

sudo cp -a /var/ossec/etc/rules \
  /root/wazuh-rules.before-edge-cleanup.$(date -u +%Y%m%dT%H%M%SZ)

sudo mkdir -p /root/wazuh-phishing-legacy-backup
sudo cp -a /var/ossec/integrations/custom-phishing-detection.py \
  /var/ossec/integrations/model.joblib \
  /var/ossec/integrations/scaler.joblib \
  /root/wazuh-phishing-legacy-backup/ 2>/dev/null || true
```

Review the backup paths before continuing.

## 2. Required Windows Endpoint Cleanup

### Keep the new Edge collection

Do not remove this Phase 2 block:

```xml
<localfile>
  <location>C:\ProgramData\PhishingDetection\browser-navigation.json</location>
  <log_format>json</log_format>
  <only-future-events>no</only-future-events>
</localfile>
```

Keep the extension, native host, navigation file, and `wazuh-agent` configuration.

### Decide whether to keep Sysmon collection

The original project added this block to the Windows Wazuh agent:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Sysmon provides valuable endpoint telemetry beyond this project. Keep the block if other Wazuh detections use Sysmon. If Sysmon was installed solely to discover browser URLs, remove only that block from:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Before editing, make a backup in elevated PowerShell:

```powershell
$config = "C:\Program Files (x86)\ossec-agent\ossec.conf"
Copy-Item $config "$config.before-sysmon-cleanup.bak"
```

After removing the Sysmon `<localfile>` block, restart and check Wazuh:

```powershell
Restart-Service -Name wazuh
Get-Service -Name wazuh
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100
```

Confirm that `browser-navigation.json` is still reported as an analyzed file.

### Optional: uninstall Sysmon

Do this only if no security monitoring, incident-response, or compliance use still depends on it. From an elevated terminal in the directory containing Sysmon:

```powershell
.\Sysmon64.exe -u
```

Use `-u force` only when ordinary removal cannot complete. Removing Sysmon is not required for the Edge pilot.

Do not delete the Microsoft-Windows-Sysmon/Operational event log merely to clean up this project; existing events may be needed for investigations or retention requirements.

## 3. Required Ubuntu Wazuh Server Cleanup

### Remove the original integration block

Edit:

```text
/var/ossec/etc/ossec.conf
```

Remove only the original block that invokes rule `100002`, typically:

```xml
<integration>
  <name>custom-phishing-detection.py</name>
  <hook_url>https://checkurl.phishtank.com/checkurl/</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Do not remove unrelated integrations.

### Remove the original rules

From `/var/ossec/etc/rules/local_rules.xml`, or whichever custom file the audit reports, remove only the old rules:

- `100002`: Chrome process command-line match.
- `100003`: original PhishTank result alert.
- `100004`: original ML result alert.

Do not remove the new Phase 3 rule `100100` or its file:

```text
/var/ossec/etc/rules/edge_navigation_rules.xml
```

Search again to confirm the old IDs are gone:

```bash
sudo grep -RInE --include='*.xml' '<rule id="10000[234]"' /var/ossec/etc/rules || true
sudo grep -nEi 'custom-phishing|100002' /var/ossec/etc/ossec.conf || true
```

Validate before restart:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Then restart and verify:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
sudo tail -n 100 /var/ossec/logs/ossec.log
```

### Preserve integration files for Phase 4

Once the `<integration>` block is removed, the old script is no longer invoked by that configuration. Keep the backed-up files until Phase 4 determines whether the model and scaler will be reused:

```text
/var/ossec/integrations/custom-phishing-detection.py
/var/ossec/integrations/model.joblib
/var/ossec/integrations/scaler.joblib
```

For a cleaner active integration directory, move them to the backup directory after stopping their invocation:

```bash
sudo mv /var/ossec/integrations/custom-phishing-detection.py \
  /var/ossec/integrations/model.joblib \
  /var/ossec/integrations/scaler.joblib \
  /root/wazuh-phishing-legacy-backup/
```

Run the command only after confirming the backup and filenames. File removal is optional at this stage.

## 4. Items That Should Not Be Deleted

- The Edge extension and native host.
- `C:\ProgramData\PhishingDetection\browser-navigation.json` during the pilot.
- The new Windows Wazuh `localfile` block.
- `/var/ossec/etc/rules/edge_navigation_rules.xml` during Phase 3.
- Wazuh agent enrollment keys or certificates.
- Historical Wazuh alerts, indexes, or Sysmon events unless a retention policy authorizes deletion.
- Model and scaler backups until the Phase 4 model decision is complete.

## 5. Cleanup Acceptance Checks

- The Windows Wazuh service is running and still analyzes `browser-navigation.json`.
- The Ubuntu `wazuh-manager` service is active.
- Rules `100002`, `100003`, and `100004` are absent.
- The old `custom-phishing-detection.py` integration block is absent.
- Rule `100100` passes `wazuh-logtest` and produces the Phase 3 pilot alert.
- No new invocations of the old integration appear in `/var/ossec/logs/integrations.log`.
