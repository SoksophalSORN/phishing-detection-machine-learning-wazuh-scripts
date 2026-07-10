# Phase 3: Wazuh Server Receipt and Pilot Alert

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
