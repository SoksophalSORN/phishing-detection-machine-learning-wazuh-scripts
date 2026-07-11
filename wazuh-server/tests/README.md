# Wazuh Server Development Tests

These tests validate source behavior and installer interfaces. They are not
copied into `/var/ossec` and are not executed by the production installer.

Run all server unit tests from the repository root:

```bash
python3 -m unittest discover -s wazuh-server/tests/unit -p 'test_*.py'
```

Operational checks against an installed Wazuh manager live in
`wazuh-server/verification`, not in this directory.
