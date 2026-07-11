# Original Fork Implementation

These files are retained only as historical source from the forked project:

- `integration-script.py` extracts URLs from process command lines, queries
  PhishTank, and performs legacy model inference.
- `main.py` and `url_feature_extraction.py` generate the original feature data.

They are not installed by the finalized Edge/Wazuh deployment scripts. New
deployments must use the structured extension, native host, Wazuh agent, and
`wazuh-server/install-wazuh-server.sh` workflow documented at the repository
root. See `wazuh-server/cleanup-original-implementation.md` before removing an
existing legacy deployment.
