# Google Web Risk Preparation Guide

This guide prepares Google Cloud and the staging Wazuh environment before the
Google Web Risk provider is implemented. It reflects Google documentation
available on 2026-07-12. Verify pricing and quotas again immediately before
production rollout because Google can change them.

Do not disable the working PhishTank deployment during preparation. The future
Web Risk installer must back up and disable PhishTank integration/rules
transactionally before it writes Web Risk configuration.

## 1. Decide the Environment Boundaries

Prepare separate staging and production resources where practical:

| Resource | Staging | Production |
| --- | --- | --- |
| Google Cloud project | Dedicated staging project | Dedicated production project |
| API key | Staging-only restricted key | Production-only restricted key |
| Allowed public IP | Staging Wazuh egress | Production Wazuh egress |
| Budget and alerts | Staging project scope | Production project scope |
| Wazuh manager | Non-production manager | Production manager after acceptance |

Separate projects make quota, billing, audit, and incident response easier to
attribute. At minimum, use separate restricted keys and keep an inventory that
maps each key to its Wazuh manager and environment.

Choose globally unique project IDs, for example:

```text
edge-phishing-webrisk-staging-ORG
edge-phishing-webrisk-production-ORG
```

Do not place API keys in project names, labels, annotations, or repository
files.

## 2. Confirm Administrative Access

Complete Google Cloud administration from Cloud Shell or a secured
administrator workstation. Do not install or retain administrator `gcloud`
credentials on the Wazuh manager.

Depending on your organization, request these permissions from the relevant
administrators:

- Permission to create/select a project.
- Permission to link the project to a Cloud Billing account. This commonly
  requires Project Billing Manager or Project Owner on the project plus Billing
  Account User on the billing account.
- Service Usage Admin (`roles/serviceusage.serviceUsageAdmin`) to enable APIs.
- API Keys Admin (`roles/serviceusage.apiKeysAdmin`) to create and manage keys.
- Permission to configure a project-scoped billing budget and view API usage.

If duties are separated, the billing, project, and key steps can be completed by
different administrators. Record who owns each responsibility.

Official references:

- [Web Risk setup](https://docs.cloud.google.com/web-risk/docs/detect-malicious-urls)
- [API Keys API setup and roles](https://docs.cloud.google.com/api-keys/docs/get-started-api-keys)
- [Cloud Billing access](https://docs.cloud.google.com/billing/docs/how-to/billing-access)

## 3. Install or Open the Google Cloud CLI

Cloud Shell already provides `gcloud`. On an administrator workstation, install
the current Google Cloud CLI using Google's platform-specific instructions.

Authenticate and inspect the active identity:

```bash
gcloud auth login
gcloud auth list
gcloud config list
```

For an organization using workforce identity federation, follow its federated
login process instead of creating unmanaged user credentials.

## 4. Create and Select the Staging Project

Set your intended project ID and create the project if it does not already
exist:

```bash
export WEB_RISK_PROJECT_ID='edge-phishing-webrisk-staging-ORG'

gcloud projects create "$WEB_RISK_PROJECT_ID" \
  --name='Edge Phishing Web Risk Staging'

gcloud config set project "$WEB_RISK_PROJECT_ID"
gcloud projects describe "$WEB_RISK_PROJECT_ID"
```

If an administrator created the project for you, omit `projects create` and
only select and describe it. Confirm the displayed project number and lifecycle
state before continuing.

## 5. Link and Verify Billing

Web Risk setup requires billing to be enabled even when usage is expected to
remain in the no-charge tier.

List billing accounts visible to your identity:

```bash
gcloud billing accounts list
```

After choosing the approved billing account, link it:

```bash
export BILLING_ACCOUNT_ID='000000-000000-000000'

gcloud billing projects link "$WEB_RISK_PROJECT_ID" \
  --billing-account="$BILLING_ACCOUNT_ID"

gcloud billing projects describe "$WEB_RISK_PROJECT_ID"
```

Confirm that `billingEnabled` is true and that the billing account is the
approved account. If your organization handles billing centrally, ask its
billing administrator to perform this step instead.

Google notes that projects not linked to an active billing account cannot use
Google Cloud services, including services with free usage. See
[Cloud Billing account guidance](https://docs.cloud.google.com/billing/docs/how-to/create-billing-account).

## 6. Enable Web Risk and API Key Management

Enable the services in the staging project:

```bash
gcloud services enable \
  webrisk.googleapis.com \
  apikeys.googleapis.com \
  --project="$WEB_RISK_PROJECT_ID"
```

Verify them:

```bash
gcloud services list --enabled \
  --project="$WEB_RISK_PROJECT_ID" \
  --filter='config.name:webrisk.googleapis.com OR config.name:apikeys.googleapis.com'
```

The runtime Wazuh integration will use only
`https://webrisk.googleapis.com/v1/uris:search`. It will not use the Update,
Evaluate, or Submission APIs.

## 7. Establish Stable Wazuh Egress

Before restricting the key, determine the public source address that Google
will see for outbound connections from the staging Wazuh manager.

- Ask the network administrator for the public NAT/egress IPv4 or IPv6 address.
- Do not use the manager's RFC1918/private address as an API-key restriction.
- If egress rotates or uses a pool, obtain the approved CIDR or arrange stable
  egress before production.
- Confirm outbound DNS and HTTPS access to
  `webrisk.googleapis.com:443` through the firewall/proxy.
- Confirm the manager has current CA certificates and reliable NTP time.

Record the approved value without any API key:

```bash
export WAZUH_EGRESS_IP='203.0.113.10'
```

Use the actual organization-approved address; the documentation address above
is only an example.

## 8. Create a Restricted Staging API Key

Create the key with both restrictions from the beginning:

```bash
gcloud services api-keys create \
  --project="$WEB_RISK_PROJECT_ID" \
  --display-name='edge-phishing-wazuh-staging' \
  --api-target='service=webrisk.googleapis.com' \
  --allowed-ips="$WAZUH_EGRESS_IP"
```

The API restriction prevents use with other Google APIs. The allowed-IP
restriction limits callers to the staging Wazuh server's public egress.

List and inspect key metadata without retrieving the secret:

```bash
gcloud services api-keys list --project="$WEB_RISK_PROJECT_ID"
```

In Google Cloud Console, open **APIs & Services → Credentials**, select the key,
and verify:

- Application restriction: IP addresses.
- Allowed IP: the staging public egress address/CIDR.
- API restriction: Web Risk API only.
- Display name clearly identifies staging.

Google recommends applying both application and API restrictions to API keys.
See [API key restrictions](https://docs.cloud.google.com/api-keys/docs/add-restrictions-api-keys)
and the current [`gcloud services api-keys create` reference](https://docs.cloud.google.com/sdk/gcloud/reference/services/api-keys/create).

## 9. Store the Key Safely for Later Installation

Retrieve/copy the key string once using the Google Cloud Console or the approved
organizational secret-management process. Store it in a password manager or
secret vault with:

- Google Cloud project ID and number.
- Key resource ID and display name.
- Allowed egress IP/CIDR.
- Environment and Wazuh manager owner.
- Creation and planned rotation date.
- Revocation contact and incident procedure.

Do not:

- Commit it to Git or place it in `.env`.
- Paste it into issue trackers, chat, screenshots, or documentation.
- Put it into the current PhishTank configuration.
- Save it permanently in shell history or a command argument.
- Install it on the Wazuh server before the Web Risk installer exists.

The future installer will prompt without echo and atomically install the key at
`/var/ossec/etc/edge-google-web-risk.key` with `root:wazuh` ownership and mode
`0640`.

## 10. Perform an Optional One-Call Connectivity Test

This optional test consumes one Lookup API call. It sends Google's documented
malware test URL to Web Risk but does not open or download that target. It tests
API enablement, key restrictions, DNS, TLS, and egress from the machine where it
is run.

Because the key is restricted to the staging Wazuh egress IP, run the test on
that Wazuh server. Paste the key only into the hidden Python prompt:

```bash
python3 - <<'PY'
import getpass
import json
import urllib.error
import urllib.parse
import urllib.request

key = getpass.getpass("Google Web Risk API key: ")
params = [
    ("threatTypes", "MALWARE"),
    ("uri", "http://testsafebrowsing.appspot.com/s/malware.html"),
    ("key", key),
]
endpoint = "https://webrisk.googleapis.com/v1/uris:search?" + urllib.parse.urlencode(params)
request = urllib.request.Request(endpoint, headers={"Accept": "application/json"})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = response.read(65537)
        if len(payload) > 65536:
            raise RuntimeError("response exceeded 65536 bytes")
except urllib.error.HTTPError as exc:
    raise SystemExit(f"Web Risk HTTP status: {exc.code}") from None
except urllib.error.URLError as exc:
    raise SystemExit(f"Web Risk connection failed: {exc.reason}") from None
finally:
    key = ""
print(json.dumps(json.loads(payload), indent=2))
PY
```

Expected successful connectivity is HTTP `200` and a response containing a
`threat` object with `MALWARE`. The URL comes from Google's current Lookup API
example. This test verifies the API path, not the project's future
`SOCIAL_ENGINEERING` rule or Wazuh integration.

Common failures:

- `400`: malformed request.
- `403`: API disabled, invalid key, or key restrictions do not match the
  service/egress IP.
- `429`: quota or rate limit.
- TLS/DNS timeout: server network, proxy, CA, or time configuration.

Allow several minutes for a newly created or updated key restriction to
propagate before diagnosing a persistent failure.

Official request format and example:
[Using the Web Risk Lookup API](https://docs.cloud.google.com/web-risk/docs/lookup-api).

## 11. Configure Cost and Quota Guardrails

Google currently documents:

- Lookup API `uris.search`: no charge for up to 100,000 calls per month.
- `SearchUris`: 6,000 requests per minute per project, shared across callers.

These values can change. Verify [current pricing](https://cloud.google.com/web-risk/pricing)
and [current quotas](https://docs.cloud.google.com/web-risk/quotas) in the
staging and production projects before rollout.

In Google Cloud Console:

1. Open **APIs & Services → Web Risk API → Quotas & System Limits**.
2. Review `SearchUris requests per minute`.
3. If Google allows a consumer override, lower it to an operationally reasonable
   value based on the staging traffic estimate rather than leaving 6,000/minute.
4. Open **Billing → Budgets & alerts**.
5. Create a project-scoped monthly budget with low thresholds suitable for the
   pilot, such as 50%, 90%, and 100% notifications.
6. Confirm the notification recipients include both the technical owner and the
   billing owner.

A Google Cloud budget sends notifications but does not automatically cap usage
or spending. The planned application therefore adds its own default 90,000-call
monthly ceiling. See [budget behavior](https://docs.cloud.google.com/billing/docs/how-to/budgets).

## 12. Estimate Expected Monthly Lookups

Before implementation, estimate:

```text
monthly outbound calls ≈ navigation events
                       × unique-URL fraction after cache
                       × cache-miss fraction
                       + retry calls
```

The 100,000-call tier averages approximately 3,333 calls per day in a 30-day
month. The planned 90,000 application ceiling averages 3,000 per day. Do not use
the average as a burst quota; measure staging traffic and preserve headroom for
retries and more endpoints.

Collect at least several representative days of:

- Navigation events per day.
- Unique privacy-normalized URLs per day.
- Repeated URL frequency within five-minute windows.
- Number of pilot endpoints feeding the manager.
- Expected growth during production rollout.

Do not send those historical URLs to Google during estimation. Analyze the
existing local/Wazuh event data and store only aggregate counts in planning
notes.

## 13. Complete Privacy and Security Approval

The Lookup API sends the complete privacy-normalized URL to Google. Before
implementation, obtain agreement on:

- Whether full normalized URLs may be transferred to Google Web Risk.
- Which query parameters must be removed before lookup.
- Whether the existing search-term and secret redaction policy is sufficient.
- Wazuh/index retention for URLs and Web Risk verdicts.
- Who can read the API key and classifier configuration.
- Key rotation, revocation, and incident response.
- Whether staging and production require separate Google Cloud projects.

No cookies, page contents, form data, authorization headers, browser identity,
or endpoint username will be sent to Web Risk.

## 14. Prepare the Staging Wazuh Manager

Before code implementation begins:

1. Take a VM/hypervisor snapshot or approved system backup.
2. Confirm `wazuh-manager` is active and `wazuh-analysisd -t` succeeds.
3. Preserve `/var/ossec/etc/ossec.conf`, active custom rules, the classifier
   configuration, policy/deployment manifests, integration modules, and ML
   artifacts.
4. Inventory active PhishTank integrations and rules without disabling them.
5. Record the current configurable rule IDs and levels.
6. Confirm the current ML offline verifier passes.
7. Confirm outbound HTTPS to `webrisk.googleapis.com:443` is allowed.
8. Keep the staging API key in the approved vault until the future installer
   securely prompts for it.

Useful non-mutating checks:

```bash
sudo systemctl is-active wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t
sudo grep -RIn -- 'phishtank\|edge-phishing-classifier' \
  /var/ossec/etc/ossec.conf /var/ossec/etc/rules /var/ossec/integrations
sudo python3 ./wazuh-server/verification/verify-ml-integration.py \
  --url 'https://controlled-test.example/login'
```

The grep output might reveal configuration paths but should not print API key
contents. Do not run broad `cat` commands against secret-bearing configuration
when saving terminal output to tickets or chat.

## 15. Information to Have Ready for Implementation

Prepare this worksheet without including the API key value:

```text
Staging GCP project ID:
Staging GCP project number:
Billing account owner/contact:
Web Risk API enabled: yes/no
API key resource ID/display name:
API restriction verified: yes/no
Allowed staging egress IP/CIDR:
Budget notification recipients:
Requested per-minute quota:
Application monthly ceiling (planned default 90000):
Negative-cache TTL (planned default 300 seconds):
Threat types (planned default SOCIAL_ENGINEERING):
Wazuh staging manager hostname:
Current PhishTank rule IDs:
Current PhishTank integration marker/file:
Current ML rule ID and level:
Backup/snapshot reference:
Privacy approval owner:
Key rotation owner/date:
```

## Ready-to-Implement Gate

Implementation can begin when:

- A staging project has active billing and Web Risk enabled.
- A staging key is restricted to Web Risk and the correct Wazuh public egress.
- The optional one-call test returns a valid Web Risk response, or a documented
  network exception is being resolved independently.
- Budget/quota alerts and ownership are established.
- Expected traffic fits below the planned ceiling with headroom.
- Privacy/security review approves sending normalized URLs to Google.
- The current PhishTank state is inventoried and backed up but still active.
- A staging Wazuh snapshot and rollback owner are available.
- The API key remains outside the repository and Wazuh until the secure
  installer is implemented.

## Official References

- [Detect malicious URLs with Web Risk](https://docs.cloud.google.com/web-risk/docs/detect-malicious-urls)
- [Using the Lookup API](https://docs.cloud.google.com/web-risk/docs/lookup-api)
- [Web Risk pricing](https://cloud.google.com/web-risk/pricing)
- [Web Risk quotas](https://docs.cloud.google.com/web-risk/quotas)
- [Create restricted API keys with gcloud](https://docs.cloud.google.com/sdk/gcloud/reference/services/api-keys/create)
- [API key restrictions](https://docs.cloud.google.com/api-keys/docs/add-restrictions-api-keys)
- [Cloud Billing budgets](https://docs.cloud.google.com/billing/docs/how-to/budgets)
