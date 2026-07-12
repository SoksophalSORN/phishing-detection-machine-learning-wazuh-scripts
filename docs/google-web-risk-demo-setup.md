# Google Web Risk Demo Setup

Use this guide when you only need a Google Web Risk API key for a small
experiment or demonstration. It uses the Google Cloud Console, not `gcloud`.

For production ownership, separate environments, budgets, traffic estimation,
and rollback preparation, use the
[production preparation guide](google-web-risk-preparation-guide.md).

## What You Need

- A Google account.
- Access to [Google Cloud Console](https://console.cloud.google.com/).
- A billing account or permission to link one. Google requires billing to be
  enabled even when usage remains within the free tier.
- The public outbound IP of the Ubuntu Wazuh server if you want to restrict the
  key to that server. This restriction is recommended but optional for a short
  isolated demo.

Do not disable PhishTank yet. Creating a Web Risk key does not modify Wazuh.
The future installer will handle the provider switch after the implementation
is ready.

## 1. Create a Google Cloud Project

1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Open the project selector in the top bar.
3. Select **New Project**.
4. Enter a name such as `Wazuh Web Risk Demo`.
5. Select the appropriate organization/location if Google asks for one.
6. Select **Create**.
7. After creation, make sure this new project is selected in the top bar.

You can reuse a suitable existing project, but a separate demo project makes
usage and cleanup easier to understand.

## 2. Enable Billing

1. Open the navigation menu and select **Billing**.
2. If the project is not linked, select **Link a billing account**.
3. Select the approved billing account and confirm.

If you cannot select a billing account, ask its administrator to link the
project. Projects without active billing cannot use Web Risk, including its
free usage.

## 3. Enable the Web Risk API

1. Open **APIs & Services → Library**.
2. Search for `Web Risk API`.
3. Open **Web Risk API**.
4. Select **Enable**.
5. Wait until the API overview page confirms it is enabled.

For this project, use the Lookup API only. You do not need to enable the Update,
Submission, Evaluate, or Safe Browsing APIs.

## 4. Create the API Key

1. Open **APIs & Services → Credentials**.
2. Select **Create credentials → API key**.
3. Google displays the new key. Do not paste it into this repository or `.env`.
4. Select **Edit API key** or open the new key from the credentials list.
5. Rename it to something recognizable, such as
   `wazuh-web-risk-demo`.

## 5. Restrict the Key

On the key-editing page:

1. Under **API restrictions**, select **Restrict key**.
2. Select only **Web Risk API**.
3. For a server/IP restriction:
   - Under **Application restrictions**, select **IP addresses**.
   - Add the Wazuh server's public NAT/egress IP, not its private LAN address.
4. Select **Save**.

If the demo server has a changing public IP and you omit the IP restriction,
keep the key only for the short demo and delete it afterward. The Web Risk API
restriction should still be applied.

Google may need a few minutes to apply new key restrictions.

## 6. Copy and Store the Key Temporarily

From **APIs & Services → Credentials**:

1. Open the `wazuh-web-risk-demo` key.
2. Select **Show key** if necessary.
3. Copy it into a password manager or other temporary secret storage.

Do not store the key in:

- `.env` or another repository file.
- The current PhishTank configuration.
- A shell command or shell history.
- Screenshots, tickets, or chat messages.

The future installer will use a hidden prompt and install the key in a
root-controlled file. Nothing needs to be added to `/var/ossec` yet.

## 7. Optional One-Call Test

This test consumes one Web Risk Lookup call. It asks for the key through a
hidden prompt, sends Google's documented malware test URL to Web Risk, and does
not open or download that URL.

Run it on the Wazuh server if the key has an IP restriction for that server:

```bash
python3 - <<'PY'
import getpass
import json
import urllib.error
import urllib.parse
import urllib.request

key = getpass.getpass("Google Web Risk API key: ")
query = urllib.parse.urlencode([
    ("threatTypes", "MALWARE"),
    ("uri", "http://testsafebrowsing.appspot.com/s/malware.html"),
    ("key", key),
])
request = urllib.request.Request(
    "https://webrisk.googleapis.com/v1/uris:search?" + query,
    headers={"Accept": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
except urllib.error.HTTPError as exc:
    raise SystemExit(f"Web Risk HTTP status: {exc.code}") from None
except urllib.error.URLError as exc:
    raise SystemExit(f"Web Risk connection failed: {exc.reason}") from None
finally:
    key = ""
print(json.dumps(result, indent=2))
PY
```

A successful test returns HTTP `200` with a `threat` object containing
`MALWARE`. This verifies the key and API connectivity. The planned phishing
integration will normally request `SOCIAL_ENGINEERING` instead.

Common errors:

- `403`: key restriction, billing, project, or API-enablement problem.
- `429`: request quota/rate problem.
- Connection or TLS error: DNS, firewall, proxy, certificate, or system-time
  problem on the Wazuh server.

## 8. Keep or Delete the Key

If implementation will begin soon, leave the restricted key in the password
manager until the installer is ready.

If the experiment is finished:

1. Return to **APIs & Services → Credentials**.
2. Select the demo key.
3. Select **Delete** and confirm.
4. Optionally delete the demo project if it has no other purpose.

## Ready for the Demo Implementation

You are ready when:

- The project has billing enabled.
- Web Risk API is enabled.
- The API key is restricted to Web Risk.
- The optional IP restriction matches the Wazuh public egress.
- The one-call test succeeds, or the key is securely stored for later testing.
- PhishTank remains unchanged until the Web Risk installer is implemented.

## Official References

- [Web Risk setup](https://docs.cloud.google.com/web-risk/docs/detect-malicious-urls)
- [Using the Lookup API](https://docs.cloud.google.com/web-risk/docs/lookup-api)
- [Managing and restricting API keys](https://docs.cloud.google.com/docs/authentication/api-keys)
- [Web Risk pricing](https://cloud.google.com/web-risk/pricing)
