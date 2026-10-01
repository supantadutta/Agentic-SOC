#!/var/ossec/framework/python/bin/python3
"""Wazuh custom integration: forward alerts to the Agentic SOC orchestrator.

Install on the Wazuh manager (inside the wazuh.manager container for Docker deployments):

    cp custom-agentic-soc.py /var/ossec/integrations/custom-agentic-soc.py
    chown root:wazuh /var/ossec/integrations/custom-agentic-soc.py
    chmod 750 /var/ossec/integrations/custom-agentic-soc.py

and add the <integration> block from ossec-manager.xml. wazuh-integratord calls this script as
``custom-agentic-soc.py <alert_file> <api_key> <hook_url>``. Standard library only, so it
runs on the Python interpreter bundled with Wazuh.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

LOG_FILE = "/var/ossec/logs/integrations.log"
# Optional: CA certificate for an HTTPS hook_url signed by the lab CA.
CA_FILE = "/var/ossec/etc/agentic-soc-ca.pem"
TIMEOUT_SECONDS = 10
RETRIES = 3


def log(message: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-agentic-soc: {message}\n")
    except OSError:
        pass


def main(argv: list) -> int:
    if len(argv) < 4:
        log("usage: custom-agentic-soc.py <alert_file> <api_key> <hook_url>")
        return 2
    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    try:
        with open(alert_file, encoding="utf-8") as fh:
            alert = json.load(fh)
    except (OSError, ValueError) as exc:
        log(f"cannot read alert file {alert_file}: {exc}")
        return 1

    if not hook_url.startswith(("http://", "https://")):
        log(f"refusing hook_url with unsupported scheme: {hook_url[:40]}")
        return 1
    body = json.dumps(alert).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        hook_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    context = ssl.create_default_context(cafile=CA_FILE if os.path.exists(CA_FILE) else None)
    for attempt in range(1, RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as resp:  # noqa: S310
                if resp.status in (200, 202):
                    return 0
                log(f"unexpected HTTP {resp.status} for alert {alert.get('id')}")
        except urllib.error.HTTPError as exc:
            log(f"HTTP {exc.code} for alert {alert.get('id')}: {exc.read()[:200]!r}")
            if exc.code in (400, 401, 403, 413, 422):
                return 1  # not retryable
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log(f"attempt {attempt} failed for alert {alert.get('id')}: {exc}")
        time.sleep(attempt)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
