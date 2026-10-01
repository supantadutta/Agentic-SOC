"""Replay scenario alerts into a running orchestrator through its ingest API.

Useful for an end-to-end demonstration of the deployed stack (Wazuh integration path aside)
without running attacks:

    export SOC_INGEST_API_KEY=...
    python scripts/replay_alerts.py --url http://192.168.50.20:8000 --scenario phishing_powershell_download
    python scripts/replay_alerts.py --url http://127.0.0.1:8000 --all --sync

Alerts are re-stamped to the current time (keeping their relative spacing) unless --keep-time.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agentic_soc.integrations.wazuh import parse_timestamp  # noqa: E402
from evaluation.scenarios import load_scenarios  # noqa: E402


def restamp(alerts: list[dict]) -> list[dict]:
    if not alerts:
        return alerts
    first = parse_timestamp(alerts[0]["timestamp"])
    now = datetime.now(UTC)
    out = []
    for i, alert in enumerate(alerts):
        alert = copy.deepcopy(alert)
        ts = now + (parse_timestamp(alert["timestamp"]) - first)
        alert["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        alert["id"] = f"replay-{int(now.timestamp())}-{i}"
        out.append(alert)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", help="scenario name from evaluation/scenarios.py")
    group.add_argument("--all", action="store_true")
    group.add_argument("--file", type=Path, help="JSON file with a list of Wazuh alerts")
    parser.add_argument("--sync", action="store_true", help="wait for each alert to be processed")
    parser.add_argument("--keep-time", action="store_true")
    parser.add_argument("--ca", help="CA bundle for an HTTPS orchestrator URL")
    args = parser.parse_args()

    key = os.environ.get("SOC_INGEST_API_KEY")
    if not key:
        raise SystemExit("set SOC_INGEST_API_KEY")
    if args.file:
        batches = {args.file.stem: json.loads(args.file.read_text(encoding="utf-8"))}
    else:
        scenarios = {s.name: s.alerts for s in load_scenarios()}
        if args.scenario and args.scenario not in scenarios:
            raise SystemExit(f"unknown scenario; choose from: {', '.join(scenarios)}")
        batches = scenarios if args.all else {args.scenario: scenarios[args.scenario]}

    with httpx.Client(base_url=args.url, verify=args.ca or True, timeout=300) as client:
        for name, alerts in batches.items():
            print(f"== {name}")
            for alert in alerts if args.keep_time else restamp(alerts):
                resp = client.post(
                    "/api/v1/alerts/wazuh",
                    params={"sync": str(args.sync).lower()},
                    json=alert,
                    headers={"Authorization": f"Bearer {key}"},
                )
                resp.raise_for_status()
                body = resp.json()
                outcome = body.get("outcome") or {}
                print(
                    f"  rule {alert['rule']['id']:>6} lvl {alert['rule']['level']:>2} -> "
                    f"{outcome.get('status', 'queued')} incident={outcome.get('incident_id')} "
                    f"policy={outcome.get('policy_outcome')} action={outcome.get('action')}"
                )


if __name__ == "__main__":
    main()
