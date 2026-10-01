"""Download the MITRE ATT&CK Enterprise STIX bundle used to validate technique ids.

    python scripts/fetch_attack_data.py [--out data/enterprise-attack.json]

Without the bundle the orchestrator falls back to a small built-in subset and only checks
that technique ids are well-formed.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("data/enterprise-attack.json"))
    parser.add_argument("--url", default=URL)
    args = parser.parse_args()
    if not args.url.startswith("https://"):
        raise SystemExit("refusing non-HTTPS URL")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(args.url, timeout=120) as resp:  # noqa: S310 - fixed HTTPS URL
        body = resp.read()
    bundle = json.loads(body)
    techniques = sum(1 for o in bundle.get("objects", []) if o.get("type") == "attack-pattern")
    args.out.write_bytes(body)
    print(f"wrote {args.out} ({techniques} attack-pattern objects)")


if __name__ == "__main__":
    main()
