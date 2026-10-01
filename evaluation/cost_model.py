"""Cost model (blueprint section 25).

Total cost      = hardware + storage + electricity + cloud/API + backup + maintenance
AI cost / alert = input tokens x input price + output tokens x output price
Monthly AI cost = alerts/month x AI cost/alert

python -m evaluation.cost_model --config config/cost_model.yaml --results results/cloud/metrics.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def compute(config: dict[str, Any], results: dict[str, Any] | None = None) -> dict[str, Any]:
    months = float(config.get("period_months", 12))
    hw = config.get("hardware", {})
    storage = config.get("storage", {})
    power = config.get("electricity", {})
    backup = config.get("backup", {})
    maint = config.get("maintenance", {})
    api = config.get("cloud_api", {})

    amortization = max(float(hw.get("amortization_months", 36)), 1.0)
    hardware_monthly = float(hw.get("purchase_usd", 0)) / amortization
    storage_monthly = float(storage.get("purchase_usd", 0)) / amortization + float(storage.get("monthly_usd", 0))
    kwh_month = float(power.get("average_watts", 0)) / 1000 * float(power.get("hours_per_day", 24)) * 30.4
    electricity_monthly = kwh_month * float(power.get("price_per_kwh_usd", 0))
    backup_monthly = float(backup.get("monthly_usd", 0))
    maintenance_monthly = float(maint.get("hours_per_month", 0)) * float(maint.get("hourly_rate_usd", 0))

    ai_cost_per_alert = api.get("ai_cost_per_alert_usd")
    source = "config"
    if ai_cost_per_alert is None and results:
        ai_cost_per_alert = results["summary"]["agentic"]["llm_cost_per_alert_usd"]
        source = f"evaluation results ({results.get('provider')}, {results.get('model')})"
    ai_cost_per_alert = float(ai_cost_per_alert or 0.0)
    alerts_per_month = float(api.get("alerts_per_month", 0))
    ai_monthly = alerts_per_month * ai_cost_per_alert

    monthly = {
        "hardware": hardware_monthly,
        "storage": storage_monthly,
        "electricity": electricity_monthly,
        "cloud_api": ai_monthly,
        "backup": backup_monthly,
        "maintenance": maintenance_monthly,
    }
    total_monthly = sum(monthly.values())
    return {
        "period_months": months,
        "monthly_usd": {k: round(v, 2) for k, v in monthly.items()},
        "total_monthly_usd": round(total_monthly, 2),
        "total_period_usd": round(total_monthly * months, 2),
        "ai_cost_per_alert_usd": ai_cost_per_alert,
        "ai_cost_per_alert_source": source,
        "alerts_per_month": alerts_per_month,
        "monthly_ai_cost_usd": round(ai_monthly, 4),
        "electricity_kwh_per_month": round(kwh_month, 1),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, default=Path("config/cost_model.yaml"))
    parser.add_argument("--results", type=Path, help="metrics.json from run_evaluation")
    args = parser.parse_args(argv)
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    results = json.loads(args.results.read_text(encoding="utf-8")) if args.results else None
    model = compute(config, results)
    print(f"Cost model over {model['period_months']:.0f} months")
    print("| Component | USD / month |")
    print("|---|---|")
    for name, value in model["monthly_usd"].items():
        print(f"| {name} | {value:.2f} |")
    print(f"| **total** | **{model['total_monthly_usd']:.2f}** |")
    print()
    print(f"Total for period: ${model['total_period_usd']:.2f}")
    print(f"AI cost per alert: ${model['ai_cost_per_alert_usd']:.6f} (from {model['ai_cost_per_alert_source']})")
    print(
        f"Monthly AI cost: {model['alerts_per_month']:.0f} alerts x AI cost/alert = ${model['monthly_ai_cost_usd']:.4f}"
    )


if __name__ == "__main__":
    main()
