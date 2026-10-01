"""Baseline SOC vs Agentic SOC evaluation (blueprint section 24).

Replays the scenario library through a fresh pipeline (dry-run playbooks, offline threat
intelligence from the scenario seeds) and compares it with a Wazuh-only baseline.

    python -m evaluation.run_evaluation --provider heuristic --out results/heuristic
    python -m evaluation.run_evaluation --provider ollama --out results/ollama
    python -m evaluation.run_evaluation --provider cloud --out results/cloud
    python -m evaluation.run_evaluation --provider hybrid --out results/hybrid

Human-baseline timings (triage/response time measured with analysts) can be merged with
``--human-baseline evaluation/human_baseline_template.csv``.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select

from agentic_soc.agents.enrichment_agent import StaticThreatIntel
from agentic_soc.config.settings import Settings
from agentic_soc.database.audit import verify_chain
from agentic_soc.database.models import HumanApproval, Incident, LLMDecision, PlaybookRun
from agentic_soc.llm.base import LLMProvider
from agentic_soc.pipeline.metrics import collect_metrics
from agentic_soc.pipeline.orchestrator import SOCOrchestrator
from agentic_soc.policy.policy_engine import PolicyEngine
from evaluation.scenarios import AGENTS, Scenario, load_from_directory, load_scenarios

POSITIVE = {"malicious", "suspicious"}


@dataclass
class ScenarioResult:
    scenario: str
    label: str
    alerts: int
    incidents: int
    # agentic
    classification: str | None
    risk_score: int | None
    policy_outcome: str | None
    action: str | None
    action_correct: bool
    approvals_requested: int
    playbook_runs: int
    playbook_successes: int
    triage_calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    time_to_triage_ms: float | None
    time_to_response_ms: float | None
    audit_chain_valid: bool
    # baseline (Wazuh rules + human)
    baseline_max_level: int
    baseline_flagged: bool
    baseline_alerts_for_human: int
    notes: list[str] = field(default_factory=list)


def _settings(out: Path, provider: str, overrides: dict[str, Any]) -> Settings:
    return Settings(
        database_url=f"sqlite:///{out / 'evaluation.db'}",
        llm_provider=provider,
        execution_mode="dry_run",
        evidence_dir=out / "evidence",
        wazuh_api_url=None,
        wazuh_indexer_url=None,
        misp_url=None,
        virustotal_api_key=None,
        opnsense_url=None,
        notify_webhook_url=None,
        **overrides,
    )


def run(
    out: Path,
    provider_name: str = "heuristic",
    scenarios: list[Scenario] | None = None,
    policy_file: Path | None = None,
    baseline_level: int = 10,
    simulate_analyst: str = "none",
    provider: LLMProvider | None = None,
    settings_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    db_file = out / "evaluation.db"
    if db_file.exists():
        db_file.unlink()
    scenarios = scenarios or load_scenarios()
    # The lab DC's Wazuh agent receives account-containment commands.
    overrides = {"ad_dc_agent_id": AGENTS["dc"]["id"], **(settings_overrides or {})}
    settings = _settings(out, provider_name, overrides)
    if policy_file:
        settings.policy_file = policy_file
    seeds: dict[str, str] = {}
    for scenario in scenarios:
        seeds.update(scenario.threat_intel)
    orchestrator = SOCOrchestrator.from_settings(
        settings,
        provider=provider,
        ti_sources=[StaticThreatIntel(seeds)],
        policy=PolicyEngine.load(settings.policy_file),
    )

    results = []
    for scenario in scenarios:
        results.append(_run_scenario(orchestrator, scenario, baseline_level, simulate_analyst))

    with orchestrator.db.session() as session:
        pipeline_metrics = collect_metrics(session)
    summary = summarize(results)
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "provider": provider_name,
        "model": getattr(orchestrator.triage_agent.provider, "model", provider_name),
        "policy_version": orchestrator.policy.version,
        "baseline_alert_level": baseline_level,
        "simulate_analyst": simulate_analyst,
        "summary": summary,
        "pipeline_metrics": pipeline_metrics,
        "scenarios": [asdict(r) for r in results],
    }
    (out / "metrics.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    with (out / "scenarios.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[k for k in asdict(results[0]) if k != "notes"])
        writer.writeheader()
        for r in results:
            writer.writerow({k: v for k, v in asdict(r).items() if k != "notes"})
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def _run_scenario(
    orchestrator: SOCOrchestrator, scenario: Scenario, baseline_level: int, simulate_analyst: str
) -> ScenarioResult:
    incident_ids: list[int] = []
    elapsed = 0.0
    time_to_triage = time_to_response = None
    for raw in scenario.alerts:
        outcome = orchestrator.process_wazuh_alert(raw)
        elapsed += outcome.processing_ms
        if outcome.incident_id and outcome.incident_id not in incident_ids:
            incident_ids.append(outcome.incident_id)
        if outcome.status == "triaged" and time_to_triage is None:
            time_to_triage = elapsed
        if outcome.playbook_run_id and time_to_response is None:
            time_to_response = elapsed

    if simulate_analyst in ("approve", "reject"):
        with orchestrator.db.session() as session:
            pending = (
                session.execute(
                    select(HumanApproval.id)
                    .where(HumanApproval.incident_id.in_(incident_ids))
                    .where(HumanApproval.status == "pending")
                )
                .scalars()
                .all()
            )
        for approval_id in pending:
            decided = orchestrator.decide_approval(approval_id, "simulated-analyst", simulate_analyst == "approve")
            if decided.get("playbook_run_id") and time_to_response is None:
                time_to_response = elapsed

    with orchestrator.db.session() as session:
        incidents = session.execute(select(Incident).where(Incident.id.in_(incident_ids))).scalars().all()
        primary = max(incidents, key=lambda i: (i.risk_score or -1, len(i.alerts)), default=None)
        decisions = (
            session.execute(select(LLMDecision).where(LLMDecision.incident_id.in_(incident_ids))).scalars().all()
        )
        last = max((d for d in decisions if primary and d.incident_id == primary.id), key=lambda d: d.id, default=None)
        approvals = (
            session.execute(select(HumanApproval).where(HumanApproval.incident_id.in_(incident_ids))).scalars().all()
        )
        runs = session.execute(select(PlaybookRun).where(PlaybookRun.incident_id.in_(incident_ids))).scalars().all()
        chain_ok = all(verify_chain(session, i).valid for i in incident_ids)
        action = last.recommended_action if last else None
        expected = set(scenario.expected_actions)
        notes = [n for d in decisions for n in (d.validation_notes or [])]
        return ScenarioResult(
            scenario=scenario.name,
            label=scenario.label,
            alerts=len(scenario.alerts),
            incidents=len(incident_ids),
            classification=primary.classification if primary else None,
            risk_score=primary.risk_score if primary else None,
            policy_outcome=last.policy_outcome if last else None,
            action=action,
            action_correct=(action in expected) if action else (scenario.label == "benign"),
            approvals_requested=sum(1 for a in approvals if a.status != "superseded"),
            playbook_runs=len(runs),
            playbook_successes=sum(1 for r in runs if r.status in ("success", "dry_run")),
            triage_calls=len(decisions),
            input_tokens=sum(d.input_tokens for d in decisions),
            output_tokens=sum(d.output_tokens for d in decisions),
            cost_usd=round(sum(d.cost_usd for d in decisions), 8),
            time_to_triage_ms=round(time_to_triage, 1) if time_to_triage is not None else None,
            time_to_response_ms=round(time_to_response, 1) if time_to_response is not None else None,
            audit_chain_valid=chain_ok,
            baseline_max_level=max(int(a["rule"]["level"]) for a in scenario.alerts),
            baseline_flagged=max(int(a["rule"]["level"]) for a in scenario.alerts) >= baseline_level,
            baseline_alerts_for_human=sum(1 for a in scenario.alerts if int(a["rule"]["level"]) >= 7),
            notes=notes[:20],
        )


def _confusion(pairs: list[tuple[str, bool]]) -> dict[str, int]:
    tp = sum(1 for label, flagged in pairs if label == "malicious" and flagged)
    fn = sum(1 for label, flagged in pairs if label == "malicious" and not flagged)
    fp = sum(1 for label, flagged in pairs if label == "benign" and flagged)
    tn = sum(1 for label, flagged in pairs if label == "benign" and not flagged)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _classification_correct(r: ScenarioResult) -> bool:
    if r.label == "malicious":
        return r.classification == "malicious"
    return r.classification in (None, "benign")


def summarize(results: list[ScenarioResult]) -> dict[str, Any]:
    agentic = _confusion([(r.label, (r.classification or "benign") in POSITIVE) for r in results])
    baseline = _confusion([(r.label, r.baseline_flagged) for r in results])
    correct = sum(1 for r in results if _classification_correct(r))
    runs = sum(r.playbook_runs for r in results)
    total_alerts = sum(r.alerts for r in results)
    total_cost = sum(r.cost_usd for r in results)
    triage_times = [r.time_to_triage_ms for r in results if r.time_to_triage_ms is not None]
    response_times = [r.time_to_response_ms for r in results if r.time_to_response_ms is not None]
    return {
        "scenarios": len(results),
        "alerts": total_alerts,
        "agentic": {
            **agentic,
            "correct_classifications": correct,
            "correct_actions": sum(1 for r in results if r.action_correct),
            "analyst_interventions": sum(r.approvals_requested for r in results),
            "median_time_to_triage_ms": round(statistics.median(triage_times), 1) if triage_times else None,
            "median_time_to_response_ms": round(statistics.median(response_times), 1) if response_times else None,
            "triage_calls": sum(r.triage_calls for r in results),
            "input_tokens": sum(r.input_tokens for r in results),
            "output_tokens": sum(r.output_tokens for r in results),
            "llm_cost_usd": round(total_cost, 6),
            "llm_cost_per_alert_usd": round(total_cost / total_alerts, 8) if total_alerts else 0.0,
            "automation_success_rate": round(sum(r.playbook_successes for r in results) / runs, 3) if runs else None,
            "audit_chains_valid": all(r.audit_chain_valid for r in results),
        },
        "baseline": {
            **baseline,
            "correct_classifications": sum(1 for r in results if r.baseline_flagged == (r.label == "malicious")),
            "analyst_interventions": sum(r.baseline_alerts_for_human for r in results),
        },
    }


def merge_human_baseline(report: dict[str, Any], csv_path: Path) -> None:
    """Add median human triage/response minutes measured in the lab to the baseline column."""
    triage, response = [], []
    with csv_path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                received = datetime.fromisoformat(row["alert_received_at"])
                if row.get("triage_completed_at"):
                    triage.append((datetime.fromisoformat(row["triage_completed_at"]) - received).total_seconds())
                if row.get("response_completed_at"):
                    response.append((datetime.fromisoformat(row["response_completed_at"]) - received).total_seconds())
            except (KeyError, ValueError):
                continue
    baseline = report["summary"]["baseline"]
    baseline["median_time_to_triage_ms"] = round(statistics.median(triage) * 1000, 1) if triage else None
    baseline["median_time_to_response_ms"] = round(statistics.median(response) * 1000, 1) if response else None


def _fmt(value: Any) -> str:
    if value is None:
        return "Measure"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    a, b = s["agentic"], s["baseline"]
    rows = [
        ("True positives", b["tp"], a["tp"]),
        ("False positives", b["fp"], a["fp"]),
        ("False negatives", b["fn"], a["fn"]),
        ("Triage time (median, ms)", b.get("median_time_to_triage_ms"), a["median_time_to_triage_ms"]),
        ("Response time (median, ms)", b.get("median_time_to_response_ms"), a["median_time_to_response_ms"]),
        ("Correct classifications", b["correct_classifications"], a["correct_classifications"]),
        ("Correct actions", "n/a", a["correct_actions"]),
        ("Analyst interventions", b["analyst_interventions"], a["analyst_interventions"]),
        ("LLM cost (USD)", 0, a["llm_cost_usd"]),
        ("Token usage (in/out)", "0/0", f"{a['input_tokens']}/{a['output_tokens']}"),
        ("Automation success rate", "n/a", a["automation_success_rate"]),
    ]
    lines = [
        f"# Evaluation report - {report['provider']} ({report['model']})",
        "",
        f"Generated {report['generated_at']}; policy `{report['policy_version']}`; "
        f"{s['scenarios']} scenarios, {s['alerts']} alerts; baseline flags incidents with a Wazuh rule "
        f"level >= {report['baseline_alert_level']}; simulated analyst: {report['simulate_analyst']}.",
        "",
        "| Metric | Baseline SOC (Wazuh + human) | Agentic SOC |",
        "|---|---|---|",
        *[f"| {name} | {_fmt(base)} | {_fmt(agent)} |" for name, base, agent in rows],
        "",
        f"Audit chains valid: {a['audit_chains_valid']}. LLM cost per alert: ${a['llm_cost_per_alert_usd']}. "
        "Baseline timings read `Measure` until human timings are merged with `--human-baseline`.",
        "",
        *(
            [
                "> The heuristic arm is a deterministic reference that was written alongside the bundled "
                "synthetic scenarios, so its scores on them are not evidence of real-world accuracy. Use it "
                "as the zero-cost comparison arm and replay alerts captured from your lab for the study.",
                "",
            ]
            if report["provider"] == "heuristic"
            else []
        ),
        "## Per-scenario results",
        "",
        "| Scenario | Truth | Classification | Risk | Policy | Action | Action OK | Approvals | Runs | Triage calls |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in report["scenarios"]:
        lines.append(
            f"| {r['scenario']} | {r['label']} | {r['classification']} | {r['risk_score']} | "
            f"{r['policy_outcome']} | {r['action']} | {r['action_correct']} | {r['approvals_requested']} | "
            f"{r['playbook_runs']} | {r['triage_calls']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--provider", choices=["heuristic", "ollama", "cloud", "hybrid"], default="heuristic")
    parser.add_argument("--out", type=Path, default=Path("results/latest"))
    parser.add_argument("--scenarios", type=Path, help="directory of scenario JSON files (default: built-in)")
    parser.add_argument("--policy", type=Path, default=Path("config/policy.yaml"))
    parser.add_argument("--baseline-level", type=int, default=10)
    parser.add_argument("--simulate-analyst", choices=["none", "approve", "reject"], default="none")
    parser.add_argument("--human-baseline", type=Path, help="CSV of human triage/response timings")
    args = parser.parse_args(argv)

    scenarios = load_from_directory(args.scenarios) if args.scenarios else None
    report = run(args.out, args.provider, scenarios, args.policy, args.baseline_level, args.simulate_analyst)
    if args.human_baseline:
        merge_human_baseline(report, args.human_baseline)
        (args.out / "metrics.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        (args.out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    print(render_markdown(report))
    print(f"Results written to {args.out}/ (metrics.json, scenarios.csv, report.md)")


if __name__ == "__main__":
    main()
