"""Operational and research metrics computed from the research database."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_soc.database.models import Alert, HumanApproval, Incident, LLMDecision, PlaybookRun


def collect_metrics(session: Session) -> dict[str, Any]:
    alerts = session.execute(select(func.count(Alert.id))).scalar_one()
    duplicates = session.execute(select(func.coalesce(func.sum(Alert.duplicate_count), 0))).scalar_one()
    incidents = session.execute(select(func.count(Incident.id))).scalar_one()
    llm = session.execute(
        select(
            func.count(LLMDecision.id),
            func.coalesce(func.sum(LLMDecision.input_tokens), 0),
            func.coalesce(func.sum(LLMDecision.output_tokens), 0),
            func.coalesce(func.sum(LLMDecision.cost_usd), 0.0),
            func.coalesce(func.avg(LLMDecision.latency_ms), 0.0),
        )
    ).one()
    escalations = session.execute(
        select(func.count(LLMDecision.id)).where(LLMDecision.escalated.is_(True))
    ).scalar_one()
    fallback = session.execute(
        select(func.count(LLMDecision.id)).where(LLMDecision.fallback_used.is_(True))
    ).scalar_one()
    approvals = dict(
        session.execute(select(HumanApproval.status, func.count(HumanApproval.id)).group_by(HumanApproval.status)).all()
    )
    runs = dict(
        session.execute(select(PlaybookRun.status, func.count(PlaybookRun.id)).group_by(PlaybookRun.status)).all()
    )
    executed = sum(n for s, n in runs.items() if s in ("success", "failed", "dry_run"))
    succeeded = sum(n for s, n in runs.items() if s in ("success", "dry_run"))
    total_alerts_seen = alerts + duplicates
    return {
        "alerts_received": total_alerts_seen,
        "alerts_unique": alerts,
        "alerts_deduplicated": duplicates,
        "incidents": incidents,
        "triage_calls": llm[0],
        "triage_calls_avoided": max(0, total_alerts_seen - llm[0]),
        "input_tokens": llm[1],
        "output_tokens": llm[2],
        "llm_cost_usd": round(float(llm[3]), 6),
        "llm_cost_per_alert_usd": round(float(llm[3]) / total_alerts_seen, 8) if total_alerts_seen else 0.0,
        "avg_llm_latency_ms": round(float(llm[4]), 1),
        "escalations": escalations,
        "fallback_decisions": fallback,
        "approvals": approvals,
        "playbook_runs": runs,
        "automation_success_rate": round(succeeded / executed, 3) if executed else None,
    }
