"""Correlation Agent: multiple alerts -> incident with an incident-level narrative.

An alert joins an open incident when they share a correlatable entity (host, user, hash,
domain, URL or a non-infrastructure IP) inside the correlation window. Windows are
computed from alert timestamps, so replays and evaluations are deterministic.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_soc.database.models import Alert, EntityRecord, Incident, alert_entities
from agentic_soc.integrations.mitre import TACTIC_ORDER, AttackKnowledgeBase
from agentic_soc.models.schemas import EntityType, NormalizedAlert

CORRELATABLE = {EntityType.HOST, EntityType.USER, EntityType.HASH, EntityType.DOMAIN, EntityType.URL, EntityType.IP}
OPEN_STATUSES = ("open", "awaiting_approval", "contained")


class CorrelationAgent:
    name = "correlation"

    def __init__(self, window_minutes: int = 60, ignore_values: set[str] | None = None) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.ignore = {v.lower() for v in (ignore_values or set())}

    def correlation_keys(self, alert: NormalizedAlert) -> set[tuple[str, str]]:
        return {
            (e.type.value, e.value.lower())
            for e in alert.entities
            if e.type in CORRELATABLE and e.value.lower() not in self.ignore
        }

    def find_incident(self, session: Session, alert: NormalizedAlert) -> tuple[Incident | None, list[str]]:
        keys = self.correlation_keys(alert)
        if not keys:
            return None, []
        ts = alert.timestamp
        rows = session.execute(
            select(Incident.id, EntityRecord.type, EntityRecord.value)
            .join(Alert, Alert.incident_id == Incident.id)
            .join(alert_entities, alert_entities.c.alert_id == Alert.id)
            .join(EntityRecord, EntityRecord.id == alert_entities.c.entity_id)
            .where(Incident.status.in_(OPEN_STATUSES))
            .where(Incident.last_seen >= ts - self.window)
            .where(Incident.first_seen <= ts + self.window)
        ).all()
        shared: dict[int, set[str]] = {}
        for inc_id, etype, value in rows:
            if (etype, value.lower()) in keys:
                shared.setdefault(inc_id, set()).add(f"{etype}:{value}")
        if not shared:
            return None, []
        best = max(shared, key=lambda i: (len(shared[i]), i))
        return session.get(Incident, best), sorted(shared[best])

    def attach(self, session: Session, alert_row: Alert, alert: NormalizedAlert) -> tuple[Incident, bool, list[str]]:
        incident, shared = self.find_incident(session, alert)
        created = incident is None
        if incident is None:
            subject = alert.agent_name if alert.source not in ("suricata", "zeek") else (alert.src_ip or alert.dst_ip)
            incident = Incident(
                title=f"{alert.rule_description or 'Alert ' + alert.rule_id} ({subject or 'unknown'})"[:512],
                status="open",
                first_seen=alert.timestamp,
                last_seen=alert.timestamp,
                max_rule_level=alert.rule_level,
                tactics=[],
            )
            session.add(incident)
            session.flush()
        else:
            incident.first_seen = min(incident.first_seen, alert.timestamp)
            incident.last_seen = max(incident.last_seen, alert.timestamp)
            incident.max_rule_level = max(incident.max_rule_level, alert.rule_level)
        alert_row.incident_id = incident.id
        session.flush()
        return incident, created, shared

    @staticmethod
    def update_tactics(incident: Incident, alerts: list[Alert], attack_kb: AttackKnowledgeBase) -> list[str]:
        technique_ids = sorted({t for a in alerts for t in (a.mitre_ids or [])})
        incident.tactics = attack_kb.tactics_for(technique_ids)
        return incident.tactics

    @staticmethod
    def narrative(incident: Incident, alerts: list[Alert]) -> str:
        hosts = Counter(a.agent_name for a in alerts if a.agent_name and a.source not in ("suricata", "zeek"))
        sources = Counter(a.source for a in alerts)
        progression = [t for t in TACTIC_ORDER if t in (incident.tactics or [])]
        top_rules = Counter(f"{a.rule_id} ({a.rule_description[:60]})" for a in alerts).most_common(5)
        parts = [
            f"Incident {incident.id}: {len(alerts)} alert(s) from {incident.first_seen.isoformat()} "
            f"to {incident.last_seen.isoformat()}, max Wazuh level {incident.max_rule_level}.",
            f"Telemetry sources: {', '.join(f'{s}={n}' for s, n in sources.items())}.",
        ]
        if hosts:
            parts.append(f"Hosts: {', '.join(h for h, _ in hosts.most_common(5))}.")
        if progression:
            parts.append(f"ATT&CK progression: {' -> '.join(progression)}.")
        parts.append("Top rules: " + "; ".join(f"{r} x{n}" for r, n in top_rules) + ".")
        return " ".join(parts)
