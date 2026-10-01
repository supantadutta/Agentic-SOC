"""Agentic SOC orchestrator (blueprint section 13).

    Wazuh alert -> normalize -> deduplicate -> correlate -> retrieve related alerts
    -> threat-intelligence enrichment (MISP, VirusTotal, MITRE ATT&CK)
    -> build incident context -> LLM triage -> risk + confidence -> policy engine
    -> log/recommend | analyst approval | predefined automation | human review

Every stage is written to the hash-chained audit trail.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_soc.agents import (
    CorrelationAgent,
    InvestigationAgent,
    ResponseAgent,
    ThreatIntelAgent,
    TriageAgent,
)
from agentic_soc.agents.enrichment_agent import ThreatIntelSource
from agentic_soc.config.settings import Settings
from agentic_soc.database.audit import AuditStage, append_event
from agentic_soc.database.models import (
    IOC,
    AgentAction,
    Alert,
    EntityRecord,
    Host,
    HumanApproval,
    Incident,
    LLMDecision,
    PlaybookRun,
    User,
)
from agentic_soc.database.session import Database
from agentic_soc.integrations.mitre import AttackKnowledgeBase
from agentic_soc.integrations.wazuh import (
    NetworkClassifier,
    alert_fingerprint,
    normalize_wazuh_alert,
)
from agentic_soc.llm.base import LLMProvider, LLMResult
from agentic_soc.models.schemas import (
    NON_EXECUTABLE_ACTIONS,
    AlertSummary,
    Entity,
    EntityType,
    IncidentContext,
    NormalizedAlert,
    PlaybookResult,
    PlaybookStatus,
    PolicyOutcome,
    ResponseAction,
    ThreatIntelResult,
    ThreatIntelVerdict,
)
from agentic_soc.pipeline.notifier import Notifier
from agentic_soc.playbooks import build_playbooks
from agentic_soc.playbooks.base import PlaybookContext, ResponseServices
from agentic_soc.policy.policy_engine import PolicyEngine

log = logging.getLogger(__name__)

APPROVAL_KIND = {
    PolicyOutcome.RECOMMEND: "optional",
    PolicyOutcome.REQUIRE_APPROVAL: "required",
    PolicyOutcome.HUMAN_REVIEW: "review",
}
CONTAINMENT_ACTIONS = {ResponseAction.ISOLATE_HOST, ResponseAction.BLOCK_IP, ResponseAction.DISABLE_USER}
MAX_CONTEXT_ENTITIES = 50


class OrchestratorError(RuntimeError):
    pass


@dataclass
class ProcessingOutcome:
    status: str  # duplicate | stored | correlated | triaged
    alert_id: int | None = None
    incident_id: int | None = None
    created_incident: bool = False
    duplicate_of: int | None = None
    llm_decision_id: int | None = None
    policy_outcome: str | None = None
    action: str | None = None
    targets: list[str] = field(default_factory=list)
    approval_id: int | None = None
    playbook_run_id: int | None = None
    playbook_status: str | None = None
    processing_ms: float = 0.0
    notes: list[str] = field(default_factory=list)


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[:limit] + f"...[truncated {len(value) - limit} chars]"


class SOCOrchestrator:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        policy: PolicyEngine,
        attack_kb: AttackKnowledgeBase,
        classifier: NetworkClassifier,
        triage: TriageAgent,
        investigation: InvestigationAgent,
        threat_intel: ThreatIntelAgent,
        correlation: CorrelationAgent,
        response: ResponseAgent,
        notifier: Notifier | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.policy = policy
        self.attack_kb = attack_kb
        self.classifier = classifier
        self.triage_agent = triage
        self.investigation_agent = investigation
        self.threat_intel_agent = threat_intel
        self.correlation_agent = correlation
        self.response_agent = response
        self.notifier = notifier or Notifier(None)
        # Serializes database-mutating stages (alert processing vs. analyst decisions).
        # The LLM call itself runs outside the lock.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------------------------------
    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        provider: LLMProvider | None = None,
        ti_sources: list[ThreatIntelSource] | None = None,
        db: Database | None = None,
        policy: PolicyEngine | None = None,
    ) -> SOCOrchestrator:
        from agentic_soc.integrations.misp import MISPClient
        from agentic_soc.integrations.opnsense import OPNsenseClient
        from agentic_soc.integrations.virustotal import VirusTotalClient
        from agentic_soc.integrations.wazuh import WazuhAPIClient, WazuhIndexerClient
        from agentic_soc.llm.providers import build_provider

        s = settings
        db = db or Database(s.database_url)
        db.create_all()
        policy = policy or PolicyEngine.load(s.policy_file)
        attack_kb = AttackKnowledgeBase.load(s.attack_data_path)
        classifier = NetworkClassifier(policy.config.network.internal_cidrs)

        wazuh = indexer = opnsense = None
        if s.wazuh_api_url and s.wazuh_api_user and s.wazuh_api_password:
            wazuh = WazuhAPIClient(
                s.wazuh_api_url,
                s.wazuh_api_user,
                s.wazuh_api_password.get_secret_value(),
                verify=s.tls,
                timeout=s.http_timeout_seconds,
            )
        if s.wazuh_indexer_url and s.wazuh_indexer_user and s.wazuh_indexer_password:
            indexer = WazuhIndexerClient(
                s.wazuh_indexer_url,
                s.wazuh_indexer_user,
                s.wazuh_indexer_password.get_secret_value(),
                verify=s.tls,
                timeout=s.http_timeout_seconds,
            )
        if s.opnsense_url and s.opnsense_api_key and s.opnsense_api_secret:
            opnsense = OPNsenseClient(
                s.opnsense_url,
                s.opnsense_api_key.get_secret_value(),
                s.opnsense_api_secret.get_secret_value(),
                verify=s.tls,
                timeout=s.http_timeout_seconds,
            )
        if ti_sources is None:
            ti_sources = []
            if s.misp_url and s.misp_api_key:
                ti_sources.append(
                    MISPClient(
                        s.misp_url, s.misp_api_key.get_secret_value(), verify=s.tls, timeout=s.http_timeout_seconds
                    )
                )
            if s.virustotal_api_key:
                ti_sources.append(
                    VirusTotalClient(
                        s.virustotal_api_key.get_secret_value(),
                        per_minute=s.virustotal_requests_per_minute,
                        per_day=s.virustotal_daily_quota,
                        timeout=s.http_timeout_seconds,
                    )
                )

        services = ResponseServices(settings=s, policy=policy, wazuh=wazuh, indexer=indexer, opnsense=opnsense)
        ignore = {v for v in policy.config.network.never_block if "/" not in v}
        return cls(
            settings=s,
            db=db,
            policy=policy,
            attack_kb=attack_kb,
            classifier=classifier,
            triage=TriageAgent(provider or build_provider(s), attack_kb),
            investigation=InvestigationAgent(indexer),
            threat_intel=ThreatIntelAgent(
                ti_sources,
                attack_kb,
                classifier,
                s.max_ti_lookups_per_incident,
                s.ioc_cache_hours,
                s.internal_domain_suffixes,
            ),
            correlation=CorrelationAgent(s.correlation_window_minutes, ignore),
            response=ResponseAgent(policy, build_playbooks(services)),
            notifier=Notifier(s.notify_webhook_url),
        )

    # ------------------------------------------------------------------------------------------
    # alert processing
    # ------------------------------------------------------------------------------------------
    def process_wazuh_alert(self, raw: dict[str, Any]) -> ProcessingOutcome:
        start = time.perf_counter()
        normalized = normalize_wazuh_alert(raw, self.classifier)
        with self._lock:
            outcome, context = self._ingest(raw, normalized)
        if context is None:
            outcome.processing_ms = (time.perf_counter() - start) * 1000
            return outcome

        result = self.triage_agent.triage(context)  # LLM call, outside the lock

        with self._lock:
            self._decide(outcome, context, result)
        outcome.processing_ms = (time.perf_counter() - start) * 1000
        self._notify(outcome)
        return outcome

    def _ingest(self, raw: dict[str, Any], alert: NormalizedAlert) -> tuple[ProcessingOutcome, IncidentContext | None]:
        with self.db.session() as session:
            duplicate = self._find_duplicate(session, alert)
            if duplicate is not None:
                duplicate.duplicate_count += 1
                duplicate.last_duplicate_at = max(duplicate.last_duplicate_at or duplicate.timestamp, alert.timestamp)
                if duplicate.incident is not None:
                    duplicate.incident.last_seen = max(duplicate.incident.last_seen, alert.timestamp)
                return ProcessingOutcome(
                    status="duplicate",
                    alert_id=duplicate.id,
                    incident_id=duplicate.incident_id,
                    duplicate_of=duplicate.id,
                ), None

            alert_row = self._store_alert(session, raw, alert)
            incident, created, shared = self.correlation_agent.attach(session, alert_row, alert)
            alerts = list(incident.alerts)
            tactics = self.correlation_agent.update_tactics(incident, alerts, self.attack_kb)
            outcome = ProcessingOutcome(
                status="stored", alert_id=alert_row.id, incident_id=incident.id, created_incident=created
            )
            append_event(
                session,
                incident.id,
                AuditStage.ALERT,
                {
                    "alert_id": alert_row.id,
                    "wazuh_id": alert.wazuh_id,
                    "rule_id": alert.rule_id,
                    "level": alert.rule_level,
                    "description": alert.rule_description,
                    "source": alert.source,
                    "incident_created": created,
                    "correlated_on": shared,
                    "tactics": tactics,
                },
            )
            self._record_agent(
                session,
                incident.id,
                "correlation",
                "attach_alert",
                {"alert_id": alert_row.id, "created": created, "shared_entities": shared},
            )

            if alert.rule_level < self.settings.min_rule_level_for_triage:
                outcome.notes.append(f"rule level {alert.rule_level} below triage threshold")
                return outcome, None
            skip_reason = self._retriage_skip_reason(incident, alert, tactics)
            if skip_reason and self._new_threat_intel_hit(session, alerts, alert_row, alert):
                skip_reason = None
                outcome.notes.append("re-triage: new indicator with a malicious/suspicious threat-intel verdict")
            if skip_reason:
                outcome.status = "correlated"
                outcome.notes.append(skip_reason)
                return outcome, None

            context = self._build_context(session, incident, alerts, alert)
            append_event(
                session,
                incident.id,
                AuditStage.ENRICHMENT,
                {
                    "threat_intel": [t.model_dump(mode="json") for t in context.threat_intel],
                    "attack_techniques": [t.id for t in context.attack_techniques],
                    "related_history": context.related_history,
                    "narrative": context.narrative,
                },
            )
            return outcome, context

    def _find_duplicate(self, session: Session, alert: NormalizedAlert) -> Alert | None:
        if alert.wazuh_id:
            same_id = session.execute(
                select(Alert).where(Alert.wazuh_id == alert.wazuh_id).limit(1)
            ).scalar_one_or_none()
            if same_id is not None:
                return same_id
        window = timedelta(seconds=self.settings.dedup_window_seconds)
        candidate = session.execute(
            select(Alert)
            .where(Alert.fingerprint == alert_fingerprint(alert))
            .where(Alert.timestamp >= alert.timestamp - window - timedelta(days=1))
            .order_by(Alert.timestamp.desc())
            .limit(1)
        ).scalar_one_or_none()
        if candidate is None:
            return None
        last = candidate.last_duplicate_at or candidate.timestamp
        if abs(alert.timestamp - last) <= window or abs(alert.timestamp - candidate.timestamp) <= window:
            return candidate
        return None

    def _store_alert(self, session: Session, raw: dict[str, Any], alert: NormalizedAlert) -> Alert:
        row = Alert(
            wazuh_id=alert.wazuh_id,
            fingerprint=alert_fingerprint(alert),
            timestamp=alert.timestamp,
            source=alert.source,
            rule_id=alert.rule_id,
            rule_level=alert.rule_level,
            rule_description=alert.rule_description,
            rule_groups=alert.rule_groups,
            mitre_ids=alert.mitre_ids,
            agent_id=alert.agent_id,
            agent_name=alert.agent_name,
            normalized=alert.model_dump(mode="json"),
            raw=raw,
        )
        session.add(row)
        for entity in alert.entities:
            row.entities.append(self._upsert_entity(session, entity, alert.timestamp))
            if entity.type == EntityType.HOST:
                self._upsert_host(session, entity, alert)
            elif entity.type == EntityType.USER:
                self._upsert_user(session, entity.value, alert.timestamp)
        session.flush()
        return row

    @staticmethod
    def _upsert_entity(session: Session, entity: Entity, seen: datetime) -> EntityRecord:
        record = session.execute(
            select(EntityRecord)
            .where(EntityRecord.type == entity.type.value)
            .where(func.lower(EntityRecord.value) == entity.value.lower())
        ).scalar_one_or_none()
        if record is None:
            record = EntityRecord(
                type=entity.type.value,
                value=entity.value,
                attributes=entity.attributes,
                first_seen=seen,
                last_seen=seen,
            )
            session.add(record)
        else:
            record.last_seen = max(record.last_seen, seen)
            record.attributes = {**(record.attributes or {}), **entity.attributes}
        session.flush()
        return record

    @staticmethod
    def _upsert_host(session: Session, entity: Entity, alert: NormalizedAlert) -> None:
        agent_id = entity.attributes.get("agent_id")
        query = (
            select(Host).where(Host.agent_id == agent_id)
            if agent_id
            else select(Host).where(func.lower(Host.name) == entity.value.lower())
        )
        host = session.execute(query).scalar_one_or_none()
        if host is None:
            session.add(
                Host(
                    agent_id=agent_id,
                    name=entity.value,
                    ip=entity.attributes.get("ip"),
                    first_seen=alert.timestamp,
                    last_seen=alert.timestamp,
                )
            )
        else:
            host.last_seen = max(host.last_seen, alert.timestamp)
            host.ip = entity.attributes.get("ip") or host.ip
        session.flush()

    def _upsert_user(self, session: Session, name: str, seen: datetime) -> None:
        user = session.execute(select(User).where(func.lower(User.name) == name.lower())).scalar_one_or_none()
        if user is None:
            session.add(
                User(name=name, privileged=self.policy.is_protected_user(name), first_seen=seen, last_seen=seen)
            )
        else:
            user.last_seen = max(user.last_seen, seen)
        session.flush()

    def _retriage_skip_reason(self, incident: Incident, alert: NormalizedAlert, tactics: list[str]) -> str | None:
        """Cost control: re-run the LLM on a known incident only when something material changed."""
        if incident.last_triaged_at is None:
            return None
        if alert.rule_level > (incident.triaged_max_level or 0):
            return None
        if set(tactics) - set(incident.triaged_tactics or []):
            return None
        elapsed = (alert.timestamp - incident.last_triaged_at).total_seconds()
        if elapsed >= self.settings.retriage_cooldown_seconds:
            return None
        return (
            f"re-triage skipped: no new tactic or higher level within "
            f"{self.settings.retriage_cooldown_seconds}s cooldown"
        )

    def _new_threat_intel_hit(
        self, session: Session, alerts: list[Alert], alert_row: Alert, alert: NormalizedAlert
    ) -> bool:
        """Enrich only the indicators this alert adds to the incident (cached, so cheap)."""
        known = {e.key for e in self._incident_entities([a for a in alerts if a.id != alert_row.id])}
        new = [e for e in alert.entities if e.key not in known]
        if not new:
            return False
        results, _ = self.threat_intel_agent.enrich(session, new, [])
        return any(r.verdict in (ThreatIntelVerdict.MALICIOUS, ThreatIntelVerdict.SUSPICIOUS) for r in results)

    def _incident_entities(self, alerts: list[Alert]) -> list[Entity]:
        entities: dict[tuple[str, str], Entity] = {}
        for alert in alerts:
            for item in alert.normalized.get("entities", []):
                entity = Entity.model_validate(item)
                entities.setdefault(entity.key, entity)
        return list(entities.values())[:MAX_CONTEXT_ENTITIES]

    def _build_context(
        self, session: Session, incident: Incident, alerts: list[Alert], trigger: NormalizedAlert
    ) -> IncidentContext:
        limit, chars = self.settings.max_alerts_in_prompt, self.settings.max_field_chars
        selected = alerts
        if len(alerts) > limit:
            selected = sorted(alerts, key=lambda a: (a.rule_level, a.timestamp), reverse=True)[:limit]
            selected.sort(key=lambda a: a.timestamp)
        summaries = []
        for alert in selected:
            n = alert.normalized
            summaries.append(
                AlertSummary(
                    timestamp=alert.timestamp,
                    rule_id=alert.rule_id,
                    level=alert.rule_level,
                    description=_truncate(alert.rule_description, chars) or "",
                    groups=alert.rule_groups or [],
                    mitre=alert.mitre_ids or [],
                    host=alert.agent_name if alert.source not in ("suricata", "zeek") else None,
                    src_ip=n.get("src_ip"),
                    dst_ip=n.get("dst_ip"),
                    user=n.get("user"),
                    process=_truncate(n.get("process"), chars),
                    command_line=_truncate(n.get("command_line"), chars),
                    url=_truncate(n.get("url"), chars),
                    domain=n.get("domain"),
                    signature=_truncate(n.get("signature"), chars),
                    duplicates=alert.duplicate_count,
                )
            )
        entities = self._incident_entities(alerts)
        technique_ids = sorted({t for a in alerts for t in (a.mitre_ids or [])})

        t0 = time.perf_counter()
        threat_intel, techniques = self.threat_intel_agent.enrich(session, entities, technique_ids)
        self._record_agent(
            session,
            incident.id,
            "threat_intel",
            "enrich",
            {"lookups": len(threat_intel), "cached": sum(t.cached for t in threat_intel)},
            (time.perf_counter() - t0) * 1000,
        )
        t0 = time.perf_counter()
        related = self.investigation_agent.investigate(session, incident.id, trigger)
        self._record_agent(
            session,
            incident.id,
            "investigation",
            "related_context",
            {k: len(v) for k, v in related.items()},
            (time.perf_counter() - t0) * 1000,
        )
        history = [{"type": "related_incident", **r} for r in related["related_incidents"]]
        history += [{"type": "siem_alert", **r} for r in related["siem_related_alerts"]]
        return IncidentContext(
            incident_id=incident.id,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            alert_count=len(alerts) + sum(a.duplicate_count for a in alerts),
            alerts=summaries,
            alerts_truncated=len(selected) < len(alerts),
            max_rule_level=incident.max_rule_level,
            entities=entities,
            threat_intel=threat_intel,
            attack_techniques=techniques,
            related_history=history,
            narrative=self.correlation_agent.narrative(incident, alerts),
        )

    def _decide(self, outcome: ProcessingOutcome, context: IncidentContext, result: LLMResult) -> None:
        decision = result.decision
        with self.db.session() as session:
            incident = session.get(Incident, context.incident_id)
            if incident is None:
                raise OrchestratorError(f"incident {context.incident_id} vanished")
            append_event(
                session,
                incident.id,
                AuditStage.LLM_INPUT,
                {
                    "provider": result.provider,
                    "model": result.model,
                    "prompt_version": result.prompt_version,
                    "prompt_sha256": result.prompt_sha256,
                    "user_prompt": result.user_prompt,
                },
            )
            append_event(
                session,
                incident.id,
                AuditStage.LLM_OUTPUT,
                {
                    "decision": decision.model_dump(mode="json"),
                    "raw_output": result.raw_output[:8000],
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "latency_ms": round(result.latency_ms, 1),
                    "cost_usd": result.cost_usd,
                    "escalated": result.escalated,
                    "fallback_used": result.fallback_used,
                    "notes": result.notes,
                },
            )
            self._record_agent(
                session,
                incident.id,
                "triage",
                "triage",
                {"provider": result.provider, "model": result.model, "classification": decision.classification.value},
                result.latency_ms,
            )

            recent_auto = session.execute(
                select(func.count(PlaybookRun.id))
                .where(PlaybookRun.triggered_by == "policy:auto")
                .where(PlaybookRun.started_at >= datetime.now(UTC) - timedelta(hours=1))
            ).scalar_one()
            policy_decision, target_notes = self.response_agent.plan(
                decision, context, fallback_used=result.fallback_used, recent_auto_actions=recent_auto
            )
            llm_row = LLMDecision(
                incident_id=incident.id,
                alert_id=outcome.alert_id,
                provider=result.provider,
                model=result.model,
                prompt_version=result.prompt_version,
                prompt_sha256=result.prompt_sha256,
                structured_response=decision.model_dump(mode="json"),
                severity=decision.severity.value,
                confidence=decision.confidence,
                classification=decision.classification.value,
                recommended_action=decision.recommended_action.value,
                requires_human_approval=decision.requires_human_approval,
                risk_score=policy_decision.risk_score,
                policy_outcome=policy_decision.outcome.value,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                latency_ms=result.latency_ms,
                cost_usd=result.cost_usd,
                escalated=result.escalated,
                fallback_used=result.fallback_used,
                validation_notes=result.notes + target_notes,
            )
            session.add(llm_row)
            session.flush()
            append_event(
                session,
                incident.id,
                AuditStage.POLICY_DECISION,
                {
                    "llm_decision_id": llm_row.id,
                    **policy_decision.model_dump(mode="json"),
                    "target_notes": target_notes,
                },
            )
            self._record_agent(
                session,
                incident.id,
                "response",
                "plan",
                {
                    "outcome": policy_decision.outcome.value,
                    "action": policy_decision.action.value,
                    "targets": policy_decision.targets,
                },
            )

            incident.severity = decision.severity.value
            incident.classification = decision.classification.value
            incident.confidence = decision.confidence
            incident.risk_score = policy_decision.risk_score
            incident.last_triaged_at = context.last_seen
            incident.triaged_max_level = incident.max_rule_level
            incident.triaged_tactics = list(incident.tactics or [])
            self._supersede_pending(session, incident.id)

            outcome.status = "triaged"
            outcome.llm_decision_id = llm_row.id
            outcome.policy_outcome = policy_decision.outcome.value
            outcome.action = policy_decision.action.value
            outcome.targets = policy_decision.targets
            outcome.notes.extend(result.notes + target_notes)

            if policy_decision.outcome in APPROVAL_KIND and (
                policy_decision.outcome == PolicyOutcome.HUMAN_REVIEW
                or policy_decision.action not in NON_EXECUTABLE_ACTIONS
            ):
                approval = HumanApproval(
                    incident_id=incident.id,
                    llm_decision_id=llm_row.id,
                    kind=APPROVAL_KIND[policy_decision.outcome],
                    action=policy_decision.action.value,
                    targets=policy_decision.targets,
                    risk_score=policy_decision.risk_score,
                    confidence=decision.confidence,
                    policy_outcome=policy_decision.outcome.value,
                    reasons=policy_decision.reasons,
                )
                session.add(approval)
                session.flush()
                llm_row.approval_state = "pending"
                incident.status = "awaiting_approval"
                outcome.approval_id = approval.id
            elif policy_decision.outcome == PolicyOutcome.AUTO_EXECUTE:
                run = self._run_playbook(
                    session,
                    incident,
                    policy_decision.action,
                    policy_decision.targets,
                    triggered_by="policy:auto",
                    llm_row=llm_row,
                    policy_outcome=policy_decision.outcome.value,
                )
                outcome.playbook_run_id = run.id
                outcome.playbook_status = run.status

    def _supersede_pending(self, session: Session, incident_id: int) -> None:
        pending = session.execute(
            select(HumanApproval)
            .where(HumanApproval.incident_id == incident_id)
            .where(HumanApproval.status == "pending")
        ).scalars()
        for approval in pending:
            approval.status = "superseded"
            approval.decided_at = datetime.now(UTC)
            approval.comment = "superseded by a newer triage of the same incident"

    def _threat_intel_for(self, session: Session, entities: list[Entity]) -> list[ThreatIntelResult]:
        values = [e.value for e in entities]
        if not values:
            return []
        rows = session.execute(select(IOC).where(IOC.indicator.in_(values))).scalars()
        return [ThreatIntelResult.model_validate(r) for row in rows for r in row.details.get("results", [])]

    def _run_playbook(
        self,
        session: Session,
        incident: Incident,
        action: ResponseAction,
        targets: list[str],
        *,
        triggered_by: str,
        llm_row: LLMDecision | None,
        policy_outcome: str,
        approval: HumanApproval | None = None,
        analyst: str | None = None,
    ) -> PlaybookRun:
        alerts = list(incident.alerts)
        entities = self._incident_entities(alerts)
        decisions = session.execute(
            select(LLMDecision).where(LLMDecision.incident_id == incident.id).order_by(LLMDecision.id)
        ).scalars()
        ctx = PlaybookContext(
            incident_id=incident.id,
            mode=self.settings.execution_mode,
            entities=entities,
            threat_intel=self._threat_intel_for(session, entities),
            alerts=[a.normalized | {"rule_groups": a.rule_groups, "rule_id": a.rule_id} for a in alerts],
            approved_by=analyst,
            policy_outcome=policy_outcome,
            reason=(llm_row.structured_response.get("reason", "") if llm_row else ""),
            extra={"decisions": [d.structured_response | {"id": d.id, "model": d.model} for d in decisions]},
        )
        append_event(
            session,
            incident.id,
            AuditStage.ACTION,
            {
                "action": action.value,
                "targets": targets,
                "mode": ctx.mode,
                "triggered_by": triggered_by,
                "approval_id": approval.id if approval else None,
            },
            actor=triggered_by,
        )
        t0 = time.perf_counter()
        result = self.response_agent.execute(action, targets, ctx)
        run = self._store_run(session, incident, result, ctx.mode, triggered_by, llm_row, approval)
        self._record_agent(
            session,
            incident.id,
            "response",
            f"playbook:{result.playbook}",
            {"run_id": run.id, "status": run.status},
            (time.perf_counter() - t0) * 1000,
        )
        if llm_row is not None:
            llm_row.execution_state = result.status.value
        if result.status in (PlaybookStatus.SUCCESS, PlaybookStatus.DRY_RUN) and action in CONTAINMENT_ACTIONS:
            incident.status = "contained"
        elif incident.status == "awaiting_approval":
            incident.status = "open"
        return run

    @staticmethod
    def _store_run(
        session: Session,
        incident: Incident,
        result: PlaybookResult,
        mode: str,
        triggered_by: str,
        llm_row: LLMDecision | None,
        approval: HumanApproval | None,
    ) -> PlaybookRun:
        run = PlaybookRun(
            incident_id=incident.id,
            approval_id=approval.id if approval else None,
            llm_decision_id=llm_row.id if llm_row else None,
            playbook=result.playbook,
            action=result.action.value,
            targets=result.targets,
            mode=mode,
            status=result.status.value,
            steps=[s.model_dump(mode="json") for s in result.steps],
            output=result.output,
            triggered_by=triggered_by,
            finished_at=datetime.now(UTC),
        )
        session.add(run)
        session.flush()
        append_event(
            session,
            incident.id,
            AuditStage.RESULT,
            {
                "playbook_run_id": run.id,
                "playbook": result.playbook,
                "status": result.status.value,
                "steps": run.steps,
                "output": result.output,
            },
            actor=triggered_by,
        )
        return run

    @staticmethod
    def _record_agent(
        session: Session, incident_id: int, agent: str, action: str, details: dict[str, Any], duration_ms: float = 0.0
    ) -> None:
        session.add(
            AgentAction(incident_id=incident_id, agent=agent, action=action, details=details, duration_ms=duration_ms)
        )

    def _notify(self, outcome: ProcessingOutcome) -> None:
        if outcome.approval_id or outcome.playbook_run_id:
            self.notifier.send({"event": "incident_update", **outcome.__dict__})

    # ------------------------------------------------------------------------------------------
    # analyst actions
    # ------------------------------------------------------------------------------------------
    def decide_approval(
        self, approval_id: int, analyst: str, approve: bool, comment: str | None = None
    ) -> dict[str, Any]:
        with self._lock, self.db.session() as session:
            approval = session.get(HumanApproval, approval_id)
            if approval is None:
                raise OrchestratorError(f"approval {approval_id} not found")
            if approval.status != "pending":
                raise OrchestratorError(f"approval {approval_id} is already {approval.status}")
            incident = session.get(Incident, approval.incident_id)
            llm_row = session.get(LLMDecision, approval.llm_decision_id) if approval.llm_decision_id else None
            approval.status = "approved" if approve else "rejected"
            approval.decided_at = datetime.now(UTC)
            approval.analyst = analyst
            approval.comment = comment
            if llm_row is not None:
                llm_row.approval_state = approval.status
            append_event(
                session,
                incident.id,
                AuditStage.HUMAN_DECISION,
                {
                    "approval_id": approval.id,
                    "kind": approval.kind,
                    "decision": approval.status,
                    "action": approval.action,
                    "targets": approval.targets,
                    "comment": comment,
                },
                actor=f"analyst:{analyst}",
            )

            response: dict[str, Any] = {
                "approval_id": approval.id,
                "status": approval.status,
                "incident_id": incident.id,
            }
            action = ResponseAction(approval.action)
            if approve and action not in NON_EXECUTABLE_ACTIONS and approval.targets:
                run = self._run_playbook(
                    session,
                    incident,
                    action,
                    list(approval.targets),
                    triggered_by=f"analyst:{analyst}",
                    llm_row=llm_row,
                    policy_outcome=approval.policy_outcome,
                    approval=approval,
                    analyst=analyst,
                )
                response.update({"playbook_run_id": run.id, "playbook_status": run.status})
            else:
                incident.status = "open"
            response["incident_status"] = incident.status
        self.notifier.send({"event": "approval_decided", **response})
        return response

    def rollback_run(self, run_id: int, analyst: str) -> dict[str, Any]:
        with self._lock, self.db.session() as session:
            run = session.get(PlaybookRun, run_id)
            if run is None:
                raise OrchestratorError(f"playbook run {run_id} not found")
            if run.status not in ("success", "dry_run"):
                raise OrchestratorError(f"run {run_id} has status {run.status}; nothing to roll back")
            action = ResponseAction(run.action)
            playbook = self.response_agent.playbooks[action]
            if not playbook.supports_rollback:
                raise OrchestratorError(f"{playbook.name} does not support rollback")
            incident = session.get(Incident, run.incident_id)
            entities = self._incident_entities(list(incident.alerts))
            ctx = PlaybookContext(
                incident_id=incident.id,
                mode=run.mode,
                entities=entities,
                approved_by=analyst,
                extra={"previous_output": run.output},
            )
            actor = f"analyst:{analyst}"
            append_event(
                session,
                incident.id,
                AuditStage.ACTION,
                {"rollback_of": run.id, "action": run.action, "targets": run.targets},
                actor=actor,
            )
            result = self.response_agent.rollback(action, list(run.targets), ctx)
            result.playbook = f"{result.playbook}:rollback"
            rollback = self._store_run(session, incident, result, run.mode, actor, None, None)
            if result.status in (PlaybookStatus.ROLLED_BACK, PlaybookStatus.DRY_RUN):
                run.status = "rolled_back" if run.mode == "live" else run.status
                incident.status = "open"
            return {"rollback_run_id": rollback.id, "status": result.status.value, "incident_id": incident.id}

    def set_disposition(
        self, incident_id: int, disposition: str, analyst: str, comment: str | None = None
    ) -> dict[str, Any]:
        if disposition not in ("true_positive", "false_positive", "benign"):
            raise OrchestratorError("disposition must be true_positive, false_positive or benign")
        with self._lock, self.db.session() as session:
            incident = session.get(Incident, incident_id)
            if incident is None:
                raise OrchestratorError(f"incident {incident_id} not found")
            incident.disposition = disposition
            incident.disposition_by = analyst
            incident.disposition_at = datetime.now(UTC)
            incident.status = "closed"
            self._supersede_pending(session, incident.id)
            append_event(
                session,
                incident.id,
                AuditStage.HUMAN_DECISION,
                {"disposition": disposition, "comment": comment},
                actor=f"analyst:{analyst}",
            )
            return {"incident_id": incident.id, "disposition": disposition, "status": incident.status}
