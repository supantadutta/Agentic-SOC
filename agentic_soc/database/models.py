"""PostgreSQL research database (blueprint section 18).

Tables: incidents, alerts, entities, hosts, users, iocs, llm_decisions, agent_actions,
playbook_runs, human_approvals and audit_events. SQLite is supported for tests and
offline evaluation runs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Stores naive UTC and always returns timezone-aware UTC, on SQLite and PostgreSQL alike."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON, datetime: UTCDateTime}


alert_entities = Table(
    "alert_entities",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("entity_id", ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    severity: Mapped[str | None] = mapped_column(String(32))
    classification: Mapped[str | None] = mapped_column(String(32))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[float | None] = mapped_column(Float)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    last_triaged_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    triaged_max_level: Mapped[int] = mapped_column(Integer, default=0)
    triaged_tactics: Mapped[list[Any]] = mapped_column(JSON, default=list)
    max_rule_level: Mapped[int] = mapped_column(Integer, default=0)
    tactics: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # Analyst ground truth, used by the evaluation (true_positive / false_positive / benign).
    disposition: Mapped[str | None] = mapped_column(String(32))
    disposition_by: Mapped[str | None] = mapped_column(String(128))
    disposition_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    alerts: Mapped[list[Alert]] = relationship(back_populates="incident", order_by="Alert.timestamp")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    wazuh_id: Mapped[str | None] = mapped_column(String(128), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    source: Mapped[str] = mapped_column(String(32), default="wazuh")
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_level: Mapped[int] = mapped_column(Integer, default=0)
    rule_description: Mapped[str] = mapped_column(Text, default="")
    rule_groups: Mapped[list[Any]] = mapped_column(JSON, default=list)
    mitre_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    agent_id: Mapped[str | None] = mapped_column(String(32))
    agent_name: Mapped[str | None] = mapped_column(String(255))
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    last_duplicate_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSON)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    incident: Mapped[Incident | None] = relationship(back_populates="alerts")
    entities: Mapped[list[EntityRecord]] = relationship(secondary=alert_entities)


class EntityRecord(Base):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_entity_type_value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(1024), index=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    os: Mapped[str | None] = mapped_column(String(64))
    criticality: Mapped[str] = mapped_column(String(16), default="normal")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(1024), unique=True)
    ioc_type: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[str] = mapped_column(String(32), default="unknown")
    score: Mapped[float | None] = mapped_column(Float)
    sources: Mapped[list[Any]] = mapped_column(JSON, default=list)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sightings: Mapped[int] = mapped_column(Integer, default=0)
    last_checked: Mapped[datetime] = mapped_column(UTCDateTime)


class LLMDecision(Base):
    """One AI decision. Retains model/provider, prompt version, structured response,
    confidence, recommended action, approval and execution state, and timestamp."""

    __tablename__ = "llm_decisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"))
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64))
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    structured_response: Mapped[dict[str, Any]] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float)
    classification: Mapped[str] = mapped_column(String(32))
    recommended_action: Mapped[str] = mapped_column(String(32))
    requires_human_approval: Mapped[bool] = mapped_column(Boolean)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    policy_outcome: Mapped[str | None] = mapped_column(String(32))
    approval_state: Mapped[str] = mapped_column(String(32), default="not_required")
    execution_state: Mapped[str] = mapped_column(String(32), default="not_executed")
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    fallback_used: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_notes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AgentAction(Base):
    __tablename__ = "agent_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    agent: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class HumanApproval(Base):
    __tablename__ = "human_approvals"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    llm_decision_id: Mapped[int | None] = mapped_column(ForeignKey("llm_decisions.id"))
    kind: Mapped[str] = mapped_column(String(16))  # optional | required | review
    action: Mapped[str] = mapped_column(String(32))
    targets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    policy_outcome: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    analyst: Mapped[str | None] = mapped_column(String(128))
    comment: Mapped[str | None] = mapped_column(Text)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    approval_id: Mapped[int | None] = mapped_column(ForeignKey("human_approvals.id"))
    llm_decision_id: Mapped[int | None] = mapped_column(ForeignKey("llm_decisions.id"))
    playbook: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    targets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    mode: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    steps: Mapped[list[Any]] = mapped_column(JSON, default=list)
    output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    triggered_by: Mapped[str] = mapped_column(String(128))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuditEvent(Base):
    """Append-only, hash-chained audit trail (blueprint section 19)."""

    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("incident_id", "seq", name="uq_audit_incident_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    ts: Mapped[str] = mapped_column(String(64))  # ISO-8601 UTC, part of the hashed content
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
