"""Hash-chained audit trail.

Every incident has its own chain: ALERT -> ENRICHMENT -> LLM_INPUT -> LLM_OUTPUT ->
POLICY_DECISION -> HUMAN_DECISION -> ACTION -> RESULT. Each event stores the SHA-256 of
its own content plus the previous event's hash, so editing or deleting a row breaks
verification. This makes it possible to reconstruct *why* a response occurred.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentic_soc.database.models import AuditEvent

GENESIS = "0" * 64


class AuditStage(StrEnum):
    ALERT = "ALERT"
    ENRICHMENT = "ENRICHMENT"
    LLM_INPUT = "LLM_INPUT"
    LLM_OUTPUT = "LLM_OUTPUT"
    POLICY_DECISION = "POLICY_DECISION"
    HUMAN_DECISION = "HUMAN_DECISION"
    ACTION = "ACTION"
    RESULT = "RESULT"


def to_jsonable(payload: Any) -> Any:
    """Round-trip through JSON so what is hashed is exactly what is stored."""
    return json.loads(json.dumps(payload, default=str))


def _digest(incident_id: int, seq: int, stage: str, actor: str, ts: str, payload: Any, prev: str) -> str:
    body = json.dumps(
        {
            "incident_id": incident_id,
            "seq": seq,
            "stage": stage,
            "actor": actor,
            "ts": ts,
            "payload": payload,
            "prev_hash": prev,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode()).hexdigest()


def append_event(
    session: Session, incident_id: int, stage: AuditStage, payload: dict[str, Any], actor: str = "system"
) -> AuditEvent:
    last = session.execute(
        select(AuditEvent).where(AuditEvent.incident_id == incident_id).order_by(AuditEvent.seq.desc()).limit(1)
    ).scalar_one_or_none()
    seq = (last.seq + 1) if last else 1
    prev = last.hash if last else GENESIS
    ts = datetime.now(UTC).isoformat()
    data = to_jsonable(payload)
    event = AuditEvent(
        incident_id=incident_id,
        seq=seq,
        stage=stage.value,
        actor=actor,
        payload=data,
        ts=ts,
        prev_hash=prev,
        hash=_digest(incident_id, seq, stage.value, actor, ts, data, prev),
    )
    session.add(event)
    session.flush()
    return event


@dataclass
class ChainVerification:
    valid: bool
    events: int
    broken_at_seq: int | None = None
    detail: str = "ok"


def verify_chain(session: Session, incident_id: int) -> ChainVerification:
    events = session.execute(
        select(AuditEvent).where(AuditEvent.incident_id == incident_id).order_by(AuditEvent.seq)
    ).scalars()
    prev = GENESIS
    count = 0
    for expected_seq, event in enumerate(events, start=1):
        count += 1
        if event.seq != expected_seq:
            return ChainVerification(False, count, event.seq, "sequence gap (event deleted?)")
        if event.prev_hash != prev:
            return ChainVerification(False, count, event.seq, "previous-hash mismatch")
        digest = _digest(
            event.incident_id, event.seq, event.stage, event.actor, event.ts, event.payload, event.prev_hash
        )
        if digest != event.hash:
            return ChainVerification(False, count, event.seq, "content hash mismatch (event modified)")
        prev = event.hash
    return ChainVerification(True, count)


def count_events(session: Session, incident_id: int) -> int:
    return session.execute(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.incident_id == incident_id)
    ).scalar_one()
