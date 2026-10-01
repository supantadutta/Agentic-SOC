"""Typed data contracts shared by agents, the policy engine, playbooks and the API.

The most important contract is :class:`TriageDecision`: it is the *only* shape an LLM
response may take. The model can choose from an allowlisted set of actions and can never
emit commands, scripts or free-form instructions that are executed.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Classification(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class ResponseAction(StrEnum):
    """Allowlist of response actions. Each non-trivial action maps to one predefined playbook."""

    NONE = "NONE"
    MONITOR = "MONITOR"
    COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    DISABLE_USER = "DISABLE_USER"


NON_EXECUTABLE_ACTIONS = {ResponseAction.NONE, ResponseAction.MONITOR}


class EntityType(StrEnum):
    HOST = "host"
    IP = "ip"
    USER = "user"
    HASH = "hash"
    DOMAIN = "domain"
    URL = "url"
    PROCESS = "process"


class Entity(BaseModel):
    type: EntityType
    value: str
    attributes: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return (self.type.value, self.value.lower())


class NormalizedAlert(BaseModel):
    """Source-agnostic view of a Wazuh alert (Wazuh, Sysmon, Suricata or Zeek origin)."""

    wazuh_id: str | None = None
    timestamp: datetime
    source: str = "wazuh"
    rule_id: str
    rule_level: int = 0
    rule_description: str = ""
    rule_groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_name: str | None = None
    agent_ip: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    user: str | None = None
    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    domain: str | None = None
    file_path: str | None = None
    signature: str | None = None
    entities: list[Entity] = Field(default_factory=list)


class ThreatIntelVerdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"


class ThreatIntelResult(BaseModel):
    indicator: str
    indicator_type: EntityType
    source: str
    verdict: ThreatIntelVerdict = ThreatIntelVerdict.UNKNOWN
    score: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False


class AttackTechnique(BaseModel):
    id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None


class AlertSummary(BaseModel):
    """Compact alert representation used inside the LLM prompt (keeps token usage low)."""

    timestamp: datetime
    rule_id: str
    level: int
    description: str
    groups: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    process: str | None = None
    command_line: str | None = None
    url: str | None = None
    domain: str | None = None
    signature: str | None = None
    duplicates: int = 0


class IncidentContext(BaseModel):
    """Everything the triage agent may see about an incident."""

    incident_id: int
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    alerts: list[AlertSummary]
    alerts_truncated: bool = False
    max_rule_level: int = 0
    entities: list[Entity] = Field(default_factory=list)
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    related_history: list[dict[str, Any]] = Field(default_factory=list)
    narrative: str | None = None
    allowed_actions: list[ResponseAction] = Field(default_factory=lambda: list(ResponseAction))

    def entity_values(self) -> set[str]:
        return {e.value.lower() for e in self.entities}


class TriageDecision(BaseModel):
    """Strict structured output of the triage LLM (blueprint section 15).

    ``extra="forbid"`` rejects any additional field (e.g. a ``command`` key), and
    ``recommended_action`` must be one of :class:`ResponseAction`.
    """

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    classification: Classification
    techniques: list[str] = Field(default_factory=list, max_length=20)
    recommended_action: ResponseAction
    requires_human_approval: bool
    reason: str = Field(min_length=1, max_length=2000)
    targets: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("techniques")
    @classmethod
    def _validate_techniques(cls, value: list[str]) -> list[str]:
        cleaned = []
        for tid in value:
            tid = tid.strip().upper()
            if not TECHNIQUE_ID_RE.match(tid):
                raise ValueError(f"invalid ATT&CK technique id: {tid!r}")
            if tid not in cleaned:
                cleaned.append(tid)
        return cleaned

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, value: list[str]) -> list[str]:
        for target in value:
            if len(target) > 255:
                raise ValueError("target too long")
        return [t.strip() for t in value if t.strip()]


# JSON schema handed to the LLM runtime (Ollama ``format`` / Claude ``output_config.format``).
# Kept hand-written and minimal so every runtime supports it; numeric bounds, patterns and the
# technique-id format are enforced afterwards by TriageDecision.
TRIAGE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "severity": {"type": "string", "enum": [s.value for s in Severity]},
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "classification": {"type": "string", "enum": [c.value for c in Classification]},
        "techniques": {
            "type": "array",
            "items": {"type": "string", "description": "MITRE ATT&CK technique id, e.g. T1059.001"},
        },
        "recommended_action": {"type": "string", "enum": [a.value for a in ResponseAction]},
        "requires_human_approval": {"type": "boolean"},
        "reason": {"type": "string"},
        "targets": {
            "type": "array",
            "items": {"type": "string", "description": "Entity value from the incident entity list"},
        },
    },
    "required": [
        "severity",
        "confidence",
        "classification",
        "techniques",
        "recommended_action",
        "requires_human_approval",
        "reason",
        "targets",
    ],
    "additionalProperties": False,
}


class PolicyOutcome(StrEnum):
    LOG_ONLY = "LOG_ONLY"  # record, no automation
    RECOMMEND = "RECOMMEND"  # recommendation; analyst may approve execution
    AUTO_EXECUTE = "AUTO_EXECUTE"  # predefined playbook runs without waiting for a human
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"  # playbook runs only after analyst approval
    HUMAN_REVIEW = "HUMAN_REVIEW"  # low confidence: analyst must review the triage itself


class PolicyDecision(BaseModel):
    outcome: PolicyOutcome
    action: ResponseAction
    targets: list[str] = Field(default_factory=list)
    risk_score: int
    confidence: float
    band: str
    reasons: list[str] = Field(default_factory=list)
    policy_version: str


class PlaybookStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    REJECTED = "rejected"  # pre-execution validation refused to act
    ROLLED_BACK = "rolled_back"


class PlaybookStep(BaseModel):
    name: str
    status: str  # ok | failed | skipped | planned
    detail: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class PlaybookResult(BaseModel):
    playbook: str
    action: ResponseAction
    status: PlaybookStatus
    targets: list[str]
    steps: list[PlaybookStep] = Field(default_factory=list)
    output: dict[str, Any] = Field(default_factory=dict)
