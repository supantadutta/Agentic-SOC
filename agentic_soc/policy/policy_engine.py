"""Policy engine: turns a validated triage decision into an execution outcome.

The LLM recommends; this deterministic engine decides. It applies risk bands, a
confidence floor, an action allowlist, protected assets, never-block networks, a
per-hour automation budget and a global kill switch. Every outcome carries the list of
reasons that produced it, which is written to the audit trail.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from agentic_soc.models.schemas import (
    NON_EXECUTABLE_ACTIONS,
    Classification,
    PolicyDecision,
    PolicyOutcome,
    ResponseAction,
    Severity,
    ThreatIntelResult,
    ThreatIntelVerdict,
    TriageDecision,
)


class RiskScoring(BaseModel):
    severity_scores: dict[Severity, int] = {
        Severity.INFORMATIONAL: 1,
        Severity.LOW: 3,
        Severity.MEDIUM: 6,
        Severity.HIGH: 8,
        Severity.CRITICAL: 10,
    }
    llm_weight: float = 0.7
    rule_level_weight: float = 0.3
    threat_intel_bonus: int = 1
    benign_cap: int = 4


class Band(BaseModel):
    name: str
    min: int
    max: int
    outcome: PolicyOutcome


class ConfidencePolicy(BaseModel):
    min_for_automation: float = 0.80
    below_threshold_outcome: PolicyOutcome = PolicyOutcome.HUMAN_REVIEW


class AutomationPolicy(BaseModel):
    enabled: bool = True
    auto_allowed_actions: list[ResponseAction] = [
        ResponseAction.COLLECT_EVIDENCE,
        ResponseAction.BLOCK_IP,
        ResponseAction.ISOLATE_HOST,
    ]
    always_require_approval: list[ResponseAction] = [ResponseAction.DISABLE_USER]
    max_targets_per_action: int = 3
    max_auto_actions_per_hour: int = 10
    allow_auto_on_fallback_triage: bool = False


class NetworkPolicy(BaseModel):
    internal_cidrs: list[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    never_block: list[str] = ["127.0.0.0/8"]


class ProtectedAssets(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    version: str = "policy-default"
    risk_scoring: RiskScoring = RiskScoring()
    bands: list[Band] = [
        Band(name="low", min=0, max=4, outcome=PolicyOutcome.LOG_ONLY),
        Band(name="medium", min=5, max=7, outcome=PolicyOutcome.RECOMMEND),
        Band(name="high", min=8, max=9, outcome=PolicyOutcome.AUTO_EXECUTE),
        Band(name="critical", min=10, max=10, outcome=PolicyOutcome.REQUIRE_APPROVAL),
    ]
    confidence: ConfidencePolicy = ConfidencePolicy()
    automation: AutomationPolicy = AutomationPolicy()
    network: NetworkPolicy = NetworkPolicy()
    protected_assets: ProtectedAssets = ProtectedAssets()


def _parse_networks(values: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(v, strict=False) for v in values]


class PolicyEngine:
    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()
        self._never_block = _parse_networks(self.config.network.never_block)
        self._protected_hosts = {h.lower() for h in self.config.protected_assets.hosts}
        self._protected_users = {u.lower() for u in self.config.protected_assets.users}
        covered = set()
        for band in self.config.bands:
            covered.update(range(band.min, band.max + 1))
        missing = set(range(0, 11)) - covered
        if missing:
            raise ValueError(f"policy bands do not cover risk scores {sorted(missing)}")

    @classmethod
    def load(cls, path: Path | str | None) -> PolicyEngine:
        if path and Path(path).exists():
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            return cls(PolicyConfig.model_validate(data))
        return cls()

    @property
    def version(self) -> str:
        return self.config.version

    # --- helpers used by agents and playbooks ------------------------------------------
    def is_never_block(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # not an IP: never hand it to the firewall
        return any(addr in net for net in self._never_block)

    def is_protected_host(self, value: str) -> bool:
        return value.lower() in self._protected_hosts

    def is_protected_user(self, value: str) -> bool:
        return value.lower() in self._protected_users

    def is_protected_target(self, action: ResponseAction, target: str) -> bool:
        if action == ResponseAction.DISABLE_USER:
            return self.is_protected_user(target)
        if action == ResponseAction.BLOCK_IP:
            return self.is_never_block(target)
        return self.is_protected_host(target)

    # --- scoring -------------------------------------------------------------------------
    def risk_score(self, decision: TriageDecision, max_rule_level: int, threat_intel: list[ThreatIntelResult]) -> int:
        cfg = self.config.risk_scoring
        llm_score = cfg.severity_scores.get(decision.severity, 0)
        rule_score = round(max(0, min(max_rule_level, 15)) * 10 / 15)
        score = round(cfg.llm_weight * llm_score + cfg.rule_level_weight * rule_score)
        if any(t.verdict == ThreatIntelVerdict.MALICIOUS for t in threat_intel):
            score += cfg.threat_intel_bonus
        if decision.classification == Classification.BENIGN:
            score = min(score, cfg.benign_cap)
        return max(0, min(10, score))

    def band_for(self, score: int) -> Band:
        for band in self.config.bands:
            if band.min <= score <= band.max:
                return band
        raise ValueError(f"no band for score {score}")  # unreachable: validated in __init__

    # --- decision ------------------------------------------------------------------------
    def evaluate(
        self,
        decision: TriageDecision,
        risk_score: int,
        targets: list[str],
        *,
        fallback_used: bool = False,
        recent_auto_actions: int = 0,
    ) -> PolicyDecision:
        cfg = self.config
        band = self.band_for(risk_score)
        action = decision.recommended_action
        reasons = [f"risk score {risk_score} falls in band '{band.name}' ({band.outcome.value})"]

        def result(outcome: PolicyOutcome, final_targets: list[str]) -> PolicyDecision:
            return PolicyDecision(
                outcome=outcome,
                action=action,
                targets=final_targets,
                risk_score=risk_score,
                confidence=decision.confidence,
                band=band.name,
                reasons=reasons,
                policy_version=cfg.version,
            )

        # Never hand infrastructure addresses to the firewall, whoever approves.
        valid_targets = list(dict.fromkeys(targets))
        if action == ResponseAction.BLOCK_IP:
            dropped = [t for t in valid_targets if self.is_never_block(t)]
            if dropped:
                reasons.append(f"removed never-block / invalid addresses from targets: {dropped}")
            valid_targets = [t for t in valid_targets if t not in dropped]

        if decision.confidence < cfg.confidence.min_for_automation:
            reasons.append(
                f"confidence {decision.confidence:.2f} < {cfg.confidence.min_for_automation:.2f}: "
                "human review regardless of severity"
            )
            return result(cfg.confidence.below_threshold_outcome, valid_targets)

        if action in NON_EXECUTABLE_ACTIONS:
            reasons.append(f"action {action.value} performs no containment")
            return result(PolicyOutcome.LOG_ONLY, [])

        if not valid_targets:
            reasons.append("no valid target for the recommended action")
            outcome = PolicyOutcome.HUMAN_REVIEW if band.outcome != PolicyOutcome.LOG_ONLY else PolicyOutcome.LOG_ONLY
            return result(outcome, [])

        outcome = band.outcome
        if outcome != PolicyOutcome.AUTO_EXECUTE:
            return result(outcome, valid_targets)

        blockers = []
        if not cfg.automation.enabled:
            blockers.append("automation disabled (kill switch)")
        if action not in cfg.automation.auto_allowed_actions:
            blockers.append(f"{action.value} is not in auto_allowed_actions")
        if action in cfg.automation.always_require_approval:
            blockers.append(f"{action.value} always requires approval")
        if decision.requires_human_approval:
            blockers.append("model requested human approval")
        if fallback_used and not cfg.automation.allow_auto_on_fallback_triage:
            blockers.append("triage came from the fallback path, not the configured LLM")
        protected = [t for t in valid_targets if self.is_protected_target(action, t)]
        if protected:
            blockers.append(f"protected targets: {protected}")
        if len(valid_targets) > cfg.automation.max_targets_per_action:
            blockers.append(
                f"{len(valid_targets)} targets exceeds max_targets_per_action ({cfg.automation.max_targets_per_action})"
            )
        if recent_auto_actions >= cfg.automation.max_auto_actions_per_hour:
            blockers.append(f"automation budget exhausted ({recent_auto_actions} auto actions in the last hour)")
        if blockers:
            reasons.extend(blockers)
            reasons.append("escalated to analyst approval")
            return result(PolicyOutcome.REQUIRE_APPROVAL, valid_targets)

        reasons.append("all automation guards passed")
        return result(PolicyOutcome.AUTO_EXECUTE, valid_targets)
