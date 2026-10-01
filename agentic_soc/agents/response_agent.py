"""Response Agent: incident context -> recommended *approved* action.

Resolves concrete targets for the recommended action from the incident's own entities,
asks the policy engine for an outcome, and runs predefined playbooks. It never builds
commands from model text.
"""

from __future__ import annotations

from agentic_soc.models.schemas import (
    NON_EXECUTABLE_ACTIONS,
    EntityType,
    IncidentContext,
    PlaybookResult,
    PolicyDecision,
    ResponseAction,
    ThreatIntelVerdict,
    TriageDecision,
)
from agentic_soc.playbooks.base import Playbook, PlaybookContext
from agentic_soc.policy.policy_engine import PolicyEngine

HOST_ACTIONS = {ResponseAction.ISOLATE_HOST, ResponseAction.COLLECT_EVIDENCE}


class ResponseAgent:
    name = "response"

    def __init__(self, policy: PolicyEngine, playbooks: dict[ResponseAction, Playbook]) -> None:
        self.policy = policy
        self.playbooks = playbooks

    def _allowed_target_types(self, action: ResponseAction) -> set[EntityType]:
        if action in HOST_ACTIONS:
            return {EntityType.HOST, EntityType.IP}
        if action == ResponseAction.BLOCK_IP:
            return {EntityType.IP}
        if action == ResponseAction.DISABLE_USER:
            return {EntityType.USER}
        return set()

    def resolve_targets(self, decision: TriageDecision, context: IncidentContext) -> tuple[list[str], list[str]]:
        action = decision.recommended_action
        notes: list[str] = []
        if action in NON_EXECUTABLE_ACTIONS:
            return [], notes
        allowed = self._allowed_target_types(action)
        by_value = {e.value.lower(): e for e in context.entities}

        targets = []
        for target in decision.targets:
            entity = by_value.get(target.lower())
            if entity is None or entity.type not in allowed:
                notes.append(f"target {target!r} is not a valid {action.value} target")
                continue
            if action in HOST_ACTIONS and entity.type == EntityType.IP and not entity.attributes.get("internal"):
                notes.append(f"target {target!r} is external; cannot be an endpoint")
                continue
            targets.append(entity.value)

        if not targets:
            targets = self._default_targets(action, context)
            if targets:
                notes.append(f"targets derived from incident entities: {targets}")
        return list(dict.fromkeys(targets)), notes

    @staticmethod
    def _default_targets(action: ResponseAction, context: IncidentContext) -> list[str]:
        entities = context.entities
        if action in HOST_ACTIONS:
            hosts = [e.value for e in entities if e.type == EntityType.HOST]
            if hosts:
                return hosts
            return [
                e.value
                for e in entities
                if e.type == EntityType.IP
                and e.attributes.get("internal")
                and e.attributes.get("role") == "destination"
            ]
        if action == ResponseAction.BLOCK_IP:
            flagged = {
                t.indicator
                for t in context.threat_intel
                if t.indicator_type == EntityType.IP
                and t.verdict in (ThreatIntelVerdict.MALICIOUS, ThreatIntelVerdict.SUSPICIOUS)
            }
            if flagged:
                return sorted(flagged)
            return [e.value for e in entities if e.type == EntityType.IP and not e.attributes.get("internal")]
        if action == ResponseAction.DISABLE_USER:
            return [e.value for e in entities if e.type == EntityType.USER]
        return []

    def plan(
        self,
        decision: TriageDecision,
        context: IncidentContext,
        *,
        fallback_used: bool,
        recent_auto_actions: int,
    ) -> tuple[PolicyDecision, list[str]]:
        risk = self.policy.risk_score(decision, context.max_rule_level, context.threat_intel)
        targets, notes = self.resolve_targets(decision, context)
        policy_decision = self.policy.evaluate(
            decision, risk, targets, fallback_used=fallback_used, recent_auto_actions=recent_auto_actions
        )
        return policy_decision, notes

    def execute(self, action: ResponseAction, targets: list[str], ctx: PlaybookContext) -> PlaybookResult:
        playbook = self.playbooks[action]
        return playbook.run(targets, ctx)

    def rollback(self, action: ResponseAction, targets: list[str], ctx: PlaybookContext) -> PlaybookResult:
        return self.playbooks[action].rollback(targets, ctx)
