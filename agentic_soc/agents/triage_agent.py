"""Triage Agent: Wazuh alert/incident context -> severity, confidence, classification.

Wraps the configured LLM provider and post-validates its answer:
  * unknown ATT&CK technique ids are dropped,
  * targets that are not entities of the incident are dropped (hallucination / prompt
    injection guard),
  * if the LLM fails, the deterministic heuristic decides and the result is flagged so
    the policy engine will not auto-execute on it.
"""

from __future__ import annotations

import logging

from agentic_soc.integrations.mitre import AttackKnowledgeBase
from agentic_soc.llm.base import LLMError, LLMProvider, LLMResult
from agentic_soc.llm.heuristic import HeuristicProvider
from agentic_soc.models.schemas import IncidentContext

log = logging.getLogger(__name__)


class TriageAgent:
    name = "triage"

    def __init__(
        self, provider: LLMProvider, attack_kb: AttackKnowledgeBase, fallback: LLMProvider | None = None
    ) -> None:
        self.provider = provider
        self.attack_kb = attack_kb
        self.fallback = fallback or HeuristicProvider()

    def triage(self, context: IncidentContext) -> LLMResult:
        try:
            result = self.provider.analyze(context)
        except LLMError as exc:
            log.warning("LLM provider %s failed for incident %s: %s", self.provider.name, context.incident_id, exc)
            result = self.fallback.analyze(context)
            result.provider = f"fallback:{self.fallback.name}"
            result.fallback_used = True
            result.notes.append(f"{self.provider.name} unavailable ({exc}); deterministic fallback used")
        return self.post_validate(result, context)

    def post_validate(self, result: LLMResult, context: IncidentContext) -> LLMResult:
        decision = result.decision
        valid_techniques = [t for t in decision.techniques if self.attack_kb.is_valid(t)]
        dropped_techniques = sorted(set(decision.techniques) - set(valid_techniques))
        if dropped_techniques:
            result.notes.append(f"dropped unknown ATT&CK technique ids: {dropped_techniques}")

        known = context.entity_values()
        valid_targets = [t for t in decision.targets if t.lower() in known]
        dropped_targets = [t for t in decision.targets if t.lower() not in known]
        if dropped_targets:
            result.notes.append(
                f"dropped targets that are not incident entities (possible hallucination or injection): "
                f"{dropped_targets}"
            )
        result.decision = decision.model_copy(update={"techniques": valid_techniques, "targets": valid_targets})
        return result
