"""Deterministic, zero-cost triage used for offline runs, tests, as the comparison arm in the
evaluation, and as the conservative fallback when an LLM is unavailable."""

from __future__ import annotations

import time

from agentic_soc.llm.base import LLMProvider, LLMResult
from agentic_soc.llm.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt, prompt_digest
from agentic_soc.models.schemas import (
    SEVERITY_ORDER,
    Classification,
    EntityType,
    IncidentContext,
    ResponseAction,
    Severity,
    ThreatIntelVerdict,
    TriageDecision,
)

LEVEL_TO_SEVERITY = [
    (13, Severity.CRITICAL),
    (10, Severity.HIGH),
    (7, Severity.MEDIUM),
    (4, Severity.LOW),
    (0, Severity.INFORMATIONAL),
]
HOST_COMPROMISE_TACTICS = {"execution", "persistence", "privilege-escalation", "lateral-movement", "impact"}
RECON_TACTICS = {"reconnaissance", "discovery", "initial-access"}


def _bump(severity: Severity) -> Severity:
    idx = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]


class HeuristicProvider(LLMProvider):
    name = "heuristic"
    model = "rules-v1"

    def analyze(self, context: IncidentContext) -> LLMResult:
        start = time.perf_counter()
        decision = self.decide(context)
        user_prompt = build_user_prompt(context)
        return LLMResult(
            decision=decision,
            provider=self.name,
            model=self.model,
            prompt_version=PROMPT_VERSION,
            prompt_sha256=prompt_digest(SYSTEM_PROMPT, user_prompt),
            user_prompt=user_prompt,
            latency_ms=(time.perf_counter() - start) * 1000,
            raw_output=decision.model_dump_json(),
        )

    @staticmethod
    def decide(ctx: IncidentContext) -> TriageDecision:
        level = ctx.max_rule_level
        severity = next(sev for threshold, sev in LEVEL_TO_SEVERITY if level >= threshold)
        malicious_ti = [t for t in ctx.threat_intel if t.verdict == ThreatIntelVerdict.MALICIOUS]
        suspicious_ti = [t for t in ctx.threat_intel if t.verdict == ThreatIntelVerdict.SUSPICIOUS]
        techniques = sorted({m for a in ctx.alerts for m in a.mitre} | {t.id for t in ctx.attack_techniques})
        tactics = {tactic for tech in ctx.attack_techniques for tactic in tech.tactics}

        # Multi-stage activity: several distinct techniques spanning several tactics. (A single
        # technique can map to several tactics, e.g. T1053.005, which alone is not multi-stage.)
        multi_stage = len(techniques) >= 2 and len(tactics) >= 3
        if malicious_ti:
            severity = _bump(severity)
        if multi_stage and SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(Severity.HIGH):
            severity = Severity.HIGH

        if malicious_ti or level >= 12 or multi_stage:
            classification = Classification.MALICIOUS
        elif level >= 7 or suspicious_ti or (tactics and level >= 5 and ctx.alert_count >= 2):
            classification = Classification.SUSPICIOUS
        else:
            classification = Classification.BENIGN

        if classification == Classification.BENIGN:
            confidence = 0.85 if level < 5 else 0.8
        else:
            confidence = 0.55
            confidence += 0.2 if malicious_ti else 0.0
            confidence += 0.1 if ctx.alert_count >= 3 else 0.0
            confidence += 0.1 if len(tactics) >= 2 else 0.0
            confidence += 0.05 if level >= 12 else 0.0
        confidence = round(min(confidence, 0.95), 2)

        hosts = [e.value for e in ctx.entities if e.type == EntityType.HOST]
        users = [e.value for e in ctx.entities if e.type == EntityType.USER]
        bad_ips = [t.indicator for t in malicious_ti if t.indicator_type == EntityType.IP]
        source_ips = [e.value for e in ctx.entities if e.type == EntityType.IP and e.attributes.get("role") == "source"]

        targets: list[str] = []
        if classification == Classification.BENIGN:
            action = ResponseAction.NONE
        elif classification == Classification.SUSPICIOUS:
            action = ResponseAction.COLLECT_EVIDENCE if hosts else ResponseAction.MONITOR
            targets = hosts[:1]
        elif "credential-access" in tactics and "T1078" in techniques and users:
            action, targets = ResponseAction.DISABLE_USER, users[:1]
        elif tactics & HOST_COMPROMISE_TACTICS and hosts:
            action, targets = ResponseAction.ISOLATE_HOST, hosts[:1]
        elif bad_ips:
            action, targets = ResponseAction.BLOCK_IP, bad_ips[:3]
        elif tactics and tactics <= RECON_TACTICS and source_ips:
            action, targets = ResponseAction.BLOCK_IP, source_ips[:1]
        elif hosts:
            action, targets = ResponseAction.COLLECT_EVIDENCE, hosts[:1]
        else:
            action = ResponseAction.MONITOR

        reason = (
            f"Heuristic triage: max rule level {level}, {ctx.alert_count} alert(s), "
            f"{len(malicious_ti)} malicious and {len(suspicious_ti)} suspicious threat-intel hit(s), "
            f"tactics: {', '.join(sorted(tactics)) or 'none'}."
        )
        return TriageDecision(
            severity=severity,
            confidence=confidence,
            classification=classification,
            techniques=techniques[:20],
            recommended_action=action,
            requires_human_approval=action in {ResponseAction.ISOLATE_HOST, ResponseAction.DISABLE_USER},
            reason=reason,
            targets=targets,
        )
