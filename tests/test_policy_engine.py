import pytest

from agentic_soc.models.schemas import (
    EntityType,
    PolicyOutcome,
    ThreatIntelResult,
    ThreatIntelVerdict,
    TriageDecision,
)
from agentic_soc.policy.policy_engine import PolicyConfig, PolicyEngine


def decision(**kw) -> TriageDecision:
    base = dict(
        severity="high",
        confidence=0.9,
        classification="malicious",
        techniques=[],
        recommended_action="ISOLATE_HOST",
        requires_human_approval=False,
        reason="test",
        targets=[],
    )
    return TriageDecision(**{**base, **kw})


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (2, PolicyOutcome.LOG_ONLY),
        (6, PolicyOutcome.RECOMMEND),
        (8, PolicyOutcome.AUTO_EXECUTE),
        (10, PolicyOutcome.REQUIRE_APPROVAL),
    ],
)
def test_severity_bands(policy, risk, expected):
    result = policy.evaluate(decision(), risk, ["win-client01"])
    assert result.outcome == expected


def test_low_confidence_goes_to_human_review_regardless_of_severity(policy):
    result = policy.evaluate(decision(confidence=0.6, severity="critical"), 9, ["win-client01"])
    assert result.outcome == PolicyOutcome.HUMAN_REVIEW
    assert any("human review" in r for r in result.reasons)


def test_model_can_escalate_but_not_bypass(policy):
    assert (
        policy.evaluate(decision(requires_human_approval=True), 9, ["win-client01"]).outcome
        == PolicyOutcome.REQUIRE_APPROVAL
    )


def test_disable_user_always_requires_approval(policy):
    result = policy.evaluate(decision(recommended_action="DISABLE_USER"), 9, ["bob"])
    assert result.outcome == PolicyOutcome.REQUIRE_APPROVAL


def test_protected_assets_block_automation(policy):
    result = policy.evaluate(decision(), 9, ["dc01"])
    assert result.outcome == PolicyOutcome.REQUIRE_APPROVAL
    assert any("protected" in r for r in result.reasons)


def test_never_block_addresses_are_removed(policy):
    result = policy.evaluate(decision(recommended_action="BLOCK_IP"), 9, ["192.168.50.10", "203.0.113.45"])
    assert result.targets == ["203.0.113.45"]
    assert result.outcome == PolicyOutcome.AUTO_EXECUTE
    only_infra = policy.evaluate(decision(recommended_action="BLOCK_IP"), 9, ["192.168.50.1"])
    assert only_infra.targets == [] and only_infra.outcome == PolicyOutcome.HUMAN_REVIEW


def test_fallback_triage_never_auto_executes(policy):
    result = policy.evaluate(decision(), 9, ["win-client01"], fallback_used=True)
    assert result.outcome == PolicyOutcome.REQUIRE_APPROVAL


def test_kill_switch_and_rate_limit():
    config = PolicyConfig()
    config.automation.enabled = False
    assert PolicyEngine(config).evaluate(decision(), 9, ["h"]).outcome == PolicyOutcome.REQUIRE_APPROVAL
    engine = PolicyEngine()
    assert engine.evaluate(decision(), 9, ["h"], recent_auto_actions=10).outcome == PolicyOutcome.REQUIRE_APPROVAL


def test_non_executable_actions_only_log(policy):
    assert policy.evaluate(decision(recommended_action="MONITOR"), 9, []).outcome == PolicyOutcome.LOG_ONLY


def test_risk_score(policy):
    ti = [
        ThreatIntelResult(
            indicator="203.0.113.45", indicator_type=EntityType.IP, source="misp", verdict=ThreatIntelVerdict.MALICIOUS
        )
    ]
    assert policy.risk_score(decision(severity="high"), 12, []) == 8
    assert policy.risk_score(decision(severity="high"), 12, ti) == 9
    assert policy.risk_score(decision(severity="critical"), 15, []) == 10
    assert policy.risk_score(decision(severity="critical", classification="benign"), 15, ti) == 4


def test_bands_must_cover_every_score():
    config = PolicyConfig()
    config.bands = config.bands[:2]
    with pytest.raises(ValueError):
        PolicyEngine(config)
