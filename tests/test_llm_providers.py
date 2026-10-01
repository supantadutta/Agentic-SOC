import json
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from agentic_soc.agents.triage_agent import TriageAgent
from agentic_soc.integrations.mitre import AttackKnowledgeBase
from agentic_soc.llm.base import LLMError, LLMOutputError, LLMProvider, LLMRefusalError, LLMResult, PricingTable
from agentic_soc.llm.heuristic import HeuristicProvider
from agentic_soc.llm.providers import AnthropicProvider, HybridProvider, OllamaProvider
from agentic_soc.models.schemas import (
    AlertSummary,
    Entity,
    EntityType,
    IncidentContext,
    TriageDecision,
)

NOW = datetime(2026, 1, 12, 9, 0, tzinfo=UTC)
DECISION = {
    "severity": "high",
    "confidence": 0.9,
    "classification": "malicious",
    "techniques": ["T1059.001"],
    "recommended_action": "ISOLATE_HOST",
    "requires_human_approval": False,
    "reason": "Encoded PowerShell spawned by Word.",
    "targets": ["win-client01"],
}
PRICING = PricingTable({"claude-opus-5-5": {"input": 4.0, "output": 20.0}, "local": {"input": 0, "output": 0}})


def context() -> IncidentContext:
    return IncidentContext(
        incident_id=1,
        first_seen=NOW,
        last_seen=NOW,
        alert_count=1,
        max_rule_level=12,
        alerts=[
            AlertSummary(
                timestamp=NOW,
                rule_id="100211",
                level=12,
                description="Office spawned PowerShell",
                mitre=["T1059.001"],
                host="win-client01",
            )
        ],
        entities=[Entity(type=EntityType.HOST, value="win-client01", attributes={"agent_id": "002"})],
    )


def ollama_transport(contents: list[str]):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        assert body["format"]["additionalProperties"] is False
        assert body["options"]["temperature"] == 0
        return httpx.Response(
            200, json={"message": {"content": contents[len(calls) - 1]}, "prompt_eval_count": 700, "eval_count": 90}
        )

    return httpx.MockTransport(handler), calls


def test_ollama_provider_success():
    transport, calls = ollama_transport([json.dumps(DECISION)])
    result = OllamaProvider("http://ollama:11434", "llama3.1:8b", pricing=PRICING, transport=transport).analyze(
        context()
    )
    assert result.decision.recommended_action == "ISOLATE_HOST"
    assert (result.input_tokens, result.output_tokens, result.cost_usd) == (700, 90, 0.0)
    assert len(calls) == 1 and calls[0]["messages"][0]["role"] == "system"


def test_ollama_provider_retries_once_then_fails():
    transport, calls = ollama_transport(["not json", json.dumps({**DECISION, "recommended_action": "rm -rf"})])
    with pytest.raises(LLMOutputError):
        OllamaProvider("http://ollama:11434", "m", transport=transport).analyze(context())
    assert len(calls) == 2


def test_ollama_network_error_is_llm_error():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(LLMError):
        OllamaProvider("http://ollama:11434", "m", transport=httpx.MockTransport(handler)).analyze(context())


class FakeAnthropic:
    def __init__(self, response):
        self.response = response
        self.kwargs = None
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def anthropic_response(text, stop_reason="end_turn", model="claude-opus-5-5"):
    return SimpleNamespace(
        stop_reason=stop_reason,
        stop_details=SimpleNamespace(category="cyber") if stop_reason == "refusal" else None,
        model=model,
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(
            input_tokens=1000, output_tokens=200, cache_read_input_tokens=0, cache_creation_input_tokens=0
        ),
    )


def test_anthropic_provider_structured_output_and_cost():
    fake = FakeAnthropic(anthropic_response(json.dumps(DECISION)))
    result = AnthropicProvider("claude-opus-5-5", effort="low", pricing=PRICING, client=fake).analyze(context())
    assert result.decision.severity == "high"
    assert fake.kwargs["output_config"]["format"]["type"] == "json_schema"
    assert fake.kwargs["output_config"]["effort"] == "low"
    assert fake.kwargs["fallbacks"] == "default"
    assert fake.kwargs["betas"] == ["server-side-fallback-2026-07-01"]
    assert result.cost_usd == pytest.approx((1000 * 4 + 200 * 20) / 1_000_000)


def test_anthropic_provider_records_server_side_fallback_model():
    fake = FakeAnthropic(anthropic_response(json.dumps(DECISION), model="claude-opus-4-8"))
    result = AnthropicProvider("claude-opus-5-5", client=fake, pricing=PRICING).analyze(context())
    assert result.model == "claude-opus-4-8"
    assert any("server-side fallback" in n for n in result.notes)


def test_anthropic_refusal_and_truncation():
    with pytest.raises(LLMRefusalError):
        AnthropicProvider("m", client=FakeAnthropic(anthropic_response("", "refusal"))).analyze(context())
    with pytest.raises(LLMOutputError):
        AnthropicProvider("m", client=FakeAnthropic(anthropic_response("{", "max_tokens"))).analyze(context())


def test_anthropic_without_server_fallback_uses_plain_messages():
    fake = FakeAnthropic(anthropic_response(json.dumps(DECISION)))
    AnthropicProvider("claude-haiku-4-5", effort=None, server_fallback=False, client=fake).analyze(context())
    assert "fallbacks" not in fake.kwargs and "effort" not in fake.kwargs["output_config"]


class Fixed(LLMProvider):
    def __init__(self, name, decision=None, error=None, cost=0.0):
        self.name, self.model, self.decision, self.error, self.cost = name, name, decision, error, cost

    def analyze(self, ctx):
        if self.error:
            raise self.error
        return LLMResult(
            decision=TriageDecision(**self.decision),
            provider=self.name,
            model=self.model,
            prompt_version="v",
            prompt_sha256="x",
            input_tokens=100,
            output_tokens=10,
            cost_usd=self.cost,
        )


def test_hybrid_keeps_confident_local_answer():
    local = Fixed("local", {**DECISION, "severity": "medium", "confidence": 0.95})
    cloud = Fixed("cloud", DECISION, cost=0.01)
    result = HybridProvider(local, cloud, 0.8, ["high", "critical"]).analyze(context())
    assert result.provider == "hybrid:local" and not result.escalated and result.cost_usd == 0


def test_hybrid_escalates_uncertain_answer_and_sums_usage():
    local = Fixed("local", {**DECISION, "severity": "medium", "confidence": 0.5})
    cloud = Fixed("cloud", DECISION, cost=0.01)
    result = HybridProvider(local, cloud, 0.8, ["high"]).analyze(context())
    assert result.escalated and result.input_tokens == 200 and result.cost_usd == 0.01


def test_hybrid_survives_cloud_failure():
    local = Fixed("local", {**DECISION, "confidence": 0.5})
    cloud = Fixed("cloud", error=LLMError("quota"))
    result = HybridProvider(local, cloud, 0.8).analyze(context())
    assert result.provider == "hybrid:local" and any("failed" in n for n in result.notes)


def test_triage_agent_falls_back_and_strips_hallucinated_targets():
    agent = TriageAgent(Fixed("broken", error=LLMError("down")), AttackKnowledgeBase.builtin())
    result = agent.triage(context())
    assert result.fallback_used and result.provider == "fallback:heuristic"

    injected = Fixed("llm", {**DECISION, "targets": ["win-client01", "dc01"], "techniques": ["T1059.001"]})
    result = TriageAgent(injected, AttackKnowledgeBase.builtin()).triage(context())
    assert result.decision.targets == ["win-client01"]
    assert any("not incident entities" in n for n in result.notes)


def test_heuristic_is_deterministic():
    assert HeuristicProvider.decide(context()) == HeuristicProvider.decide(context())
