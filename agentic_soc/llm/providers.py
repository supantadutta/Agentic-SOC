"""Concrete LLM providers: local Ollama, cloud (Claude API) and a hybrid router.

Each provider returns the same validated TriageDecision plus token usage, latency and cost,
so local, cloud and hybrid invocation can be compared on accuracy, latency, tokens and
cost per alert (blueprint section 20).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from agentic_soc.config.settings import Settings
from agentic_soc.llm.base import (
    LLMError,
    LLMOutputError,
    LLMProvider,
    LLMRefusalError,
    LLMResult,
    PricingTable,
    parse_decision,
)
from agentic_soc.llm.heuristic import HeuristicProvider
from agentic_soc.llm.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt, prompt_digest
from agentic_soc.models.schemas import TRIAGE_JSON_SCHEMA, IncidentContext

log = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """Local model served by Ollama, constrained to the triage JSON schema."""

    name = "ollama"

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float = 180.0,
        pricing: PricingTable | None = None,
        max_attempts: int = 2,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.pricing = pricing or PricingTable()
        self.max_attempts = max_attempts
        self._client = httpx.Client(timeout=timeout, transport=transport)

    def analyze(self, context: IncidentContext) -> LLMResult:
        user_prompt = build_user_prompt(context)
        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        input_tokens = output_tokens = 0
        start = time.perf_counter()
        last_error: LLMOutputError | None = None
        notes: list[str] = []
        for attempt in range(1, self.max_attempts + 1):
            try:
                resp = self._client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": messages,
                        "stream": False,
                        "format": TRIAGE_JSON_SCHEMA,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                raise LLMError(f"Ollama request failed: {exc}") from exc
            body = resp.json()
            input_tokens += int(body.get("prompt_eval_count") or 0)
            output_tokens += int(body.get("eval_count") or 0)
            content = (body.get("message") or {}).get("content", "")
            try:
                decision = parse_decision(content)
            except LLMOutputError as exc:
                last_error = exc
                notes.append(f"attempt {attempt}: invalid output ({exc})")
                # Ask once for a corrected object; the schema stays enforced either way.
                messages = messages[:2] + [
                    {"role": "assistant", "content": content[:4000]},
                    {
                        "role": "user",
                        "content": "That output was invalid. Return only one JSON object that matches the schema.",
                    },
                ]
                continue
            return LLMResult(
                decision=decision,
                provider=self.name,
                model=self.model,
                prompt_version=PROMPT_VERSION,
                prompt_sha256=prompt_digest(SYSTEM_PROMPT, user_prompt),
                user_prompt=user_prompt,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=(time.perf_counter() - start) * 1000,
                cost_usd=self.pricing.cost("local", input_tokens, output_tokens),
                raw_output=content,
                notes=notes,
            )
        raise LLMOutputError(f"Ollama output invalid after {self.max_attempts} attempts: {last_error}")


class AnthropicProvider(LLMProvider):
    """Cloud provider using the Claude API with structured outputs."""

    name = "anthropic"
    FALLBACK_BETA = "server-side-fallback-2026-07-01"

    def __init__(
        self,
        model: str,
        effort: str | None = "low",
        max_tokens: int = 4096,
        server_fallback: bool = True,
        timeout: float = 120.0,
        pricing: PricingTable | None = None,
        client: Any = None,
    ) -> None:
        self.model = model
        self.effort = effort or None
        self.max_tokens = max_tokens
        self.server_fallback = server_fallback
        self.pricing = pricing or PricingTable()
        if client is None:
            import anthropic  # optional dependency: pip install "agentic-soc[cloud]"

            client = anthropic.Anthropic(timeout=timeout, max_retries=2)
        self._client = client

    def _request(self, user_prompt: str) -> Any:
        output_config: dict[str, Any] = {"format": {"type": "json_schema", "schema": TRIAGE_JSON_SCHEMA}}
        if self.effort:
            output_config["effort"] = self.effort
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_prompt}],
            "output_config": output_config,
        }
        if self.server_fallback:
            return self._client.beta.messages.create(**kwargs, betas=[self.FALLBACK_BETA], fallbacks="default")
        return self._client.messages.create(**kwargs)

    def analyze(self, context: IncidentContext) -> LLMResult:
        user_prompt = build_user_prompt(context)
        start = time.perf_counter()
        try:
            response = self._request(user_prompt)
        except LLMError:
            raise
        except Exception as exc:  # anthropic.APIError hierarchy; kept generic so the SDK stays optional
            raise LLMError(f"Claude API request failed: {type(exc).__name__}: {exc}") from exc
        latency_ms = (time.perf_counter() - start) * 1000

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise LLMRefusalError(f"model declined the request (category={category})")
        if response.stop_reason == "max_tokens":
            raise LLMOutputError("response truncated at max_tokens")

        text = next((block.text for block in response.content if getattr(block, "type", "") == "text"), "")
        decision = parse_decision(text)

        usage = response.usage
        base_in = int(getattr(usage, "input_tokens", 0) or 0)
        cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        cache_write = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        out = int(getattr(usage, "output_tokens", 0) or 0)
        served_model = getattr(response, "model", None) or self.model
        notes = [f"server-side fallback: served by {served_model}"] if served_model != self.model else []
        return LLMResult(
            decision=decision,
            provider=self.name,
            model=served_model,
            prompt_version=PROMPT_VERSION,
            prompt_sha256=prompt_digest(SYSTEM_PROMPT, user_prompt),
            user_prompt=user_prompt,
            input_tokens=base_in + cache_read + cache_write,
            output_tokens=out,
            latency_ms=latency_ms,
            cost_usd=self.pricing.cost(served_model, base_in, out, cache_read, cache_write),
            raw_output=text,
            notes=notes,
        )


class HybridProvider(LLMProvider):
    """Local first; escalate to the cloud model when the local answer is uncertain or severe."""

    name = "hybrid"

    def __init__(
        self,
        local: LLMProvider,
        cloud: LLMProvider,
        escalation_confidence: float = 0.8,
        escalate_severities: list[str] | None = None,
    ) -> None:
        self.local = local
        self.cloud = cloud
        self.escalation_confidence = escalation_confidence
        self.escalate_severities = set(escalate_severities or [])
        self.model = f"{local.model}->{cloud.model}"

    def analyze(self, context: IncidentContext) -> LLMResult:
        try:
            local_result = self.local.analyze(context)
        except LLMError as exc:
            result = self.cloud.analyze(context)
            result.provider = f"hybrid:{self.cloud.name}"
            result.escalated = True
            result.notes.append(f"local provider failed ({exc}); used cloud")
            return result

        decision = local_result.decision
        reasons = []
        if decision.confidence < self.escalation_confidence:
            reasons.append(f"local confidence {decision.confidence:.2f} < {self.escalation_confidence}")
        if decision.severity.value in self.escalate_severities:
            reasons.append(f"local severity {decision.severity.value}")
        if not reasons:
            local_result.provider = f"hybrid:{self.local.name}"
            return local_result

        try:
            cloud_result = self.cloud.analyze(context)
        except LLMError as exc:
            local_result.provider = f"hybrid:{self.local.name}"
            local_result.notes.append(f"escalation ({'; '.join(reasons)}) failed: {exc}")
            return local_result
        cloud_result.provider = f"hybrid:{self.local.name}+{self.cloud.name}"
        cloud_result.escalated = True
        cloud_result.input_tokens += local_result.input_tokens
        cloud_result.output_tokens += local_result.output_tokens
        cloud_result.latency_ms += local_result.latency_ms
        cloud_result.cost_usd += local_result.cost_usd
        cloud_result.notes = local_result.notes + [f"escalated: {'; '.join(reasons)}"] + cloud_result.notes
        return cloud_result


def build_provider(settings: Settings, pricing: PricingTable | None = None) -> LLMProvider:
    pricing = pricing or PricingTable.load(settings.llm_pricing_file)
    if settings.llm_provider == "heuristic":
        return HeuristicProvider()

    def ollama() -> OllamaProvider:
        return OllamaProvider(settings.ollama_url, settings.ollama_model, settings.ollama_timeout_seconds, pricing)

    def cloud() -> AnthropicProvider:
        return AnthropicProvider(
            model=settings.cloud_model,
            effort=settings.cloud_effort,
            max_tokens=settings.cloud_max_tokens,
            server_fallback=settings.cloud_server_fallback,
            timeout=settings.cloud_timeout_seconds,
            pricing=pricing,
        )

    if settings.llm_provider == "ollama":
        return ollama()
    if settings.llm_provider == "cloud":
        return cloud()
    return HybridProvider(ollama(), cloud(), settings.hybrid_escalation_confidence, settings.hybrid_escalate_severities)
