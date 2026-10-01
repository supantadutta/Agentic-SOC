"""LLM provider abstraction (blueprint section 20) and shared helpers."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from agentic_soc.models.schemas import IncidentContext, TriageDecision

log = logging.getLogger(__name__)


class LLMError(RuntimeError):
    """The provider could not produce a decision (network, quota, server error)."""


class LLMOutputError(LLMError):
    """The provider answered, but the output was not a valid TriageDecision."""


class LLMRefusalError(LLMError):
    """The model declined the request."""


@dataclass
class LLMResult:
    decision: TriageDecision
    provider: str
    model: str
    prompt_version: str
    prompt_sha256: str
    user_prompt: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    escalated: bool = False
    # True when the configured LLM failed and the deterministic fallback produced the decision.
    fallback_used: bool = False
    raw_output: str = ""
    notes: list[str] = field(default_factory=list)


class LLMProvider(ABC):
    name: str = "base"
    model: str = "unknown"

    @abstractmethod
    def analyze(self, context: IncidentContext) -> LLMResult:
        """Return a validated triage decision for the incident."""


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def parse_decision(text: str) -> TriageDecision:
    """Parse and strictly validate model output. Raises LLMOutputError on any deviation."""
    cleaned = _FENCE_RE.sub("", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise LLMOutputError("model output contained no JSON object")
    try:
        data = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMOutputError(f"model output is not valid JSON: {exc}") from exc
    try:
        return TriageDecision.model_validate(data)
    except ValidationError as exc:
        raise LLMOutputError(f"model output failed schema validation: {exc.errors(include_url=False)}") from exc


class PricingTable:
    """USD per 1M tokens, loaded from config/llm_pricing.yaml."""

    def __init__(self, prices: dict[str, dict[str, float]] | None = None) -> None:
        self.prices = prices or {}

    @classmethod
    def load(cls, path: Path | None) -> PricingTable:
        if path and Path(path).exists():
            return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
        return cls()

    def cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> float:
        price = self.prices.get(model)
        if price is None:
            if model not in ("local", "heuristic"):
                log.warning("no pricing configured for model %s; cost recorded as 0", model)
            return 0.0
        per_in = float(price.get("input", 0.0))
        per_out = float(price.get("output", 0.0))
        per_cache_read = float(price.get("cache_read", per_in))
        per_cache_write = float(price.get("cache_write", per_in * 1.25))
        total = (
            input_tokens * per_in
            + output_tokens * per_out
            + cache_read_tokens * per_cache_read
            + cache_write_tokens * per_cache_write
        )
        return round(total / 1_000_000, 8)
