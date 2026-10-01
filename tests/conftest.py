from __future__ import annotations

from pathlib import Path

import pytest

from agentic_soc.agents.enrichment_agent import StaticThreatIntel
from agentic_soc.config.settings import Settings
from agentic_soc.llm.heuristic import HeuristicProvider
from agentic_soc.pipeline.orchestrator import SOCOrchestrator
from agentic_soc.policy.policy_engine import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        policy_file=ROOT / "config" / "policy.yaml",
        llm_pricing_file=ROOT / "config" / "llm_pricing.yaml",
        evidence_dir=tmp_path / "evidence",
        attack_data_path=tmp_path / "missing-attack.json",
        llm_provider="heuristic",
        execution_mode="dry_run",
        ingest_api_key="ingest-secret",
        analyst_api_keys={"alice": "alice-secret", "bob": "bob-secret"},
        wazuh_api_url=None,
        wazuh_indexer_url=None,
        misp_url=None,
        virustotal_api_key=None,
        opnsense_url=None,
        notify_webhook_url=None,
    )


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine.load(ROOT / "config" / "policy.yaml")


@pytest.fixture
def make_orchestrator(settings: Settings, policy: PolicyEngine):
    def factory(provider=None, threat_intel: dict[str, str] | None = None, **overrides) -> SOCOrchestrator:
        s = settings.model_copy(update=overrides)
        return SOCOrchestrator.from_settings(
            s,
            provider=provider or HeuristicProvider(),
            ti_sources=[StaticThreatIntel(threat_intel or {})],
            policy=policy,
        )

    return factory
