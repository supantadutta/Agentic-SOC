"""Runtime configuration, loaded from environment variables (prefix ``SOC_``) or a ``.env`` file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_", env_file=".env", extra="ignore")

    # --- Storage -----------------------------------------------------------------
    database_url: str = "sqlite:///./agentic_soc.db"
    policy_file: Path = Path("config/policy.yaml")
    llm_pricing_file: Path = Path("config/llm_pricing.yaml")
    evidence_dir: Path = Path("evidence")

    # --- API authentication --------------------------------------------------------
    # Key used by the Wazuh integration script to push alerts.
    ingest_api_key: SecretStr | None = None
    # Analyst name -> API key, e.g. SOC_ANALYST_API_KEYS='{"alice": "long-random-key"}'.
    # The analyst identity recorded in the audit trail is derived from the key.
    analyst_api_keys: dict[str, SecretStr] = {}
    max_alert_bytes: int = 1_000_000

    # --- Pipeline ------------------------------------------------------------------
    dedup_window_seconds: int = 600
    correlation_window_minutes: int = 60
    min_rule_level_for_triage: int = 3
    retriage_cooldown_seconds: int = 300
    max_alerts_in_prompt: int = 20
    max_field_chars: int = 1000

    # --- LLM -----------------------------------------------------------------------
    llm_provider: Literal["heuristic", "ollama", "cloud", "hybrid"] = "heuristic"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_timeout_seconds: float = 180.0
    cloud_model: str = "claude-opus-5-5"
    # Effort for the cloud model. Triage is a short classification task, so "low" keeps
    # cost down; raise it if evaluation shows quality headroom. Set to empty for models
    # that do not support the effort parameter.
    cloud_effort: str | None = "low"
    cloud_max_tokens: int = 4096
    cloud_timeout_seconds: float = 120.0
    # Server-side refusal fallback (Claude API only). Security telemetry can trip safety
    # classifiers; the fallback re-runs a declined request on Anthropic's recommended model.
    cloud_server_fallback: bool = True
    hybrid_escalation_confidence: float = 0.80
    hybrid_escalate_severities: list[str] = ["high", "critical"]

    # --- Integrations ----------------------------------------------------------------
    tls_verify: bool = True
    tls_ca_bundle: str | None = None  # path to the lab CA certificate (Wazuh uses self-signed certs)
    http_timeout_seconds: float = 15.0

    wazuh_api_url: str | None = None  # e.g. https://192.168.50.10:55000
    wazuh_api_user: str | None = None
    wazuh_api_password: SecretStr | None = None
    wazuh_indexer_url: str | None = None  # e.g. https://192.168.50.10:9200
    wazuh_indexer_user: str | None = None
    wazuh_indexer_password: SecretStr | None = None
    wazuh_manager_ip: str = "192.168.50.10"  # kept reachable while a host is isolated

    misp_url: str | None = None  # e.g. https://192.168.50.30
    misp_api_key: SecretStr | None = None

    virustotal_api_key: SecretStr | None = None
    virustotal_requests_per_minute: int = 4  # public API limit
    virustotal_daily_quota: int = 500

    attack_data_path: Path = Path("data/enterprise-attack.json")
    max_ti_lookups_per_incident: int = 10
    # Domains never sent to external reputation services.
    internal_domain_suffixes: list[str] = [".local", ".lan", ".internal", ".home.arpa", ".lab"]
    ioc_cache_hours: int = 24

    # --- Response --------------------------------------------------------------------
    # dry_run records what a playbook would do without touching any system.
    execution_mode: Literal["dry_run", "live"] = "dry_run"
    block_backend: Literal["opnsense", "wazuh"] = "opnsense"
    opnsense_url: str | None = None
    opnsense_api_key: SecretStr | None = None
    opnsense_api_secret: SecretStr | None = None
    opnsense_alias: str = "AGENTIC_SOC_BLOCK"
    ad_dc_agent_id: str | None = None  # Wazuh agent on the domain controller (account containment)

    notify_webhook_url: str | None = None  # e.g. an n8n webhook for analyst notifications

    @property
    def tls(self) -> bool | str:
        """Value for httpx ``verify=``."""
        if self.tls_ca_bundle:
            return self.tls_ca_bundle
        return self.tls_verify


@lru_cache
def get_settings() -> Settings:
    return Settings()
