"""Threat Intelligence Agent: IPs, domains, URLs, hashes -> reputation / CTI evidence.

Sources: MISP, VirusTotal and MITRE ATT&CK. Results are cached in the ``iocs`` table so a
recurring indicator does not spend VirusTotal quota again. Internal addresses and
internal domain names are never sent to external services.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_soc.database.models import IOC
from agentic_soc.integrations.mitre import AttackKnowledgeBase
from agentic_soc.integrations.wazuh import NetworkClassifier
from agentic_soc.models.schemas import (
    AttackTechnique,
    Entity,
    EntityType,
    ThreatIntelResult,
    ThreatIntelVerdict,
)

log = logging.getLogger(__name__)

VERDICT_RANK = {
    ThreatIntelVerdict.UNKNOWN: 0,
    ThreatIntelVerdict.HARMLESS: 1,
    ThreatIntelVerdict.SUSPICIOUS: 2,
    ThreatIntelVerdict.MALICIOUS: 3,
}
LOOKUP_ORDER = [EntityType.HASH, EntityType.IP, EntityType.DOMAIN, EntityType.URL]


class ThreatIntelSource(Protocol):
    name: str

    def lookup(self, indicator: str, indicator_type: EntityType) -> ThreatIntelResult: ...


class StaticThreatIntel:
    """In-memory source for offline evaluation and tests: indicator -> verdict."""

    name = "static"

    def __init__(self, verdicts: dict[str, str] | None = None) -> None:
        self.verdicts = {k.lower(): ThreatIntelVerdict(v) for k, v in (verdicts or {}).items()}

    def lookup(self, indicator: str, indicator_type: EntityType) -> ThreatIntelResult:
        verdict = self.verdicts.get(indicator.lower(), ThreatIntelVerdict.UNKNOWN)
        return ThreatIntelResult(indicator=indicator, indicator_type=indicator_type, source=self.name, verdict=verdict)


class ThreatIntelAgent:
    name = "threat_intel"

    def __init__(
        self,
        sources: list[ThreatIntelSource],
        attack_kb: AttackKnowledgeBase,
        classifier: NetworkClassifier,
        max_lookups: int = 10,
        cache_hours: int = 24,
        internal_domain_suffixes: list[str] | None = None,
    ) -> None:
        self.sources = sources
        self.attack_kb = attack_kb
        self.classifier = classifier
        self.max_lookups = max_lookups
        self.cache_ttl = timedelta(hours=cache_hours)
        self.internal_suffixes = tuple(s.lower() for s in (internal_domain_suffixes or []))

    # --- privacy filter --------------------------------------------------------------------
    def _is_external_service(self, source: ThreatIntelSource) -> bool:
        return source.name == "virustotal"

    def _shareable(self, entity: Entity) -> bool:
        """May this indicator leave the lab (be sent to a public reputation service)?"""
        if entity.type == EntityType.IP:
            return self.classifier.is_global(entity.value) and not self.classifier.is_internal(entity.value)
        if entity.type == EntityType.DOMAIN:
            return "." in entity.value and not entity.value.lower().endswith(self.internal_suffixes)
        if entity.type == EntityType.URL:
            host = entity.value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
            return "." in host and not host.endswith(self.internal_suffixes)
        return entity.type == EntityType.HASH

    # --- enrichment ---------------------------------------------------------------------------
    def indicators(self, entities: list[Entity]) -> list[Entity]:
        candidates = [e for e in entities if e.type in LOOKUP_ORDER]
        candidates.sort(key=lambda e: LOOKUP_ORDER.index(e.type))
        return candidates[: self.max_lookups]

    def enrich(
        self, session: Session, entities: list[Entity], technique_ids: list[str]
    ) -> tuple[list[ThreatIntelResult], list[AttackTechnique]]:
        results: list[ThreatIntelResult] = []
        for entity in self.indicators(entities):
            results.extend(self._lookup_cached(session, entity))
        return results, self.attack_kb.describe(technique_ids)

    def _lookup_cached(self, session: Session, entity: Entity) -> list[ThreatIntelResult]:
        now = datetime.now(UTC)
        row = session.execute(select(IOC).where(IOC.indicator == entity.value)).scalar_one_or_none()
        if row and now - row.last_checked < self.cache_ttl:
            row.sightings += 1
            return [ThreatIntelResult.model_validate({**r, "cached": True}) for r in row.details.get("results", [])]

        results = []
        for source in self.sources:
            if self._is_external_service(source) and not self._shareable(entity):
                continue
            try:
                results.append(source.lookup(entity.value, entity.type))
            except Exception as exc:  # noqa: BLE001 - one failing source must not stop enrichment
                log.warning("%s lookup failed for %s: %s", source.name, entity.value, exc)
                results.append(
                    ThreatIntelResult(
                        indicator=entity.value,
                        indicator_type=entity.type,
                        source=source.name,
                        details={"error": f"{type(exc).__name__}: {exc}"[:300]},
                    )
                )
        self._store(session, row, entity, results, now)
        return results

    @staticmethod
    def _store(
        session: Session, row: IOC | None, entity: Entity, results: list[ThreatIntelResult], now: datetime
    ) -> None:
        # Do not cache lookups that errored: they should be retried next time.
        cacheable = [r for r in results if "error" not in r.details]
        worst = max((r.verdict for r in cacheable), key=lambda v: VERDICT_RANK[v], default=ThreatIntelVerdict.UNKNOWN)
        details: dict[str, Any] = {"results": [r.model_dump(mode="json") for r in cacheable]}
        if row is None:
            row = IOC(indicator=entity.value, ioc_type=entity.type.value, sightings=0)
            session.add(row)
        row.verdict = worst.value
        row.sources = sorted({r.source for r in cacheable})
        row.details = details
        row.score = max((r.score for r in cacheable if r.score is not None), default=None)
        row.sightings = (row.sightings or 0) + 1
        row.last_checked = now if len(cacheable) == len(results) else now - timedelta(days=365)
        session.flush()
