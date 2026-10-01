"""Investigation Agent: alert + historical context -> related alerts and entities.

Looks for (1) earlier incidents in the research database that share entities with the
alert and (2) lower-level Wazuh alerts in the indexer that never reached the orchestrator
(the integration forwards only alerts above a level threshold) but add context.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentic_soc.database.models import Alert, EntityRecord, Incident, alert_entities
from agentic_soc.integrations.wazuh import WazuhIndexerClient
from agentic_soc.models.schemas import NormalizedAlert

log = logging.getLogger(__name__)


class InvestigationAgent:
    name = "investigation"

    def __init__(
        self, indexer: WazuhIndexerClient | None = None, lookback_hours: int = 24, max_results: int = 10
    ) -> None:
        self.indexer = indexer
        self.lookback = timedelta(hours=lookback_hours)
        self.max_results = max_results

    def investigate(self, session: Session, incident_id: int, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "related_incidents": self._related_incidents(session, incident_id, alert),
            "siem_related_alerts": self._siem_related(alert),
        }

    def _related_incidents(self, session: Session, incident_id: int, alert: NormalizedAlert) -> list[dict]:
        keys = [(e.type.value, e.value) for e in alert.entities]
        if not keys:
            return []
        since = alert.timestamp - self.lookback
        rows = session.execute(
            select(Alert.incident_id, EntityRecord.type, EntityRecord.value)
            .join(alert_entities, alert_entities.c.alert_id == Alert.id)
            .join(EntityRecord, EntityRecord.id == alert_entities.c.entity_id)
            .where(Alert.incident_id.is_not(None))
            .where(Alert.incident_id != incident_id)
            .where(Alert.timestamp >= since)
        ).all()
        wanted = {(t, v.lower()) for t, v in keys}
        shared: dict[int, set[str]] = defaultdict(set)
        for inc_id, etype, value in rows:
            if (etype, value.lower()) in wanted:
                shared[inc_id].add(f"{etype}:{value}")
        if not shared:
            return []
        incidents = session.execute(select(Incident).where(Incident.id.in_(shared))).scalars()
        out = [
            {
                "incident_id": inc.id,
                "title": inc.title,
                "status": inc.status,
                "classification": inc.classification,
                "severity": inc.severity,
                "disposition": inc.disposition,
                "shared_entities": sorted(shared[inc.id]),
            }
            for inc in incidents
        ]
        out.sort(key=lambda r: len(r["shared_entities"]), reverse=True)
        return out[: self.max_results]

    def _siem_related(self, alert: NormalizedAlert) -> list[dict]:
        if not self.indexer:
            return []
        try:
            hits = self.indexer.search_related(
                alert.entities, alert.timestamp - self.lookback, alert.timestamp, size=self.max_results
            )
        except Exception as exc:  # noqa: BLE001 - context is best effort
            log.warning("indexer search failed: %s", exc)
            return [{"error": f"indexer search failed: {type(exc).__name__}"}]
        return [
            {
                "timestamp": hit.get("timestamp"),
                "rule_id": (hit.get("rule") or {}).get("id"),
                "level": (hit.get("rule") or {}).get("level"),
                "description": (hit.get("rule") or {}).get("description"),
                "agent": (hit.get("agent") or {}).get("name"),
            }
            for hit in hits
            if str(hit.get("id")) != str(alert.wazuh_id)
        ]
