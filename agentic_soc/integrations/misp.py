"""MISP threat-intelligence lookups (attribute restSearch).

External threat intelligence is treated as *evidence to correlate*, never as an automatic
instruction to block an indicator.
"""

from __future__ import annotations

from typing import Any

import httpx

from agentic_soc.models.schemas import EntityType, ThreatIntelResult, ThreatIntelVerdict


class MISPClient:
    name = "misp"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool | str = True,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            verify=verify,
            timeout=timeout,
            transport=transport,
            headers={"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"},
        )

    def lookup(self, indicator: str, indicator_type: EntityType) -> ThreatIntelResult:
        resp = self._client.post(
            f"{self.base_url}/attributes/restSearch",
            json={"returnFormat": "json", "value": indicator, "limit": 50, "includeEventTags": True},
        )
        resp.raise_for_status()
        attributes = resp.json().get("response", {}).get("Attribute", []) or []
        return self.to_result(indicator, indicator_type, attributes)

    @staticmethod
    def to_result(indicator: str, indicator_type: EntityType, attributes: list[dict[str, Any]]) -> ThreatIntelResult:
        if not attributes:
            return ThreatIntelResult(indicator=indicator, indicator_type=indicator_type, source="misp")
        ids_hits = [a for a in attributes if a.get("to_ids") in (True, "1", 1)]
        events = []
        tags: set[str] = set()
        for attr in attributes[:10]:
            event = attr.get("Event") or {}
            events.append(
                {
                    "event_id": event.get("id") or attr.get("event_id"),
                    "info": event.get("info"),
                    "threat_level_id": event.get("threat_level_id"),
                    "category": attr.get("category"),
                    "type": attr.get("type"),
                    "to_ids": attr.get("to_ids"),
                }
            )
            for tag in attr.get("Tag") or []:
                if tag.get("name"):
                    tags.add(tag["name"])
        verdict = ThreatIntelVerdict.MALICIOUS if ids_hits else ThreatIntelVerdict.SUSPICIOUS
        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            source="misp",
            verdict=verdict,
            score=min(1.0, 0.5 + 0.1 * len(ids_hits)) if ids_hits else 0.4,
            details={"hits": len(attributes), "ids_hits": len(ids_hits), "events": events, "tags": sorted(tags)},
        )

    def close(self) -> None:
        self._client.close()
