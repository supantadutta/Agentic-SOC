"""VirusTotal v3 reputation lookups with rate limiting and a daily quota.

Only *lookups* are performed: nothing is ever uploaded or submitted, and callers must not
pass internal/private indicators (the enrichment agent filters them).
"""

from __future__ import annotations

import base64
import threading
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any

import httpx

from agentic_soc.models.schemas import EntityType, ThreatIntelResult, ThreatIntelVerdict


class QuotaExceeded(RuntimeError):
    pass


class RateLimiter:
    """Sliding-window limiter (requests per minute) plus a daily quota."""

    def __init__(self, per_minute: int, per_day: int, clock=time.monotonic, sleep=time.sleep) -> None:
        self.per_minute = per_minute
        self.per_day = per_day
        self._clock = clock
        self._sleep = sleep
        self._window: deque[float] = deque()
        self._day = datetime.now(UTC).date()
        self._day_count = 0
        self._lock = threading.Lock()

    def acquire(self, max_wait: float = 0.0) -> None:
        with self._lock:
            today = datetime.now(UTC).date()
            if today != self._day:
                self._day, self._day_count = today, 0
            if self._day_count >= self.per_day:
                raise QuotaExceeded("VirusTotal daily quota exhausted")
            now = self._clock()
            while self._window and now - self._window[0] >= 60:
                self._window.popleft()
            if len(self._window) >= self.per_minute:
                wait = 60 - (now - self._window[0])
                if wait > max_wait:
                    raise QuotaExceeded(f"VirusTotal per-minute limit reached (retry in {wait:.0f}s)")
                self._sleep(wait)
                now = self._clock()
                self._window.popleft()
            self._window.append(now)
            self._day_count += 1


class VirusTotalClient:
    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"
    PATHS = {
        EntityType.IP: "ip_addresses",
        EntityType.DOMAIN: "domains",
        EntityType.HASH: "files",
        EntityType.URL: "urls",
    }

    def __init__(
        self,
        api_key: str,
        per_minute: int = 4,
        per_day: int = 500,
        malicious_threshold: int = 3,
        timeout: float = 15.0,
        max_wait: float = 0.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.limiter = RateLimiter(per_minute, per_day)
        self.malicious_threshold = malicious_threshold
        self.max_wait = max_wait
        self._client = httpx.Client(
            timeout=timeout, transport=transport, headers={"x-apikey": api_key, "Accept": "application/json"}
        )

    @staticmethod
    def _object_id(indicator: str, indicator_type: EntityType) -> str:
        if indicator_type == EntityType.URL:
            return base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        return indicator

    def supports(self, indicator_type: EntityType) -> bool:
        return indicator_type in self.PATHS

    def lookup(self, indicator: str, indicator_type: EntityType) -> ThreatIntelResult:
        if not self.supports(indicator_type):
            return ThreatIntelResult(indicator=indicator, indicator_type=indicator_type, source=self.name)
        self.limiter.acquire(self.max_wait)
        path = self.PATHS[indicator_type]
        resp = self._client.get(f"{self.BASE_URL}/{path}/{self._object_id(indicator, indicator_type)}")
        if resp.status_code == 404:
            return ThreatIntelResult(
                indicator=indicator, indicator_type=indicator_type, source=self.name, details={"found": False}
            )
        resp.raise_for_status()
        attributes = resp.json().get("data", {}).get("attributes", {})
        return self.to_result(indicator, indicator_type, attributes)

    def to_result(self, indicator: str, indicator_type: EntityType, attributes: dict[str, Any]) -> ThreatIntelResult:
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        if malicious >= self.malicious_threshold:
            verdict = ThreatIntelVerdict.MALICIOUS
        elif malicious or suspicious:
            verdict = ThreatIntelVerdict.SUSPICIOUS
        elif harmless:
            verdict = ThreatIntelVerdict.HARMLESS
        else:
            verdict = ThreatIntelVerdict.UNKNOWN
        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            source=self.name,
            verdict=verdict,
            score=round(malicious / total, 3) if total else None,
            details={
                "found": True,
                "last_analysis_stats": stats,
                "reputation": attributes.get("reputation"),
                "tags": attributes.get("tags", [])[:10],
            },
        )

    def close(self) -> None:
        self._client.close()
