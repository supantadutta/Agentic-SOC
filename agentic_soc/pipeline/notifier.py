"""Optional outbound notifications (e.g. an n8n webhook that forwards to chat or e-mail)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


class Notifier:
    def __init__(
        self, webhook_url: str | None, timeout: float = 5.0, transport: httpx.BaseTransport | None = None
    ) -> None:
        self.webhook_url = webhook_url
        self._client = httpx.Client(timeout=timeout, transport=transport) if webhook_url else None

    def send(self, event: dict[str, Any]) -> None:
        if not self._client or not self.webhook_url:
            return
        try:
            self._client.post(self.webhook_url, json=event).raise_for_status()
        except httpx.HTTPError as exc:  # notifications must never break the pipeline
            log.warning("notification webhook failed: %s", exc)
