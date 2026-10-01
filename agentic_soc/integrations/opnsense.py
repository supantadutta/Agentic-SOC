"""OPNsense firewall alias management (controlled IOC blocking).

Blocking works by adding addresses to a pre-created *host alias* that is referenced by a
block rule on the lab firewall, so the orchestrator never edits firewall rules directly.
"""

from __future__ import annotations

from typing import Any

import httpx


class OPNsenseClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        verify: bool | str = True,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(verify=verify, timeout=timeout, auth=(api_key, api_secret), transport=transport)

    def _post(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._client.post(f"{self.base_url}/api/{path}", json=payload or {})
        resp.raise_for_status()
        return resp.json()

    def add_to_alias(self, alias: str, address: str) -> dict[str, Any]:
        return self._post(f"firewall/alias_util/add/{alias}", {"address": address})

    def remove_from_alias(self, alias: str, address: str) -> dict[str, Any]:
        return self._post(f"firewall/alias_util/delete/{alias}", {"address": address})

    def list_alias(self, alias: str) -> dict[str, Any]:
        resp = self._client.get(f"{self.base_url}/api/firewall/alias_util/list/{alias}")
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._client.close()
