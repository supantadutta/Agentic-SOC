"""Wazuh integration: alert normalization, Wazuh server API (active response) and indexer search."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import httpx

from agentic_soc.models.schemas import Entity, EntityType, NormalizedAlert

log = logging.getLogger(__name__)

NETWORK_SOURCES = {"suricata", "zeek"}
NON_HUMAN_ACCOUNTS = {
    "system",
    "local service",
    "network service",
    "-",
    "anonymous logon",
    "dwm-1",
    "umfd-0",
    "umfd-1",
}
_HASH_ALGOS = {"sha256": 64, "sha1": 40, "md5": 32}


def _get(data: Any, path: str) -> Any:
    """Look up a dotted path, accepting both nested keys and literal dotted keys (Zeek's ``id.orig_h``)."""
    if not isinstance(data, dict) or not path:
        return None
    parts = path.split(".")
    for i in range(len(parts), 0, -1):
        key = ".".join(parts[:i])
        if key in data:
            if i == len(parts):
                return data[key]
            found = _get(data[key], ".".join(parts[i:]))
            if found is not None:
                return found
    return None


def _first(data: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _get(data, path)
        if value not in (None, "", [], {}):
            return value
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _valid_ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        ts = value
    elif isinstance(value, str) and value:
        text = value.strip().replace("Z", "+00:00")
        # Wazuh uses "+0000"; fromisoformat in 3.11 accepts it, but normalize defensively.
        text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
        ts = datetime.fromisoformat(text)
    else:
        ts = datetime.now(UTC)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)


def normalize_user(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    name = value.strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    if not name or name.lower() in NON_HUMAN_ACCOUNTS or name.endswith("$"):
        return None
    return name


def parse_hashes(value: Any) -> dict[str, str]:
    """Parse Sysmon ``SHA1=..,MD5=..,SHA256=..`` strings or plain hex digests."""
    hashes: dict[str, str] = {}
    if not value or not isinstance(value, str):
        return hashes
    for part in value.split(","):
        if "=" in part:
            algo, digest = part.split("=", 1)
            algo = algo.strip().lower()
            digest = digest.strip().lower()
        else:
            digest = part.strip().lower()
            algo = next((a for a, n in _HASH_ALGOS.items() if len(digest) == n), "")
        if algo in _HASH_ALGOS and re.fullmatch(r"[0-9a-f]+", digest) and len(digest) == _HASH_ALGOS[algo]:
            hashes[algo] = digest
    return hashes


def detect_source(alert: dict[str, Any]) -> str:
    groups = [g.lower() for g in _get(alert, "rule.groups") or []]
    data = alert.get("data") or {}
    if "suricata" in groups or ("event_type" in data and "alert" in data and "src_ip" in data):
        return "suricata"
    label = str(_first(alert, "data.agentic_source", "agentic_source") or "")
    if "zeek" in groups or label.startswith("zeek") or _get(data, "id.orig_h") is not None:
        return "zeek"
    if "sysmon" in groups:
        return "sysmon"
    if "windows" in groups:
        return "windows"
    if "syscheck" in groups:
        return "fim"
    return "wazuh"


class NetworkClassifier:
    def __init__(self, internal_cidrs: Iterable[str] | None = None) -> None:
        self.networks = [ipaddress.ip_network(c, strict=False) for c in (internal_cidrs or [])]

    def is_internal(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        if self.networks:
            return any(addr in net for net in self.networks) or addr.is_loopback or addr.is_link_local
        return addr.is_private or addr.is_loopback or addr.is_link_local

    @staticmethod
    def is_global(ip: str) -> bool:
        return ipaddress.ip_address(ip).is_global


def normalize_wazuh_alert(alert: dict[str, Any], classifier: NetworkClassifier | None = None) -> NormalizedAlert:
    """Convert a raw Wazuh alert (alerts.json format) into a NormalizedAlert with entities."""
    classifier = classifier or NetworkClassifier()
    source = detect_source(alert)

    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    mitre_ids = [str(t).upper() for t in (_get(rule, "mitre.id") or [])]

    src_ip = _valid_ip(
        _first(
            alert,
            "data.srcip",
            "data.src_ip",
            "data.win.eventdata.ipAddress",
            "data.win.eventdata.sourceIp",
            "data.id.orig_h",
        )
    )
    dst_ip = _valid_ip(
        _first(alert, "data.dstip", "data.dest_ip", "data.win.eventdata.destinationIp", "data.id.resp_h")
    )
    raw_user = _first(
        alert,
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.user",
        "data.dstuser",
        "data.srcuser",
        "data.audit.auid_name",
    )
    hashes = parse_hashes(_first(alert, "data.win.eventdata.hashes", "data.fileinfo.sha256", "data.sha256"))
    for algo in ("sha256", "md5", "sha1"):
        digest = _get(alert, f"syscheck.{algo}_after")
        if digest:
            hashes.update(parse_hashes(f"{algo}={digest}"))

    http_host = _first(alert, "data.http.hostname", "data.host")
    http_path = _first(alert, "data.http.url", "data.uri")
    url = _first(alert, "data.url")
    if not url and http_host and http_path:
        url = f"http://{http_host}{http_path}"
    domain = (
        _first(
            alert,
            "data.win.eventdata.queryName",
            "data.dns.rrname",
            "data.query",
            "data.win.eventdata.destinationHostname",
        )
        or http_host
    )

    normalized = NormalizedAlert(
        wazuh_id=str(alert.get("id")) if alert.get("id") else None,
        timestamp=parse_timestamp(alert.get("timestamp")),
        source=source,
        rule_id=str(rule.get("id", "0")),
        rule_level=_as_int(rule.get("level")) or 0,
        rule_description=str(rule.get("description", "")),
        rule_groups=[str(g) for g in rule.get("groups") or []],
        mitre_ids=mitre_ids,
        agent_id=str(agent["id"]) if agent.get("id") is not None else None,
        agent_name=agent.get("name"),
        agent_ip=_valid_ip(agent.get("ip")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_as_int(
            _first(alert, "data.srcport", "data.src_port", "data.win.eventdata.sourcePort", "data.id.orig_p")
        ),
        dst_port=_as_int(
            _first(alert, "data.dstport", "data.dest_port", "data.win.eventdata.destinationPort", "data.id.resp_p")
        ),
        user=normalize_user(raw_user),
        process=_first(alert, "data.win.eventdata.image", "data.audit.exe"),
        parent_process=_first(alert, "data.win.eventdata.parentImage"),
        command_line=_first(alert, "data.win.eventdata.commandLine", "data.audit.command"),
        hashes=hashes,
        url=str(url) if url else None,
        domain=str(domain).lower().rstrip(".") if domain else None,
        file_path=_first(alert, "syscheck.path", "data.win.eventdata.targetFilename"),
        signature=_first(alert, "data.alert.signature", "data.note", "data.msg"),
    )
    normalized.entities = extract_entities(normalized, classifier)
    return normalized


def extract_entities(alert: NormalizedAlert, classifier: NetworkClassifier) -> list[Entity]:
    entities: dict[tuple[str, str], Entity] = {}

    def add(etype: EntityType, value: str | None, **attrs: Any) -> None:
        if not value:
            return
        entity = Entity(type=etype, value=str(value), attributes={k: v for k, v in attrs.items() if v is not None})
        entities.setdefault(entity.key, entity)

    for ip, role in ((alert.src_ip, "source"), (alert.dst_ip, "destination")):
        if ip:
            add(EntityType.IP, ip, internal=classifier.is_internal(ip), role=role)
    # Network sensors observe traffic; the sensor itself is not the affected host.
    if alert.source not in NETWORK_SOURCES:
        add(EntityType.HOST, alert.agent_name, agent_id=alert.agent_id, ip=alert.agent_ip)
        # The host's own address links endpoint alerts with network alerts about that host.
        if alert.agent_ip and alert.agent_ip not in ("any", "127.0.0.1"):
            add(
                EntityType.IP,
                alert.agent_ip,
                internal=classifier.is_internal(alert.agent_ip),
                role="host",
                host=alert.agent_name,
            )
    add(EntityType.USER, alert.user)
    if alert.process:
        add(EntityType.PROCESS, alert.process)
    for algo in ("sha256", "sha1", "md5"):
        if algo in alert.hashes:
            add(EntityType.HASH, alert.hashes[algo], algorithm=algo)
            break
    add(EntityType.DOMAIN, alert.domain)
    add(EntityType.URL, alert.url)
    return list(entities.values())


def alert_fingerprint(alert: NormalizedAlert) -> str:
    """Stable fingerprint used for deduplication (timestamp deliberately excluded)."""
    parts = [
        alert.rule_id,
        alert.agent_id or "",
        alert.src_ip or "",
        alert.dst_ip or "",
        alert.user or "",
        (alert.process or "").lower(),
        alert.command_line or "",
        alert.hashes.get("sha256", ""),
        alert.domain or "",
        alert.url or "",
        alert.file_path or "",
        alert.signature or "",
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


class WazuhAPIError(RuntimeError):
    pass


class WazuhAPIClient:
    """Minimal Wazuh server API client (JWT auth, agent lookup, active response)."""

    TOKEN_TTL_SECONDS = 800  # Wazuh tokens expire after 900 s by default

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        verify: bool | str = True,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._auth = (user, password)
        self._client = httpx.Client(verify=verify, timeout=timeout, transport=transport)
        self._token: str | None = None
        self._token_at = 0.0

    def _headers(self) -> dict[str, str]:
        if not self._token or time.monotonic() - self._token_at > self.TOKEN_TTL_SECONDS:
            resp = self._client.post(f"{self.base_url}/security/user/authenticate", auth=self._auth)
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            self._token_at = time.monotonic()
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        resp = self._client.request(method, f"{self.base_url}{path}", headers=self._headers(), **kwargs)
        if resp.status_code == 401:  # token revoked/expired early: retry once
            self._token = None
            resp = self._client.request(method, f"{self.base_url}{path}", headers=self._headers(), **kwargs)
        resp.raise_for_status()
        body = resp.json()
        if body.get("error", 0) not in (0, None):
            raise WazuhAPIError(f"Wazuh API error: {body}")
        return body

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        body = self._request(
            "GET", "/agents", params={"agents_list": agent_id, "select": "id,name,ip,status,os.platform"}
        )
        items = body.get("data", {}).get("affected_items", [])
        return items[0] if items else None

    def find_agent_by_ip(self, ip: str) -> dict[str, Any] | None:
        body = self._request("GET", "/agents", params={"q": f"ip={ip}", "select": "id,name,ip,status,os.platform"})
        items = body.get("data", {}).get("affected_items", [])
        return items[0] if items else None

    def run_active_response(
        self,
        agent_ids: list[str],
        command: str,
        arguments: list[str] | None = None,
        alert_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"command": command, "arguments": arguments or []}
        if alert_data is not None:
            payload["alert"] = {"data": alert_data}
        body = self._request("PUT", "/active-response", params={"agents_list": ",".join(agent_ids)}, json=payload)
        failed = body.get("data", {}).get("failed_items") or []
        if failed:
            raise WazuhAPIError(f"active response failed on agents: {failed}")
        return body

    def close(self) -> None:
        self._client.close()


class WazuhIndexerClient:
    """Query historical alerts in the Wazuh indexer (OpenSearch)."""

    ENTITY_FIELDS = {
        EntityType.HOST: ["agent.name"],
        EntityType.IP: ["data.srcip", "data.dstip", "data.src_ip", "data.dest_ip", "data.win.eventdata.ipAddress"],
        EntityType.USER: ["data.win.eventdata.targetUserName", "data.dstuser", "data.srcuser"],
        EntityType.HASH: ["syscheck.sha256_after"],
        EntityType.DOMAIN: ["data.win.eventdata.queryName", "data.dns.rrname"],
    }

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        verify: bool | str = True,
        timeout: float = 15.0,
        index: str = "wazuh-alerts-*",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.index = index
        self._client = httpx.Client(verify=verify, timeout=timeout, auth=(user, password), transport=transport)

    def _entity_query(self, entities: Iterable[Entity]) -> list[dict[str, Any]]:
        should = []
        for entity in entities:
            for field in self.ENTITY_FIELDS.get(entity.type, []):
                should.append({"term": {field: entity.value}})
        return should

    def search_related(
        self, entities: Iterable[Entity], since: datetime, until: datetime, size: int = 25
    ) -> list[dict[str, Any]]:
        should = self._entity_query(entities)
        if not should:
            return []
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "should": should,
                    "minimum_should_match": 1,
                    "filter": [{"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}}],
                }
            },
        }
        resp = self._client.post(f"{self.base_url}/{self.index}/_search", json=query)
        resp.raise_for_status()
        return [hit["_source"] for hit in resp.json().get("hits", {}).get("hits", [])]

    def count_sightings(self, entity: Entity, since: datetime) -> int:
        should = self._entity_query([entity])
        if not should:
            return 0
        query = {
            "query": {
                "bool": {
                    "should": should,
                    "minimum_should_match": 1,
                    "filter": [{"range": {"timestamp": {"gte": since.isoformat()}}}],
                }
            }
        }
        resp = self._client.post(f"{self.base_url}/{self.index}/_count", json=query)
        resp.raise_for_status()
        return int(resp.json().get("count", 0))

    def close(self) -> None:
        self._client.close()
