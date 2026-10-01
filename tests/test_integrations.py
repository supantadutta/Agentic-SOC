import json
from datetime import UTC, datetime

import httpx
import pytest

from agentic_soc.agents.enrichment_agent import StaticThreatIntel, ThreatIntelAgent
from agentic_soc.database.session import Database
from agentic_soc.integrations.misp import MISPClient
from agentic_soc.integrations.mitre import AttackKnowledgeBase
from agentic_soc.integrations.virustotal import QuotaExceeded, RateLimiter, VirusTotalClient
from agentic_soc.integrations.wazuh import NetworkClassifier, WazuhIndexerClient
from agentic_soc.models.schemas import Entity, EntityType, ThreatIntelVerdict


def test_misp_lookup_parses_attributes():
    def handler(request):
        assert request.headers["Authorization"] == "misp-key"
        assert json.loads(request.content)["value"] == "203.0.113.45"
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "to_ids": True,
                            "category": "Network activity",
                            "type": "ip-dst",
                            "Event": {"id": "12", "info": "Lab C2", "threat_level_id": "1"},
                            "Tag": [{"name": "tlp:amber"}],
                        }
                    ]
                }
            },
        )

    client = MISPClient("https://misp", "misp-key", transport=httpx.MockTransport(handler))
    result = client.lookup("203.0.113.45", EntityType.IP)
    assert result.verdict == ThreatIntelVerdict.MALICIOUS
    assert result.details["tags"] == ["tlp:amber"]
    assert MISPClient.to_result("x", EntityType.IP, []).verdict == ThreatIntelVerdict.UNKNOWN


def test_virustotal_lookup_and_url_ids():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 20}
                    }
                }
            },
        )

    vt = VirusTotalClient("vt-key", transport=httpx.MockTransport(handler))
    assert vt.lookup("8.8.8.8", EntityType.IP).verdict == ThreatIntelVerdict.MALICIOUS
    vt.lookup("http://evil.example/a", EntityType.URL)
    assert seen[-1] == "/api/v3/urls/aHR0cDovL2V2aWwuZXhhbXBsZS9h"


def test_rate_limiter_enforces_minute_and_daily_quota():
    now = [0.0]
    limiter = RateLimiter(per_minute=2, per_day=3, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    limiter.acquire()
    limiter.acquire()
    with pytest.raises(QuotaExceeded):
        limiter.acquire()  # third call inside the minute, no waiting allowed
    limiter.acquire(max_wait=60)  # waits for the window, uses the 3rd daily slot
    with pytest.raises(QuotaExceeded):
        limiter.acquire(max_wait=60)


class CountingSource(StaticThreatIntel):
    def __init__(self, name, verdicts):
        super().__init__(verdicts)
        self.name = name
        self.calls = []

    def lookup(self, indicator, indicator_type):
        self.calls.append(indicator)
        return super().lookup(indicator, indicator_type)


def test_threat_intel_privacy_filter_and_cache(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'ti.db'}")
    db.create_all()
    misp = CountingSource("misp", {"192.168.50.100": "suspicious"})
    vt = CountingSource("virustotal", {"8.8.4.4": "harmless"})
    agent = ThreatIntelAgent(
        [misp, vt],
        AttackKnowledgeBase.builtin(),
        NetworkClassifier(["192.168.50.0/24"]),
        internal_domain_suffixes=[".local"],
    )
    entities = [
        Entity(type=EntityType.IP, value="192.168.50.100"),
        Entity(type=EntityType.IP, value="8.8.4.4"),
        Entity(type=EntityType.DOMAIN, value="dc01.lab.local"),
        Entity(type=EntityType.USER, value="bob"),
    ]
    with db.session() as s:
        results, techniques = agent.enrich(s, entities, ["T1059.001"])
    assert vt.calls == ["8.8.4.4"], "internal IPs and domains never reach VirusTotal"
    assert sorted(misp.calls) == ["192.168.50.100", "8.8.4.4", "dc01.lab.local"]
    assert techniques[0].name == "PowerShell"
    with db.session() as s:
        cached, _ = agent.enrich(s, entities, [])
    assert len(misp.calls) == 3 and all(r.cached for r in cached)


def test_attack_kb_loads_stix_bundle(tmp_path):
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "PowerShell",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            },
            {
                "type": "attack-pattern",
                "name": "Old",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            },
        ]
    }
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(bundle))
    kb = AttackKnowledgeBase.load(path)
    assert kb.is_complete and kb.is_valid("T1059.001") and not kb.is_valid("T9999")
    assert not kb.is_valid("T1105")  # not in this bundle, so rejected as unknown
    assert AttackKnowledgeBase.builtin().is_valid("T1105.999")  # builtin subset only checks the format


def test_indexer_related_query():
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"hits": {"hits": [{"_source": {"id": "1", "rule": {"id": "5710"}}}]}})

    client = WazuhIndexerClient("https://idx:9200", "u", "p", transport=httpx.MockTransport(handler))
    now = datetime(2026, 1, 1, tzinfo=UTC)
    hits = client.search_related([Entity(type=EntityType.USER, value="bob")], now, now)
    assert captured["path"] == "/wazuh-alerts-*/_search"
    assert {"term": {"data.dstuser": "bob"}} in captured["body"]["query"]["bool"]["should"]
    assert hits[0]["rule"]["id"] == "5710"
