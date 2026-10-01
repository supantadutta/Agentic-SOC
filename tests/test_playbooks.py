import json

import httpx
import pytest

from agentic_soc.integrations.opnsense import OPNsenseClient
from agentic_soc.integrations.wazuh import WazuhAPIClient
from agentic_soc.models.schemas import Entity, EntityType, PlaybookStatus, ThreatIntelResult, ThreatIntelVerdict
from agentic_soc.playbooks import build_playbooks
from agentic_soc.playbooks.base import PlaybookContext, ResponseServices

HOST = Entity(type=EntityType.HOST, value="win-client01", attributes={"agent_id": "002", "ip": "192.168.50.60"})
DC = Entity(type=EntityType.HOST, value="dc01", attributes={"agent_id": "001", "ip": "192.168.50.50"})
BOB = Entity(type=EntityType.USER, value="bob")


def wazuh_mock(calls):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(
            (
                request.method,
                request.url.path,
                dict(request.url.params),
                json.loads(request.content) if request.content else None,
            )
        )
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        if request.url.path == "/agents":
            return httpx.Response(
                200,
                json={
                    "error": 0,
                    "data": {
                        "affected_items": [
                            {
                                "id": "002",
                                "name": "win-client01",
                                "ip": "192.168.50.60",
                                "status": "active",
                                "os": {"platform": "windows"},
                            }
                        ]
                    },
                },
            )
        if request.url.path == "/active-response":
            return httpx.Response(
                200,
                json={
                    "error": 0,
                    "message": "AR command was sent",
                    "data": {"affected_items": ["002"], "failed_items": []},
                },
            )
        return httpx.Response(404)

    return WazuhAPIClient("https://wazuh:55000", "u", "p", transport=httpx.MockTransport(handler))


def services(settings, policy, **kw):
    return build_playbooks(ResponseServices(settings=settings, policy=policy, **kw))


def ctx(mode="dry_run", **kw):
    base = dict(incident_id=7, mode=mode, entities=[HOST, DC, BOB], policy_outcome="AUTO_EXECUTE")
    return PlaybookContext(**{**base, **kw})


def test_isolate_live_uses_wazuh_active_response(settings, policy):
    calls = []
    pbs = services(settings, policy, wazuh=wazuh_mock(calls))
    result = pbs["ISOLATE_HOST"].run(["win-client01"], ctx(mode="live"))
    assert result.status == PlaybookStatus.SUCCESS
    ar = [c for c in calls if c[1] == "/active-response"]
    assert ar[0][2] == {"agents_list": "002"}
    assert ar[0][3] == {"command": "agentic-isolate-windows", "arguments": ["isolate", "192.168.50.10"]}
    assert ar[1][3]["command"] == "agentic-collect-evidence-windows"
    assert [s.name for s in result.steps][:3] == [
        "confirm_host:win-client01".split(":")[0],
        "validate_policy",
        "human_approval",
    ]


def test_isolate_refuses_protected_host_without_approval(settings, policy):
    result = services(settings, policy)["ISOLATE_HOST"].run(["dc01"], ctx())
    assert result.status == PlaybookStatus.REJECTED


def test_isolate_live_without_wazuh_fails_closed(settings, policy):
    result = services(settings, policy)["ISOLATE_HOST"].run(["win-client01"], ctx(mode="live"))
    assert result.status == PlaybookStatus.REJECTED


def test_block_ip_dry_run_and_never_block(settings, policy):
    pbs = services(settings, policy)
    ti = [
        ThreatIntelResult(
            indicator="203.0.113.45", indicator_type=EntityType.IP, source="misp", verdict=ThreatIntelVerdict.MALICIOUS
        )
    ]
    ok = pbs["BLOCK_IP"].run(["203.0.113.45"], ctx(threat_intel=ti))
    assert ok.status == PlaybookStatus.DRY_RUN
    assert ok.steps[-2].data["request"] == {"alias": "AGENTIC_SOC_BLOCK", "address": "203.0.113.45"}
    assert pbs["BLOCK_IP"].run(["192.168.50.10"], ctx()).status == PlaybookStatus.REJECTED
    assert pbs["BLOCK_IP"].run(["not-an-ip"], ctx()).status == PlaybookStatus.REJECTED


def test_block_ip_refuses_harmless_reputation_without_approval(settings, policy):
    ti = [
        ThreatIntelResult(
            indicator="198.51.100.200",
            indicator_type=EntityType.IP,
            source="virustotal",
            verdict=ThreatIntelVerdict.HARMLESS,
        )
    ]
    pb = services(settings, policy)["BLOCK_IP"]
    assert pb.run(["198.51.100.200"], ctx(threat_intel=ti)).status == PlaybookStatus.REJECTED
    assert pb.run(["198.51.100.200"], ctx(threat_intel=ti, approved_by="alice")).status == PlaybookStatus.DRY_RUN


def test_block_ip_live_opnsense(settings, policy):
    calls = []

    def handler(request):
        calls.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"status": "done"})

    opn = OPNsenseClient("https://fw", "k", "s", transport=httpx.MockTransport(handler))
    result = services(settings, policy, opnsense=opn)["BLOCK_IP"].run(["203.0.113.45"], ctx(mode="live"))
    assert result.status == PlaybookStatus.SUCCESS
    assert calls == [("/api/firewall/alias_util/add/AGENTIC_SOC_BLOCK", {"address": "203.0.113.45"})]


@pytest.mark.parametrize("user", ["krbtgt", "bob; rm -rf /", "../etc"])
def test_disable_user_rejects_unsafe_targets(settings, policy, user):
    result = services(settings, policy)["DISABLE_USER"].run([user], ctx(approved_by="alice"))
    assert result.status == PlaybookStatus.REJECTED


def test_disable_user_requires_approval_and_domain_scope(settings, policy):
    alerts = [
        {
            "user": "bob",
            "source": "windows",
            "agent_id": "001",
            "rule_id": "100220",
            "rule_groups": ["authentication_failed"],
        }
    ]
    pb = services(settings.model_copy(update={"ad_dc_agent_id": "001"}), policy)["DISABLE_USER"]
    assert pb.run(["bob"], ctx(alerts=alerts)).status == PlaybookStatus.REJECTED
    result = pb.run(["bob"], ctx(alerts=alerts, approved_by="alice"))
    assert result.status == PlaybookStatus.DRY_RUN
    request = next(s for s in result.steps if s.status == "planned").data["request"]
    assert request == {
        "agents_list": ["001"],
        "command": "agentic-disable-user-windows",
        "arguments": ["disable", "bob"],
    }


def test_collect_evidence_writes_hashed_package(settings, policy, tmp_path):
    result = services(settings, policy)["COLLECT_EVIDENCE"].run(["win-client01"], ctx(alerts=[{"rule_id": "1"}]))
    assert result.status == PlaybookStatus.DRY_RUN
    package = result.output["package"]
    import hashlib
    from pathlib import Path

    body = Path(package["path"]).read_bytes()
    assert hashlib.sha256(body).hexdigest() == package["sha256"]
    assert Path(package["path"]).with_suffix(".sha256").read_text().startswith(package["sha256"])
