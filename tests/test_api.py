import json

import pytest
from fastapi.testclient import TestClient

from agentic_soc.api.app import create_app
from evaluation import scenarios as sc

INGEST = {"Authorization": "Bearer ingest-secret"}
ALICE = {"Authorization": "Bearer alice-secret"}


@pytest.fixture
def client(settings, make_orchestrator):
    scenario = sc.phishing_powershell(0)
    app = create_app(settings, make_orchestrator(threat_intel=scenario.threat_intel), start_worker=False)
    with TestClient(app) as test_client:
        yield test_client


def ingest(client, alert, sync=True):
    return client.post(f"/api/v1/alerts/wazuh?sync={str(sync).lower()}", content=json.dumps(alert), headers=INGEST)


def test_health_endpoints(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json()["execution_mode"] == "dry_run"


def test_ingest_requires_key(client):
    alert = sc.benign_failed_ssh(0).alerts[0]
    assert client.post("/api/v1/alerts/wazuh", json=alert).status_code == 401
    assert client.post("/api/v1/alerts/wazuh", json=alert, headers=ALICE).status_code == 401
    assert client.post("/api/v1/alerts/wazuh", json=alert, headers={"X-API-Key": "ingest-secret"}).status_code == 202


def test_ingest_validation(client):
    assert client.post("/api/v1/alerts/wazuh", content="{nope", headers=INGEST).status_code == 400
    assert client.post("/api/v1/alerts/wazuh", json={"no": "rule"}, headers=INGEST).status_code == 422


def test_async_ingest_queues(client):
    resp = ingest(client, sc.benign_failed_ssh(0).alerts[0], sync=False)
    assert resp.status_code == 202 and resp.json()["queued"] is True


def test_analyst_workflow(client):
    for alert in sc.phishing_powershell(0).alerts:
        assert ingest(client, alert).status_code == 202

    assert client.get("/api/v1/approvals").status_code == 401
    pending = client.get("/api/v1/approvals", headers=ALICE).json()
    assert len(pending) == 1 and pending[0]["action"] == "ISOLATE_HOST"
    outcome = {"approval_id": pending[0]["id"], "incident_id": pending[0]["incident_id"]}

    decided = client.post(
        f"/api/v1/approvals/{outcome['approval_id']}/decision",
        json={"approve": True, "comment": "confirmed"},
        headers=ALICE,
    )
    assert decided.status_code == 200 and decided.json()["playbook_status"] == "dry_run"
    again = client.post(f"/api/v1/approvals/{outcome['approval_id']}/decision", json={"approve": True}, headers=ALICE)
    assert again.status_code == 409

    incident = client.get(f"/api/v1/incidents/{outcome['incident_id']}", headers=ALICE).json()
    assert incident["status"] == "contained"
    assert incident["playbook_runs"][0]["triggered_by"] == "analyst:alice"
    assert "raw" not in incident["alerts"][0]

    audit = client.get(f"/api/v1/incidents/{outcome['incident_id']}/audit", headers=ALICE).json()
    assert audit["chain"]["valid"] is True
    assert audit["events"][-1]["stage"] == "RESULT"
    human = next(e for e in audit["events"] if e["stage"] == "HUMAN_DECISION")
    assert human["actor"] == "analyst:alice"

    disposition = client.post(
        f"/api/v1/incidents/{outcome['incident_id']}/disposition", json={"disposition": "true_positive"}, headers=ALICE
    )
    assert disposition.json()["status"] == "closed"

    metrics = client.get("/api/v1/metrics", headers=ALICE).json()
    assert metrics["alerts_unique"] == 6 and metrics["playbook_runs"] == {"dry_run": 1}
