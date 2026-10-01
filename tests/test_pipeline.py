from sqlalchemy import select, update

from agentic_soc.database.audit import AuditStage, verify_chain
from agentic_soc.database.models import IOC, Alert, AuditEvent, HumanApproval, Incident, LLMDecision, PlaybookRun
from evaluation import scenarios as sc


def pending_approval(orch):
    with orch.db.session() as s:
        return s.execute(select(HumanApproval).where(HumanApproval.status == "pending")).scalar_one()


def stages(orch, incident_id):
    with orch.db.session() as s:
        return [
            e.stage
            for e in s.execute(
                select(AuditEvent).where(AuditEvent.incident_id == incident_id).order_by(AuditEvent.seq)
            ).scalars()
        ]


def test_phishing_scenario_end_to_end(make_orchestrator):
    scenario = sc.phishing_powershell(0)
    orch = make_orchestrator(threat_intel=scenario.threat_intel)
    outcomes = [orch.process_wazuh_alert(a) for a in scenario.alerts]

    incident_ids = {o.incident_id for o in outcomes}
    assert len(incident_ids) == 1, "all alerts correlate into one incident"
    incident_id = incident_ids.pop()

    final = [o for o in outcomes if o.status == "triaged"][-1]
    assert final.action == "ISOLATE_HOST"
    # The heuristic marks isolation as needing approval, so it must not auto-execute.
    assert final.policy_outcome == "REQUIRE_APPROVAL" and final.approval_id
    # The C2 address arrived inside the cooldown, but its malicious verdict forced a re-triage.
    assert any("threat-intel verdict" in n for o in outcomes for n in o.notes)
    assert final.approval_id == pending_approval(orch).id

    with orch.db.session() as s:
        incident = s.get(Incident, incident_id)
        assert incident.classification == "malicious"
        assert incident.status == "awaiting_approval"
        assert "execution" in incident.tactics and "command-and-control" in incident.tactics
        assert s.execute(select(IOC).where(IOC.indicator == sc.C2_IP)).scalar_one().verdict == "malicious"
        assert verify_chain(s, incident_id).valid

    observed = stages(orch, incident_id)
    for stage in ("ALERT", "ENRICHMENT", "LLM_INPUT", "LLM_OUTPUT", "POLICY_DECISION"):
        assert stage in observed

    # Analyst approves: dry-run isolation runs and the trail gains HUMAN_DECISION, ACTION, RESULT.
    result = orch.decide_approval(final.approval_id, "alice", approve=True, comment="confirmed")
    assert result["playbook_status"] == "dry_run"
    assert result["incident_status"] == "contained"
    assert stages(orch, incident_id)[-3:] == ["HUMAN_DECISION", "ACTION", "RESULT"]
    with orch.db.session() as s:
        run = s.get(PlaybookRun, result["playbook_run_id"])
        assert run.triggered_by == "analyst:alice"
        planned = [st for st in run.steps if st["status"] == "planned"]
        # No Wazuh API in dry run, so the OS platform is unknown and the Linux command is planned.
        assert planned[0]["data"]["request"]["command"] == "agentic-isolate-linux"
        assert planned[0]["data"]["request"]["agents_list"] == ["002"]


def test_deduplication_avoids_llm_calls(make_orchestrator):
    scenario = sc.credential_lateral(0)
    orch = make_orchestrator()
    outcomes = [orch.process_wazuh_alert(a) for a in scenario.alerts]
    assert sum(o.status == "duplicate" for o in outcomes) == 7
    with orch.db.session() as s:
        first = s.execute(select(Alert).where(Alert.rule_id == "100220")).scalar_one()
        assert first.duplicate_count == 7
        decisions = s.execute(select(LLMDecision)).scalars().all()
        assert len(decisions) < len(scenario.alerts)
    # Lateral movement on another host still correlates through the shared account / source.
    assert len({o.incident_id for o in outcomes}) == 1


def test_same_wazuh_id_is_idempotent(make_orchestrator):
    orch = make_orchestrator()
    raw = sc.benign_failed_ssh(0).alerts[0]
    first = orch.process_wazuh_alert(raw)
    again = orch.process_wazuh_alert(raw)
    assert again.status == "duplicate" and again.duplicate_of == first.alert_id


def test_network_alerts_correlate_with_endpoint_alerts(make_orchestrator):
    scenario = sc.malicious_file_linux(0)
    orch = make_orchestrator(threat_intel=scenario.threat_intel)
    outcomes = [orch.process_wazuh_alert(a) for a in scenario.alerts]
    assert len({o.incident_id for o in outcomes}) == 1


def test_auto_execution_when_policy_permits(make_orchestrator):
    # A confident, high (not critical) decision that does not ask for approval, on an unprotected
    # host: risk 8 lands in the automation band and every guard passes.
    from agentic_soc.llm.heuristic import HeuristicProvider
    from agentic_soc.models.schemas import TriageDecision

    class Confident(HeuristicProvider):
        def analyze(self, context):
            result = super().analyze(context)
            result.decision = TriageDecision(
                severity="high",
                confidence=0.9,
                classification="malicious",
                techniques=["T1204.002"],
                recommended_action="ISOLATE_HOST",
                requires_human_approval=False,
                reason="Binary executed from a hidden temp directory.",
                targets=["linux-srv01"],
            )
            return result

    orch = make_orchestrator(provider=Confident())
    outcome = orch.process_wazuh_alert(sc.malicious_file_linux(0).alerts[1])  # level 12
    assert outcome.policy_outcome == "AUTO_EXECUTE" and outcome.playbook_status == "dry_run"
    with orch.db.session() as s:
        run = s.get(PlaybookRun, outcome.playbook_run_id)
        assert run.triggered_by == "policy:auto"
        assert s.get(Incident, outcome.incident_id).status == "contained"
        decision = s.get(LLMDecision, outcome.llm_decision_id)
        assert (decision.risk_score, decision.execution_state) == (8, "dry_run")


def test_benign_alert_is_logged_without_approval(make_orchestrator):
    orch = make_orchestrator()
    outcome = orch.process_wazuh_alert(sc.benign_failed_ssh(0).alerts[0])
    assert outcome.status == "triaged"
    assert outcome.action == "NONE"
    assert outcome.policy_outcome == "LOG_ONLY"
    assert outcome.approval_id is None


def test_retriage_cooldown_skips_llm(make_orchestrator):
    orch = make_orchestrator()
    alerts = sc.scan_exploit(0).alerts
    first = orch.process_wazuh_alert(alerts[0])
    assert first.status == "triaged"
    # Same incident, same level, no new tactic, inside the cooldown: no new LLM call.
    # Same scanner, another internal target: correlates (shared source) but is not a duplicate.
    repeat = dict(alerts[0], id="repeat-1")
    repeat["data"] = dict(alerts[0]["data"], **{"id.resp_h": "192.168.50.71"})
    second = orch.process_wazuh_alert(repeat)
    assert second.status == "correlated" and "re-triage skipped" in second.notes[0]


def test_new_triage_supersedes_pending_approval(make_orchestrator):
    scenario = sc.phishing_powershell(0)
    orch = make_orchestrator(threat_intel=scenario.threat_intel)
    for alert in scenario.alerts:
        orch.process_wazuh_alert(alert)
    with orch.db.session() as s:
        statuses = [a.status for a in s.execute(select(HumanApproval)).scalars()]
    assert statuses.count("pending") == 1


def test_rejection_and_disposition(make_orchestrator):
    scenario = sc.phishing_powershell(0)
    orch = make_orchestrator(threat_intel=scenario.threat_intel)
    for alert in scenario.alerts:
        orch.process_wazuh_alert(alert)
    approval = pending_approval(orch)
    result = orch.decide_approval(approval.id, "bob", approve=False, comment="needs more evidence")
    assert result["status"] == "rejected" and "playbook_run_id" not in result
    closed = orch.set_disposition(approval.incident_id, "true_positive", "bob")
    assert closed["status"] == "closed"


def test_rollback_of_dry_run(make_orchestrator):
    scenario = sc.phishing_powershell(0)
    orch = make_orchestrator(threat_intel=scenario.threat_intel)
    for alert in scenario.alerts:
        orch.process_wazuh_alert(alert)
    run = orch.decide_approval(pending_approval(orch).id, "alice", approve=True)
    rolled = orch.rollback_run(run["playbook_run_id"], "alice")
    assert rolled["status"] == "dry_run"
    with orch.db.session() as s:
        rb = s.get(PlaybookRun, rolled["rollback_run_id"])
        assert rb.playbook == "isolate_host:rollback"
        assert rb.steps[0]["data"]["request"]["arguments"][0] == "release"


def test_audit_chain_detects_tampering(make_orchestrator):
    orch = make_orchestrator()
    outcome = orch.process_wazuh_alert(sc.benign_failed_ssh(0).alerts[0])
    with orch.db.session() as s:
        assert verify_chain(s, outcome.incident_id).valid
        s.execute(
            update(AuditEvent)
            .where(AuditEvent.incident_id == outcome.incident_id)
            .where(AuditEvent.stage == AuditStage.LLM_OUTPUT.value)
            .values(payload={"decision": {"recommended_action": "NONE"}, "tampered": True})
        )
    with orch.db.session() as s:
        check = verify_chain(s, outcome.incident_id)
        assert not check.valid and "modified" in check.detail
