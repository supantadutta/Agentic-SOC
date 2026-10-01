import json

from evaluation.cost_model import compute
from evaluation.run_evaluation import run
from evaluation.scenarios import export, load_from_directory, load_scenarios


def test_heuristic_evaluation_runs_offline(tmp_path):
    report = run(tmp_path / "out", "heuristic")
    summary = report["summary"]
    assert summary["scenarios"] == len(load_scenarios())
    agentic = summary["agentic"]
    assert agentic["tp"] + agentic["fn"] == 5 and agentic["fp"] + agentic["tn"] == 4
    assert agentic["audit_chains_valid"] is True
    assert agentic["llm_cost_usd"] == 0
    assert (tmp_path / "out" / "report.md").read_text().count("|") > 20
    assert json.loads((tmp_path / "out" / "metrics.json").read_text())["provider"] == "heuristic"
    # Each scenario forms exactly one incident.
    assert all(s["incidents"] == 1 for s in report["scenarios"])


def test_simulated_analyst_exercises_playbooks(tmp_path):
    report = run(tmp_path / "out", "heuristic", simulate_analyst="approve")
    assert report["summary"]["agentic"]["automation_success_rate"] == 1.0


def test_scenarios_round_trip(tmp_path):
    export(tmp_path)
    assert [s.name for s in load_from_directory(tmp_path)] == sorted(s.name for s in load_scenarios())


def test_cost_model():
    model = compute(
        {
            "period_months": 12,
            "electricity": {"average_watts": 100, "hours_per_day": 24, "price_per_kwh_usd": 0.2},
            "cloud_api": {"alerts_per_month": 1000},
        },
        {"provider": "cloud", "model": "m", "summary": {"agentic": {"llm_cost_per_alert_usd": 0.002}}},
    )
    assert model["monthly_usd"]["cloud_api"] == 2.0
    assert model["monthly_usd"]["electricity"] == round(0.1 * 24 * 30.4 * 0.2, 2)
