import json

import pytest

from agentic_soc.llm.base import LLMOutputError, parse_decision
from agentic_soc.models.schemas import TRIAGE_JSON_SCHEMA, TriageDecision

GOOD = {
    "severity": "high",
    "confidence": 0.91,
    "classification": "malicious",
    "techniques": ["T1059.001", "t1105"],
    "recommended_action": "ISOLATE_HOST",
    "requires_human_approval": True,
    "reason": "Correlated PowerShell execution and suspicious transfer activity",
    "targets": ["win-client01"],
}


def test_blueprint_example_validates():
    decision = parse_decision(json.dumps(GOOD))
    assert decision.techniques == ["T1059.001", "T1105"]


def test_code_fences_are_tolerated():
    assert parse_decision("```json\n" + json.dumps(GOOD) + "\n```").severity == "high"


@pytest.mark.parametrize(
    "mutation",
    [
        {"recommended_action": "RUN_COMMAND"},
        {"recommended_action": "powershell -c Remove-Item C:\\ -Recurse"},
        {"confidence": 1.7},
        {"severity": "apocalyptic"},
        {"techniques": ["T99"]},
        {"command": "rm -rf /"},  # extra fields are forbidden
        {"reason": ""},
    ],
)
def test_rejects_unsafe_or_malformed_output(mutation):
    with pytest.raises(LLMOutputError):
        parse_decision(json.dumps({**GOOD, **mutation}))


def test_rejects_missing_fields_and_non_json():
    with pytest.raises(LLMOutputError):
        parse_decision(json.dumps({k: v for k, v in GOOD.items() if k != "recommended_action"}))
    with pytest.raises(LLMOutputError):
        parse_decision("I think you should isolate the host.")


def test_runtime_schema_matches_model():
    assert set(TRIAGE_JSON_SCHEMA["required"]) == set(TriageDecision.model_fields)
    assert TRIAGE_JSON_SCHEMA["additionalProperties"] is False
