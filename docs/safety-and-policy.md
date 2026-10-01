# Safety model and policy engine

The design rule: **the LLM recommends, deterministic code decides, predefined playbooks act,
and every step is recorded.**

## Guardrails between the model and any action

| Risk | Control | Where |
|---|---|---|
| Model emits commands or scripts | Output must match `TriageDecision` (`extra="forbid"`); the action is an enum of six allowlisted values; nothing from the model is executed | `models/schemas.py`, `llm/base.py::parse_decision` |
| Malformed or out-of-range output | Strict validation (confidence 0–1, technique-id format, field lengths); one corrective retry for Ollama, then the deterministic fallback | `llm/providers.py` |
| Hallucinated ATT&CK techniques | Dropped unless present in the ATT&CK bundle | `agents/triage_agent.py` |
| Hallucinated or injected targets | Targets must be entities extracted from the incident's own alerts and of the right type for the action | `agents/triage_agent.py`, `agents/response_agent.py` |
| Prompt injection via telemetry (command lines, URLs, user names) | Prompt marks incident data as untrusted; the injection can at most change a *recommendation*, which still faces every control below | `llm/prompts.py` |
| Over-confident automation | Confidence < 0.80 → human review regardless of severity | `policy/policy_engine.py` |
| Disruptive actions | `DISABLE_USER` always needs approval; the model may ask for approval but can never waive it | `config/policy.yaml` |
| Hitting infrastructure | Protected hosts/users require approval; never-block addresses are removed from block targets; the Wazuh manager is never isolated; `krbtgt`/`root`/system accounts are never disabled | policy + playbooks + endpoint scripts |
| Runaway automation | `max_auto_actions_per_hour`, `max_targets_per_action`, global kill switch `automation.enabled` | `config/policy.yaml` |
| LLM outage | Deterministic triage takes over and is flagged; flagged decisions never auto-execute | `agents/triage_agent.py`, policy |
| Unsafe parameters reaching endpoints | Playbooks re-validate targets; endpoint scripts validate IPs/usernames again and refuse system accounts | `playbooks/`, `deploy/wazuh/active-response/` |
| Unreviewed changes in live systems | `SOC_EXECUTION_MODE=dry_run` by default: playbooks record the exact API call they *would* make | `playbooks/base.py` |
| Irreversible actions | Isolation, IP blocks (OPNsense) and account disables have rollback (`POST /api/v1/playbook-runs/{id}/rollback`) | playbooks |
| Repudiation | Analyst identity comes from their API key, not from request bodies; hash-chained audit trail | `api/app.py`, `database/audit.py` |

## Policy engine (blueprint §16)

```
risk = round(0.7 * severity_score(LLM) + 0.3 * wazuh_level_score) + 1 if any malicious CTI
       (capped at 4 when the LLM says "benign"; clamped to 0..10)

Confidence < 0.80          -> HUMAN_REVIEW (regardless of severity)
Risk 0-4                   -> LOG_ONLY
Risk 5-7                   -> RECOMMEND (optional analyst approval executes it)
Risk 8-9                   -> AUTO_EXECUTE if every guard passes, else REQUIRE_APPROVAL
Risk 10                    -> REQUIRE_APPROVAL
```

Guards for `AUTO_EXECUTE`: automation enabled; action in `auto_allowed_actions`; not in
`always_require_approval`; the model did not request approval; the triage did not come from the
fallback path; no protected targets; at most `max_targets_per_action` targets; hourly
automation budget not exhausted. Each failing guard is listed in the decision's `reasons`.

All thresholds live in [`config/policy.yaml`](../config/policy.yaml) and are **experimental
parameters**: evaluate alternatives with `python -m evaluation.run_evaluation --policy <file>`
rather than presenting any value as universally correct.

## Moving from dry run to live

1. Run every attack scenario in `dry_run` and review the planned API calls in
   `playbook_runs.steps` and the audit trail.
2. Test each endpoint script by hand on a snapshot (`echo '{"parameters":{"extra_args":["isolate","192.168.50.10"]}}' | sudo /var/ossec/active-response/bin/agentic-isolate.sh`)
   and confirm release/rollback works.
3. Start live mode with `automation.enabled: false` (every action needs approval), then enable
   automation for `COLLECT_EVIDENCE` only, then the others.
4. Keep VM snapshots so scenarios can be reset.

## Data handling

* Only alert-derived context goes to the LLM; raw `full_log` is not included and long fields are
  truncated. With the **cloud** provider, host names, user names, IPs and command lines from the
  lab leave the network; use the local provider when that is not acceptable.
* VirusTotal receives only public IPs, public domains/URLs and file hashes; internal addresses
  and internal domain suffixes are filtered. Nothing is uploaded or submitted.
* Cloud model safety classifiers can occasionally decline security telemetry. The cloud provider
  enables server-side fallback to Anthropic's recommended model; if the request is still
  declined, the deterministic triage is used and the decision requires analyst approval.
* Secrets come from environment variables / `.env` and are never written to the database.
