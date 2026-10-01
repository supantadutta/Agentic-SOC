# Architecture

## Overview (blueprint §2)

```
Internet
   |
OPNsense firewall (192.168.50.1) <------------------------------------+
   |                                                                   | BLOCK_IP (alias API)
Lab network 192.168.50.0/24 (Proxmox vmbr1)                            |
   +--> Suricata IDS  --+                                              |
   +--> Zeek NSM      --+--> Wazuh agent (sensor) --+                  |
Endpoints: Sysmon + Wazuh agents ------------------+                   |
                                                    v                  |
                                    WAZUH SIEM/XDR (192.168.50.10)     |
                                    manager -> indexer -> dashboard    |
                                       |  custom-agentic-soc.py        |
                                       v  (level >= 7)                 |
                       Agentic SOC orchestrator (192.168.50.20) -------+
                         |  normalize, deduplicate, correlate
                         |  enrichment: MISP | VirusTotal | MITRE ATT&CK
                         |  LLM layer: Ollama (local) / Claude API (cloud) / hybrid
                         |  policy engine
                         +--> LOG_ONLY / RECOMMEND / HUMAN_REVIEW
                         +--> REQUIRE_APPROVAL --(analyst)--+
                         +--> AUTO_EXECUTE -----------------+--> predefined playbooks
                                                               isolate host | block IOC |
                                                               disable user | collect evidence
                                                               (Wazuh active response / OPNsense)
                         PostgreSQL research database + hash-chained audit trail
```

## Agent workflow (blueprint §13)

Implemented in [`agentic_soc/pipeline/orchestrator.py`](../agentic_soc/pipeline/orchestrator.py):

| Step | Code | Notes |
|---|---|---|
| Wazuh alert | `POST /api/v1/alerts/wazuh` | Pushed by [`custom-agentic-soc.py`](../deploy/wazuh/manager/integrations/custom-agentic-soc.py); queued and processed in order |
| Normalize | `integrations/wazuh.py::normalize_wazuh_alert` | Sysmon, Windows Security, Linux, Suricata, Zeek fields → `NormalizedAlert` + entities |
| Deduplicate | `SOCOrchestrator._find_duplicate` | Same Wazuh id, or same fingerprint inside `dedup_window_seconds`; duplicates only increment a counter |
| Correlate | `agents/correlation_agent.py` | Shared host/user/hash/domain/URL/IP inside `correlation_window_minutes` (alert time, not wall time) |
| Retrieve related alerts | `agents/investigation_agent.py` | Earlier incidents sharing entities (database) + lower-level alerts from the Wazuh indexer |
| Threat-intel enrichment | `agents/enrichment_agent.py` | MISP, VirusTotal (public indicators only), ATT&CK; cached in `iocs` |
| Build incident context | `SOCOrchestrator._build_context` | Compact, truncated alert summaries + entities + CTI + narrative |
| LLM triage | `agents/triage_agent.py`, `llm/` | Strict JSON schema; post-validation of techniques and targets |
| Risk + confidence | `policy/policy_engine.py::risk_score` | Weighted LLM severity + Wazuh level + CTI bonus |
| Policy engine | `PolicyEngine.evaluate` | Bands, confidence floor, guards → outcome with reasons |
| Act | `agents/response_agent.py`, `playbooks/` | Auto-execute, or create an approval request |

**Cost controls.** Alerts below `min_rule_level_for_triage` are stored without triage.
Duplicates never reach the LLM. An incident is only re-triaged when a new alert raises the
maximum rule level, adds a new ATT&CK tactic, introduces an indicator with a
malicious/suspicious threat-intelligence verdict, or arrives after `retriage_cooldown_seconds`.
`GET /api/v1/metrics` reports `triage_calls_avoided`.

## Multi-agent design (blueprint §14)

| Agent | Module | Input | Output |
|---|---|---|---|
| Triage | `agents/triage_agent.py` | Incident context | Severity, confidence, classification, techniques, recommended action |
| Investigation | `agents/investigation_agent.py` | Alert + history | Related incidents and SIEM alerts |
| Threat Intelligence | `agents/enrichment_agent.py` | IPs, domains, URLs, hashes | Reputation / CTI evidence, ATT&CK details |
| Correlation | `agents/correlation_agent.py` | Multiple alerts | Incident grouping, tactic progression, narrative |
| Response | `agents/response_agent.py` | Incident context + decision | Targets, policy outcome, playbook execution |

Only the triage agent uses an LLM, and it makes one call per (re-)triage. The other agents are
deterministic, which keeps cost low and the behaviour reproducible for the research comparison.

## LLM layer (blueprint §15, §20)

```python
class LLMProvider:                 # agentic_soc/llm/base.py
    def analyze(self, incident) -> LLMResult: ...

class OllamaProvider(LLMProvider)  # local, JSON-schema constrained output (format=...)
class AnthropicProvider(LLMProvider)  # cloud (CloudProvider alias), structured outputs
class HybridProvider(LLMProvider)  # local first, escalate when uncertain or severe
class HeuristicProvider(LLMProvider)  # deterministic, zero cost: baseline arm and fallback
```

Every provider returns the same validated `TriageDecision` plus input/output tokens, latency
and cost, so local, cloud and hybrid invocation can be compared per alert. The prompt is
versioned (`PROMPT_VERSION`) and every decision stores a SHA-256 of the exact prompt.

## Data model (blueprint §18)

`incidents`, `alerts`, `entities` (+ `alert_entities`), `hosts`, `users`, `iocs`,
`llm_decisions`, `agent_actions`, `playbook_runs`, `human_approvals`, `audit_events`
([`database/models.py`](../agentic_soc/database/models.py)). Each `llm_decisions` row keeps the
provider/model, prompt version and hash, structured response, confidence, recommended action,
risk score, policy outcome, approval state, execution state, tokens, latency, cost and
timestamp. No credentials are stored.

## Audit trail (blueprint §19)

```
ALERT -> ENRICHMENT -> LLM_INPUT -> LLM_OUTPUT -> POLICY_DECISION -> HUMAN_DECISION -> ACTION -> RESULT
```

Each `audit_events` row stores its payload, actor (`system`, `policy:auto`, `analyst:<name>`),
timestamp, the previous event's hash and its own SHA-256. `GET /api/v1/incidents/{id}/audit`
returns the events with a chain verification, so editing or deleting an event is detectable.
