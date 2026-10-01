# Agentic SOC

A low-cost, agentic Security Operations Center for a research lab, built from the
[deployment blueprint](docs/blueprint/Low-Cost_Agentic_SOC_Deployment_Blueprint.docx). It uses:

* **Open-source detection:** Wazuh SIEM/XDR, Sysmon, Suricata and Zeek.
* **Threat intelligence:** MISP, VirusTotal and MITRE ATT&CK.
* **LLM triage:** a local model (Ollama), a cloud model (Claude API), or a hybrid of the two.
* **Policy-governed response:** a deterministic policy engine decides when predefined playbooks
  may run.
* **Human approval** for anything risky.
* **A hash-chained audit trail** that shows why each response happened.

> **Research question:** can a resource-constrained agentic SOC improve alert triage,
> correlation and response efficiency while keeping infrastructure and LLM costs low?

```
Wazuh alert -> normalize -> deduplicate -> correlate -> related alerts -> MISP / VirusTotal / ATT&CK
  -> incident context -> LLM triage (strict JSON) -> risk + confidence -> policy engine
  -> log | recommend | analyst approval | predefined automation  -> audit trail
```

## What is in this repository

| Path | Blueprint | Contents |
|---|---|---|
| `agentic_soc/` | §12–§20 | The orchestrator: FastAPI service, five agents, LLM providers, policy engine, playbooks, PostgreSQL models, audit trail |
| `config/` | §16, §25 | `policy.yaml` (thresholds, guards, protected assets), LLM pricing, cost-model inputs |
| `deploy/` | §4–§11, §21 | Proxmox network, Wazuh Docker install, Wazuh integration and rules, Wazuh active-response scripts (Linux and Windows), agent configs, Suricata, Zeek, MISP, Sysmon, n8n, Docker Compose and systemd for the orchestrator |
| `evaluation/` | §22–§25 | Replayable scenarios with ground truth, baseline vs agentic evaluation, cost model |
| `scripts/` | | ATT&CK bundle download, alert replay into a running deployment |
| `tests/` | | 80 tests: normalization, schema safety, policy, providers, pipeline, playbooks, API, evaluation |
| `docs/` | | [Architecture](docs/architecture.md), [deployment guide](docs/deployment-guide.md), [safety model](docs/safety-and-policy.md), [evaluation](docs/evaluation.md), [checklist](docs/implementation-checklist.md) |

## Quick start (no lab required)

Python 3.11+.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest

# Offline evaluation with the zero-cost heuristic triage (SQLite, dry-run playbooks):
python -m evaluation.run_evaluation --provider heuristic --out results/heuristic

# Run the API locally and replay a scenario through it:
export SOC_INGEST_API_KEY=dev-ingest SOC_ANALYST_API_KEYS='{"analyst1": "dev-analyst"}' SOC_LLM_PROVIDER=heuristic
uvicorn --factory agentic_soc.api.app:app_factory --port 8000 &
python scripts/replay_alerts.py --url http://127.0.0.1:8000 --scenario phishing_powershell_download --sync
curl -H "Authorization: Bearer dev-analyst" http://127.0.0.1:8000/api/v1/approvals
```

Interactive API docs: `http://127.0.0.1:8000/docs`. To use a local model, run Ollama, pull a
model and set `SOC_LLM_PROVIDER=ollama`. For the cloud provider, set `SOC_LLM_PROVIDER=cloud`
and `ANTHROPIC_API_KEY`, then install with `pip install -e ".[cloud]"`. All settings are listed in
[`.env.example`](.env.example).

## Lab deployment

Follow [docs/deployment-guide.md](docs/deployment-guide.md). Its nine phases are Proxmox and
the isolated network; Wazuh; agents and Sysmon; Suricata and Zeek; MISP; the orchestrator and
PostgreSQL; the LLM; policy and playbooks; and evaluation. On the Agentic SOC VM:

```bash
cp .env.example .env   # set secrets; keep SOC_EXECUTION_MODE=dry_run at first
docker compose --env-file .env -f deploy/agentic-soc/docker-compose.yml up -d --build
```

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/v1/alerts/wazuh` | ingest key | Alert intake from the Wazuh integration (`?sync=true` processes inline) |
| `GET /api/v1/incidents[/{id}]` | analyst | Incidents with alerts, LLM decisions, approvals, playbook runs |
| `GET /api/v1/incidents/{id}/audit` | analyst | Audit events + hash-chain verification |
| `POST /api/v1/incidents/{id}/disposition` | analyst | Ground truth: `true_positive` / `false_positive` / `benign` |
| `GET /api/v1/approvals` | analyst | Pending approval / review requests, highest risk first |
| `POST /api/v1/approvals/{id}/decision` | analyst | Approve (runs the playbook) or reject |
| `POST /api/v1/playbook-runs/{id}/rollback` | analyst | Release isolation, unblock IP, re-enable account |
| `GET /api/v1/metrics` | analyst | Volumes, deduplication, triage calls avoided, tokens, cost, automation success |

## Safety in one paragraph

The model can only choose from six allowlisted actions, inside a schema that rejects any other
field. Its targets must be entities from the incident's own alerts. The deterministic policy
engine applies confidence and risk thresholds, protected assets, never-block lists, an hourly
automation budget and a kill switch. Account containment always needs an analyst. Playbooks
validate their inputs again, and so do the endpoint scripts. Everything runs in `dry_run` until
you switch it to live. Details are in [docs/safety-and-policy.md](docs/safety-and-policy.md).

## Status and limitations

* Verified here: the test suite and the offline evaluation (heuristic provider, SQLite, dry-run
  playbooks), plus the API served by uvicorn with alerts replayed over HTTP.
* The Ollama and Claude providers are tested against mocked HTTP/SDK responses. Validate them
  against your local model and API key before collecting results.
* Wazuh, Suricata, Zeek, MISP, OPNsense and the active-response scripts are configuration and
  scripts for your lab. Test them there (each file notes how) before enabling live mode.
* The bundled scenarios are synthetic, and the heuristic was written alongside them, so its
  scores on them are not evidence of real-world performance. See
  [threats to validity](docs/evaluation.md#threats-to-validity-report-these).

Run attack simulations only against isolated systems you own or are explicitly authorized to
test.
