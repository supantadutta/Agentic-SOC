# Deployment guide

The deployment follows the blueprint's nine phases. Commands for external products (Wazuh,
Suricata, Zeek, MISP) follow their official documentation at the time of writing. Check each
project's current guide for the version you install.

## Network and sizing (blueprint §3–§5)

| Component | IP | vCPU | RAM | Disk |
|---|---|---|---|---|
| Gateway / OPNsense | 192.168.50.1 | 2 | 2 GB | 20 GB |
| Wazuh | 192.168.50.10 | 8 | 10–12 GB | 200 GB |
| Agentic SOC | 192.168.50.20 | 4 | 6 GB | 50 GB |
| MISP | 192.168.50.30 | 4 | 6 GB | 80 GB |
| Network sensor | 192.168.50.40 | 4 | 4–6 GB | 80 GB |
| Windows DC | 192.168.50.50 | 4 | 6–8 GB | 80 GB |
| Windows client | 192.168.50.60 | 4 | 4–6 GB | 60 GB |
| Linux server | 192.168.50.70 | 2 | 2–4 GB | 30 GB |
| Kali | 192.168.50.100 | 2–4 | 4 GB | 50 GB |

Keep the lab isolated. Never expose Wazuh (443, 1514, 1515, 9200, 55000), MISP, PostgreSQL or
the orchestrator API (8000) to the Internet.

## Phase 1 — Proxmox and the isolated network

[`deploy/proxmox/README.md`](../deploy/proxmox/README.md): create `vmbr1` (no uplink, hub
mode for the sensor), install OPNsense as the lab gateway, create the `AGENTIC_SOC_BLOCK`
alias and an API key limited to alias management.

## Phase 2 — Wazuh manager, indexer and dashboard

```bash
WAZUH_TAG=v4.x.y deploy/wazuh/install-wazuh-docker.sh
```

Change all default passwords, then create:
* an API user for the orchestrator (`SOC_WAZUH_API_USER`) with a role allowing
  `agent:read` and `active-response:command`;
* an indexer user with read access to `wazuh-alerts-*` (`SOC_WAZUH_INDEXER_USER`).

Install the integration and rules on the manager:

```bash
deploy/wazuh/install-agent-integration.sh manager   # inside the wazuh.manager container
```

Merge [`ossec-manager.xml`](../deploy/wazuh/manager/ossec-manager.xml) (set `<api_key>` to
`SOC_INGEST_API_KEY`), check the rules with `wazuh-logtest`, and restart the manager.

## Phase 3 — Agents and Sysmon

* Windows: install the Wazuh agent, Sysmon ([`deploy/sysmon`](../deploy/sysmon/README.md)) and
  merge [`ossec-agent-windows.xml`](../deploy/wazuh/agents/ossec-agent-windows.xml). Copy
  `deploy/wazuh/active-response/windows/*` into `active-response\bin`.
* Linux: install the agent and auditd, merge
  [`ossec-agent-linux.xml`](../deploy/wazuh/agents/ossec-agent-linux.xml), run
  `deploy/wazuh/install-agent-integration.sh linux`.
* Start with one Windows and one Linux endpoint, validate telemetry in the dashboard, then
  scale.

## Phase 4 — Suricata and Zeek

```bash
CAPTURE_IF=ens19 deploy/suricata/setup-suricata.sh
CAPTURE_IF=ens19 deploy/zeek/setup-zeek.sh
```

Install a Wazuh agent on the sensor and merge
[`ossec-agent-sensor.xml`](../deploy/wazuh/agents/ossec-agent-sensor.xml). Only selected
events are forwarded: Suricata alerts/anomalies and Zeek notice/ssl/files logs. Suricata provides
signature/IDS context and Zeek provides network context.

## Phase 5 — MISP

```bash
deploy/misp/setup-misp.sh
```

Create a read-only automation user and set `SOC_MISP_URL` / `SOC_MISP_API_KEY`.
Optionally set `SOC_VIRUSTOTAL_API_KEY`; the public API is limited to 4 requests/minute and 500
per day, which the client enforces.

## Phase 6 — Orchestrator and PostgreSQL

```bash
git clone <this repository> /opt/agentic-soc && cd /opt/agentic-soc
cp .env.example .env            # set every secret; keep SOC_EXECUTION_MODE=dry_run
mkdir -p tls && cp <wazuh root-ca.pem> tls/root-ca.pem
docker compose --env-file .env -f deploy/agentic-soc/docker-compose.yml up -d --build
# ATT&CK bundle for technique validation (stored in a volume; restart to load it):
docker compose --env-file .env -f deploy/agentic-soc/docker-compose.yml exec orchestrator \
    python scripts/fetch_attack_data.py --out /opt/agentic-soc/data/enterprise-attack.json
docker compose --env-file .env -f deploy/agentic-soc/docker-compose.yml restart orchestrator
curl http://192.168.50.20:8000/healthz
```

Without Docker, use the systemd unit [`deploy/agentic-soc/agentic-soc.service`](../deploy/agentic-soc/agentic-soc.service)
(Python venv in `/opt/agentic-soc/.venv`, as in blueprint §12).

## Phase 7 — LLM

Local first (blueprint §20):

```bash
docker compose --env-file .env -f deploy/agentic-soc/docker-compose.yml --profile local-llm up -d
docker compose --env-file .env -f deploy/agentic-soc/docker-compose.yml exec ollama ollama pull llama3.1:8b
```

Set `SOC_LLM_PROVIDER=ollama`. For the cloud comparison set `SOC_LLM_PROVIDER=cloud` (Claude
API, `ANTHROPIC_API_KEY`) or `hybrid` (local first, escalate below
`SOC_HYBRID_ESCALATION_CONFIDENCE` or for high/critical severity). Any Ollama model that can
follow a JSON schema works. Pick one that fits the VM's RAM, or give the VM a GPU.

## Phase 8 — Policy, approvals and playbooks

Review [`config/policy.yaml`](../config/policy.yaml) (protected assets, never-block list,
automation guards). Analysts use the API (interactive docs at `http://192.168.50.20:8000/docs`):

```bash
H="Authorization: Bearer <analyst key>"
curl -H "$H" http://192.168.50.20:8000/api/v1/approvals
curl -H "$H" -X POST http://192.168.50.20:8000/api/v1/approvals/12/decision \
     -H 'Content-Type: application/json' -d '{"approve": true, "comment": "confirmed C2"}'
curl -H "$H" http://192.168.50.20:8000/api/v1/incidents/5/audit
```

Optional notifications: [`deploy/n8n`](../deploy/n8n/README.md). Follow
[the dry-run → live checklist](safety-and-policy.md#moving-from-dry-run-to-live) before
switching `SOC_EXECUTION_MODE=live`.

## Phase 9 — Scenarios and evaluation

See [evaluation.md](evaluation.md). To exercise the deployed pipeline without running attacks:

```bash
SOC_INGEST_API_KEY=... python scripts/replay_alerts.py --url http://192.168.50.20:8000 --all --sync
```

## Ports used by the orchestrator

| From | To | Port | Purpose |
|---|---|---|---|
| Wazuh manager | Agentic SOC | 8000/tcp | Alert push (integration) |
| Agentic SOC | Wazuh | 55000/tcp | API: agents, active response |
| Agentic SOC | Wazuh | 9200/tcp | Indexer: related alerts, sightings |
| Agentic SOC | MISP | 443/tcp | Threat intelligence |
| Agentic SOC | OPNsense | 443/tcp | Block alias API |
| Agentic SOC | Internet | 443/tcp | VirusTotal / Claude API (optional) |
