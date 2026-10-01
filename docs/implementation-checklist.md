# Implementation checklist (blueprint §27)

| ✓ | Item | How to verify |
|---|---|---|
| ☐ | Proxmox installed | Web UI on `https://<host>:8006` |
| ☐ | Isolated SOC network created | `vmbr1` has no physical port; Kali cannot reach the Internet |
| ☐ | Wazuh deployed | `docker compose ps` shows manager, indexer and dashboard healthy |
| ☐ | Wazuh dashboard secured | Default passwords changed; 443/9200/55000 reachable from the lab only |
| ☐ | Windows agent deployed | Agent `active` in the dashboard |
| ☐ | Linux agent deployed | Agent `active`; auth and auditd events visible |
| ☐ | Sysmon deployed | `rule.groups: sysmon` events from the Windows client |
| ☐ | Suricata deployed | `suricata -T` passes; test alert appears in Wazuh (rule group `suricata`) |
| ☐ | Zeek deployed | `zeekctl status` running; Zeek notice reaches Wazuh (rule 100101/100102) |
| ☐ | MISP deployed | Web UI reachable; orchestrator user and auth key created |
| ☐ | Wazuh → Agentic SOC API working | `/var/ossec/logs/integrations.log` clean; `GET /api/v1/metrics` shows `alerts_received` rising |
| ☐ | MISP enrichment working | A seeded indicator shows `source: misp` in the incident's ENRICHMENT audit event |
| ☐ | LLM provider working | `llm_decisions.provider` is `ollama`/`anthropic`, not `fallback:heuristic` |
| ☐ | Structured LLM output validated | `pytest tests/test_schemas.py`; no `invalid output` notes in `llm_decisions.validation_notes` |
| ☐ | Policy engine implemented | `pytest tests/test_policy_engine.py`; POLICY_DECISION events list their reasons |
| ☐ | Human approval implemented | Approve a pending request via the API; HUMAN_DECISION event names the analyst |
| ☐ | First playbook tested | COLLECT_EVIDENCE in dry run, then live on a snapshot; archive + `.sha256` on the endpoint |
| ☐ | Audit trail implemented | `GET /api/v1/incidents/{id}/audit` → `chain.valid: true` |
| ☐ | Attack scenarios repeatable | Each chain run twice from snapshots produces comparable alerts |
| ☐ | Baseline vs Agentic evaluation completed | `results/*/report.md` for baseline, local, cloud and hybrid arms |
