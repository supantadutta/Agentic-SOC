# Optional — n8n as the integration/notification layer

n8n is the visual connector and notification layer, **not** the security reasoning engine.
The split used here:

| Python orchestrator (this repo) | n8n |
|---|---|
| Normalization, correlation, enrichment, LLM triage | Chat/e-mail/ticket notifications |
| Policy engine and playbooks | Calling the approval API from a chat button or form |
| Audit trail and research database | Scheduled reports (e.g. `GET /api/v1/metrics` weekly) |

## Notification flow

1. Run n8n on the Agentic SOC VM, bound to the lab address only:
   `docker run -d --name n8n -p 192.168.50.20:5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n`
2. Create a workflow with a **Webhook** trigger (POST, path `agentic-soc`).
3. Set `SOC_NOTIFY_WEBHOOK_URL=http://192.168.50.20:5678/webhook/agentic-soc` on the orchestrator.
   It posts an event whenever an approval is requested, a playbook runs, or an analyst decides.
4. Add nodes that format the event (`incident_id`, `policy_outcome`, `action`, `targets`,
   `approval_id`) and send it to your channel.
5. To approve from n8n, call
   `POST http://192.168.50.20:8000/api/v1/approvals/{approval_id}/decision` with
   `{"approve": true, "comment": "..."}` and the analyst's own key as a Bearer token. Give each
   analyst their own key so the audit trail names the person who approved.

See the n8n documentation: <https://docs.n8n.io/>.
