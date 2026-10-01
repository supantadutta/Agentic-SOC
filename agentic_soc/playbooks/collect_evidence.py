"""Evidence collection: process list -> network connections -> recent files -> hashes ->
relevant logs -> evidence package.

Endpoint artefacts are gathered by the ``agentic-collect-evidence`` active-response script
on each host. The orchestrator also writes an incident evidence package (alerts, entities,
threat intelligence, decisions) with a SHA-256 manifest for chain of custody.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentic_soc.models.schemas import EntityType, PlaybookStep, ResponseAction
from agentic_soc.playbooks.base import Playbook, PlaybookContext

ENDPOINT_ARTEFACTS = ["process_list", "network_connections", "recent_files", "file_hashes", "relevant_logs"]


class CollectEvidencePlaybook(Playbook):
    name = "collect_evidence"
    action = ResponseAction.COLLECT_EVIDENCE

    def execute(
        self, targets: list[str], ctx: PlaybookContext, steps: list[PlaybookStep], output: dict[str, Any]
    ) -> None:
        collected = []
        for target in targets:
            agent = self.resolve_agent(target, ctx)
            if not agent or not agent.get("id"):
                steps.append(
                    PlaybookStep(
                        name=f"endpoint_collection:{target}",
                        status="skipped",
                        detail="no Wazuh agent for target; package built from SIEM data only",
                    )
                )
                continue
            platform = self.platform_of(agent) or "linux"
            self.active_response(
                ctx,
                steps,
                f"endpoint_collection:{target}",
                [str(agent["id"])],
                f"agentic-collect-evidence-{platform}",
                [f"incident-{ctx.incident_id}"],
            )
            collected.append({"target": target, "agent_id": str(agent["id"]), "artefacts": ENDPOINT_ARTEFACTS})
        output["endpoint_collection"] = collected
        output["package"] = self.write_package(ctx, steps)

    def write_package(self, ctx: PlaybookContext, steps: list[PlaybookStep]) -> dict[str, str]:
        """Write the SIEM-side evidence package. Harmless to target systems, so it also runs in dry_run."""
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        directory = Path(self.services.settings.evidence_dir) / f"incident-{ctx.incident_id}"
        directory.mkdir(parents=True, exist_ok=True)
        package = {
            "incident_id": ctx.incident_id,
            "created_at": stamp,
            "reason": ctx.reason,
            "alerts": ctx.alerts,
            "entities": [e.model_dump() for e in ctx.entities],
            "hosts": [e.value for e in ctx.entities if e.type == EntityType.HOST],
            "threat_intel": [t.model_dump() for t in ctx.threat_intel],
            "decisions": ctx.extra.get("decisions", []),
        }
        path = directory / f"evidence-{stamp}.json"
        body = json.dumps(package, indent=2, default=str, sort_keys=True).encode()
        path.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        manifest = directory / f"evidence-{stamp}.sha256"
        manifest.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
        steps.append(PlaybookStep(name="evidence_package", status="ok", detail=str(path), data={"sha256": digest}))
        return {"path": str(path), "sha256": digest}
