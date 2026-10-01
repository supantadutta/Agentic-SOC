"""Host isolation: confirm host -> validate policy -> human approval where required ->
isolate -> collect evidence -> record result."""

from __future__ import annotations

from typing import Any

from agentic_soc.models.schemas import (
    PlaybookResult,
    PlaybookStatus,
    PlaybookStep,
    ResponseAction,
)
from agentic_soc.playbooks.base import Playbook, PlaybookAbort, PlaybookContext


class IsolateHostPlaybook(Playbook):
    name = "isolate_host"
    action = ResponseAction.ISOLATE_HOST
    supports_rollback = True

    def _confirm(self, target: str, ctx: PlaybookContext, steps: list[PlaybookStep]) -> tuple[str, str | None]:
        if self.services.policy.is_protected_host(target) and not ctx.approved_by:
            raise PlaybookAbort(f"{target} is a protected asset; analyst approval required")
        agent = self.resolve_agent(target, ctx)
        if not agent or not agent.get("id"):
            raise PlaybookAbort(f"cannot map {target} to a Wazuh agent")
        if str(agent["id"]) == "000":
            raise PlaybookAbort("refusing to isolate the Wazuh manager")
        if agent.get("ip") and self.services.policy.is_protected_host(str(agent["ip"])) and not ctx.approved_by:
            raise PlaybookAbort(f"{agent['ip']} is a protected asset; analyst approval required")
        platform = self.platform_of(agent)
        if ctx.live and agent.get("status") not in (None, "active"):
            raise PlaybookAbort(f"agent {agent['id']} is {agent.get('status')}; cannot deliver isolation")
        if ctx.live and platform is None:
            raise PlaybookAbort(f"unknown OS platform for agent {agent['id']}")
        steps.append(
            PlaybookStep(
                name="confirm_host",
                status="ok",
                detail=f"{target} -> agent {agent['id']} ({platform or 'platform unknown'})",
                data={"agent": agent},
            )
        )
        return str(agent["id"]), platform

    def execute(
        self, targets: list[str], ctx: PlaybookContext, steps: list[PlaybookStep], output: dict[str, Any]
    ) -> None:
        resolved = [(t, *self._confirm(t, ctx, steps)) for t in targets]
        steps.append(PlaybookStep(name="validate_policy", status="ok", detail=f"policy outcome {ctx.policy_outcome}"))
        steps.append(
            PlaybookStep(
                name="human_approval",
                status="ok" if ctx.approved_by else "skipped",
                detail=f"approved by {ctx.approved_by}" if ctx.approved_by else "not required by policy",
            )
        )
        manager_ip = self.services.settings.wazuh_manager_ip
        isolated = []
        for target, agent_id, platform in resolved:
            platform = platform or "linux"
            self.active_response(
                ctx, steps, f"isolate:{target}", [agent_id], f"agentic-isolate-{platform}", ["isolate", manager_ip]
            )
            self.active_response(
                ctx,
                steps,
                f"collect_evidence:{target}",
                [agent_id],
                f"agentic-collect-evidence-{platform}",
                [f"incident-{ctx.incident_id}"],
            )
            isolated.append({"target": target, "agent_id": agent_id, "platform": platform})
        output["isolated"] = isolated

    def rollback(self, targets: list[str], ctx: PlaybookContext) -> PlaybookResult:
        steps: list[PlaybookStep] = []
        previous = ctx.extra.get("previous_output", {}).get("isolated", [])
        for item in previous:
            if item["target"] not in targets:
                continue
            self.active_response(
                ctx,
                steps,
                f"release:{item['target']}",
                [item["agent_id"]],
                f"agentic-isolate-{item['platform']}",
                ["release", self.services.settings.wazuh_manager_ip],
            )
        status = PlaybookStatus.ROLLED_BACK if ctx.live else PlaybookStatus.DRY_RUN
        return PlaybookResult(playbook=self.name, action=self.action, status=status, targets=targets, steps=steps)
