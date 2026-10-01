"""Account containment: correlate authentication anomalies -> review evidence -> obtain
approval -> disable account -> record result."""

from __future__ import annotations

import re
from typing import Any

from agentic_soc.models.schemas import (
    EntityType,
    PlaybookResult,
    PlaybookStatus,
    PlaybookStep,
    ResponseAction,
)
from agentic_soc.playbooks.base import Playbook, PlaybookAbort, PlaybookContext

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Never disabled by automation, even with approval: doing so breaks the domain or the host.
HARD_PROTECTED = {"krbtgt", "root", "system"}
AUTH_GROUPS = {
    "authentication_failed",
    "authentication_failures",
    "authentication_success",
    "win_authentication_failed",
    "invalid_login",
    "brute_force",
}
WINDOWS_SOURCES = {"windows", "sysmon"}


class DisableUserPlaybook(Playbook):
    name = "disable_user"
    action = ResponseAction.DISABLE_USER
    supports_rollback = True

    def _scope(self, user: str, ctx: PlaybookContext) -> tuple[str, list[str]]:
        """Return ("windows", [dc agent]) for domain accounts, else ("linux", [host agents])."""
        user_alerts = [a for a in ctx.alerts if (a.get("user") or "").lower() == user.lower()]
        if any(a.get("source") in WINDOWS_SOURCES for a in user_alerts):
            dc = self.services.settings.ad_dc_agent_id
            if not dc:
                raise PlaybookAbort("domain account but SOC_AD_DC_AGENT_ID is not configured")
            return "windows", [dc]
        agents = sorted({str(a["agent_id"]) for a in user_alerts if a.get("agent_id") and a["agent_id"] != "000"})
        if not agents:
            raise PlaybookAbort(f"no host found where {user} was observed")
        return "linux", agents

    def _arguments(self, verb: str, user: str) -> list[str]:
        return [verb, user]

    def execute(
        self, targets: list[str], ctx: PlaybookContext, steps: list[PlaybookStep], output: dict[str, Any]
    ) -> None:
        disabled = []
        for user in targets:
            if not USERNAME_RE.match(user):
                raise PlaybookAbort(f"refusing unsafe account name {user!r}")
            if user.lower() in HARD_PROTECTED:
                raise PlaybookAbort(f"{user} can never be disabled by the SOC orchestrator")
            if not any(e.type == EntityType.USER and e.value.lower() == user.lower() for e in ctx.entities):
                raise PlaybookAbort(f"{user} is not an entity of this incident")

            auth_alerts = [
                a
                for a in ctx.alerts
                if (a.get("user") or "").lower() == user.lower() and AUTH_GROUPS & set(a.get("rule_groups", []))
            ]
            steps.append(
                PlaybookStep(
                    name=f"correlate_auth_anomalies:{user}",
                    status="ok",
                    detail=f"{len(auth_alerts)} authentication alert(s) for {user}",
                    data={"rule_ids": sorted({a.get("rule_id") for a in auth_alerts})},
                )
            )
            steps.append(
                PlaybookStep(
                    name=f"review_evidence:{user}",
                    status="ok",
                    detail=f"{len(ctx.alerts)} incident alert(s), {len(ctx.threat_intel)} threat-intel result(s)",
                )
            )
            if not ctx.approved_by:
                raise PlaybookAbort("account containment requires analyst approval")
            steps.append(PlaybookStep(name=f"approval:{user}", status="ok", detail=f"approved by {ctx.approved_by}"))

            platform, agent_ids = self._scope(user, ctx)
            self.active_response(
                ctx,
                steps,
                f"disable_account:{user}",
                agent_ids,
                f"agentic-disable-user-{platform}",
                self._arguments("disable", user),
            )
            disabled.append({"user": user, "platform": platform, "agent_ids": agent_ids})
        output["disabled"] = disabled

    def rollback(self, targets: list[str], ctx: PlaybookContext) -> PlaybookResult:
        steps: list[PlaybookStep] = []
        for item in ctx.extra.get("previous_output", {}).get("disabled", []):
            if item["user"] in targets:
                self.active_response(
                    ctx,
                    steps,
                    f"enable_account:{item['user']}",
                    item["agent_ids"],
                    f"agentic-disable-user-{item['platform']}",
                    self._arguments("enable", item["user"]),
                )
        status = PlaybookStatus.ROLLED_BACK if ctx.live else PlaybookStatus.DRY_RUN
        return PlaybookResult(playbook=self.name, action=self.action, status=status, targets=targets, steps=steps)
