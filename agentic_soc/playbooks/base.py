"""Predefined, auditable response playbooks (blueprint section 17).

Playbooks are the only code that changes systems. Each one:
  * accepts only targets that already passed the policy engine,
  * re-validates them (defence in depth),
  * records every step, and
  * in ``dry_run`` mode reports the exact API calls it *would* make without making them.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from agentic_soc.config.settings import Settings
from agentic_soc.integrations.opnsense import OPNsenseClient
from agentic_soc.integrations.wazuh import WazuhAPIClient, WazuhIndexerClient
from agentic_soc.models.schemas import (
    Entity,
    EntityType,
    PlaybookResult,
    PlaybookStatus,
    PlaybookStep,
    ResponseAction,
    ThreatIntelResult,
)
from agentic_soc.policy.policy_engine import PolicyEngine

log = logging.getLogger(__name__)


@dataclass
class ResponseServices:
    settings: Settings
    policy: PolicyEngine
    wazuh: WazuhAPIClient | None = None
    indexer: WazuhIndexerClient | None = None
    opnsense: OPNsenseClient | None = None


@dataclass
class PlaybookContext:
    incident_id: int
    mode: str  # dry_run | live
    entities: list[Entity] = field(default_factory=list)
    threat_intel: list[ThreatIntelResult] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)  # normalized alert dicts
    approved_by: str | None = None
    policy_outcome: str | None = None
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def live(self) -> bool:
        return self.mode == "live"


class PlaybookAbort(Exception):
    """Raised by a step to stop the playbook with REJECTED status."""


class Playbook(ABC):
    name: str = "base"
    action: ResponseAction = ResponseAction.NONE
    supports_rollback: bool = False

    def __init__(self, services: ResponseServices) -> None:
        self.services = services

    def run(self, targets: list[str], ctx: PlaybookContext) -> PlaybookResult:
        steps: list[PlaybookStep] = []
        output: dict[str, Any] = {}
        try:
            self.execute(targets, ctx, steps, output)
        except PlaybookAbort as exc:
            steps.append(PlaybookStep(name="abort", status="failed", detail=str(exc)))
            return PlaybookResult(
                playbook=self.name,
                action=self.action,
                status=PlaybookStatus.REJECTED,
                targets=targets,
                steps=steps,
                output=output,
            )
        except Exception as exc:  # noqa: BLE001 - every failure must be recorded, never swallowed silently
            log.exception("playbook %s failed", self.name)
            steps.append(PlaybookStep(name="error", status="failed", detail=f"{type(exc).__name__}: {exc}"))
            return PlaybookResult(
                playbook=self.name,
                action=self.action,
                status=PlaybookStatus.FAILED,
                targets=targets,
                steps=steps,
                output=output,
            )
        if any(step.status == "failed" for step in steps):
            status = PlaybookStatus.FAILED
        elif ctx.live:
            status = PlaybookStatus.SUCCESS
        else:
            status = PlaybookStatus.DRY_RUN
        steps.append(PlaybookStep(name="record_result", status="ok", detail=f"status={status.value}"))
        return PlaybookResult(
            playbook=self.name, action=self.action, status=status, targets=targets, steps=steps, output=output
        )

    @abstractmethod
    def execute(
        self, targets: list[str], ctx: PlaybookContext, steps: list[PlaybookStep], output: dict[str, Any]
    ) -> None: ...

    def rollback(self, targets: list[str], ctx: PlaybookContext) -> PlaybookResult:
        return PlaybookResult(
            playbook=self.name,
            action=self.action,
            status=PlaybookStatus.REJECTED,
            targets=targets,
            steps=[PlaybookStep(name="rollback", status="failed", detail="rollback not supported")],
        )

    # --- shared helpers ------------------------------------------------------------------
    @staticmethod
    def platform_of(agent: dict[str, Any] | None) -> str | None:
        if not agent:
            return None
        platform = str((agent.get("os") or {}).get("platform", "")).lower()
        if not platform:
            return None
        return "windows" if platform == "windows" else "linux"

    def resolve_agent(self, target: str, ctx: PlaybookContext) -> dict[str, Any] | None:
        """Map a host name or IP to a Wazuh agent ({id, name, ip, status, os})."""
        for entity in ctx.entities:
            if entity.type == EntityType.HOST and (
                entity.value.lower() == target.lower() or entity.attributes.get("ip") == target
            ):
                agent = {
                    "id": entity.attributes.get("agent_id"),
                    "name": entity.value,
                    "ip": entity.attributes.get("ip"),
                }
                wazuh = self.services.wazuh
                if wazuh and agent["id"]:
                    return wazuh.get_agent(agent["id"]) or agent
                return agent if agent["id"] else None
        if self.services.wazuh:
            return self.services.wazuh.find_agent_by_ip(target)
        return None

    def active_response(
        self,
        ctx: PlaybookContext,
        steps: list[PlaybookStep],
        step_name: str,
        agent_ids: list[str],
        command: str,
        arguments: list[str],
        alert_data: dict[str, Any] | None = None,
    ) -> None:
        request = {"agents_list": agent_ids, "command": command, "arguments": arguments}
        if alert_data:
            request["alert"] = {"data": alert_data}
        if not ctx.live:
            steps.append(
                PlaybookStep(
                    name=step_name, status="planned", detail="dry run: Wazuh active response", data={"request": request}
                )
            )
            return
        if not self.services.wazuh:
            raise PlaybookAbort("Wazuh API is not configured (SOC_WAZUH_API_URL)")
        response = self.services.wazuh.run_active_response(agent_ids, command, arguments, alert_data)
        steps.append(
            PlaybookStep(name=step_name, status="ok", detail=response.get("message", "sent"), data={"request": request})
        )
