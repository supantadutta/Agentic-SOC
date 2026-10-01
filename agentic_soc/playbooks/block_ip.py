"""IOC block: validate reputation -> check internal sightings -> create controlled firewall
block -> record action."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from agentic_soc.models.schemas import (
    Entity,
    EntityType,
    PlaybookResult,
    PlaybookStatus,
    PlaybookStep,
    ResponseAction,
    ThreatIntelVerdict,
)
from agentic_soc.playbooks.base import Playbook, PlaybookAbort, PlaybookContext


class BlockIPPlaybook(Playbook):
    name = "block_ip"
    action = ResponseAction.BLOCK_IP
    supports_rollback = True

    def _validate(self, ip: str, ctx: PlaybookContext, steps: list[PlaybookStep]) -> None:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise PlaybookAbort(f"{ip!r} is not an IP address") from exc
        if self.services.policy.is_never_block(ip):
            raise PlaybookAbort(f"{ip} is on the never-block list")
        verdicts = {t.source: t.verdict.value for t in ctx.threat_intel if t.indicator == ip}
        bad = [v for v in verdicts.values() if v in (ThreatIntelVerdict.MALICIOUS, ThreatIntelVerdict.SUSPICIOUS)]
        harmless = [v for v in verdicts.values() if v == ThreatIntelVerdict.HARMLESS]
        if harmless and not bad and not ctx.approved_by:
            raise PlaybookAbort(f"{ip} has only harmless reputation {verdicts}; analyst approval required")
        steps.append(
            PlaybookStep(
                name=f"validate_reputation:{ip}",
                status="ok",
                detail="reputation evidence" if bad else "no reputation evidence; relying on behavioural detection",
                data={"verdicts": verdicts},
            )
        )

    def _sightings(self, ip: str, ctx: PlaybookContext, steps: list[PlaybookStep]) -> None:
        local = sum(1 for a in ctx.alerts if ip in (a.get("src_ip"), a.get("dst_ip")))
        data: dict[str, Any] = {"incident_alerts": local}
        indexer = self.services.indexer
        if indexer:
            try:
                data["indexer_7d"] = indexer.count_sightings(
                    Entity(type=EntityType.IP, value=ip), datetime.now(UTC) - timedelta(days=7)
                )
            except Exception as exc:  # noqa: BLE001 - sightings are informational
                data["indexer_error"] = str(exc)
        steps.append(PlaybookStep(name=f"internal_sightings:{ip}", status="ok", data=data))

    def execute(
        self, targets: list[str], ctx: PlaybookContext, steps: list[PlaybookStep], output: dict[str, Any]
    ) -> None:
        for ip in targets:
            self._validate(ip, ctx, steps)
            self._sightings(ip, ctx, steps)
        settings = self.services.settings
        blocked = []
        for ip in targets:
            if settings.block_backend == "opnsense":
                request = {"alias": settings.opnsense_alias, "address": ip}
                if not ctx.live:
                    steps.append(
                        PlaybookStep(
                            name=f"firewall_block:{ip}",
                            status="planned",
                            detail="dry run: OPNsense alias add",
                            data={"request": request},
                        )
                    )
                else:
                    if not self.services.opnsense:
                        raise PlaybookAbort("OPNsense API is not configured (SOC_OPNSENSE_URL)")
                    resp = self.services.opnsense.add_to_alias(settings.opnsense_alias, ip)
                    steps.append(PlaybookStep(name=f"firewall_block:{ip}", status="ok", data={"response": resp}))
            else:
                agent_ids = sorted(
                    {
                        str(e.attributes["agent_id"])
                        for e in ctx.entities
                        if e.type == EntityType.HOST and e.attributes.get("agent_id")
                    }
                )
                if not agent_ids:
                    raise PlaybookAbort("no Wazuh agents in the incident to apply an endpoint block on")
                self.active_response(
                    ctx, steps, f"endpoint_block:{ip}", agent_ids, "firewall-drop", [], alert_data={"srcip": ip}
                )
            blocked.append(ip)
        output["blocked"] = blocked
        output["backend"] = settings.block_backend

    def rollback(self, targets: list[str], ctx: PlaybookContext) -> PlaybookResult:
        settings = self.services.settings
        steps: list[PlaybookStep] = []
        if settings.block_backend != "opnsense":
            steps.append(
                PlaybookStep(
                    name="rollback", status="failed", detail="Wazuh firewall-drop blocks expire via the command timeout"
                )
            )
            return PlaybookResult(
                playbook=self.name, action=self.action, status=PlaybookStatus.REJECTED, targets=targets, steps=steps
            )
        for ip in targets:
            if not ctx.live:
                steps.append(
                    PlaybookStep(
                        name=f"unblock:{ip}", status="planned", data={"alias": settings.opnsense_alias, "address": ip}
                    )
                )
                continue
            if not self.services.opnsense:
                steps.append(PlaybookStep(name=f"unblock:{ip}", status="failed", detail="OPNsense not configured"))
                continue
            resp = self.services.opnsense.remove_from_alias(settings.opnsense_alias, ip)
            steps.append(PlaybookStep(name=f"unblock:{ip}", status="ok", data={"response": resp}))
        failed = any(s.status == "failed" for s in steps)
        status = (
            PlaybookStatus.FAILED if failed else (PlaybookStatus.ROLLED_BACK if ctx.live else PlaybookStatus.DRY_RUN)
        )
        return PlaybookResult(playbook=self.name, action=self.action, status=status, targets=targets, steps=steps)
