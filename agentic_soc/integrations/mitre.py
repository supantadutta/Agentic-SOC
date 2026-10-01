"""MITRE ATT&CK knowledge base.

Loads the Enterprise ATT&CK STIX bundle (``scripts/fetch_attack_data.py`` downloads it) to
map technique ids to names/tactics and to reject technique ids the LLM made up. When the
bundle is absent a small built-in table covering the lab scenarios is used.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agentic_soc.models.schemas import TECHNIQUE_ID_RE, AttackTechnique

log = logging.getLogger(__name__)

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"

# Fallback subset (technique id -> (name, tactics)).
BUILTIN_TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1003": ("OS Credential Dumping", ["credential-access"]),
    "T1003.001": ("LSASS Memory", ["credential-access"]),
    "T1021": ("Remote Services", ["lateral-movement"]),
    "T1021.001": ("Remote Desktop Protocol", ["lateral-movement"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["lateral-movement"]),
    "T1021.004": ("SSH", ["lateral-movement"]),
    "T1027": ("Obfuscated Files or Information", ["defense-evasion"]),
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1053.005": ("Scheduled Task", ["execution", "persistence", "privilege-escalation"]),
    "T1059": ("Command and Scripting Interpreter", ["execution"]),
    "T1059.001": ("PowerShell", ["execution"]),
    "T1059.003": ("Windows Command Shell", ["execution"]),
    "T1059.004": ("Unix Shell", ["execution"]),
    "T1070.001": ("Clear Windows Event Logs", ["defense-evasion"]),
    "T1071": ("Application Layer Protocol", ["command-and-control"]),
    "T1071.001": ("Web Protocols", ["command-and-control"]),
    "T1078": ("Valid Accounts", ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1110.001": ("Password Guessing", ["credential-access"]),
    "T1110.003": ("Password Spraying", ["credential-access"]),
    "T1136": ("Create Account", ["persistence"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1204": ("User Execution", ["execution"]),
    "T1204.002": ("Malicious File", ["execution"]),
    "T1486": ("Data Encrypted for Impact", ["impact"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["persistence", "privilege-escalation"]),
    "T1548.003": ("Sudo and Sudo Caching", ["privilege-escalation", "defense-evasion"]),
    "T1566": ("Phishing", ["initial-access"]),
    "T1566.001": ("Spearphishing Attachment", ["initial-access"]),
    "T1566.002": ("Spearphishing Link", ["initial-access"]),
    "T1569.002": ("Service Execution", ["execution"]),
    "T1595": ("Active Scanning", ["reconnaissance"]),
    "T1595.001": ("Scanning IP Blocks", ["reconnaissance"]),
}

# Kill-chain order, used to describe incident progression.
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


class AttackKnowledgeBase:
    def __init__(self, techniques: dict[str, AttackTechnique], source: str) -> None:
        self.techniques = techniques
        self.source = source

    @classmethod
    def load(cls, path: Path | None) -> AttackKnowledgeBase:
        if path and Path(path).exists():
            try:
                return cls(_parse_stix_bundle(Path(path)), source=str(path))
            except (OSError, ValueError, KeyError) as exc:
                log.warning("could not parse ATT&CK bundle %s (%s); using built-in subset", path, exc)
        return cls.builtin()

    @classmethod
    def builtin(cls) -> AttackKnowledgeBase:
        techniques = {
            tid: AttackTechnique(id=tid, name=name, tactics=tactics, url=_url(tid))
            for tid, (name, tactics) in BUILTIN_TECHNIQUES.items()
        }
        return cls(techniques, source="builtin")

    @property
    def is_complete(self) -> bool:
        return self.source != "builtin"

    def get(self, technique_id: str) -> AttackTechnique | None:
        tid = technique_id.strip().upper()
        if tid in self.techniques:
            return self.techniques[tid]
        if "." in tid and tid.split(".")[0] in self.techniques:
            parent = self.techniques[tid.split(".")[0]]
            if not self.is_complete:
                return AttackTechnique(
                    id=tid, name=f"{parent.name} (sub-technique)", tactics=parent.tactics, url=_url(tid)
                )
        return None

    def is_valid(self, technique_id: str) -> bool:
        """With the full bundle, ids must exist. With the built-in subset, well-formed ids pass."""
        if not TECHNIQUE_ID_RE.match(technique_id.strip().upper()):
            return False
        if self.is_complete:
            return self.get(technique_id) is not None
        return True

    def describe(self, technique_ids: list[str]) -> list[AttackTechnique]:
        out = []
        for tid in technique_ids:
            tech = self.get(tid)
            if tech:
                out.append(tech)
        return out

    def tactics_for(self, technique_ids: list[str]) -> list[str]:
        tactics = {t for tech in self.describe(technique_ids) for t in tech.tactics}
        return [t for t in TACTIC_ORDER if t in tactics]


def _url(tid: str) -> str:
    return ATTACK_URL.format(tid.replace(".", "/"))


def _parse_stix_bundle(path: Path) -> dict[str, AttackTechnique]:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    techniques: dict[str, AttackTechnique] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ref or not ref.get("external_id"):
            continue
        tid = ref["external_id"].upper()
        tactics = [
            p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[tid] = AttackTechnique(
            id=tid, name=obj.get("name", tid), tactics=tactics, url=ref.get("url") or _url(tid)
        )
    if not techniques:
        raise ValueError("no attack-pattern objects found")
    return techniques
