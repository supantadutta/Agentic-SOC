# Phase 3 — Sysmon on Windows endpoints

Sysmon supplies the process-creation (1), network-connection (3), file-create (11), registry
(12–14) and DNS-query (22) events the triage agent relies on.

1. Download Sysmon from Microsoft Sysinternals: <https://learn.microsoft.com/sysinternals/downloads/sysmon>.
2. Pick a maintained community configuration and review it before use, for example
   [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (a
   balanced default) or [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
   (modular, ATT&CK-tagged).
3. Install from an elevated prompt:

   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   # later updates to the configuration:
   .\Sysmon64.exe -c sysmonconfig.xml
   ```

4. Add the `Microsoft-Windows-Sysmon/Operational` channel to the Wazuh agent
   ([`../wazuh/agents/ossec-agent-windows.xml`](../wazuh/agents/ossec-agent-windows.xml)) and
   restart the agent: `Restart-Service WazuhSvc`.
5. Confirm in the Wazuh dashboard that `rule.groups: sysmon` events arrive from the endpoint.

Start with one Windows and one Linux endpoint, validate their telemetry, then scale out.
