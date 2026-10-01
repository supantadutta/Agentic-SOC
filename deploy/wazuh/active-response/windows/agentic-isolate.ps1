# Wazuh active response (Windows): network-isolate this host, keeping only the Wazuh manager
# reachable. Called via agentic-isolate.cmd with arguments ["isolate"|"release", "<manager_ip>"].
#
# Uses explicit Block rules for every IPv4 address except the manager. Block rules take
# precedence over allow rules in Windows Defender Firewall, so pre-existing allow rules
# cannot bypass the isolation. The lab is IPv4-only; disable IPv6 on lab endpoints or add an
# equivalent IPv6 block rule.
$ErrorActionPreference = "Stop"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$Group = "AgenticSOC-Isolation"

function Write-Log([string]$Message) {
    Add-Content -Path $LogFile -Value ("{0} agentic-isolate: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $Message)
}

function ConvertTo-UInt32([System.Net.IPAddress]$Ip) {
    $bytes = $Ip.GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32([uint32]$Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

$message = [Console]::In.ReadLine() | ConvertFrom-Json
$extra = @($message.parameters.extra_args)
$action = [string]$extra[0]
$managerText = [string]$extra[1]
$manager = $null
if (-not [System.Net.IPAddress]::TryParse($managerText, [ref]$manager) -or
    $manager.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    Write-Log "refusing: invalid manager address '$managerText'"
    exit 1
}

if ($action -eq "isolate") {
    $m = ConvertTo-UInt32 $manager
    $ranges = @()
    if ($m -gt 0) { $ranges += "0.0.0.0-" + (ConvertFrom-UInt32 ($m - 1)) }
    if ($m -lt [uint32]::MaxValue) { $ranges += (ConvertFrom-UInt32 ($m + 1)) + "-255.255.255.255" }
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName "AgenticSOC isolation (outbound)" -Group $Group -Direction Outbound `
        -Action Block -RemoteAddress $ranges -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "AgenticSOC isolation (inbound)" -Group $Group -Direction Inbound `
        -Action Block -RemoteAddress $ranges -Profile Any | Out-Null
    Set-NetFirewallProfile -All -Enabled True
    Write-Log "host isolated (manager $managerText still reachable)"
}
elseif ($action -eq "release") {
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Log "host released from isolation"
}
else {
    Write-Log "refusing: unknown action '$action'"
    exit 1
}
exit 0
