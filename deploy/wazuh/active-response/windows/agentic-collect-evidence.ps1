# Wazuh active response (Windows): collect volatile evidence into a local, hashed archive.
#   process list -> network connections -> recent files -> hashes -> relevant logs
# Called via agentic-collect-evidence.cmd with arguments ["incident-<id>"].
# Output: C:\ProgramData\AgenticSOC\evidence\<tag>-<UTC>.zip (+ .sha256)
$ErrorActionPreference = "Continue"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
function Write-Log([string]$Message) {
    Add-Content -Path $LogFile -Value ("{0} agentic-collect-evidence: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $Message)
}

$message = [Console]::In.ReadLine() | ConvertFrom-Json
$tag = ([string](@($message.parameters.extra_args)[0])) -replace '[^A-Za-z0-9_-]', ''
if (-not $tag) { $tag = "manual" }
$tag = $tag.Substring(0, [Math]::Min(64, $tag.Length))
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$base = "C:\ProgramData\AgenticSOC\evidence"
$out = Join-Path $base "$tag-$stamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null

Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
    Export-Csv (Join-Path $out "process_list.csv") -NoTypeInformation
Get-NetTCPConnection |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime |
    Export-Csv (Join-Path $out "network_connections.csv") -NoTypeInformation
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess |
    Export-Csv (Join-Path $out "udp_endpoints.csv") -NoTypeInformation
Get-DnsClientCache | Export-Csv (Join-Path $out "dns_cache.csv") -NoTypeInformation

$since = (Get-Date).AddHours(-24)
$paths = @("C:\Users\*\Downloads", "C:\Users\*\AppData\Local\Temp", "C:\Users\Public", "C:\Windows\Temp")
$recent = Get-ChildItem -Path $paths -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $since } | Select-Object -First 2000
$recent | Select-Object FullName, Length, CreationTime, LastWriteTime |
    Export-Csv (Join-Path $out "recent_files.csv") -NoTypeInformation
$recent | Where-Object { $_.Length -lt 50MB -and $_.Extension -match '^\.(exe|dll|ps1|bat|cmd|vbs|js|hta|docm|xlsm|lnk|scr)$' } |
    Select-Object -First 500 | Get-FileHash -Algorithm SHA256 |
    Export-Csv (Join-Path $out "file_hashes.csv") -NoTypeInformation

$logs = @("Security", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational")
foreach ($log in $logs) {
    $name = ($log -replace '[\\/ ]', '_')
    Get-WinEvent -LogName $log -MaxEvents 2000 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, ProviderName, Message |
        Export-Csv (Join-Path $out "$name.csv") -NoTypeInformation
}
Get-ScheduledTask | Select-Object TaskPath, TaskName, State, Author |
    Export-Csv (Join-Path $out "scheduled_tasks.csv") -NoTypeInformation

$zip = "$out.zip"
Compress-Archive -Path "$out\*" -DestinationPath $zip -Force
Remove-Item -Recurse -Force $out
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
Set-Content -Path "$zip.sha256" -Value "$hash  $(Split-Path $zip -Leaf)"
Write-Log "evidence written to $zip ($hash)"
exit 0
