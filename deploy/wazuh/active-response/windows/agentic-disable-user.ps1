# Wazuh active response (Windows domain controller): disable or re-enable an AD account.
# Called via agentic-disable-user.cmd with arguments ["disable"|"enable", "<sAMAccountName>"].
# Runs on the DC agent configured as SOC_AD_DC_AGENT_ID (requires the ActiveDirectory module).
$ErrorActionPreference = "Stop"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$Protected = @("krbtgt")
function Write-Log([string]$Message) {
    Add-Content -Path $LogFile -Value ("{0} agentic-disable-user: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $Message)
}

$message = [Console]::In.ReadLine() | ConvertFrom-Json
$extra = @($message.parameters.extra_args)
$action = [string]$extra[0]
$user = [string]$extra[1]
if ($user -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { Write-Log "refusing: invalid account name"; exit 1 }
if ($Protected -contains $user.ToLower()) { Write-Log "refusing: $user is protected"; exit 1 }

Import-Module ActiveDirectory
try {
    $account = Get-ADUser -Identity $user
}
catch {
    Write-Log "refusing: account $user not found"
    exit 1
}
switch ($action) {
    "disable" { Disable-ADAccount -Identity $account; Write-Log "account $user disabled" }
    "enable" { Enable-ADAccount -Identity $account; Write-Log "account $user enabled" }
    default { Write-Log "refusing: unknown action '$action'"; exit 1 }
}
exit 0
