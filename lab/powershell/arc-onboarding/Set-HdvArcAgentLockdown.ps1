#Requires -Version 5.1
<#
.SYNOPSIS
    Applies or verifies Microsoft's Tier 0 lockdown of the Azure Connected Machine agent.

.DESCRIPTION
    Implements the local agent security controls that Microsoft recommends for Tier 0 assets
    such as domain controllers (Azure Arc documentation, "Security considerations for Tier 0
    assets" and "Extensions security"):

        azcmagent config set incomingconnections.enabled false
        azcmagent config set guestconfiguration.enabled false
        azcmagent config set extensions.allowlist "Microsoft.Azure.Monitor/AzureMonitorWindowsAgent"

    These settings are stored locally and cannot be overridden from Azure, not even by a
    subscription Owner. Apply them BEFORE 'azcmagent connect' (Microsoft documents that allow
    lists can be configured before the agent is connected).

    Project rule (ADR-0011): a domain controller is connected to Azure Arc only if a dedicated
    Tier 0 subscription exists. This script does not connect anything.

    STATUS: written in Phase 0. NOT executed against a real agent. The JSON shape returned by
    'azcmagent config get --json' is not documented; values that cannot be read are reported
    as UNKNOWN and treated as NON-compliant (fail closed). Run with -VerifyOnly first.

.PARAMETER VerifyOnly
    Read-only. Reports compliance and changes nothing.

.PARAMETER AllowedExtensions
    Extensions to allow-list. Script-execution extensions (Run Command, Custom Script,
    Hybrid Worker) are refused.

.PARAMETER AzcmagentPath
    Path to azcmagent.exe.

.EXAMPLE
    .\Set-HdvArcAgentLockdown.ps1 -VerifyOnly

.EXAMPLE
    .\Set-HdvArcAgentLockdown.ps1 -WhatIf

.OUTPUTS
    One object per setting: Setting, Desired, Actual, Compliant. Exit code 0 if all settings
    are compliant, 1 otherwise.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch] $VerifyOnly,

    [ValidateNotNullOrEmpty()]
    [string[]] $AllowedExtensions = @('Microsoft.Azure.Monitor/AzureMonitorWindowsAgent'),

    [ValidateNotNullOrEmpty()]
    [string] $AzcmagentPath = "${env:ProgramFiles}\AzureConnectedMachineAgent\azcmagent.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptExecutionExtensions = 'RunCommand|CustomScript|HybridWorker'
foreach ($extension in $AllowedExtensions) {
    if ($extension -notmatch '^[A-Za-z0-9.]+/[A-Za-z0-9.]+$') {
        throw "Invalid extension name '$extension'. Expected Publisher/Type."
    }
    if ($extension -match $scriptExecutionExtensions) {
        throw "Extension '$extension' can execute arbitrary code as SYSTEM and must not be allow-listed on a Tier 0 server."
    }
}

if (-not (Test-Path -LiteralPath $AzcmagentPath -PathType Leaf)) {
    throw "azcmagent not found at '$AzcmagentPath'. Install the Azure Connected Machine agent first (do not connect it yet)."
}

$desired = [ordered]@{
    'incomingconnections.enabled' = 'false'
    'guestconfiguration.enabled'  = 'false'
    'extensions.allowlist'        = (($AllowedExtensions | Sort-Object -Unique) -join ',')
}

function Invoke-Azcmagent {
    param([Parameter(Mandatory = $true)] [string[]] $Arguments)
    $output = & $AzcmagentPath @Arguments 2>&1
    [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = ($output | Out-String).Trim()
    }
}

function Get-AgentValue {
    param([Parameter(Mandatory = $true)] [string] $Name)
    $result = Invoke-Azcmagent -Arguments @('config', 'get', $Name, '--json')
    if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($result.Output)) {
        return $null
    }
    try {
        $parsed = $result.Output | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return $result.Output.Trim().Trim('"')
    }
    if ($parsed -is [string] -or $parsed -is [bool]) {
        return [string]$parsed
    }
    foreach ($property in @('value', $Name)) {
        if ($parsed.PSObject.Properties.Name -contains $property) {
            return [string]$parsed.$property
        }
    }
    return $null
}

function ConvertTo-NormalizedValue {
    param([string] $Name, [AllowNull()] [string] $Value)
    if ($null -eq $Value) {
        return $null
    }
    if ($Name -eq 'extensions.allowlist') {
        $items = $Value -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique
        return ($items -join ',')
    }
    return $Value.Trim().ToLowerInvariant()
}

$results = foreach ($name in $desired.Keys) {
    $want = ConvertTo-NormalizedValue -Name $name -Value $desired[$name]
    $have = ConvertTo-NormalizedValue -Name $name -Value (Get-AgentValue -Name $name)
    $compliant = ($null -ne $have) -and ($have -eq $want)

    if (-not $compliant -and -not $VerifyOnly) {
        if ($PSCmdlet.ShouldProcess('Azure Connected Machine agent', "azcmagent config set $name $($desired[$name])")) {
            $set = Invoke-Azcmagent -Arguments @('config', 'set', $name, $desired[$name])
            if ($set.ExitCode -ne 0) {
                throw "azcmagent config set $name failed (exit $($set.ExitCode)): $($set.Output)"
            }
            $have = ConvertTo-NormalizedValue -Name $name -Value (Get-AgentValue -Name $name)
            $compliant = ($null -ne $have) -and ($have -eq $want)
        }
    }

    [pscustomobject]@{
        Setting   = $name
        Desired   = $desired[$name]
        Actual    = $(if ($null -eq $have) { 'UNKNOWN' } else { $have })
        Compliant = $compliant
    }
}

$results
if (@($results | Where-Object { -not $_.Compliant }).Count -gt 0) {
    Write-Warning 'Agent is NOT compliant with the Tier 0 lockdown. Do not connect this server to Azure Arc.'
    exit 1
}
exit 0
