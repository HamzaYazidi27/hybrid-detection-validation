#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only validation of directory synchronisation from the Entra side (Module 2.1, step 11).

.DESCRIPTION
    Run on the management host by the owner, with an interactive, delegated, READ-ONLY sign-in
    (Organization.Read.All, User.Read.All, Group.Read.All, Application.Read.All,
    OnPremDirectorySynchronization.Read.All). Fails closed on a tenant mismatch.

      E1  signed-in tenant ID = Tenant.TenantId AND initial domain = Tenant.ExpectedInitialDomain
      E2  tenant directory synchronisation enabled; last sync within MaxSyncAgeMinutes
      E3  canary user exists as a synchronised, disabled user
      E4  canary group exists as a synchronised group
      E5  the connector account is NOT present in Entra ID (best effort, by display name)
      E6  hard-match takeover is blocked
      E7  the Entra Connect application has a valid certificate credential and no client secret

    While EntraConnect.ExpectStagingMode is true, nothing has been exported yet: E2-E4 report
    MANUAL instead of FAIL.

    Exit code: 0 all PASS, 1 any FAIL, 2 only WARN/MANUAL remain.

.EXAMPLE
    .\Test-HdvEntraSyncState.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ConfigPath,
    [ValidateRange(1, 60)] [int] $CertificateWarningDays = 14
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force

$config = Import-HdvConfig -Path $ConfigPath
$tenantId = Assert-HdvGuid -Value (Get-HdvConfigValue -Config $config -Path 'Tenant.TenantId' -Required) -Name 'Tenant.TenantId'
$expectedInitial = ([string](Get-HdvConfigValue -Config $config -Path 'Tenant.ExpectedInitialDomain' -Required)).Trim().ToLowerInvariant()
$appId = Get-HdvConfigValue -Config $config -Path 'EntraConnect.ApplicationId'
if ($appId) { $appId = Assert-HdvGuid -Value $appId -Name 'EntraConnect.ApplicationId' }
$staging = [bool](Get-HdvConfigValue -Config $config -Path 'EntraConnect.ExpectStagingMode')
$maxAge = [int](Get-HdvConfigValue -Config $config -Path 'EntraConnect.MaxSyncAgeMinutes' -Required)
$canaryUser = Get-HdvConfigValue -Config $config -Path 'Canary.UserDisplayName' -Required
$canarySam = Get-HdvConfigValue -Config $config -Path 'Canary.UserSamAccountName' -Required
$canaryGroup = Get-HdvConfigValue -Config $config -Path 'Canary.GroupName' -Required
$connectorSam = Get-HdvConfigValue -Config $config -Path 'ConnectorAccount.SamAccountName' -Required
$notExported = if ($staging) { 'MANUAL' } else { 'FAIL' }

function ConvertTo-ODataLiteral { param([string] $Value) return $Value.Replace("'", "''") }

foreach ($probe in @(
        @{ Module = 'Microsoft.Graph.Authentication'; Command = 'Connect-MgGraph' },
        @{ Module = 'Microsoft.Graph.Identity.DirectoryManagement'; Command = 'Get-MgOrganization' },
        @{ Module = 'Microsoft.Graph.Users'; Command = 'Get-MgUser' },
        @{ Module = 'Microsoft.Graph.Groups'; Command = 'Get-MgGroup' },
        @{ Module = 'Microsoft.Graph.Applications'; Command = 'Get-MgApplication' })) {
    if (-not (Import-HdvRequiredModule -Name $probe.Module -ProbeCommand $probe.Command)) {
        throw "PowerShell module '$($probe.Module)' is required on the management host. This script never installs it."
    }
}

$results = New-Object System.Collections.Generic.List[object]
$scopes = 'Organization.Read.All', 'User.Read.All', 'Group.Read.All', 'Application.Read.All', 'OnPremDirectorySynchronization.Read.All'
Connect-MgGraph -TenantId $tenantId -Scopes $scopes | Out-Null
try {
    # E1
    $context = Get-MgContext
    if ([string]$context.TenantId -ne $tenantId) {
        $results.Add((New-HdvResult 'E1 tenant' ([string]$context.TenantId) "not the configured lab tenant $tenantId; nothing else was read" 'FAIL'))
        return
    }
    $org = @(Get-MgOrganization)[0]
    $initial = @($org.VerifiedDomains | Where-Object { $_.IsInitial } | ForEach-Object { ([string]$_.Name).ToLowerInvariant() })
    if ($initial.Count -ne 1 -or $initial[0] -ne $expectedInitial) {
        $results.Add((New-HdvResult 'E1 tenant' $tenantId "initial domain [$($initial -join ', ')] is not the configured lab initial domain $expectedInitial; nothing else was read" 'FAIL'))
        return
    }
    $results.Add((New-HdvResult 'E1 tenant' $tenantId "tenant ID and initial domain $expectedInitial verified" 'PASS'))

    # E2
    if ($org.OnPremisesSyncEnabled) {
        $results.Add((New-HdvResult 'E2 directory sync enabled' $tenantId 'OnPremisesSyncEnabled = True' 'PASS'))
    }
    else {
        $results.Add((New-HdvResult 'E2 directory sync enabled' $tenantId 'OnPremisesSyncEnabled is not True' $notExported))
    }
    if ($org.OnPremisesLastSyncDateTime) {
        $age = [int]((Get-Date).ToUniversalTime() - ([datetime]$org.OnPremisesLastSyncDateTime).ToUniversalTime()).TotalMinutes
        $ageResult = if ($age -le $maxAge) { 'PASS' } else { 'WARN' }
        $results.Add((New-HdvResult 'E2 last directory sync' $tenantId "$age minute(s) ago (limit $maxAge)" $ageResult))
    }
    else {
        $results.Add((New-HdvResult 'E2 last directory sync' $tenantId 'no sync recorded' $notExported))
    }

    # E3
    $users = @(Get-MgUser -Filter "displayName eq '$(ConvertTo-ODataLiteral $canaryUser)'" -Property 'id,displayName,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName')
    $syncedCanary = @($users | Where-Object { $_.OnPremisesSyncEnabled -and ([string]$_.OnPremisesSamAccountName -eq $canarySam) })
    if ($syncedCanary.Count -eq 1) {
        $enabledResult = if ($syncedCanary[0].AccountEnabled) { 'WARN' } else { 'PASS' }
        $results.Add((New-HdvResult 'E3 canary user synchronised' $canaryUser "synchronised; accountEnabled=$($syncedCanary[0].AccountEnabled)" $enabledResult))
    }
    else {
        $results.Add((New-HdvResult 'E3 canary user synchronised' $canaryUser "found $($syncedCanary.Count) synchronised match(es)" $notExported))
    }

    # E4
    $groups = @(Get-MgGroup -Filter "displayName eq '$(ConvertTo-ODataLiteral $canaryGroup)'" -Property 'id,displayName,onPremisesSyncEnabled')
    $syncedGroup = @($groups | Where-Object { $_.OnPremisesSyncEnabled })
    $groupResult = if ($syncedGroup.Count -eq 1) { 'PASS' } else { $notExported }
    $results.Add((New-HdvResult 'E4 canary group synchronised' $canaryGroup "found $($syncedGroup.Count) synchronised match(es)" $groupResult))

    # E5
    $leaked = @(Get-MgUser -Filter "displayName eq '$(ConvertTo-ODataLiteral $connectorSam)'" -Property 'id,displayName,onPremisesSyncEnabled' |
            Where-Object { $_.OnPremisesSyncEnabled })
    $leakResult = if ($leaked.Count -eq 0) { 'PASS' } else { 'FAIL' }
    $results.Add((New-HdvResult 'E5 connector account not synchronised' $connectorSam "$($leaked.Count) synchronised user(s) with this display name" $leakResult))

    # E6
    $sync = @(Get-MgDirectoryOnPremiseSynchronization)
    if ($sync.Count -eq 1 -and [bool]$sync[0].Features.BlockCloudObjectTakeoverThroughHardMatchEnabled) {
        $results.Add((New-HdvResult 'E6 hard-match takeover blocked' $tenantId 'True' 'PASS'))
    }
    else {
        $results.Add((New-HdvResult 'E6 hard-match takeover blocked' $tenantId 'not enabled: run Set-HdvHardMatchTakeoverBlock.ps1' 'FAIL'))
    }

    # E7
    if (-not $appId) {
        $results.Add((New-HdvResult 'E7 Connect application credentials' 'EntraConnect.ApplicationId' 'not configured yet (fill it in after installation)' 'MANUAL'))
    }
    else {
        $apps = @(Get-MgApplication -Filter "appId eq '$appId'" -Property 'id,appId,displayName,keyCredentials,passwordCredentials')
        if ($apps.Count -ne 1) {
            $results.Add((New-HdvResult 'E7 Connect application credentials' $appId "expected 1 application, found $($apps.Count)" 'FAIL'))
        }
        else {
            $now = (Get-Date).ToUniversalTime()
            $valid = @($apps[0].KeyCredentials | Where-Object { $_.EndDateTime -and ([datetime]$_.EndDateTime).ToUniversalTime() -gt $now })
            if ($valid.Count -eq 0) {
                $results.Add((New-HdvResult 'E7 Connect application certificate' $appId 'no valid certificate credential' 'FAIL'))
            }
            else {
                $latest = ($valid | ForEach-Object { ([datetime]$_.EndDateTime).ToUniversalTime() } | Sort-Object -Descending | Select-Object -First 1)
                $days = [int]($latest - $now).TotalDays
                $certResult = if ($days -le $CertificateWarningDays) { 'WARN' } else { 'PASS' }
                $results.Add((New-HdvResult 'E7 Connect application certificate' $appId "latest certificate valid for $days more day(s)" $certResult))
            }
            $secrets = @($apps[0].PasswordCredentials)
            $secretResult = if ($secrets.Count -eq 0) { 'PASS' } else { 'WARN' }
            $results.Add((New-HdvResult 'E7 no client secret on Connect application' $appId "$($secrets.Count) password credential(s); Connect uses certificates only" $secretResult))
        }
    }
}
finally {
    # Runs on every path, including the early return on a tenant mismatch.
    Disconnect-MgGraph | Out-Null
    $results
    exit (Get-HdvExitCode -Results $results.ToArray())
}
