#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only validation of an installed Microsoft Entra Connect Sync server (Module 2.1, steps 7 and 9).

.DESCRIPTION
    Run on SYNC01, elevated. Changes nothing (no sync cycle is started).

      C1  not a domain controller
      C2  version >= EntraConnect.MinimumVersion (2.6.84.0)
      C3  ADSync PowerShell module available
      C4  application-based authentication (Get-ADSyncEntraConnectorCredential: ConnectorIdentityType)
          and, when configured, the expected application ID
      C5  scheduler: SyncCycleEnabled, StagingModeEnabled as expected, not suspended
      C6  AD DS connector account is the dedicated account (Get-ADSyncADConnectorAccount)
      C7  Password Hash Sync state as expected (Get-ADSyncAADCompanyFeature)
      C8  certificate lifetime events: 1012 (expired) = FAIL, 1011 (>= 70% of lifetime) = WARN
      C9  recent run-profile results (output properties are undocumented: MANUAL if unreadable)
      C10 sync engine status (Get-ADSyncConnectorRunStatus)
      C11 TPM present and ready (recommended)

    Exit code: 0 all PASS, 1 any FAIL, 2 only WARN/MANUAL remain.

.EXAMPLE
    .\Test-HdvEntraConnectConfiguration.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 | Format-Table -AutoSize
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ConfigPath,
    [string] $MiiserverPath = "${env:ProgramFiles}\Microsoft Azure AD Sync\Bin\miiserver.exe",
    [string] $AdSyncConfigModulePath = "${env:ProgramFiles}\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1",
    [ValidateRange(1, 90)] [int] $EventLookbackDays = 7
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force

$config = Import-HdvConfig -Path $ConfigPath
$results = New-Object System.Collections.Generic.List[object]
$server = $env:COMPUTERNAME
if (-not $server) { $server = 'localhost' }

$minimumVersion = Get-HdvConfigValue -Config $config -Path 'EntraConnect.MinimumVersion' -Required
$expectedType = Get-HdvConfigValue -Config $config -Path 'EntraConnect.ExpectedIdentityType' -Required
$expectStaging = [bool](Get-HdvConfigValue -Config $config -Path 'EntraConnect.ExpectStagingMode')
$expectPhs = [bool](Get-HdvConfigValue -Config $config -Path 'EntraConnect.ExpectPasswordHashSync')
$expectedAppId = Get-HdvConfigValue -Config $config -Path 'EntraConnect.ApplicationId'
if ($expectedAppId) { $expectedAppId = Assert-HdvGuid -Value $expectedAppId -Name 'EntraConnect.ApplicationId' }
$sam = Get-HdvConfigValue -Config $config -Path 'ConnectorAccount.SamAccountName' -Required

# C1
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    if ([int]$os.ProductType -eq 2) {
        $results.Add((New-HdvResult 'C1 not a domain controller' $server 'Entra Connect is installed on a DOMAIN CONTROLLER (violates ADR-0003)' 'FAIL'))
    }
    else {
        $results.Add((New-HdvResult 'C1 not a domain controller' $server 'member server' 'PASS'))
    }
}
catch {
    $results.Add((New-HdvResult 'C1 not a domain controller' $server "cannot read Win32_OperatingSystem: $($_.Exception.Message)" 'MANUAL'))
}

# C2
if (Test-Path -LiteralPath $MiiserverPath -PathType Leaf) {
    $version = [string](Get-Item -LiteralPath $MiiserverPath).VersionInfo.ProductVersion
    try {
        if ((Compare-HdvVersion -Actual $version -Minimum $minimumVersion) -ge 0) {
            $results.Add((New-HdvResult 'C2 version' $MiiserverPath "$version >= $minimumVersion" 'PASS'))
        }
        else {
            $results.Add((New-HdvResult 'C2 version' $MiiserverPath "$version < ${minimumVersion}: synchronisation stops after 7 April 2027" 'FAIL'))
        }
    }
    catch {
        $results.Add((New-HdvResult 'C2 version' $MiiserverPath "unparseable version '$version'" 'MANUAL'))
    }
}
else {
    $results.Add((New-HdvResult 'C2 version' $MiiserverPath 'sync engine binary not found: Entra Connect is not installed' 'FAIL'))
}

# C3
if (-not (Import-HdvRequiredModule -Name ADSync -ProbeCommand 'Get-ADSyncScheduler')) {
    $results.Add((New-HdvResult 'C3 ADSync module' $server 'unavailable: run on SYNC01 after installation (Import-Module ADSync)' 'FAIL'))
    $results
    exit 1
}
$results.Add((New-HdvResult 'C3 ADSync module' $server 'available' 'PASS'))

# C4
try {
    $credential = Get-ADSyncEntraConnectorCredential
    $type = [string]$credential.ConnectorIdentityType
    $typeResult = if ($type -eq $expectedType) { 'PASS' } else { 'FAIL' }
    $results.Add((New-HdvResult 'C4 authentication type' $server "ConnectorIdentityType=$type (expected $expectedType)" $typeResult))

    $guids = @($credential.PSObject.Properties | ForEach-Object {
            $value = [string]$_.Value
            $parsed = [guid]::Empty
            if ([guid]::TryParse($value, [ref]$parsed) -and $parsed -ne [guid]::Empty) { $parsed.ToString() }
        } | Sort-Object -Unique)
    if (-not $expectedAppId) {
        $found = if ($guids.Count -gt 0) { $guids -join ', ' } else { 'none found' }
        $results.Add((New-HdvResult 'C4 application ID' $server "EntraConnect.ApplicationId not configured; candidate value(s): $found. Record it in the local config" 'WARN'))
    }
    elseif ($guids -contains $expectedAppId) {
        $results.Add((New-HdvResult 'C4 application ID' $server "$expectedAppId" 'PASS'))
    }
    else {
        $results.Add((New-HdvResult 'C4 application ID' $server "configured $expectedAppId not found in Get-ADSyncEntraConnectorCredential output" 'FAIL'))
    }
}
catch {
    $results.Add((New-HdvResult 'C4 authentication type' $server "Get-ADSyncEntraConnectorCredential failed (version too old?): $($_.Exception.Message)" 'FAIL'))
}

# C5
$scheduler = Get-ADSyncScheduler
$enabledResult = if ($scheduler.SyncCycleEnabled) { 'PASS' } else { 'WARN' }
$results.Add((New-HdvResult 'C5 scheduler enabled' $server "SyncCycleEnabled=$($scheduler.SyncCycleEnabled)" $enabledResult))
$stagingResult = if ([bool]$scheduler.StagingModeEnabled -eq $expectStaging) { 'PASS' } else { 'FAIL' }
$results.Add((New-HdvResult 'C5 staging mode' $server "StagingModeEnabled=$($scheduler.StagingModeEnabled) (expected $expectStaging)" $stagingResult))
if ($scheduler.PSObject.Properties['SchedulerSuspended'] -and $scheduler.SchedulerSuspended) {
    $results.Add((New-HdvResult 'C5 scheduler suspended' $server 'SchedulerSuspended=True (set by Connect during upgrades)' 'WARN'))
}

# C6
if (-not (Get-Command -Name 'Get-ADSyncADConnectorAccount' -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $AdSyncConfigModulePath -PathType Leaf)) {
    Import-Module -Name $AdSyncConfigModulePath -ErrorAction SilentlyContinue
}
if (Get-Command -Name 'Get-ADSyncADConnectorAccount' -ErrorAction SilentlyContinue) {
    # Compare property VALUES: rendered table output (Out-String) truncates columns.
    $values = @(Get-ADSyncADConnectorAccount | ForEach-Object {
            if ($_ -is [string]) { $_ } else { $_.PSObject.Properties | ForEach-Object { [string]$_.Value } }
        })
    $matched = @($values | Where-Object { $_ -match "(?i)(^|[\\@])$([regex]::Escape($sam))($|@)" })
    if ($matched.Count -gt 0) {
        $results.Add((New-HdvResult 'C6 connector account' $server "dedicated account '$sam' in use" 'PASS'))
    }
    else {
        $results.Add((New-HdvResult 'C6 connector account' $server "'$sam' not found in Get-ADSyncADConnectorAccount output (express-mode MSOL_ account?)" 'FAIL'))
    }
}
else {
    $results.Add((New-HdvResult 'C6 connector account' $server 'ADSyncConfig module unavailable' 'MANUAL'))
}

# C7
try {
    $features = Get-ADSyncAADCompanyFeature
    $phs = [bool]$features.PasswordHashSync
    $phsResult = if ($phs -eq $expectPhs) { 'PASS' } else { 'FAIL' }
    $results.Add((New-HdvResult 'C7 Password Hash Sync' $server "PasswordHashSync=$phs (expected $expectPhs)" $phsResult))
}
catch {
    $results.Add((New-HdvResult 'C7 Password Hash Sync' $server "Get-ADSyncAADCompanyFeature failed: $($_.Exception.Message)" 'MANUAL'))
}

# C8 - Microsoft: 1011 = certificate >= 70% of lifetime, 1012 = expired (Application log)
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1011, 1012; StartTime = (Get-Date).AddDays(-$EventLookbackDays) } -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.ProviderName -match 'Directory Synchronization|ADSync|Entra|AAD' })
if (@($events | Where-Object { $_.Id -eq 1012 }).Count -gt 0) {
    $results.Add((New-HdvResult 'C8 application certificate' $server "event 1012 in the last $EventLookbackDays day(s): certificate EXPIRED" 'FAIL'))
}
elseif (@($events | Where-Object { $_.Id -eq 1011 }).Count -gt 0) {
    $results.Add((New-HdvResult 'C8 application certificate' $server "event 1011 in the last $EventLookbackDays day(s): certificate past 70% of its lifetime; confirm automatic rotation" 'WARN'))
}
else {
    $results.Add((New-HdvResult 'C8 application certificate' $server "no 1011/1012 events in the last $EventLookbackDays day(s)" 'PASS'))
}

# C9 - run history (property names undocumented: read defensively)
$runs = @(Get-ADSyncRunProfileResult -ErrorAction SilentlyContinue)
if ($runs.Count -eq 0) {
    $results.Add((New-HdvResult 'C9 recent sync runs' $server 'no run history yet (no sync cycle has run)' 'MANUAL'))
}
elseif (-not ($runs[0].PSObject.Properties['Result'] -and $runs[0].PSObject.Properties['StartDate'])) {
    $results.Add((New-HdvResult 'C9 recent sync runs' $server 'run history properties not readable; check the Synchronization Service Manager Operations tab' 'MANUAL'))
}
else {
    $recent = @($runs | Sort-Object -Property StartDate -Descending | Select-Object -First 20)
    $failed = @($recent | Where-Object { [string]$_.Result -ne 'success' })
    if ($failed.Count -eq 0) {
        $results.Add((New-HdvResult 'C9 recent sync runs' $server "last $($recent.Count) run(s): success" 'PASS'))
    }
    else {
        $distinct = @($failed | ForEach-Object { [string]$_.Result } | Sort-Object -Unique) -join ', '
        $results.Add((New-HdvResult 'C9 recent sync runs' $server "$($failed.Count) of the last $($recent.Count) run(s) not 'success' ($distinct)" 'WARN'))
    }
}

# C10
$running = @(Get-ADSyncConnectorRunStatus)
$status = if ($running.Count -eq 0) { 'idle' } else { "running: $(@($running | ForEach-Object { [string]$_ }) -join ', ')" }
$results.Add((New-HdvResult 'C10 sync engine status' $server $status 'PASS'))

# C11
try {
    $tpm = Get-Tpm
    $tpmResult = if ($tpm.TpmPresent -and $tpm.TpmReady) { 'PASS' } else { 'WARN' }
    $results.Add((New-HdvResult 'C11 TPM' $server "present=$($tpm.TpmPresent) ready=$($tpm.TpmReady)" $tpmResult))
}
catch {
    $results.Add((New-HdvResult 'C11 TPM' $server "cannot query TPM: $($_.Exception.Message)" 'MANUAL'))
}

$results
exit (Get-HdvExitCode -Results $results.ToArray())
