#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies or enables BlockCloudObjectTakeoverThroughHardMatchEnabled for the LAB tenant
    (Module 2.1, step 10). Tenant-wide setting.

.DESCRIPTION
    Hardening recommended by Microsoft for Entra Connect: block hard-match takeover of
    cloud-managed objects, using the Microsoft Graph PowerShell SDK as documented
    (Get-/Update-MgDirectoryOnPremiseSynchronization).

    Modes (exactly one is required; nothing happens by default):
      -VerifyOnly : read-only; scopes OnPremDirectorySynchronization.Read.All + Organization.Read.All
      -WhatIf     : read-only preview; same read scopes
      -Apply      : scopes OnPremDirectorySynchronization.ReadWrite.All + Organization.Read.All;
                    also requires the VERIFIED lab tenant initial domain to be TYPED interactively
                    (Read-Host) before the update. No parameter or configuration value can supply
                    it; redirected input is refused; -Confirm:$false never skips it.

    DOUBLE TENANT VERIFICATION (fail closed, before anything else is read or changed):
      1. the signed-in tenant ID equals Tenant.TenantId;
      2. the organization's initial domain (verifiedDomains[isInitial]) equals
         Tenant.ExpectedInitialDomain.

    Permissions: the delegated scopes above. Microsoft documents admin consent as required for
    Organization.Read.All, and for the OnPremDirectorySynchronization scopes; the signed-in
    owner must be able to grant it (Global Administrator in the lab tenant).

    The update is journaled. Exit codes: 0 PASS, 1 FAIL/refused (nothing changed), 2 WARN
    (preview), 3 partial.

.EXAMPLE
    .\Set-HdvHardMatchTakeoverBlock.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 -VerifyOnly
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)] [string] $ConfigPath,
    [switch] $VerifyOnly,
    [switch] $Apply,
    [string] $JournalPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force
$RecoveryDoc = 'docs/runbooks/hybrid-identity-rollback.md#6-hard-match-setting-restoration'
$feature = 'BlockCloudObjectTakeoverThroughHardMatchEnabled'

# ----------------------------------------------------------------------------- #
# Preflight: nothing is read from or changed in any tenant in this block.
# ----------------------------------------------------------------------------- #
try {
    $config = Import-HdvConfig -Path $ConfigPath
    $tenantId = Assert-HdvGuid -Value (Get-HdvConfigValue -Config $config -Path 'Tenant.TenantId' -Required) -Name 'Tenant.TenantId'
    $expectedInitial = ([string](Get-HdvConfigValue -Config $config -Path 'Tenant.ExpectedInitialDomain' -Required)).Trim().ToLowerInvariant()
    if ($expectedInitial -notmatch '^[a-z0-9][a-z0-9-]{0,62}\.onmicrosoft\.com$') {
        throw "Tenant.ExpectedInitialDomain '$expectedInitial' must be the tenant's '<name>.onmicrosoft.com' initial domain."
    }
    $preview = [bool]$WhatIfPreference
    $modes = @($VerifyOnly.IsPresent, $Apply.IsPresent, $preview) | Where-Object { $_ }
    if (@($modes).Count -ne 1) {
        throw 'Choose exactly one mode: -VerifyOnly (read), -WhatIf (preview) or -Apply (change, with typed confirmation).'
    }
    foreach ($probe in @(
            @{ Module = 'Microsoft.Graph.Authentication'; Command = 'Connect-MgGraph' },
            @{ Module = 'Microsoft.Graph.Identity.DirectoryManagement'; Command = 'Get-MgDirectoryOnPremiseSynchronization' })) {
        if (-not (Import-HdvRequiredModule -Name $probe.Module -ProbeCommand $probe.Command)) {
            throw "PowerShell module '$($probe.Module)' is required on the management host. This script never installs it."
        }
    }
    $journal = New-HdvJournal -Path $JournalPath
}
catch {
    Write-HdvRefusal -Reason "$($_.Exception.Message) Nothing was read or changed."
    exit (Get-HdvRefusedExitCode)
}

$scopes = if ($Apply) {
    @('OnPremDirectorySynchronization.ReadWrite.All', 'Organization.Read.All')
}
else {
    @('OnPremDirectorySynchronization.Read.All', 'Organization.Read.All')
}

$results = New-Object System.Collections.Generic.List[object]
$exitCode = 1
Connect-MgGraph -TenantId $tenantId -Scopes $scopes | Out-Null
try {
    # 1. tenant ID
    $context = Get-MgContext
    if ([string]$context.TenantId -ne $tenantId) {
        throw "signed-in tenant $([string]$context.TenantId) is not the configured lab tenant $tenantId"
    }
    # 2. initial domain
    $org = @(Get-MgOrganization)[0]
    $initial = @($org.VerifiedDomains | Where-Object { $_.IsInitial } | ForEach-Object { ([string]$_.Name).ToLowerInvariant() })
    if ($initial.Count -ne 1 -or $initial[0] -ne $expectedInitial) {
        throw "tenant initial domain [$($initial -join ', ')] does not match the configured lab initial domain $expectedInitial"
    }
    $results.Add((New-HdvResult 'H0 tenant identity' $tenantId "tenant ID and initial domain $expectedInitial verified" 'PASS'))

    $syncs = @(Get-MgDirectoryOnPremiseSynchronization)
    if ($syncs.Count -ne 1) {
        $results.Add((New-HdvResult 'H1 hard-match takeover block' $tenantId "expected 1 onPremisesDirectorySynchronization object, found $($syncs.Count)" 'MANUAL'))
    }
    else {
        $sync = $syncs[0]
        if ([bool]$sync.Features.$feature) {
            $results.Add((New-HdvResult 'H1 hard-match takeover block' $tenantId "$feature = True" 'PASS'))
        }
        elseif ($VerifyOnly) {
            $results.Add((New-HdvResult 'H1 hard-match takeover block' $tenantId "$feature = False (run with -Apply to enable)" 'FAIL'))
        }
        elseif ($preview -or -not $PSCmdlet.ShouldProcess("tenant $tenantId ($expectedInitial)", "Set $feature = True")) {
            Write-HdvJournalEntry -Journal $journal -Status WOULD -Step "set $feature" -Target $expectedInitial -Detail 'False -> True'
            $results.Add((New-HdvResult 'H1 hard-match takeover block' $tenantId "$feature = False; would be set to True" 'WARN'))
        }
        else {
            # Interactive only; compared with the initial domain VERIFIED live above.
            Confirm-HdvTypedConfirmation -Expected $initial[0] -What 'lab tenant initial domain'
            $sync.Features.$feature = $true
            $id = $sync.Id
            $features = $sync.Features
            Invoke-HdvJournaledAction -Journal $journal -Step "set $feature" -Target $expectedInitial -Detail 'False -> True' -Action {
                Update-MgDirectoryOnPremiseSynchronization -OnPremisesDirectorySynchronizationId $id -Features $features
            }.GetNewClosure()
            $after = [bool](@(Get-MgDirectoryOnPremiseSynchronization)[0].Features.$feature)
            $result = if ($after) { 'PASS' } else { 'FAIL' }
            $results.Add((New-HdvResult 'H1 hard-match takeover block' $tenantId "$feature set; read back = $after" $result))
        }
    }
    $exitCode = Get-HdvExitCode -Results $results.ToArray()
}
catch {
    $results.Add((New-HdvResult 'H0 tenant identity / change' $tenantId "$($_.Exception.Message). Nothing was changed unless a DONE journal entry says otherwise." 'FAIL'))
    $exitCode = 1
    if (@($journal.Entries | Where-Object { $_.Status -eq 'DONE' }).Count -gt 0) {
        Write-HdvPartialSummary -Journal $journal -RecoveryDoc $RecoveryDoc
        $exitCode = Get-HdvPartialExitCode
    }
}
finally {
    Disconnect-MgGraph | Out-Null
}

$results
exit $exitCode
