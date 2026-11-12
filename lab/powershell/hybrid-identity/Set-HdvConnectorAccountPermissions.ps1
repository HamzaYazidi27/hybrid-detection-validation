#Requires -Version 5.1
<#
.SYNOPSIS
    Creates the dedicated AD DS connector account and grants least-privilege permissions with
    Microsoft's ADSyncConfig module in the LAB domain (Module 2.1, step 4). HIGH IMPACT.

.DESCRIPTION
    Run on SYNC01, elevated, AFTER starting the Entra Connect MSI and stopping at the wizard's
    Welcome page (the MSI places the ADSyncConfig module on disk), as an Enterprise Admin of the
    single-domain lab forest.

    Changes (in this order, each journaled):
      1. creates the connector account in the NON-synced connector OU, if missing
         (enabled, password never expires, cannot change password, sensitive/not delegable);
      2. Set-ADSyncBasicReadPermissions          -ADobjectDN <each synced OU>  (that OU only)
      3. Set-ADSyncMsDsConsistencyGuidPermissions -ADobjectDN <each synced OU> (that OU only)
      4. Set-ADSyncPasswordHashSyncPermissions   only if PHS is expected: Replicating Directory
         Changes + Replicating Directory Changes All. Microsoft documents that this cmdlet acts
         on the root of EVERY domain in the forest (it has no -ADobjectDN parameter);
      5. Set-ADSyncRestrictedPermissions on the connector account object: Microsoft documents
         that it DISABLES INHERITANCE and REMOVES ALL ACEs except SELF, then adds explicit ACEs
         for SYSTEM, Enterprise Admins, Domain Admins, Administrators, Enterprise Domain
         Controllers and Authenticated Users (see docs/runbooks/hybrid-identity-rollback.md).

    FAIL-CLOSED PREFLIGHT (every check runs before the first change):
      explicit lab config; live domain DNS name + SID + DN = lab values; connector name in the
      'svc-hdv-' namespace; STRICT single-domain forest (always, with or without PHS: MVP
      requirement); lab OUs exist; an existing
      account must not be privileged (direct DA/EA/SA/Administrators membership or adminCount=1)
      and must be in the connector OU; ADSyncConfig module present; password >= 24 characters;
      without -WhatIf: -Apply, the lab domain name TYPED interactively (Read-Host; no parameter or
      configuration value can supply it; -Confirm:$false never skips it) and the admin credential.

    The password is a SecureString: never written, logged, journaled or displayed.
    Exit codes: 0 completed or preview, 1 refused (nothing changed), 3 partial.

.EXAMPLE
    .\Set-HdvConnectorAccountPermissions.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 -WhatIf

.EXAMPLE
    .\Set-HdvConnectorAccountPermissions.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 -Apply -JournalPath C:\HDV\private\journal-2.1.jsonl
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)] [string] $ConfigPath,

    # Password for a NEW connector account. Prompted securely if omitted. Never logged.
    [System.Security.SecureString] $AccountPassword,

    # Credential of the administrator running Set-ADSyncRestrictedPermissions. Prompted if omitted.
    [System.Management.Automation.PSCredential] $AdminCredential,

    [string] $AdSyncConfigModulePath = "${env:ProgramFiles}\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1",

    [switch] $Apply,
    [string] $JournalPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force
$RecoveryDoc = 'docs/runbooks/hybrid-identity-rollback.md#7-partial-execution-recovery'
$MinimumPasswordLength = 24
$PrivilegedSidPatterns = '-512$', '-518$', '-519$', '^S-1-5-32-544$'

# ----------------------------------------------------------------------------- #
# Preflight: no changes are made in this block.
# ----------------------------------------------------------------------------- #
try {
    $config = Import-HdvConfig -Path $ConfigPath
    if (-not (Import-HdvRequiredModule -Name ActiveDirectory -ProbeCommand 'Get-ADUser')) {
        throw 'The ActiveDirectory PowerShell module (RSAT) is required (run Test-HdvHybridPrerequisites.ps1).'
    }
    $lab = Assert-HdvLabDomain -Config $config
    $layout = Get-HdvLabOuLayout -Config $config -DomainDN $lab.DomainDN
    $sam = Assert-HdvLabObjectName -Value (Get-HdvConfigValue -Config $config -Path 'ConnectorAccount.SamAccountName' -Required) -Kind ServiceAccount -Name 'ConnectorAccount.SamAccountName'
    $expectPhs = [bool](Get-HdvConfigValue -Config $config -Path 'EntraConnect.ExpectPasswordHashSync')
    # MVP requirement: strict single-domain forest for the WHOLE connector operation, whether or not
    # Password Hash Sync is enabled. No configuration value can relax this.
    Assert-HdvSingleDomainForest -LabDnsRoot $lab.DnsRoot

    foreach ($ouDN in @($layout.SyncedOuDNs) + @($layout.ConnectorOuDN)) {
        $ou = $null
        try { $ou = Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction Stop } catch { $ou = $null }
        if ($null -eq $ou) { throw "OU not found: $ouDN. Run New-HdvHybridLabObjects.ps1 first." }
    }

    $account = @(Get-ADUser -LDAPFilter "(sAMAccountName=$(ConvertTo-HdvLdapFilterValue $sam))" -Properties adminCount, DistinguishedName, SID -ErrorAction SilentlyContinue)
    if ($account.Count -gt 0) {
        $existing = $account[0]
        $groups = @(Get-ADPrincipalGroupMembership -Identity $existing.DistinguishedName)
        $privileged = @($groups | Where-Object { $sid = [string]$_.SID; @($PrivilegedSidPatterns | Where-Object { $sid -match $_ }).Count -gt 0 })
        if ($privileged.Count -gt 0) {
            throw "Existing account $($existing.DistinguishedName) is a member of privileged group(s): $(@($privileged | ForEach-Object { $_.Name }) -join ', '). Microsoft: Connect rejects Domain/Enterprise Admin connector accounts."
        }
        if ($existing.PSObject.Properties.Name -contains 'adminCount' -and [int]$existing.adminCount -eq 1) {
            throw "Existing account $($existing.DistinguishedName) has adminCount=1 (currently or previously protected by AdminSDHolder). Use a fresh account."
        }
        if (-not (Test-HdvDnUnder -DistinguishedName ([string]$existing.DistinguishedName) -ContainerDN $layout.ConnectorOuDN)) {
            throw "Account $($existing.DistinguishedName) exists outside the non-synced connector OU $($layout.ConnectorOuDN). Existing objects are never moved or modified."
        }
    }

    if (-not (Get-Command -Name 'Set-ADSyncBasicReadPermissions' -ErrorAction SilentlyContinue)) {
        if (-not (Test-Path -LiteralPath $AdSyncConfigModulePath -PathType Leaf)) {
            throw "ADSyncConfig module not found at $AdSyncConfigModulePath. Start the Entra Connect MSI and stop at the Welcome page first (docs/runbooks/entra-connect-install.md)."
        }
        Import-Module -Name $AdSyncConfigModulePath -ErrorAction Stop
    }

    if ($AccountPassword -and $AccountPassword.Length -lt $MinimumPasswordLength) {
        throw "Password shorter than $MinimumPasswordLength characters."
    }

    $journal = New-HdvJournal -Path $JournalPath
    $preview = [bool]$WhatIfPreference
    if (-not $preview) {
        if (-not $Apply) {
            throw 'No changes are made without -Apply. Preview with -WhatIf, then re-run with -Apply and the typed lab domain confirmation.'
        }
        # Interactive only; compared with the VERIFIED live domain name.
        Confirm-HdvTypedConfirmation -Expected $lab.DnsRoot -What 'lab domain DNS name'
        if ($account.Count -eq 0 -and -not $AccountPassword) {
            $AccountPassword = Read-Host -AsSecureString -Prompt "Password for NEW connector account '$sam' (min $MinimumPasswordLength characters; store it in your password manager)"
            if (-not $AccountPassword -or $AccountPassword.Length -lt $MinimumPasswordLength) {
                throw "Password shorter than $MinimumPasswordLength characters."
            }
        }
        if (-not $AdminCredential) {
            $AdminCredential = Get-Credential -Message 'Administrator credential for Set-ADSyncRestrictedPermissions (must differ from the connector account)'
            if (-not $AdminCredential) { throw 'An administrator credential is required for Set-ADSyncRestrictedPermissions.' }
        }
    }
}
catch {
    Write-HdvRefusal -Reason "$($_.Exception.Message) Nothing was changed."
    exit (Get-HdvRefusedExitCode)
}

$accountDN = if ($account.Count -gt 0) { [string]$account[0].DistinguishedName } else { "CN=$sam,$($layout.ConnectorOuDN)" }
$mode = if ($preview) { 'PREVIEW (-WhatIf)' } else { 'APPLY' }
Write-HdvJournalEntry -Journal $journal -Status INFO -Step 'preflight' -Target $lab.DnsRoot -Detail "verified lab domain $($lab.DnsRoot) ($($lab.DomainSid)); single-domain forest verified; mode $mode"

# ----------------------------------------------------------------------------- #
# Changes: every action is journaled before and after execution.
# ----------------------------------------------------------------------------- #
function Invoke-HdvStep {
    param([string] $Step, [string] $Target, [string] $Detail, [scriptblock] $Action)
    if ($PSCmdlet.ShouldProcess($Target, $Step)) {
        Invoke-HdvJournaledAction -Journal $journal -Step $Step -Target $Target -Detail $Detail -Action $Action
    }
    else {
        Write-HdvJournalEntry -Journal $journal -Status WOULD -Step $Step -Target $Target -Detail $Detail
    }
}

try {
    if ($account.Count -gt 0) {
        Write-HdvJournalEntry -Journal $journal -Status EXISTS -Step 'connector account' -Target $accountDN -Detail 'left unchanged'
    }
    else {
        $password = $AccountPassword
        $ouDN = $layout.ConnectorOuDN
        $name = $sam
        Invoke-HdvStep -Step 'create connector account' -Target $accountDN -Detail 'sensitive, cannot be delegated, not synchronised' -Action {
            New-ADUser -Name $name -SamAccountName $name -Path $ouDN -AccountPassword $password -Enabled $true `
                -PasswordNeverExpires $true -CannotChangePassword $true -AccountNotDelegated $true `
                -Description 'HDV Entra Connect AD DS connector account. Has replication rights (PHS). Tier 0. Do not use interactively.'
        }.GetNewClosure()
        $password = $null
    }

    foreach ($ouDN in $layout.SyncedOuDNs) {
        $target = $ouDN
        $connector = $accountDN
        Invoke-HdvStep -Step 'Set-ADSyncBasicReadPermissions' -Target $target -Detail "basic read for $connector on this OU only" -Action {
            Set-ADSyncBasicReadPermissions -ADConnectorAccountDN $connector -ADobjectDN $target -Confirm:$false
        }.GetNewClosure()
        Invoke-HdvStep -Step 'Set-ADSyncMsDsConsistencyGuidPermissions' -Target $target -Detail "ms-DS-ConsistencyGuid write for $connector on this OU only" -Action {
            Set-ADSyncMsDsConsistencyGuidPermissions -ADConnectorAccountDN $connector -ADobjectDN $target -Confirm:$false
        }.GetNewClosure()
    }

    if ($expectPhs) {
        $connector = $accountDN
        Invoke-HdvStep -Step 'Set-ADSyncPasswordHashSyncPermissions' -Target $lab.DomainDN -Detail "Replicating Directory Changes + All for $connector at the domain root (single-domain forest verified)" -Action {
            Set-ADSyncPasswordHashSyncPermissions -ADConnectorAccountDN $connector -Confirm:$false
        }.GetNewClosure()
    }
    else {
        Write-HdvJournalEntry -Journal $journal -Status SKIPPED -Step 'Set-ADSyncPasswordHashSyncPermissions' -Target $lab.DomainDN -Detail 'Password Hash Sync not expected: no replication rights granted'
    }

    $connector = $accountDN
    $credential = $AdminCredential
    Invoke-HdvStep -Step 'Set-ADSyncRestrictedPermissions' -Target $accountDN -Detail 'disables inheritance and replaces the account DACL (see rollback runbook)' -Action {
        Set-ADSyncRestrictedPermissions -ADConnectorAccountDN $connector -Credential $credential -Confirm:$false
    }.GetNewClosure()
    $credential = $null
}
catch {
    Write-HdvPartialSummary -Journal $journal -RecoveryDoc $RecoveryDoc
    if (@($journal.Entries | Where-Object { $_.Status -eq 'DONE' }).Count -gt 0) { exit (Get-HdvPartialExitCode) }
    exit (Get-HdvRefusedExitCode)
}

$sidText = '(assigned on creation)'
$created = @(Get-ADUser -LDAPFilter "(sAMAccountName=$(ConvertTo-HdvLdapFilterValue $sam))" -Properties SID -ErrorAction SilentlyContinue)
if ($created.Count -gt 0) { $sidText = [string]$created[0].SID }
Write-HdvJournalEntry -Journal $journal -Status INFO -Step 'connector account SID' -Target $accountDN -Detail "$sidText (record it for the HDV_EntraConnect watchlist)"
exit 0
