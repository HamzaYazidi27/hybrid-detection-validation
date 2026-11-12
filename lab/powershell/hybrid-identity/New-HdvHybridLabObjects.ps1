#Requires -Version 5.1
<#
.SYNOPSIS
    Creates the HDV lab OU structure and the sync canary objects in the LAB Active Directory
    (Module 2.1, step 2). Creates only; never modifies, moves or deletes existing objects.

.DESCRIPTION
    Objects created (only those missing):
      OU=<LabRootOuName>,<lab domain DN>         protected from accidental deletion
        OU=<each SyncedOuNames>                  selected in Entra Connect OU filtering
        OU=<each NonSyncedOuNames>               never synchronised (connector account, lab admins)
      -CreateCanaryObjects:
        user  <Canary.UserSamAccountName>  in the first synced OU: DISABLED, no password, no groups
        group <Canary.GroupName>           in the last synced OU: global security group, no members

    FAIL-CLOSED PREFLIGHT (nothing is changed unless every check passes):
      1. explicit lab configuration file (the committed template is refused);
      2. live domain DNS name, domain SID and DN equal the configured lab values (Get-ADDomain);
      3. canary names validated against the lab namespace and LDAP/DN syntax;
      4. canary name collisions outside the lab OUs refuse the whole run;
      5. without -WhatIf: -Apply AND the lab domain name TYPED interactively (Read-Host) are
         required. No parameter or configuration value can supply it; redirected input and
         non-interactive sessions are refused. -Confirm:$false only skips per-object prompts.

    Every change is journaled (STARTED/DONE/FAILED) as it happens; -JournalPath also writes the
    journal to a local file outside git. Exit codes: 0 completed or preview, 1 refused (nothing
    changed), 3 partial (see the PARTIAL summary and docs/runbooks/hybrid-identity-rollback.md).

.EXAMPLE
    .\New-HdvHybridLabObjects.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 -CreateCanaryObjects -WhatIf

.EXAMPLE
    .\New-HdvHybridLabObjects.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 -CreateCanaryObjects -Apply -JournalPath C:\HDV\private\journal-2.1.jsonl
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)] [string] $ConfigPath,
    [switch] $CreateCanaryObjects,
    [switch] $Apply,
    [string] $JournalPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force
$RecoveryDoc = 'docs/runbooks/hybrid-identity-rollback.md#7-partial-execution-recovery'

# ----------------------------------------------------------------------------- #
# Preflight: no changes are made in this block.
# ----------------------------------------------------------------------------- #
try {
    $config = Import-HdvConfig -Path $ConfigPath
    if (-not (Import-HdvRequiredModule -Name ActiveDirectory -ProbeCommand 'Get-ADDomain')) {
        throw 'The ActiveDirectory PowerShell module (RSAT) is required. This script never installs it.'
    }
    $lab = Assert-HdvLabDomain -Config $config
    $layout = Get-HdvLabOuLayout -Config $config -DomainDN $lab.DomainDN

    $canary = $null
    if ($CreateCanaryObjects) {
        $canary = [pscustomobject]@{
            Sam     = Assert-HdvLabObjectName -Value (Get-HdvConfigValue -Config $config -Path 'Canary.UserSamAccountName' -Required) -Kind SamAccountName -Name 'Canary.UserSamAccountName'
            Display = Assert-HdvLabObjectName -Value (Get-HdvConfigValue -Config $config -Path 'Canary.UserDisplayName' -Required) -Kind DisplayName -Name 'Canary.UserDisplayName'
            Group   = Assert-HdvLabObjectName -Value (Get-HdvConfigValue -Config $config -Path 'Canary.GroupName' -Required) -Kind GroupName -Name 'Canary.GroupName'
            UserOu  = $layout.SyncedOuDNs[0]
            GroupOu = $layout.SyncedOuDNs[-1]
            UserExists  = $false
            GroupExists = $false
        }
        $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$(ConvertTo-HdvLdapFilterValue $canary.Sam))" -ErrorAction SilentlyContinue)
        if ($users.Count -gt 0) {
            if (-not (Test-HdvDnUnder -DistinguishedName ([string]$users[0].DistinguishedName) -ContainerDN $canary.UserOu)) {
                throw "sAMAccountName '$($canary.Sam)' already exists outside the lab OU ($($users[0].DistinguishedName)). Existing objects are never modified."
            }
            $canary.UserExists = $true
        }
        $groups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$(ConvertTo-HdvLdapFilterValue $canary.Group))" -ErrorAction SilentlyContinue)
        if ($groups.Count -gt 0) {
            if (-not (Test-HdvDnUnder -DistinguishedName ([string]$groups[0].DistinguishedName) -ContainerDN $canary.GroupOu)) {
                throw "Group '$($canary.Group)' already exists outside the lab OU ($($groups[0].DistinguishedName)). Existing objects are never modified."
            }
            $canary.GroupExists = $true
        }
    }

    $journal = New-HdvJournal -Path $JournalPath
    $preview = [bool]$WhatIfPreference
    if (-not $preview) {
        if (-not $Apply) {
            throw 'No changes are made without -Apply. Preview with -WhatIf, then re-run with -Apply and the typed lab domain confirmation.'
        }
        # Interactive only; compared with the VERIFIED live domain name.
        Confirm-HdvTypedConfirmation -Expected $lab.DnsRoot -What 'lab domain DNS name'
    }
}
catch {
    Write-HdvRefusal -Reason $_.Exception.Message
    exit (Get-HdvRefusedExitCode)
}

$mode = if ($preview) { 'PREVIEW (-WhatIf)' } else { 'APPLY' }
Write-HdvJournalEntry -Journal $journal -Status INFO -Step 'preflight' -Target $lab.DnsRoot -Detail "verified lab domain $($lab.DnsRoot) ($($lab.DomainSid)); mode $mode"

# ----------------------------------------------------------------------------- #
# Changes: every action is journaled before and after execution.
# ----------------------------------------------------------------------------- #
function Confirm-HdvOu {
    param([string] $Name, [string] $ParentDN, [string] $Description)
    $dn = "OU=$Name,$ParentDN"
    $existing = @()
    try {
        # A missing parent (for example during -WhatIf before the root exists) means "not found".
        $existing = @(Get-ADOrganizationalUnit -LDAPFilter "(ou=$(ConvertTo-HdvLdapFilterValue $Name))" -SearchBase $ParentDN -SearchScope OneLevel -ErrorAction Stop)
    }
    catch {
        $existing = @()
    }
    if ($existing.Count -gt 0) {
        Write-HdvJournalEntry -Journal $journal -Status EXISTS -Step 'organizational unit' -Target $dn -Detail 'left unchanged'
    }
    elseif ($PSCmdlet.ShouldProcess($dn, 'Create organizational unit (protected from accidental deletion)')) {
        Invoke-HdvJournaledAction -Journal $journal -Step 'create organizational unit' -Target $dn -Detail $Description -Action {
            New-ADOrganizationalUnit -Name $Name -Path $ParentDN -Description $Description -ProtectedFromAccidentalDeletion $true
        }.GetNewClosure()
    }
    else {
        Write-HdvJournalEntry -Journal $journal -Status WOULD -Step 'create organizational unit' -Target $dn -Detail $Description
    }
}

try {
    $rootName = ($layout.RootDN -split ',')[0] -replace '^OU=', ''
    Confirm-HdvOu -Name $rootName -ParentDN $layout.DomainDN -Description 'HDV lab root (hybrid detection validation). Managed by HDV scripts.'
    foreach ($dn in $layout.SyncedOuDNs) {
        Confirm-HdvOu -Name (($dn -split ',')[0] -replace '^OU=', '') -ParentDN $layout.RootDN -Description 'HDV: SYNCHRONISED to Entra ID by Entra Connect OU filtering.'
    }
    foreach ($dn in $layout.NonSyncedOuDNs) {
        Confirm-HdvOu -Name (($dn -split ',')[0] -replace '^OU=', '') -ParentDN $layout.RootDN -Description 'HDV: NEVER synchronised (Tier 0 / service accounts).'
    }

    if ($canary) {
        $userDN = "CN=$($canary.Display),$($canary.UserOu)"
        if ($canary.UserExists) {
            Write-HdvJournalEntry -Journal $journal -Status EXISTS -Step 'canary user' -Target $userDN -Detail 'left unchanged'
        }
        elseif ($PSCmdlet.ShouldProcess($userDN, 'Create DISABLED canary user without password')) {
            $c = $canary
            Invoke-HdvJournaledAction -Journal $journal -Step 'create canary user' -Target $userDN -Detail 'disabled, no password, no group membership' -Action {
                New-ADUser -Name $c.Display -DisplayName $c.Display -SamAccountName $c.Sam -Path $c.UserOu -Enabled $false `
                    -Description 'HDV sync canary: disabled, no password, no group membership. Proves OU-scoped synchronisation.'
            }.GetNewClosure()
        }
        else {
            Write-HdvJournalEntry -Journal $journal -Status WOULD -Step 'create canary user' -Target $userDN -Detail 'disabled, no password, no group membership'
        }

        $groupDN = "CN=$($canary.Group),$($canary.GroupOu)"
        if ($canary.GroupExists) {
            Write-HdvJournalEntry -Journal $journal -Status EXISTS -Step 'canary group' -Target $groupDN -Detail 'left unchanged'
        }
        elseif ($PSCmdlet.ShouldProcess($groupDN, 'Create empty global security canary group')) {
            $c = $canary
            Invoke-HdvJournaledAction -Journal $journal -Step 'create canary group' -Target $groupDN -Detail 'global security group, no members' -Action {
                New-ADGroup -Name $c.Group -SamAccountName $c.Group -GroupScope Global -GroupCategory Security -Path $c.GroupOu `
                    -Description 'HDV sync canary group: no members, no permissions.'
            }.GetNewClosure()
        }
        else {
            Write-HdvJournalEntry -Journal $journal -Status WOULD -Step 'create canary group' -Target $groupDN -Detail 'global security group, no members'
        }
    }
}
catch {
    Write-HdvPartialSummary -Journal $journal -RecoveryDoc $RecoveryDoc
    if (@($journal.Entries | Where-Object { $_.Status -eq 'DONE' }).Count -gt 0) { exit (Get-HdvPartialExitCode) }
    exit (Get-HdvRefusedExitCode)
}

Write-Host ''
Write-Host 'Select ONLY these OUs in Entra Connect "Domain and OU filtering":'
$layout.SyncedOuDNs | ForEach-Object { Write-Host "  $_" }
exit 0
