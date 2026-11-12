#Requires -Version 5.1
<#
.SYNOPSIS
    Shared helpers for HDV lab scripts: results, exit codes, configuration, fail-closed guards,
    action journal and input validation.

.DESCRIPTION
    Result objects (Check, Target, Detail, Result) with Result one of:
      PASS    the condition is verified;
      FAIL    the condition is violated (exit code 1);
      WARN    a recommendation is not met, or a value is only partially verifiable (exit code 2);
      MANUAL  cannot be checked automatically; an operator must verify (exit code 2).

    Modifying scripts use these exit codes:
      0  completed (or preview completed);
      1  REFUSED: a guard failed, nothing was changed;
      3  PARTIAL: an error occurred after at least one change; see the journal.

    Configuration files are PowerShell data files (.psd1). Committed templates contain
    '<REQUIRED...>' placeholders; real values live in untracked '*.local.psd1' copies.
#>

Set-StrictMode -Version Latest

$script:PlaceholderPattern = '^\s*<REQUIRED'
$script:ExitRefused = 1
$script:ExitPartial = 3

# --------------------------------------------------------------------------- #
# Results and exit codes
# --------------------------------------------------------------------------- #
function New-HdvResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Check,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Target,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Detail,
        [Parameter(Mandatory = $true)] [ValidateSet('PASS', 'FAIL', 'WARN', 'MANUAL')] [string] $Result
    )
    [pscustomobject]@{ Check = $Check; Target = $Target; Detail = $Detail; Result = $Result }
}

function Get-HdvExitCode {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Results)
    if (@($Results | Where-Object { $_.Result -eq 'FAIL' }).Count -gt 0) { return 1 }
    if (@($Results | Where-Object { $_.Result -in @('WARN', 'MANUAL') }).Count -gt 0) { return 2 }
    return 0
}

function Get-HdvRefusedExitCode { return $script:ExitRefused }
function Get-HdvPartialExitCode { return $script:ExitPartial }

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
function Test-HdvPlaceholder {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    return ($Value -is [string]) -and ($Value -match $script:PlaceholderPattern)
}

function Import-HdvConfig {
    <#
    .SYNOPSIS
        Loads an explicit .psd1 lab configuration and checks its schema version.
        Refuses the committed *.example.psd1 templates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [int] $SchemaVersion = 1
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Lab configuration file not found: $Path. Copy the *.example.psd1 template to *.local.psd1 and fill it in."
    }
    if ([System.IO.Path]::GetFileName($Path) -like '*.example.psd1') {
        throw "Refusing the committed template ${Path}: use your filled-in *.local.psd1 copy."
    }
    $config = Import-PowerShellDataFile -LiteralPath $Path
    if ($config['SchemaVersion'] -ne $SchemaVersion) {
        throw "Configuration $Path has SchemaVersion '$($config['SchemaVersion'])'; expected $SchemaVersion."
    }
    return $config
}

function Get-HdvConfigValue {
    <#
    .SYNOPSIS
        Reads a dotted path (for example 'EntraConnect.ApplicationId') from a configuration hashtable.
    .DESCRIPTION
        -Required: throws if the value is missing, empty or still a '<REQUIRED...>' placeholder.
        Without -Required: returns $null for missing values and for placeholders.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config,
        [Parameter(Mandatory = $true)] [string] $Path,
        [switch] $Required
    )
    $node = $Config
    foreach ($part in $Path.Split('.')) {
        if ($node -is [hashtable] -and $node.ContainsKey($part)) {
            $node = $node[$part]
        }
        else {
            $node = $null
            break
        }
    }
    $missing = ($null -eq $node) -or (($node -is [string]) -and [string]::IsNullOrWhiteSpace($node)) -or (Test-HdvPlaceholder $node)
    if ($missing) {
        if ($Required) {
            throw "Configuration value '$Path' is required but is missing or still a placeholder."
        }
        return $null
    }
    return $node
}

# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #
function Assert-HdvGuid {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Name)
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Value, [ref]$parsed) -or $parsed -eq [guid]::Empty) {
        throw "$Name must be a non-empty GUID (got '$Value')."
    }
    return $parsed.ToString()
}

function Assert-HdvDistinguishedName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Name)
    if ($Value -notmatch '^(?:(?:CN|OU)=[A-Za-z0-9 _-]+,)*(?:DC=[A-Za-z0-9-]+)(?:,DC=[A-Za-z0-9-]+)*$') {
        throw "$Name is not a valid distinguished name (got '$Value')."
    }
    return $Value
}

function Assert-HdvOuName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Value, [Parameter(Mandatory = $true)] [string] $Name)
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9 _-]{0,63}$') {
        throw "$Name must be a simple OU name (letters, digits, space, '_' or '-'; got '$Value')."
    }
    return $Value
}

function Assert-HdvLabObjectName {
    <#
    .SYNOPSIS
        Validates names of objects HDV creates or searches for in AD. Rejects empty values, LDAP filter
        and DN special characters, path/domain references and names outside the lab namespace.
    .PARAMETER Kind
        SamAccountName : 'hdv-' prefix, [A-Za-z0-9-], max 20 characters
        ServiceAccount : 'svc-hdv-' prefix, [A-Za-z0-9-], max 20 characters
        DisplayName    : 'HDV ' prefix, letters/digits/space/'-'/'_', max 64 characters
        GroupName      : 'HDV-' prefix, letters/digits/'-'/'_', max 64 characters
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [AllowNull()] [string] $Value,
        [Parameter(Mandatory = $true)] [ValidateSet('SamAccountName', 'ServiceAccount', 'DisplayName', 'GroupName')] [string] $Kind,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    $patterns = @{
        SamAccountName = '^hdv-[A-Za-z0-9-]{1,16}$'
        ServiceAccount = '^svc-hdv-[A-Za-z0-9-]{1,12}$'
        DisplayName    = '^HDV [A-Za-z0-9 _-]{1,60}$'
        GroupName      = '^HDV-[A-Za-z0-9_-]{1,60}$'
    }
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name must not be empty."
    }
    if ($Value -match '[\x00-\x1f*()\\/,+"<>;=#@.]') {
        throw "$Name contains a character that is not allowed (LDAP filter, DN, path or domain syntax): '$Value'."
    }
    if ($Value -cnotmatch $patterns[$Kind]) {
        throw "$Name '$Value' is outside the HDV lab namespace (expected pattern $($patterns[$Kind]))."
    }
    return $Value
}

function ConvertTo-HdvLdapFilterValue {
    <#
    .SYNOPSIS
        Escapes a value for use inside an RFC 4515 LDAP filter (defence in depth after validation).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Value)
    $builder = New-Object System.Text.StringBuilder
    foreach ($char in $Value.ToCharArray()) {
        switch ($char) {
            '\' { [void]$builder.Append('\5c') }
            '*' { [void]$builder.Append('\2a') }
            '(' { [void]$builder.Append('\28') }
            ')' { [void]$builder.Append('\29') }
            ([char]0) { [void]$builder.Append('\00') }
            default { [void]$builder.Append($char) }
        }
    }
    return $builder.ToString()
}

function Compare-HdvVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Actual, [Parameter(Mandatory = $true)] [string] $Minimum)
    return ([version]$Actual).CompareTo([version]$Minimum)
}

function Import-HdvRequiredModule {
    <#
    .SYNOPSIS
        Imports a module unless the probe command is already available (allows mocked tests).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $ProbeCommand
    )
    if (Get-Command -Name $ProbeCommand -ErrorAction SilentlyContinue) { return $true }
    try {
        Import-Module -Name $Name -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# --------------------------------------------------------------------------- #
# Fail-closed identity guards
# --------------------------------------------------------------------------- #
function Assert-HdvLabDomain {
    <#
    .SYNOPSIS
        Verifies that the LIVE Active Directory domain is the configured lab domain. Throws otherwise.
    .DESCRIPTION
        Requires ActiveDirectory.ExpectedDnsRoot, ActiveDirectory.ExpectedDomainSid and
        ActiveDirectory.DomainDN in the configuration (no defaults, no fallback). Reads the live
        domain with Get-ADDomain and requires all three to match. Returns the verified identity.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [hashtable] $Config)
    $expectedDns = ([string](Get-HdvConfigValue -Config $Config -Path 'ActiveDirectory.ExpectedDnsRoot' -Required)).Trim().ToLowerInvariant()
    if ($expectedDns -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') {
        throw "ActiveDirectory.ExpectedDnsRoot '$expectedDns' is not a DNS domain name."
    }
    $expectedSid = ([string](Get-HdvConfigValue -Config $Config -Path 'ActiveDirectory.ExpectedDomainSid' -Required)).Trim()
    if ($expectedSid -notmatch '^S-1-5-21-\d+-\d+-\d+$') {
        throw "ActiveDirectory.ExpectedDomainSid '$expectedSid' is not a domain SID (S-1-5-21-x-y-z)."
    }
    $configuredDN = Assert-HdvDistinguishedName -Value (Get-HdvConfigValue -Config $Config -Path 'ActiveDirectory.DomainDN' -Required) -Name 'ActiveDirectory.DomainDN'

    $live = Get-ADDomain
    $liveDns = ([string]$live.DNSRoot).Trim().ToLowerInvariant()
    $liveSid = ([string]$live.DomainSID).Trim()
    $liveDN = ([string]$live.DistinguishedName).Trim()

    if ($liveDns -ne $expectedDns) {
        throw "LIVE DOMAIN MISMATCH: this machine's domain is '$liveDns', the lab configuration expects '$expectedDns'. Nothing was changed."
    }
    if ($liveSid -ne $expectedSid) {
        throw "LIVE DOMAIN SID MISMATCH: live '$liveSid', expected '$expectedSid'. Nothing was changed."
    }
    if ($liveDN -ine $configuredDN) {
        throw "DOMAIN DN MISMATCH: live '$liveDN', configured '$configuredDN'. Nothing was changed."
    }
    [pscustomobject]@{
        DnsRoot     = $liveDns
        DomainSid   = $liveSid
        DomainDN    = $liveDN
        NetBIOSName = [string]$live.NetBIOSName
    }
}

function Assert-HdvSingleDomainForest {
    <#
    .SYNOPSIS
        Throws unless the live forest contains exactly one domain, the verified lab domain.
    .DESCRIPTION
        Microsoft documents that ADSyncConfig permission cmdlets used without -ADobjectDN act on
        the root of EVERY domain in the forest. Set-ADSyncPasswordHashSyncPermissions has no
        -ADobjectDN parameter, so in a multi-domain forest it would grant replication rights
        (DCSync-capable) on every domain root. HDV refuses instead of attempting a workaround.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $LabDnsRoot)
    $forest = Get-ADForest
    $domains = @($forest.Domains | ForEach-Object { ([string]$_).ToLowerInvariant() })
    if ($domains.Count -ne 1 -or $domains[0] -ne $LabDnsRoot.ToLowerInvariant()) {
        throw ("MULTI-DOMAIN FOREST: forest '$($forest.Name)' contains $($domains.Count) domain(s) [$($domains -join ', ')]. " +
            'Set-ADSyncPasswordHashSyncPermissions grants replication rights on the root of EVERY domain in the forest; ' +
            'HDV only supports a single-domain lab forest. Nothing was changed.')
    }
}

function Confirm-HdvTypedConfirmation {
    <#
    .SYNOPSIS
        Requires the operator to TYPE the verified lab identity interactively (Read-Host only).
    .DESCRIPTION
        There is deliberately no parameter, configuration value or environment variable that can
        supply the answer: -Confirm:$false only affects per-change ShouldProcess prompts, never this
        check. Redirected input (pipes, automation) and non-interactive sessions are refused.
        -Expected must be an identity that was VERIFIED live (domain DNS name or tenant initial
        domain), never a raw configuration value. Comparison: case-insensitive, trimmed, exact.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Expected,
        [Parameter(Mandatory = $true)] [string] $What
    )
    if ([Console]::IsInputRedirected) {
        throw "Typed confirmation of the $What requires an interactive console; input is redirected. Nothing was changed."
    }
    try {
        $typed = Read-Host -Prompt "Type the exact $What ($Expected) to authorise the changes"
    }
    catch {
        throw "Typed confirmation of the $What requires an interactive session ($($_.Exception.Message)). Nothing was changed."
    }
    if ([string]::IsNullOrWhiteSpace($typed) -or ($typed.Trim() -ine $Expected)) {
        throw "Typed confirmation '$typed' does not match the $What '$Expected'. Nothing was changed."
    }
}

# --------------------------------------------------------------------------- #
# Action journal (partial-execution reporting)
# --------------------------------------------------------------------------- #
function New-HdvJournal {
    <#
    .SYNOPSIS
        Creates an action journal. With -Path, every entry is also appended as a JSON line to a
        local file (outside any git working tree). Entries never contain credentials or secrets.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string] $Path)
    if ($Path) {
        if (Test-HdvInsideGitWorkTree -Path $Path) {
            throw "Refusing to write the journal inside a git working tree: $Path"
        }
    }
    [pscustomobject]@{ Path = $Path; Entries = (New-Object System.Collections.Generic.List[object]) }
}

function Write-HdvJournalEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Journal,
        [Parameter(Mandatory = $true)] [ValidateSet('STARTED', 'DONE', 'FAILED', 'WOULD', 'EXISTS', 'SKIPPED', 'INFO')] [string] $Status,
        [Parameter(Mandatory = $true)] [string] $Step,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Target,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Detail
    )
    $entry = [pscustomobject]@{
        Time   = (Get-Date).ToUniversalTime().ToString('o')
        Status = $Status
        Step   = $Step
        Target = $Target
        Detail = $Detail
    }
    $Journal.Entries.Add($entry)
    if ($Journal.Path) {
        Add-Content -LiteralPath $Journal.Path -Value ($entry | ConvertTo-Json -Compress)
    }
    $entry
}

function Invoke-HdvJournaledAction {
    <#
    .SYNOPSIS
        Records STARTED, runs the action, then records DONE, or FAILED (with the error message) and rethrows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Journal,
        [Parameter(Mandatory = $true)] [string] $Step,
        [Parameter(Mandatory = $true)] [string] $Target,
        [Parameter(Mandatory = $true)] [string] $Detail,
        [Parameter(Mandatory = $true)] [scriptblock] $Action
    )
    Write-HdvJournalEntry -Journal $Journal -Status STARTED -Step $Step -Target $Target -Detail $Detail
    try {
        $null = & $Action
    }
    catch {
        Write-HdvJournalEntry -Journal $Journal -Status FAILED -Step $Step -Target $Target -Detail "$Detail :: $($_.Exception.Message)"
        throw
    }
    Write-HdvJournalEntry -Journal $Journal -Status DONE -Step $Step -Target $Target -Detail $Detail
}

function Write-HdvPartialSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Journal, [Parameter(Mandatory = $true)] [string] $RecoveryDoc)
    $done = @($Journal.Entries | Where-Object { $_.Status -eq 'DONE' })
    $failed = @($Journal.Entries | Where-Object { $_.Status -eq 'FAILED' })
    Write-Host ''
    Write-Host "PARTIAL EXECUTION: $($done.Count) change(s) completed before the failure. Nothing was rolled back automatically."
    foreach ($entry in $done) { Write-Host "  DONE    $($entry.Step) -> $($entry.Target)" }
    foreach ($entry in $failed) { Write-Host "  FAILED  $($entry.Step) -> $($entry.Target): $($entry.Detail)" }
    if ($Journal.Path) { Write-Host "Journal: $($Journal.Path)" }
    Write-Host "Recovery: $RecoveryDoc"
}

function Write-HdvRefusal {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Reason)
    [pscustomobject]@{ Status = 'REFUSED'; Step = 'preflight'; Target = ''; Detail = $Reason }
}

# --------------------------------------------------------------------------- #
# Lab layout and paths
# --------------------------------------------------------------------------- #
function Get-HdvLabOuLayout {
    <#
    .SYNOPSIS
        Computes the lab OU distinguished names from configuration and the VERIFIED domain DN.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config,
        [Parameter(Mandatory = $true)] [string] $DomainDN
    )
    $null = Assert-HdvDistinguishedName -Value $DomainDN -Name 'DomainDN'
    $rootName = Assert-HdvOuName -Value (Get-HdvConfigValue -Config $Config -Path 'ActiveDirectory.LabRootOuName' -Required) -Name 'LabRootOuName'
    if ($rootName -notmatch '^HDV') {
        throw "ActiveDirectory.LabRootOuName '$rootName' must start with 'HDV' (lab namespace)."
    }
    $rootDN = "OU=$rootName,$DomainDN"
    $synced = @(Get-HdvConfigValue -Config $Config -Path 'ActiveDirectory.SyncedOuNames' -Required) |
        ForEach-Object { "OU=$(Assert-HdvOuName -Value $_ -Name 'SyncedOuNames'),$rootDN" }
    $nonSynced = @(Get-HdvConfigValue -Config $Config -Path 'ActiveDirectory.NonSyncedOuNames' -Required) |
        ForEach-Object { "OU=$(Assert-HdvOuName -Value $_ -Name 'NonSyncedOuNames'),$rootDN" }
    $overlap = @($synced | Where-Object { $nonSynced -contains $_ })
    if ($overlap.Count -gt 0) {
        throw "An OU cannot be both synced and non-synced: $($overlap -join '; ')"
    }
    $connectorOuName = Assert-HdvOuName -Value (Get-HdvConfigValue -Config $Config -Path 'ConnectorAccount.OuName' -Required) -Name 'ConnectorAccount.OuName'
    $connectorOuDN = "OU=$connectorOuName,$rootDN"
    if ($nonSynced -notcontains $connectorOuDN) {
        throw "ConnectorAccount.OuName '$connectorOuName' must be one of the NonSyncedOuNames: the connector account must never be synchronised."
    }
    [pscustomobject]@{
        DomainDN       = $DomainDN
        RootDN         = $rootDN
        SyncedOuDNs    = @($synced)
        NonSyncedOuDNs = @($nonSynced)
        ConnectorOuDN  = $connectorOuDN
    }
}

function Test-HdvDnUnder {
    <#
    .SYNOPSIS
        True if DistinguishedName equals or is below ContainerDN (case-insensitive).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $DistinguishedName, [Parameter(Mandatory = $true)] [string] $ContainerDN)
    $dn = $DistinguishedName.ToLowerInvariant()
    $container = $ContainerDN.ToLowerInvariant()
    return ($dn -eq $container) -or $dn.EndsWith(",$container")
}

function Test-HdvInsideGitWorkTree {
    <#
    .SYNOPSIS
        True if Path (file or directory) is inside a git working tree. Used to refuse writing
        lab data (SIDs, IPs, application IDs, journals) into the repository.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $current = if (Test-Path -LiteralPath $full -PathType Container) { $full } else { [System.IO.Path]::GetDirectoryName($full) }
    while ($current) {
        if (Test-Path -LiteralPath ([System.IO.Path]::Combine($current, '.git'))) { return $true }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $false
}

Export-ModuleMember -Function New-HdvResult, Get-HdvExitCode, Get-HdvRefusedExitCode, Get-HdvPartialExitCode,
    Test-HdvPlaceholder, Import-HdvConfig, Get-HdvConfigValue,
    Assert-HdvGuid, Assert-HdvDistinguishedName, Assert-HdvOuName, Assert-HdvLabObjectName, ConvertTo-HdvLdapFilterValue,
    Compare-HdvVersion, Import-HdvRequiredModule,
    Assert-HdvLabDomain, Assert-HdvSingleDomainForest, Confirm-HdvTypedConfirmation,
    New-HdvJournal, Write-HdvJournalEntry, Invoke-HdvJournaledAction, Write-HdvPartialSummary, Write-HdvRefusal,
    Get-HdvLabOuLayout, Test-HdvDnUnder, Test-HdvInsideGitWorkTree
