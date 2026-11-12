#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only check that the Entra Connect OU-filtering scope contains no privileged objects
    and matches the configured synced OUs (Module 2.1, steps 2 and 7).

.DESCRIPTION
    Active Directory side (needs the ActiveDirectory module):
      S1  every configured synced OU exists
      S2  no object with adminCount=1 (protected / privileged) is inside a synced OU
      S3  the connector account is NOT inside a synced OU

    Entra Connect side (-IncludeConnectConfiguration, on SYNC01 with the ADSync module):
      S4  the AD connector's container inclusion list equals exactly the configured synced OUs
          and does not include the domain root.
          The property names used to read the partition scope are NOT documented by Microsoft;
          if they are not present, S4 is reported as MANUAL with the steps to verify in the
          Synchronization Service Manager.

    Exit code: 0 all PASS, 1 any FAIL, 2 only WARN/MANUAL remain.

.EXAMPLE
    .\Test-HdvSyncScope.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 -IncludeConnectConfiguration
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ConfigPath,
    [switch] $IncludeConnectConfiguration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force

$config = Import-HdvConfig -Path $ConfigPath
$results = New-Object System.Collections.Generic.List[object]

if (-not (Import-HdvRequiredModule -Name ActiveDirectory -ProbeCommand 'Get-ADUser')) {
    $results.Add((New-HdvResult 'S0 prerequisites' 'ActiveDirectory module' 'missing; install RSAT yourself, then re-run' 'FAIL'))
    $results
    exit 1
}

try {
    $lab = Assert-HdvLabDomain -Config $config
}
catch {
    $results.Add((New-HdvResult 'S0 lab domain identity' 'ActiveDirectory' $_.Exception.Message 'FAIL'))
    $results
    exit 1
}
$layout = Get-HdvLabOuLayout -Config $config -DomainDN $lab.DomainDN

# S1
foreach ($ouDN in $layout.SyncedOuDNs) {
    $ou = $null
    try { $ou = Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction Stop } catch { $ou = $null }
    $result = if ($ou) { 'PASS' } else { 'FAIL' }
    $detail = if ($ou) { 'exists' } else { 'missing: run New-HdvHybridLabObjects.ps1' }
    $results.Add((New-HdvResult 'S1 synced OU exists' $ouDN $detail $result))
}

# S2
$protected = @(Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount) + @(Get-ADGroup -LDAPFilter '(adminCount=1)' -Properties adminCount)
$inScope = @($protected | Where-Object {
        $dn = [string]$_.DistinguishedName
        @($layout.SyncedOuDNs | Where-Object { Test-HdvDnUnder -DistinguishedName $dn -ContainerDN $_ }).Count -gt 0
    })
if ($inScope.Count -eq 0) {
    $results.Add((New-HdvResult 'S2 no privileged objects in scope' ($layout.SyncedOuDNs -join '; ') "$($protected.Count) adminCount=1 object(s) checked; none in scope" 'PASS'))
}
else {
    foreach ($object in $inScope) {
        $results.Add((New-HdvResult 'S2 no privileged objects in scope' ([string]$object.DistinguishedName) 'adminCount=1 object inside a synced OU: move it out before synchronising' 'FAIL'))
    }
}

# S3
$sam = Assert-HdvLabObjectName -Value (Get-HdvConfigValue -Config $config -Path 'ConnectorAccount.SamAccountName' -Required) -Kind ServiceAccount -Name 'ConnectorAccount.SamAccountName'
$connector = @(Get-ADUser -LDAPFilter "(sAMAccountName=$(ConvertTo-HdvLdapFilterValue $sam))" -ErrorAction SilentlyContinue)
if ($connector.Count -eq 0) {
    $results.Add((New-HdvResult 'S3 connector account outside scope' $sam 'account not found (not created yet?)' 'MANUAL'))
}
else {
    $dn = [string]$connector[0].DistinguishedName
    $inSynced = @($layout.SyncedOuDNs | Where-Object { Test-HdvDnUnder -DistinguishedName $dn -ContainerDN $_ }).Count -gt 0
    if ($inSynced) {
        $results.Add((New-HdvResult 'S3 connector account outside scope' $dn 'connector account is inside a synced OU' 'FAIL'))
    }
    else {
        $results.Add((New-HdvResult 'S3 connector account outside scope' $dn 'not in any synced OU' 'PASS'))
    }
}

# S4
if ($IncludeConnectConfiguration) {
    $manualSteps = 'Verify manually: Synchronization Service Manager > Connectors > <AD connector> > Properties > Configure Directory Partitions > Containers; only the synced OUs may be selected.'
    if (-not (Import-HdvRequiredModule -Name ADSync -ProbeCommand 'Get-ADSyncConnector')) {
        $results.Add((New-HdvResult 'S4 Connect OU filtering' 'ADSync module' "unavailable (run on SYNC01). $manualSteps" 'MANUAL'))
    }
    else {
        $adConnectors = @(Get-ADSyncConnector | Where-Object { $_.ConnectorTypeName -eq 'AD' })
        if ($adConnectors.Count -ne 1) {
            $results.Add((New-HdvResult 'S4 Connect OU filtering' 'AD connectors' "expected exactly 1 AD connector, found $($adConnectors.Count). $manualSteps" 'MANUAL'))
        }
        else {
            $inclusion = @()
            $readable = $false
            foreach ($partition in @($adConnectors[0].Partitions)) {
                $scope = $partition.PSObject.Properties['ConnectorPartitionScope']
                if ($scope -and $scope.Value -and $scope.Value.PSObject.Properties['ContainerInclusionList']) {
                    $readable = $true
                    $inclusion += @($scope.Value.ContainerInclusionList | ForEach-Object { [string]$_ })
                }
            }
            if (-not $readable) {
                $results.Add((New-HdvResult 'S4 Connect OU filtering' $adConnectors[0].Name "partition scope properties not readable (undocumented API). $manualSteps" 'MANUAL'))
            }
            else {
                $expected = @($layout.SyncedOuDNs | ForEach-Object { $_.ToLowerInvariant() })
                $actual = @($inclusion | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
                $missing = @($expected | Where-Object { $actual -notcontains $_ })
                $extra = @($actual | Where-Object { $expected -notcontains $_ })
                if ($actual -contains $layout.DomainDN.ToLowerInvariant()) {
                    $results.Add((New-HdvResult 'S4 Connect OU filtering' $layout.DomainDN 'the whole domain is selected: privileged accounts would synchronise' 'FAIL'))
                }
                elseif ($missing.Count -eq 0 -and $extra.Count -eq 0) {
                    $results.Add((New-HdvResult 'S4 Connect OU filtering' $adConnectors[0].Name 'inclusion list equals the configured synced OUs' 'PASS'))
                }
                else {
                    $detail = "missing: [$($missing -join '; ')] extra: [$($extra -join '; ')]"
                    $results.Add((New-HdvResult 'S4 Connect OU filtering' $adConnectors[0].Name $detail 'FAIL'))
                }
            }
        }
    }
}

$results
exit (Get-HdvExitCode -Results $results.ToArray())
