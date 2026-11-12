#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only prerequisite check for Microsoft Entra Connect Sync on SYNC01 (Module 2.1, step 1).

.DESCRIPTION
    Run on SYNC01, elevated. Changes nothing. Checks, against Microsoft's documented
    prerequisites (see lab/powershell/hybrid-identity/README.md for sources):

      P1  Windows Server (not a workstation, not a domain controller); 2022/2025 recommended
      P2  Domain joined
      P3  .NET Framework 4.8 or later (release >= 528040)
      P4  TLS 1.2 registry values from Microsoft's Connect TLS 1.2 guidance
      P5  PowerShell 5.1 or later
      P6  Execution policy allows signed scripts (Connect runs signed scripts)
      P7  ActiveDirectory PowerShell module (RSAT), needed by the ADSyncConfig module
      P8  TPM present and ready (recommended for the Connect application certificate)
      P9  No Entra Cloud Sync agent; detects an existing Connect installation
      P10 Writable domain controller reachable; forest functional level >= Windows Server 2003

    Exit code: 0 all PASS, 1 any FAIL, 2 only WARN/MANUAL remain.

.EXAMPLE
    .\Test-HdvHybridPrerequisites.ps1 | Format-Table -AutoSize
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force

$results = New-Object System.Collections.Generic.List[object]
$computer = $env:COMPUTERNAME
if (-not $computer) { $computer = 'localhost' }

# P1 - operating system
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    switch ([int]$os.ProductType) {
        2 { $results.Add((New-HdvResult 'P1 operating system' $computer "$($os.Caption) is a DOMAIN CONTROLLER; Entra Connect must not be installed on a DC (ADR-0003)" 'FAIL')) }
        1 { $results.Add((New-HdvResult 'P1 operating system' $computer "$($os.Caption) is a workstation; Entra Connect requires Windows Server" 'FAIL')) }
        default {
            if ($os.Caption -match '2022|2025') {
                $results.Add((New-HdvResult 'P1 operating system' $computer "$($os.Caption) (recommended by Microsoft)" 'PASS'))
            }
            elseif ($os.Caption -match '2016|2019') {
                $results.Add((New-HdvResult 'P1 operating system' $computer "$($os.Caption): supported only in extended support; Microsoft recommends 2022 or 2025" 'WARN'))
            }
            else {
                $results.Add((New-HdvResult 'P1 operating system' $computer "$($os.Caption) is not a supported Windows Server version for this project" 'FAIL'))
            }
        }
    }
}
catch {
    $results.Add((New-HdvResult 'P1 operating system' $computer "cannot read Win32_OperatingSystem: $($_.Exception.Message)" 'MANUAL'))
}

# P2 - domain membership
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        $results.Add((New-HdvResult 'P2 domain joined' $computer "member of $($cs.Domain)" 'PASS'))
    }
    else {
        $results.Add((New-HdvResult 'P2 domain joined' $computer 'not domain joined' 'FAIL'))
    }
}
catch {
    $results.Add((New-HdvResult 'P2 domain joined' $computer "cannot read Win32_ComputerSystem: $($_.Exception.Message)" 'MANUAL'))
}

# P3 - .NET Framework 4.8+
$net = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue
if ($null -eq $net) {
    $results.Add((New-HdvResult 'P3 .NET Framework' $computer '.NET Framework 4.x not found' 'FAIL'))
}
elseif ([int]$net.Release -ge 528040) {
    $results.Add((New-HdvResult 'P3 .NET Framework' $computer "release $($net.Release) (4.8 or later)" 'PASS'))
}
else {
    $results.Add((New-HdvResult 'P3 .NET Framework' $computer "release $($net.Release) is older than 4.8 (528040)" 'FAIL'))
}

# P4 - TLS 1.2 (Microsoft Entra Connect TLS 1.2 enforcement guidance)
$tlsChecks = @(
    @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; Name = 'SystemDefaultTlsVersions'; Expected = 1 },
    @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; Name = 'SchUseStrongCrypto'; Expected = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; Name = 'SystemDefaultTlsVersions'; Expected = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; Name = 'SchUseStrongCrypto'; Expected = 1 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'; Name = 'Enabled'; Expected = 1 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'; Name = 'DisabledByDefault'; Expected = 0 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'; Name = 'Enabled'; Expected = 1 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'; Name = 'DisabledByDefault'; Expected = 0 }
)
foreach ($check in $tlsChecks) {
    $target = "$($check.Path)\$($check.Name)"
    $item = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        $results.Add((New-HdvResult 'P4 TLS 1.2' $target "not set (expected $($check.Expected) per Microsoft's Connect TLS 1.2 guidance)" 'WARN'))
    }
    elseif ([int]$item.($check.Name) -eq $check.Expected) {
        $results.Add((New-HdvResult 'P4 TLS 1.2' $target "= $($check.Expected)" 'PASS'))
    }
    else {
        $results.Add((New-HdvResult 'P4 TLS 1.2' $target "= $($item.($check.Name)); expected $($check.Expected)" 'FAIL'))
    }
}

# P5 - PowerShell version
$psVersion = $PSVersionTable.PSVersion
if (($psVersion.Major -gt 5) -or ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1)) {
    $results.Add((New-HdvResult 'P5 PowerShell' $computer "version $psVersion" 'PASS'))
}
else {
    $results.Add((New-HdvResult 'P5 PowerShell' $computer "version $psVersion is older than 5.1" 'FAIL'))
}

# P6 - execution policy
$policy = [string](Get-ExecutionPolicy)
switch ($policy) {
    'Restricted' { $results.Add((New-HdvResult 'P6 execution policy' $computer 'Restricted: Entra Connect setup cannot run its signed scripts' 'FAIL')) }
    'AllSigned' { $results.Add((New-HdvResult 'P6 execution policy' $computer 'AllSigned: HDV scripts are unsigned and will not run' 'WARN')) }
    default { $results.Add((New-HdvResult 'P6 execution policy' $computer $policy 'PASS')) }
}

# P7 - ActiveDirectory module (RSAT)
$adModule = Get-Module -ListAvailable -Name ActiveDirectory
if ($adModule) {
    $results.Add((New-HdvResult 'P7 ActiveDirectory module' $computer 'available' 'PASS'))
}
else {
    $results.Add((New-HdvResult 'P7 ActiveDirectory module' $computer 'missing: an administrator must install RSAT-AD-PowerShell (this script never installs anything)' 'FAIL'))
}

# P8 - TPM (recommended)
try {
    $tpm = Get-Tpm
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        $results.Add((New-HdvResult 'P8 TPM' $computer 'present and ready' 'PASS'))
    }
    else {
        $results.Add((New-HdvResult 'P8 TPM' $computer "present=$($tpm.TpmPresent) ready=$($tpm.TpmReady): the Connect certificate key will use the software key storage provider" 'WARN'))
    }
}
catch {
    $results.Add((New-HdvResult 'P8 TPM' $computer "cannot query TPM (run elevated): $($_.Exception.Message)" 'MANUAL'))
}

# P9 - sync engines already present
$services = @(Get-Service -Name 'ADSync', 'AADConnectProvisioningAgent' -ErrorAction SilentlyContinue)
if ($services | Where-Object { $_.Name -eq 'AADConnectProvisioningAgent' }) {
    $results.Add((New-HdvResult 'P9 existing sync engines' $computer 'Entra Cloud Sync provisioning agent found: conflicts with ADR-0003 (Connect Sync)' 'FAIL'))
}
elseif ($services | Where-Object { $_.Name -eq 'ADSync' }) {
    $results.Add((New-HdvResult 'P9 existing sync engines' $computer 'Entra Connect (ADSync) is already installed: use Test-HdvEntraConnectConfiguration.ps1' 'WARN'))
}
else {
    $results.Add((New-HdvResult 'P9 existing sync engines' $computer 'none' 'PASS'))
}

# P10 - directory reachability and forest functional level
if ($adModule -and (Import-HdvRequiredModule -Name ActiveDirectory -ProbeCommand 'Get-ADForest')) {
    try {
        $dc = Get-ADDomainController -Discover -Writable
        $results.Add((New-HdvResult 'P10 writable domain controller' ([string]$dc.HostName) 'discovered' 'PASS'))
    }
    catch {
        $results.Add((New-HdvResult 'P10 writable domain controller' $computer "no writable DC discovered: $($_.Exception.Message)" 'FAIL'))
    }
    try {
        $mode = [string](Get-ADForest).ForestMode
        if ($mode -match '^Windows(\d{4})') {
            $year = [int]$Matches[1]
            $result = if ($year -ge 2003) { 'PASS' } else { 'FAIL' }
            $results.Add((New-HdvResult 'P10 forest functional level' $computer $mode $result))
        }
        else {
            $results.Add((New-HdvResult 'P10 forest functional level' $computer "unrecognised value '$mode'" 'MANUAL'))
        }
    }
    catch {
        $results.Add((New-HdvResult 'P10 forest functional level' $computer "cannot read forest: $($_.Exception.Message)" 'MANUAL'))
    }
}
else {
    $results.Add((New-HdvResult 'P10 directory checks' $computer 'skipped: ActiveDirectory module unavailable' 'MANUAL'))
}

$results
exit (Get-HdvExitCode -Results $results.ToArray())
