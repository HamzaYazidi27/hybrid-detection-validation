#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only isolation readiness check of VMware .vmx network settings, run on the HOST (ADR-0012).

.DESCRIPTION
    Parses .vmx files (never modifies them) and verifies:
      I1a  no virtual NIC uses bridged networking;
      I1b  every NIC of a lab VM is attached to a lab-only custom network (for example VMnet10);
      I1c  the firewall VM FW01 has exactly one lab NIC and at most one WAN NIC (NAT);
      I2   (Windows host, optional) the host has NO virtual adapter on the lab network.

    A NIC without an explicit connectionType is a FAIL: do not rely on VMware defaults.
    Results: PASS, FAIL or MANUAL (cannot be checked automatically; verify by hand).
    Exit code: 0 all PASS, 1 any FAIL, 2 no FAIL but MANUAL items remain.

    STATUS: written in Phase 0. Tested only against synthetic .vmx files.

.PARAMETER Path
    .vmx files or directories to scan recursively.

.PARAMETER LabNetworks
    Custom VMware networks reserved for the lab (for example VMnet10).

.PARAMETER FirewallVmx
    Path of FW01's .vmx file.

.PARAMETER FirewallWanNetworks
    Networks FW01 may use for its WAN NIC. 'nat' means connectionType = "nat".

.PARAMETER CheckHostAdapter
    On Windows hosts, verify that no 'VMware Network Adapter <LabNetwork>' exists on the host.

.EXAMPLE
    .\Test-HdvVmxNetworking.ps1 -Path 'D:\VMs\HDV' -LabNetworks VMnet10 -FirewallVmx 'D:\VMs\HDV\FW01\FW01.vmx' -CheckHostAdapter
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Path,

    [Parameter(Mandatory = $true)]
    [string[]] $LabNetworks,

    [Parameter(Mandatory = $true)]
    [string] $FirewallVmx,

    [string[]] $FirewallWanNetworks = @('nat', 'VMnet8'),

    [switch] $CheckHostAdapter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-VmxNics {
    param([string] $File)
    $settings = @{}
    foreach ($line in Get-Content -LiteralPath $File) {
        if ($line -match '^\s*([A-Za-z0-9_.:]+)\s*=\s*"(.*)"\s*$') {
            $settings[$Matches[1].ToLowerInvariant()] = $Matches[2]
        }
    }
    $indexes = $settings.Keys | ForEach-Object { if ($_ -match '^ethernet(\d+)\.') { [int]$Matches[1] } } | Sort-Object -Unique
    foreach ($index in $indexes) {
        $prefix = "ethernet$index"
        $present = $settings["$prefix.present"]
        if ($null -ne $present -and $present -ieq 'FALSE') { continue }
        [pscustomobject]@{
            Nic            = $prefix
            ConnectionType = $settings["$prefix.connectiontype"]
            Vnet           = $settings["$prefix.vnet"]
        }
    }
}

function New-Result {
    param([string] $Check, [string] $Target, [string] $Detail, [ValidateSet('PASS', 'FAIL', 'MANUAL')] [string] $Result)
    [pscustomobject]@{ Check = $Check; Target = $Target; Detail = $Detail; Result = $Result }
}

$labSet = $LabNetworks | ForEach-Object { $_.ToLowerInvariant() }
$wanSet = $FirewallWanNetworks | ForEach-Object { $_.ToLowerInvariant() }
$firewallFull = [System.IO.Path]::GetFullPath($FirewallVmx)

$files = foreach ($item in $Path) {
    if (Test-Path -LiteralPath $item -PathType Container) {
        Get-ChildItem -LiteralPath $item -Recurse -File -Filter '*.vmx' | ForEach-Object { $_.FullName }
    }
    elseif (Test-Path -LiteralPath $item -PathType Leaf) {
        [System.IO.Path]::GetFullPath($item)
    }
    else {
        throw "Path not found: $item"
    }
}
$files = @($files | Sort-Object -Unique)
if ($files -notcontains $firewallFull) { $files += $firewallFull }

$results = New-Object System.Collections.Generic.List[object]
foreach ($file in $files) {
    $isFirewall = ($file -eq $firewallFull)
    $nics = @(Read-VmxNics -File $file)
    $vm = [System.IO.Path]::GetFileNameWithoutExtension($file)
    if ($nics.Count -eq 0) {
        $results.Add((New-Result 'I1 NIC inventory' $vm 'no network adapter found' 'MANUAL'))
        continue
    }
    $labNics = 0
    $wanNics = 0
    foreach ($nic in $nics) {
        $target = "$vm/$($nic.Nic)"
        $type = if ($nic.ConnectionType) { $nic.ConnectionType.ToLowerInvariant() } else { $null }
        $vnet = if ($nic.Vnet) { $nic.Vnet.ToLowerInvariant() } else { $null }
        if ($null -eq $type) {
            $results.Add((New-Result 'I1a explicit connection type' $target 'connectionType missing (VMware default may be bridged)' 'FAIL'))
            continue
        }
        if ($type -eq 'bridged') {
            $results.Add((New-Result 'I1a no bridged networking' $target 'connectionType = bridged' 'FAIL'))
            continue
        }
        $onLab = ($type -eq 'custom') -and ($labSet -contains $vnet)
        $onWan = $isFirewall -and ((($type -eq 'nat') -and ($wanSet -contains 'nat')) -or (($type -eq 'custom') -and ($wanSet -contains $vnet)))
        if ($onLab) {
            $labNics++
            $results.Add((New-Result 'I1b lab network' $target "custom $($nic.Vnet)" 'PASS'))
        }
        elseif ($onWan) {
            $wanNics++
            $results.Add((New-Result 'I1c firewall WAN' $target "$type $($nic.Vnet)" 'PASS'))
        }
        else {
            $results.Add((New-Result 'I1b lab network' $target "$type $($nic.Vnet) is not an allowed network" 'FAIL'))
        }
    }
    if ($isFirewall) {
        $layoutOk = ($labNics -eq 1) -and ($wanNics -le 1)
        $results.Add((New-Result 'I1c firewall NIC layout' $vm "lab NICs=$labNics, WAN NICs=$wanNics" $(if ($layoutOk) { 'PASS' } else { 'FAIL' })))
    }
}

if ($CheckHostAdapter) {
    if (Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue) {
        foreach ($network in $LabNetworks) {
            $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$network" -or $_.InterfaceDescription -like "*$network*" })
            $result = if ($adapter.Count -eq 0) { 'PASS' } else { 'FAIL' }
            $results.Add((New-Result 'I2 no host adapter on lab network' $network "host adapters found: $($adapter.Count)" $result))
        }
    }
    else {
        $results.Add((New-Result 'I2 no host adapter on lab network' ($LabNetworks -join ',') 'Get-NetAdapter unavailable; verify in the Virtual Network Editor that "Connect a host virtual adapter" is unchecked' 'MANUAL'))
    }
}
else {
    $results.Add((New-Result 'I2 no host adapter on lab network' ($LabNetworks -join ',') 'not checked; use -CheckHostAdapter or verify manually' 'MANUAL'))
}

$results
if (@($results | Where-Object { $_.Result -eq 'FAIL' }).Count -gt 0) { exit 1 }
if (@($results | Where-Object { $_.Result -eq 'MANUAL' }).Count -gt 0) { exit 2 }
exit 0
