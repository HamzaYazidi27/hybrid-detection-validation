#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only isolation readiness check, run INSIDE a lab VM (ADR-0012).

.DESCRIPTION
    Verifies from the guest that:
      I3a  the only default route points to the lab firewall VM (FW01);
      I3b  DNS servers are lab-internal (DC01 or FW01) when -AllowedDnsServers is given;
      I3c  forbidden targets (host LAN, host IP, other RFC1918 hosts) are unreachable;
      I3d  required Microsoft endpoints are reachable on TCP 443 through FW01.

    It changes nothing. A target counts as blocked only when the TCP connection TIMES OUT:
    configure FW01 to silently DROP (block) RFC1918 traffic, not reject it, so a refused
    connection unambiguously means a path exists. Checks that cannot run (for example, a
    missing cmdlet on non-Windows systems) are reported as FAIL: the check fails closed.

    STATUS: written in Phase 0. NOT executed in the lab.

.PARAMETER ExpectedGateway
    LAN IP address of the firewall VM FW01.

.PARAMETER ForbiddenTargets
    Addresses that must NOT be reachable: host LAN gateway, host IP, other private hosts.

.PARAMETER IncludeCommonPrivateGateways
    Also probe common private gateway addresses (192.168.0.1, 192.168.1.1, 10.0.0.1, 172.16.0.1).

.PARAMETER ExcludeTargets
    Addresses inside the lab subnet to skip (for example FW01 itself).

.EXAMPLE
    .\Test-HdvLabIsolation.ps1 -ExpectedGateway 10.50.0.1 -ForbiddenTargets 192.168.1.1 -IncludeCommonPrivateGateways -ExcludeTargets 10.50.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ipaddress] $ExpectedGateway,

    [Parameter(Mandatory = $true)]
    [string[]] $ForbiddenTargets,

    [int[]] $ForbiddenPorts = @(22, 53, 80, 443, 445, 3389),

    [switch] $IncludeCommonPrivateGateways,

    [string[]] $ExcludeTargets = @(),

    [string[]] $AllowedDnsServers = @(),

    [string[]] $RequiredEndpoints = @(
        'login.microsoftonline.com',
        'management.azure.com',
        'gbl.his.arc.azure.com',
        'global.handler.control.monitor.azure.com'
    ),

    [ValidateRange(200, 30000)]
    [int] $TimeoutMs = 2000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-TcpPort {
    param([string] $Target, [int] $Port, [int] $Timeout)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($Timeout, $false)) {
            return 'Timeout'
        }
        $client.EndConnect($async)
        return 'Connected'
    }
    catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) { return 'Refused' }
        return "Error:$($_.Exception.SocketErrorCode)"
    }
    catch {
        $inner = $_.Exception.InnerException
        if ($inner -is [System.Net.Sockets.SocketException] -and $inner.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
            return 'Refused'
        }
        return 'Error'
    }
    finally {
        $client.Close()
    }
}

function New-Result {
    param([string] $Check, [string] $Target, [string] $Expected, [string] $Actual, [bool] $Pass)
    [pscustomobject]@{ Check = $Check; Target = $Target; Expected = $Expected; Actual = $Actual; Result = $(if ($Pass) { 'PASS' } else { 'FAIL' }) }
}

$results = New-Object System.Collections.Generic.List[object]

# I3a - default route
if (Get-Command -Name Get-NetRoute -ErrorAction SilentlyContinue) {
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    $hops = @($routes | ForEach-Object { $_.NextHop } | Sort-Object -Unique)
    $ok = ($hops.Count -eq 1) -and ($hops[0] -eq $ExpectedGateway.IPAddressToString)
    $results.Add((New-Result 'I3a default route' '0.0.0.0/0' $ExpectedGateway.IPAddressToString ($hops -join ',') $ok))
}
else {
    $results.Add((New-Result 'I3a default route' '0.0.0.0/0' $ExpectedGateway.IPAddressToString 'Get-NetRoute cmdlet unavailable' $false))
}

# I3b - DNS servers
if ($AllowedDnsServers.Count -gt 0) {
    if (Get-Command -Name Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
        $servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)
        $unexpected = @($servers | Where-Object { $AllowedDnsServers -notcontains $_ })
        $results.Add((New-Result 'I3b DNS servers' 'IPv4' ($AllowedDnsServers -join ',') ($servers -join ',') ($servers.Count -gt 0 -and $unexpected.Count -eq 0)))
    }
    else {
        $results.Add((New-Result 'I3b DNS servers' 'IPv4' ($AllowedDnsServers -join ',') 'Get-DnsClientServerAddress cmdlet unavailable' $false))
    }
}

# I3c - forbidden targets must time out on every probed port
$targets = New-Object System.Collections.Generic.List[string]
$ForbiddenTargets | ForEach-Object { $targets.Add($_) }
if ($IncludeCommonPrivateGateways) {
    '192.168.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1' | ForEach-Object { $targets.Add($_) }
}
foreach ($target in ($targets | Sort-Object -Unique)) {
    if ($ExcludeTargets -contains $target) { continue }
    foreach ($port in $ForbiddenPorts) {
        $state = Test-TcpPort -Target $target -Port $port -Timeout $TimeoutMs
        $results.Add((New-Result 'I3c forbidden target' "${target}:$port" 'Timeout' $state ($state -eq 'Timeout')))
    }
}

# I3d - required endpoints reachable through FW01
foreach ($endpoint in $RequiredEndpoints) {
    $state = Test-TcpPort -Target $endpoint -Port 443 -Timeout $TimeoutMs
    $results.Add((New-Result 'I3d required endpoint' "${endpoint}:443" 'Connected' $state ($state -eq 'Connected')))
}

$results
if (@($results | Where-Object { $_.Result -ne 'PASS' }).Count -gt 0) {
    Write-Warning 'Lab isolation readiness check FAILED. Do not run any scenario.'
    exit 1
}
exit 0
