#Requires -Version 5.1
<#
.SYNOPSIS
    Collects the values for the HDV_EntraConnect Sentinel watchlist on SYNC01 (Module 2.1, step 8).

.DESCRIPTION
    Read-only towards the system; writes ONE local CSV file. The watchlist feeds the DCSync
    allow-list (docs/dcsync-detection-design.md) and the hybrid verification queries
    (queries/verification/hybrid-identity/).

    Columns (watchlist search key: ConnectorSid):
      ConnectorSid             SID of the AD DS connector account (Get-ADUser)
      ConnectorSamAccountName  from configuration
      SyncServer               this computer's name
      SyncIps                  JSON array of this server's IPv4 addresses (Get-NetIPAddress;
                               loopback and link-local excluded) - read from the machine, never typed
      ConnectAppId             Entra Connect application (client) ID (configuration, or the single
                               GUID found in Get-ADSyncEntraConnectorCredential)
      LabEgressIps             EMPTY: the public egress IP of the lab is not visible from inside the
                               lab; the owner fills it in before uploading the watchlist

    Refuses to write inside a git working tree (lab identifiers must not be committed) and
    refuses to overwrite an existing file unless -Force is given.

.EXAMPLE
    .\Export-HdvEntraConnectWatchlist.ps1 -ConfigPath .\config\hybrid-identity.config.local.psd1 -OutputPath C:\HDV\private\HDV_EntraConnect.local.csv
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)] [string] $ConfigPath,
    [Parameter(Mandatory = $true)] [string] $OutputPath,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'common', 'HdvLab.psm1')) -Force

if (Test-HdvInsideGitWorkTree -Path $OutputPath) {
    throw "Refusing to write lab identifiers inside a git working tree: $OutputPath"
}
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "Output file exists: $OutputPath (use -Force to overwrite)."
}

$config = Import-HdvConfig -Path $ConfigPath
$sam = Assert-HdvLabObjectName -Value (Get-HdvConfigValue -Config $config -Path 'ConnectorAccount.SamAccountName' -Required) -Kind ServiceAccount -Name 'ConnectorAccount.SamAccountName'

if (-not (Import-HdvRequiredModule -Name ActiveDirectory -ProbeCommand 'Get-ADUser')) {
    throw 'The ActiveDirectory PowerShell module (RSAT) is required.'
}
$null = Assert-HdvLabDomain -Config $config
$account = @(Get-ADUser -LDAPFilter "(sAMAccountName=$(ConvertTo-HdvLdapFilterValue $sam))" -Properties SID)
if ($account.Count -ne 1) {
    throw "Connector account '$sam' not found (found $($account.Count))."
}
$sid = [string]$account[0].SID

$ips = @(Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { [string]$_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        ForEach-Object { [string]$_.IPAddress } | Sort-Object -Unique)
if ($ips.Count -eq 0) { throw 'No usable IPv4 address found on this server.' }

$appId = Get-HdvConfigValue -Config $config -Path 'EntraConnect.ApplicationId'
if ($appId) {
    $appId = Assert-HdvGuid -Value $appId -Name 'EntraConnect.ApplicationId'
}
elseif (Import-HdvRequiredModule -Name ADSync -ProbeCommand 'Get-ADSyncEntraConnectorCredential') {
    $credential = Get-ADSyncEntraConnectorCredential
    $guids = @($credential.PSObject.Properties | ForEach-Object {
            $parsed = [guid]::Empty
            if ([guid]::TryParse([string]$_.Value, [ref]$parsed) -and $parsed -ne [guid]::Empty) { $parsed.ToString() }
        } | Sort-Object -Unique)
    if ($guids.Count -ne 1) {
        throw "Cannot determine the Entra Connect application ID unambiguously (found $($guids.Count) GUIDs). Set EntraConnect.ApplicationId in the config."
    }
    $appId = $guids[0]
}
else {
    throw 'EntraConnect.ApplicationId is not configured and the ADSync module is unavailable.'
}

$server = $env:COMPUTERNAME
if (-not $server) { $server = 'localhost' }
$row = [pscustomobject]@{
    ConnectorSid            = $sid
    ConnectorSamAccountName = $sam
    SyncServer              = $server
    SyncIps                 = (ConvertTo-Json -InputObject @($ips) -Compress)
    ConnectAppId            = $appId
    LabEgressIps            = ''
}

if ($PSCmdlet.ShouldProcess($OutputPath, 'Write HDV_EntraConnect watchlist CSV')) {
    $row | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Written: $OutputPath. Fill in LabEgressIps before uploading the watchlist (Module 2.3/2.4)."
}
$row
