# Existing Laboratory Requirements

> **Principle:** reuse the existing VMware AD DS lab; **discover, never assume**. No IP address,
> hostname, OS version or configuration below is assumed. The owner collects values with
> **read-only** commands and stores them in an **untracked** local inventory (`lab.local.yml`,
> git-ignored). Nothing in this document installs or changes anything.

## 1. Logical roles

| Logical name | Role | Required | Notes |
|---|---|---|---|
| FW01 | Firewall VM, the lab's only egress | **Yes** | [lab-network.md](lab-network.md) |
| DC01 | Existing domain controller (AD DS + DNS) | Yes | Real hostname mapped in the local inventory |
| SYNC01 | Domain-joined **member** server for Entra Connect Sync | Yes | Tier 0. Must not be a DC |
| WEC01 | Domain-joined member server, WEF collector with Arc + AMA | Yes, unless a dedicated Tier 0 subscription exists | [ADR-0011](adr/0011-tier0-arc-isolation-wef-fallback.md) |
| WS01 | Domain-joined workstation | Recommended | Realistic origin for AD attacks |
| MGMT | Lab host that runs the validation CLI | Recommended | May be WS01; see [ADR-0009](adr/0009-scenario-execution-path.md) |

## 2. Discovery checklist (owner fills in; read-only commands)

| # | Item | Read-only command (run on) | Requirement / why | Value |
|---|---|---|---|---|
| D1 | DC OS version | `Get-CimInstance Win32_OperatingSystem \| Select Caption, Version, BuildNumber` (DC01) | Supported by AMA/WEF; extended-support OS may need paid support per Microsoft | _TBD_ |
| D2 | Forest / domain functional level, schema | `(Get-ADForest).ForestMode; (Get-ADDomain).DomainMode` | Connect requires schema and forest functional level Windows Server 2003 or later; a **writable** DC (no RODC-only) | _TBD_ |
| D3 | All DCs | `Get-ADDomainController -Filter * \| Select Name, Site, IPv4Address, OperatingSystem, IsReadOnly` | Every DC must be audited and forward events; feeds the `HDV_DomainControllers` watchlist | _TBD_ |
| D4 | DNS name & UPN suffixes | `(Get-ADDomain).DNSRoot; (Get-ADForest).UPNSuffixes` | Non-routable suffix → users sync as `@<tenant>.onmicrosoft.com` unless a verified domain is added | _TBD_ |
| D5 | Current audit policy | `auditpol /get /category:*` (DC01) | Compare with [data-flow.md §3](data-flow.md#3-windows-audit-prerequisites) | _TBD_ |
| D6 | Existing GPOs | `Get-GPO -All \| Select DisplayName, ModificationTime` | Never overwrite; a new dedicated GPO is proposed | _TBD_ |
| D7 | Existing SACL on the domain root | `(Get-Acl ("AD:\" + (Get-ADDomain).DistinguishedName) -Audit).Audit` (DC01, elevated, read-only) | Needed for DCSync auditing; entries are **added**, never replaced | _TBD_ |
| D8 | PowerShell version | `$PSVersionTable.PSVersion` (all) | ≥ 5.1 | _TBD_ |
| D9 | .NET Framework release | `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' \| Select Release` (SYNC01) | Microsoft's Connect page lists different minimums (4.6.2 and 4.7.2); the project requires **4.8** to satisfy both | _TBD_ |
| D10 | TLS 1.2 | `[Net.ServicePointManager]::SecurityProtocol` + SChannel registry review | Connect 2.x refuses to install without TLS 1.2 | _TBD_ |
| D11 | Time sync | `w32tm /query /status` (all) | Kerberos and token validation | _TBD_ |
| D12 | Existing agents / sync engines | `Get-Service himds, AzureMonitorAgent, HealthService, ADSync, AADConnectProvisioningAgent -ErrorAction SilentlyContinue` (all servers) | Leftovers conflict or duplicate data; only one engine may own an object scope | _TBD_ |
| D13 | VMware platform & version; vTPM support | VMware UI | Isolation design; vTPM for SYNC01 (recommended) | _TBD_ |
| D14 | Current network mode of every VM | `Test-HdvVmxNetworking.ps1` on the host (read-only) | Today's state before redesign | _TBD_ |
| D15 | Host RAM / disk / snapshot capacity | Host OS | See §3 | _TBD_ |
| D16 | TPM state on SYNC01 (after vTPM) | `Get-Tpm` (SYNC01) | Connect certificate key protection | _TBD_ |

## 3. Sizing guidance (lab)

| VM | vCPU | RAM | Notes |
|---|---|---|---|
| FW01 | 1–2 | 1–2 GB | Open-source firewall distribution |
| DC01 | 2 | 4 GB | Existing VM |
| SYNC01 | 2 | 4–8 GB | Windows Server 2022 or 2025 recommended by Microsoft; vTPM recommended |
| WEC01 | 2 | 4 GB | Windows Server; receives forwarded events |
| WS01 | 2 | 4 GB | Windows 10/11 Enterprise (evaluation or licensed) |

## 4. Entra and Azure prerequisites

| Item | Requirement |
|---|---|
| Entra tenant | A **dedicated lab tenant** where the owner is Global Administrator. Not a university or employer tenant |
| Entra licence | Record the actual state (Free / P1 / P2 / trial). Licensing gates LIC-001…006 are tested on it ([cost-and-licensing.md](cost-and-licensing.md)) |
| Entra Connect | **Version ≥ 2.6.84.0**, application-based authentication configured at install (mandatory by 7 April 2027). Hybrid Identity Administrator for setup, then downgraded |
| Azure subscriptions | A workload subscription (Owner during setup). A **dedicated Tier 0 subscription** only if DC01/SYNC01 are to be Arc-connected ([ADR-0011](adr/0011-tier0-arc-isolation-wef-fallback.md)) |
| Resource providers | `Microsoft.HybridCompute`, `Microsoft.GuestConfiguration`, `Microsoft.HybridConnectivity`, `Microsoft.Insights`, `Microsoft.OperationalInsights`, `Microsoft.SecurityInsights` **(verify the list in Phase 1)** |
| Region | One region for workspace, DCRs and Arc resources; chosen in Phase 1 |

## 5. Readiness gates (before Phase 2 changes anything)

- [ ] D1–D16 recorded in the local inventory.
- [ ] **G-NET:** FW01 deployed and isolation checks I1–I5 PASS ([lab-network.md](lab-network.md#4-isolation-readiness-checks-gate-g-net)).
- [ ] **G-T0:** decision recorded: dedicated Tier 0 subscription (direct AMA), or WEF via WEC01.
- [ ] Snapshots of all lab VMs taken (one consistent set).
- [ ] SYNC01 (and WEC01 if WEF) exist as domain-joined member servers.
- [ ] Owner confirms the dedicated lab tenant and subscription(s).
- [ ] Budget alerts configured (Phase 1 output).
- [ ] Existing audit GPOs and SACLs reviewed, so new configuration only adds.
- [ ] Lab state initialised with a written attestation ([ADR-0013](adr/0013-lab-state-cleanup-sweeper.md)).
