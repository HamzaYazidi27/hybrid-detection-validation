# Hybrid Identity Design: Microsoft Entra Connect Sync

> **Selected architecture:** Entra Connect Sync **≥ 2.6.84.0** with **application-based
> authentication** on SYNC01, a dedicated member server
> ([ADR-0003](adr/0003-entra-connect-sync-dedicated-member-server.md)). Cloud Sync is documented
> in §7 as an alternative only. **Nothing here has been installed.** Statements marked
> **(verify)** must be confirmed on the installed version.

## 1. Mandatory requirements (Microsoft, read 2026-11-11)

| Requirement | Source |
|---|---|
| Upgrade to **2.6.84.0 or later** and configure **application-based authentication by 7 April 2027**. Legacy authentication is retired and synchronisation stops otherwise | [Connect prerequisites](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-prerequisites) |
| The Connect server must be treated as **Tier 0 / control plane** | Same page |
| .NET Framework 4.7.2 and TLS 1.2 (TLS 1.2 is mandatory since Connect 2.0) | Same page (the page also lists 4.6.2 elsewhere; the project uses 4.8) |
| Windows Server 2025 or 2022 recommended | Same page |
| Schema and forest functional level Windows Server 2003 or later; writable DC | Same page |
| The AD DS connector account cannot be an Enterprise or Domain Admin (since 1.4.x) | [Accounts and permissions](https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions) |

## 2. Target configuration (to confirm in Phase 2)

| Setting | Proposed value | Rationale |
|---|---|---|
| Server | SYNC01, domain-joined member server, vTPM if available | Tier 0 isolation; key protection |
| Version | Latest available, ≥ 2.6.84.0, installer from the Entra admin center | Mandatory |
| Entra authentication | **Application identity, "managed by Microsoft Entra Connect"** (default): Connect creates the application, issues a certificate (90-day default lifetime) and rotates it automatically | Microsoft-recommended default; no secrets for us to manage |
| Install mode | **Custom** installation | Control of accounts, OU filtering and features |
| Sign-in method | Password Hash Sync (PHS) | Realistic hybrid scenarios; required for some ID Protection signals (P2) |
| OU filtering | Only the lab OU(s) | Never sync on-premises admins or Tier 0 accounts |
| AD DS connector account | Pre-created dedicated account; permissions set with the `ADSyncConfig` module shipped with Connect **(verify cmdlet names)** | Known SID for the DCSync allow-list |
| Sync service account | Virtual Service Account (default for custom installs on a member server) | Supported default |
| Optional writeback features | Off unless a scenario needs them | Smaller attack surface |
| Hardening | Disable **hard-match takeover**; downgrade the Hybrid Identity Administrator role after setup (Microsoft recommends lowering it rather than deleting the account) | Microsoft recommendations |

## 3. Identities and secrets

| Identity | Where | Privilege | Security note |
|---|---|---|---|
| AD DS connector account | On-premises AD | With PHS: *Replicating Directory Changes* + *Replicating Directory Changes All* | **Has DCSync rights by design.** Allow-listed by SID and only from SYNC01's IPs ([DCSync design](dcsync-detection-design.md)) |
| ADSync service account (VSA) | SYNC01 | Runs the sync engine | SYNC01 is Tier 0 |
| **Entra Connect application** | Entra ID (single-tenant application + service principal) | Directory synchronisation | Authenticates with a certificate. Private key in the `CURRENT_USER` store, protected by the TPM when available, otherwise by the software key storage provider as non-exportable |

**Certificates and private keys are never stored in Git.** `.gitignore` blocks `*.pfx`,
`*.p12`, `*.pem`, `*.key`, `*.cer` and `*.crt`; gitleaks rules detect PEM key blocks and
base64 PKCS#12 blobs. The BYOC/BYOA options (owner-managed certificate or application) are not
used unless a later ADR decides otherwise.

## 4. Configuration as code: what is realistically possible

| Concern | Mechanism | Repository artefact |
|---|---|---|
| Prerequisite checks (OS, .NET, TLS, TPM) | Read-only PowerShell | [`Test-HdvHybridPrerequisites.ps1`](../lab/powershell/hybrid-identity/Test-HdvHybridPrerequisites.ps1) (implemented, not run) |
| Connector account + delegated permissions | `ADSyncConfig` PowerShell module, with `-WhatIf` | [`Set-HdvConnectorAccountPermissions.ps1`](../lab/powershell/hybrid-identity/Set-HdvConnectorAccountPermissions.ps1) (implemented, not run) |
| Installation | Wizard, following a step-by-step runbook | [`docs/runbooks/entra-connect-install.md`](runbooks/entra-connect-install.md) |
| OU filtering, validation, hardening | Wizard for OU filtering (no supported cmdlet); read-only validation scripts; Graph for the hard-match block | [Module 2.1 package](../lab/powershell/hybrid-identity/README.md) |
| Settings export / import | Connect automatically exports `Applied-SynchronizationPolicy-*.json` to `%ProgramData%\AADConnect` whenever the wizard changes the configuration. Import is offered during a new installation; Microsoft states the exported JSON **must not be edited** for import, and an imported server starts in **staging mode** | Raw exports kept in a **protected location outside Git**. Only a reviewed, human-written change summary is committed |
| Older servers | `MigrateSettings.ps1` (Connect `Tools` directory) exports `Exported-ServerConfiguration-*` | Outside Git |

## 5. Telemetry from the hybrid identity layer

| Source | Table | What it shows | Licensing |
|---|---|---|---|
| SYNC01 Application log (ADSync) | `WindowsEvent` (WEF) or `Event` (direct AMA) | Sync cycles, errors, configuration changes | none |
| SYNC01 Security log | `WindowsEvent` or `SecurityEvent` | Logons to the Tier 0 server, process creation | none |
| DC01 4662 + 4624 | `WindowsEvent` or `SecurityEvent` | Replication requests and their source | none |
| Entra AuditLogs | `AuditLogs` | Objects changed by sync; credential changes on the Connect application | **Gate LIC-001** |
| Connect application sign-ins | `AADServicePrincipalSignInLogs` | Where the sync identity authenticates from | **Gate LIC-003** |

## 6. Hybrid detection candidates

| Planned ID | Logic | Telemetry |
|---|---|---|
| DET-HYB-001 | The Entra Connect application's service principal signs in from an IP that is not the lab egress IP (FW01 public address) | `AADServicePrincipalSignInLogs` (LIC-003) |
| DET-HYB-002 | A credential (certificate or secret) is added to the Entra Connect application by any actor other than Connect's own rotation | `AuditLogs` (LIC-001) |
| DET-AD-001 | Replication rights used by a non-DC principal, or by the connector account from a non-SYNC01 source | 4662 + 4624 |
| (hunting) | Interactive logons to SYNC01 by accounts outside the Tier 0 admin group | 4624 on SYNC01 |

The legacy design (sign-ins of the `Sync_*` user in `SigninLogs`) is **obsolete**: that account
type is being retired with legacy authentication.

## 7. Alternative: Microsoft Entra Cloud Sync (not selected)

| Aspect | Connect Sync (selected) | Cloud Sync (alternative) |
|---|---|---|
| On-premises footprint | Full sync engine + SQL LocalDB | Lightweight provisioning agent(s) |
| Configuration | Wizard + sync rules on the server | Cloud-managed (admin center / Graph) |
| High availability | Active + staging server | Multiple active agents |
| Configuration as code | Limited (export/import JSON) | Better (Graph-based) **(verify)** |
| Feature coverage | Broadest | Common scenarios; some gaps **(verify the current matrix)** |
| Logs | ADSync events on the server; AuditLogs; application sign-ins | `AADProvisioningLogs` (gate LIC-005) + AuditLogs |
| Detection-engineering value | Rich on-premises Tier 0 surface | Different, smaller surface |

**Why not switched:** the owner selected Connect Sync. A migration to Cloud Sync would require a
superseding ADR.
