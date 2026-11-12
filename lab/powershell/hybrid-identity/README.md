# Deliverable A: Module 2.1 Hybrid Identity (Entra Connect Sync)

> **Status:** implemented and unit-tested against **mocked** environments only. **Nothing has
> been executed in the lab or against the tenant.** Every change requires the owner to run the
> script, first with `-WhatIf` (or `-VerifyOnly`), then with **`-Apply` plus a typed confirmation**
> of the exact lab domain (or lab tenant initial domain).

Implements [ADR-0003](../../../docs/adr/0003-entra-connect-sync-dedicated-member-server.md) and
[docs/hybrid-identity.md](../../../docs/hybrid-identity.md): Entra Connect Sync ≥ 2.6.84.0 with
application-based authentication on SYNC01, OU filtering limited to the lab OUs, a dedicated
least-privilege connector account, and validation from both the server and the Entra side.

## 1. Files

| File | Runs on | Changes anything? | Purpose |
|---|---|---|---|
| [`config/hybrid-identity.config.example.psd1`](config/hybrid-identity.config.example.psd1) | — | — | Template. Copy to `hybrid-identity.config.local.psd1` (git-ignored) |
| [`../common/HdvLab.psm1`](../common/HdvLab.psm1) | all | no | Shared helpers: results, exit codes, config, OU layout, git-tree guard |
| [`Test-HdvHybridPrerequisites.ps1`](Test-HdvHybridPrerequisites.ps1) | SYNC01 | **no** | P1–P10 prerequisite checks |
| [`New-HdvHybridLabObjects.ps1`](New-HdvHybridLabObjects.ps1) | DC01 / MGMT (RSAT) | **yes** (creates only) | Lab OUs + disabled canary user + empty canary group |
| [`Set-HdvConnectorAccountPermissions.ps1`](Set-HdvConnectorAccountPermissions.ps1) | SYNC01 | **yes** | Connector account + ADSyncConfig least-privilege permissions |
| [`Test-HdvSyncScope.ps1`](Test-HdvSyncScope.ps1) | SYNC01 (or MGMT for AD-only checks) | **no** | No privileged objects in scope; Connect OU filter matches config |
| [`Test-HdvEntraConnectConfiguration.ps1`](Test-HdvEntraConnectConfiguration.ps1) | SYNC01 | **no** | C1–C11 post-install validation |
| [`Export-HdvEntraConnectWatchlist.ps1`](Export-HdvEntraConnectWatchlist.ps1) | SYNC01 | local CSV only | Values for the `HDV_EntraConnect` watchlist |
| [`Set-HdvHardMatchTakeoverBlock.ps1`](Set-HdvHardMatchTakeoverBlock.ps1) | MGMT (Graph) | **yes** (tenant setting) | Block hard-match takeover |
| [`Test-HdvEntraSyncState.ps1`](Test-HdvEntraSyncState.ps1) | MGMT (Graph) | **no** | E1–E7 validation from the Entra side |
| [`../../../docs/runbooks/entra-connect-install.md`](../../../docs/runbooks/entra-connect-install.md) | — | — | Step-by-step installation runbook (wizard choices) |
| [`../../../docs/runbooks/hybrid-identity-rollback.md`](../../../docs/runbooks/hybrid-identity-rollback.md) | — | — | Rollback, partial-execution recovery, inheritance restoration |
| [`../../../queries/verification/hybrid-identity/`](../../../queries/verification/hybrid-identity/) | Log Analytics | no | KQL verification queries HYB-V01…V06 |
| `tests/test_hybrid_identity.py`, `tests/test_verification_queries.py` | CI | no | Mocked tests and static query checks |

**No Terraform in Module 2.1.** Entra Connect creates and rotates its own application and
certificate, OU filtering is configured in the wizard, and nothing in this module is an Azure
resource. The `HDV_EntraConnect` watchlist is deployed with the workspace (Deliverable C/D).

## 2. Dependencies

| Dependency | Where | Who provides it |
|---|---|---|
| Gates G-NET (isolation checks I1–I5) and G-CLEAN (lab state) passed | lab | Owner |
| SYNC01: domain-joined Windows Server member (2022/2025), not a DC | lab | Owner |
| RSAT ActiveDirectory module on SYNC01 and on the host running `New-HdvHybridLabObjects.ps1` | lab | Owner installs (`Install-WindowsFeature RSAT-AD-PowerShell`); scripts never install |
| Entra Connect MSI ≥ 2.6.84.0, downloaded **only** from the Entra admin center | SYNC01 | Owner |
| Microsoft Graph PowerShell SDK modules (`Microsoft.Graph.Authentication`, `.Identity.DirectoryManagement`, `.Users`, `.Groups`, `.Applications`) | MGMT | Owner installs; scripts never install |
| `hybrid-identity.config.local.psd1` filled in | each host | Owner |
| Hybrid Identity Administrator account (cloud-only, with MFA) for the wizard | tenant | Owner |

## 3. Execution instructions (exact order)

Copy the configuration once and fill in the `<REQUIRED…>` values. Obtain the identity values
**read-only, from a lab machine** (never type them from memory): `(Get-ADDomain).DNSRoot`,
`(Get-ADDomain).DomainSID.Value` and `(Get-ADDomain).DistinguishedName`; the tenant ID and the
`<name>.onmicrosoft.com` initial domain from the Entra admin center. Scripts refuse the committed
template and any remaining placeholder.

```powershell
Copy-Item .\config\hybrid-identity.config.example.psd1 .\config\hybrid-identity.config.local.psd1
```

| Step | Host / account | Command | Expected exit code |
|---|---|---|---|
| 1 | SYNC01, local admin, elevated | `.\Test-HdvHybridPrerequisites.ps1` | 0, or 2 with WARN only (review each) |
| 2a | DC01 or MGMT (lab domain member), Domain Admin | `.\New-HdvHybridLabObjects.ps1 -ConfigPath <cfg> -CreateCanaryObjects -WhatIf` | 0 (only WOULD-CREATE / EXISTS lines) |
| 2b | same | same command with `-Apply -JournalPath <path outside the repository>` instead of `-WhatIf`; type the lab domain name when asked | 0 (3 = partial: see the rollback runbook §7) |
| 2c | same | `.\Test-HdvSyncScope.ps1 -ConfigPath <cfg>` | 0 |
| 3 | SYNC01 | Run the Entra Connect MSI, **stop at the Welcome page** ([runbook §3](../../../docs/runbooks/entra-connect-install.md)) | — |
| 4a | SYNC01, Enterprise Admin (or Domain Admin, single-domain forest), elevated | `.\Set-HdvConnectorAccountPermissions.ps1 -ConfigPath <cfg> -WhatIf` | 0 |
| 4b | same | same with `-Apply -JournalPath <path outside the repository>` instead of `-WhatIf`; type the lab domain name; enter the new account password (≥ 24 characters, store it in your password manager) and the admin credential | 0 (3 = partial) |
| 5 | SYNC01 | Complete the wizard **in staging mode** with the choices in [runbook §5](../../../docs/runbooks/entra-connect-install.md) | — |
| 6 | SYNC01 | `Get-ADSyncEntraConnectorCredential`; copy the application ID into `EntraConnect.ApplicationId` in the local config | — |
| 7 | SYNC01, elevated | `.\Test-HdvSyncScope.ps1 -ConfigPath <cfg> -IncludeConnectConfiguration` then `.\Test-HdvEntraConnectConfiguration.ps1 -ConfigPath <cfg>` | 0 (C9 may be MANUAL before the first cycle) |
| 8 | SYNC01 | `.\Export-HdvEntraConnectWatchlist.ps1 -ConfigPath <cfg> -OutputPath <path outside the repository>` | CSV written |
| 9 | SYNC01 | Leave staging mode in the wizard; set `ExpectStagingMode = $false`; re-run step 7 | 0 |
| 10a | MGMT, Global Administrator (delegated) | `.\Set-HdvHardMatchTakeoverBlock.ps1 -ConfigPath <cfg> -VerifyOnly` | 1 if not yet blocked |
| 10b | same | `.\Set-HdvHardMatchTakeoverBlock.ps1 -ConfigPath <cfg> -Apply -JournalPath <path>`; type the lab tenant initial domain | 0 |
| 11 | MGMT, reader (delegated) | `.\Test-HdvEntraSyncState.ps1 -ConfigPath <cfg>` | 0 |
| 12 | Entra admin center | Downgrade the Hybrid Identity Administrator role used for setup ([runbook §8](../../../docs/runbooks/entra-connect-install.md)) | — |

### Fail-closed safeguards (all modifying scripts)

| Safeguard | `New-HdvHybridLabObjects` | `Set-HdvConnectorAccountPermissions` | `Set-HdvHardMatchTakeoverBlock` |
|---|---|---|---|
| Explicit `*.local.psd1` config; template and placeholders refused | ✅ | ✅ | ✅ |
| Live identity = lab values | AD DNS name + domain SID + DN | AD DNS name + domain SID + DN | tenant ID + initial `onmicrosoft.com` domain |
| Strict single-domain forest (MVP; enforced with or without Password Hash Sync, also for `-WhatIf`) | — | ✅ (before any change, never relaxable by configuration) | — |
| Lab-namespace names, LDAP filter escaping | ✅ canary names | ✅ connector name | — |
| No change without `-Apply` | ✅ | ✅ | ✅ (`-VerifyOnly` / `-WhatIf` / `-Apply`, exactly one) |
| Typed confirmation: interactive `Read-Host` only, compared with the **live verified** identity; no parameter, configuration key, `-Confirm:$false`, `-NonInteractive` or piped input can supply it | lab DNS domain | lab DNS domain | lab initial domain (read from the signed-in tenant) |
| Per-change confirmation prompt (ConfirmImpact High) | ✅ | ✅ | ✅ |
| All checks before the first change | ✅ | ✅ | ✅ (before connecting) |
| Journal: STARTED → DONE / FAILED; PARTIAL summary; exit 3 | ✅ | ✅ | ✅ |
| Existing objects never modified | ✅ (collisions refused) | ✅ (unsafe accounts refused) | n/a |

Exit codes of modifying scripts: **0** completed or preview, **1** refused (nothing changed),
**3** partial ([rollback runbook §7](../../../docs/runbooks/hybrid-identity-rollback.md#7-partial-execution-recovery)).
Read-only scripts: **0** all PASS, **1** any FAIL, **2** only WARN/MANUAL.

> [!WARNING]
> **The identity guard cannot tell a lab from production if production's identity is put in the lab config.**
> It only checks that the live environment **matches the configuration file**. If someone deliberately
> (or by copy-paste mistake) enters a **production** domain's DNS name, SID and DN, or a production
> tenant's ID and initial domain, into `hybrid-identity.config.local.psd1`, every check passes
> **in that production environment**. The typed confirmation does not help either: it asks for
> the same verified identity, so the operator would just type the production name.
> Nothing in the scripts can detect this: there is no reliable, universal "this is a lab" signal in AD DS
> or Entra ID. The guards prevent **accidents** (wrong machine, wrong network, wrong tenant, stale or
> template config). They are **not** an access control against a privileged operator who
> supplies production values. The real controls are outside the scripts:
> - Run them only on the isolated lab VMs (gate G-NET).
> - Use a dedicated lab tenant and lab-only accounts.
> - Never hold production credentials on lab machines.
> - Obtain the config values read-only, **from inside the lab**, as described in §2.

## 4. Required permissions

| Script | Permission | Why |
|---|---|---|
| `Test-HdvHybridPrerequisites.ps1` | Local administrator on SYNC01 (for `Get-Tpm`) | Read-only checks |
| `New-HdvHybridLabObjects.ps1` | Create OUs at the domain root; create users and groups in the lab OUs (Domain Admins) | Creates OUs and canaries |
| `Set-HdvConnectorAccountPermissions.ps1` | Enterprise Admin (forest root), or Domain Admin in a single-domain forest | Microsoft: the ADSyncConfig cmdlets write ACLs at the domain root |
| Entra Connect wizard | Hybrid Identity Administrator (Entra); local admin on SYNC01 | Microsoft requirement; downgrade the Entra role afterwards |
| `Test-HdvEntraConnectConfiguration.ps1`, `Export-HdvEntraConnectWatchlist.ps1` | Local administrator on SYNC01 (ADSync administrators) | Read ADSync configuration |
| `Set-HdvHardMatchTakeoverBlock.ps1` | Delegated `OnPremDirectorySynchronization.ReadWrite.All` with `-Apply` (`.Read.All` otherwise) **plus `Organization.Read.All`** to read the tenant's initial domain. Microsoft documents **admin consent as required** for `Organization.Read.All`; the signed-in Global Administrator of the lab tenant must grant it for Microsoft Graph PowerShell | Documented scopes for the setting; second tenant identifier |
| `Test-HdvEntraSyncState.ps1` | Delegated `Organization.Read.All` (admin consent), `User.Read.All`, `Group.Read.All`, `Application.Read.All`, `OnPremDirectorySynchronization.Read.All` | Read only; also verifies tenant ID + initial domain |

No permanent credentials are stored anywhere. The connector password lives only in the
owner's password manager and in Connect's encrypted configuration. Graph sign-ins are
interactive and end with `Disconnect-MgGraph`.

## 5. Validation commands and expected output

| Command | Expected |
|---|---|
| `Test-HdvHybridPrerequisites.ps1` | P1–P10 PASS. WARN acceptable only for P4 values not explicitly set on Windows Server 2022/2025, or P8 without vTPM (residual risk recorded) |
| `Test-HdvSyncScope.ps1 -IncludeConnectConfiguration` | S1–S3 PASS; S4 PASS, or MANUAL with the Synchronization Service Manager steps |
| `Test-HdvEntraConnectConfiguration.ps1` | C2 `2.6.x >= 2.6.84.0`; C4 `ConnectorIdentityType=Application`; C5 staging state as configured; C6 the dedicated account; C7 `PasswordHashSync=True`; C8 no 1011/1012 |
| `Test-HdvEntraSyncState.ps1` | E2 sync enabled, last sync < `MaxSyncAgeMinutes`; E3 canary user synchronised and disabled; E4 canary group synchronised; E5 connector account absent; E6 block = True; E7 valid certificate, 0 client secrets |
| HYB-V01…V06 (after Modules 2.2–2.4) | See each query's `expected:` header |

Every check prints `Check / Target / Detail / Result` objects. Exit codes: **0** all PASS,
**1** any FAIL, **2** only WARN/MANUAL.

## 6. Rollback

Rollback is manual and deliberate. **No script deletes or rolls back anything.** Follow
[docs/runbooks/hybrid-identity-rollback.md](../../../docs/runbooks/hybrid-identity-rollback.md):

| Topic | Runbook section |
|---|---|
| Before any rollback (identity check, lab state DIRTY, staging mode) | §1 |
| Connector permissions on synced OUs (`dsacls /R`) | §2 |
| Domain replication permissions (DCSync-capable) | §3 |
| Connector account recovery (password reset, retirement) | §4 |
| OU and canary cleanup | §5 |
| Hard-match setting restoration | §6 |
| Partial execution recovery (journal, `-WhatIf`, idempotent re-run) | §7 |
| Inheritance restoration after `Set-ADSyncRestrictedPermissions`, and its security implications | §8 |

Take VM snapshots before step 2 and read [safety.md §4](../../../docs/safety.md#4-snapshot-restoration-risks) before restoring one.

## 7. Known limitations

- **Never run against a real system.** Tests mock every AD, ADSync, CIM, registry, event-log and
  Graph cmdlet. Real output shapes may differ.
- **Undocumented output properties** are read defensively and reported as MANUAL when absent:
  the Connect partition scope (S4), run-profile results (C9), and the property holding the
  application ID in `Get-ADSyncEntraConnectorCredential` (searched as any GUID-valued property).
- **Provider name** for events 1011/1012 is assumed to match `Directory Synchronization|ADSync|Entra|AAD`
  (Microsoft documents the IDs and the Application log, not the provider).
- **Microsoft documentation inconsistency:** the ADSyncConfig how-to mentions `-IncludeAdminSdHolders`,
  while the cmdlet reference lists `-SkipAdminSdHolders`. The scripts use neither: they pass
  `-ADobjectDN`, which applies permissions to that OU only.
- **OU filtering cannot be scripted:** Microsoft configures it in the wizard or the Synchronization
  Service Manager. The scripts verify it (S2, S4) but cannot set it.
- **Lab egress IP** (needed by planned DET-HYB-001) is not visible from inside the lab. With VMware
  NAT, it is the host's public IP, which may change (home ISP, university network).
- **E5** checks the connector account by display name (best effort).
- **The identity guard cannot distinguish production** if production's real identity (AD DNS name,
  SID and DN, or tenant ID and initial domain) is deliberately entered into the lab configuration:
  every check then passes against production (see the warning in §3). It also trusts
  `Get-ADDomain` and Microsoft Graph on the machine where the script runs.
- **Typed confirmation** needs an interactive console: `-Apply` cannot run from automation, CI, a
  scheduled task, `-NonInteractive` or a pipe. This is deliberate; `-WhatIf` and `-VerifyOnly` still work there.
- **Idempotency of ADSyncConfig re-runs** (identical ACEs merged rather than duplicated) is assumed, not verified.
- **Graph initial domain:** `verifiedDomains[isInitial]` is documented by Microsoft; its exact SDK object shape is
  mocked in tests and must be confirmed on the first `-VerifyOnly` run.
- **PSScriptAnalyzer** is not run (no verifiable pinned version yet); scripts are AST-parsed and behaviour-tested.
