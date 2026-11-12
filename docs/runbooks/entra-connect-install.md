# Runbook: Microsoft Entra Connect Sync installation (Module 2.1)

> Operator runbook. **Not executed yet.** Steps marked 🖥️ are performed by the owner in the lab.
> Scripts are in [`lab/powershell/hybrid-identity/`](../../lab/powershell/hybrid-identity/).
> Wizard labels follow Microsoft's documentation and may differ slightly between releases.

## 0. Preconditions

- [ ] G-NET: isolation checks I1–I5 PASS ([lab-network.md](../lab-network.md#4-isolation-readiness-checks-gate-g-net)).
- [ ] Snapshots of DC01, SYNC01 and MGMT taken (one consistent set).
- [ ] Lab state CLEAN; dedicated lab tenant confirmed (not a university or employer tenant).
- [ ] `hybrid-identity.config.local.psd1` filled in (outside Git), including the lab identity values
      (`ExpectedDnsRoot`, `ExpectedDomainSid`, `DomainDN`, `TenantId`, `ExpectedInitialDomain`) read from the lab.
      The scripts cannot detect production values entered here: the guards only compare the live
      environment with this file ([warning](../../lab/powershell/hybrid-identity/README.md#3-execution-instructions-exact-order)).

## 1. Prerequisites (SYNC01)

🖥️ `Test-HdvHybridPrerequisites.ps1`: resolve every FAIL manually before continuing.

## 2. Lab OUs and canaries (DC01 or MGMT)

🖥️ `New-HdvHybridLabObjects.ps1 -CreateCanaryObjects -WhatIf`, then with `-Apply -JournalPath <outside the repository>`
(type the lab domain DNS name when asked).
Write down the **synced OU DNs** it prints: they are the only OUs you select in step 5.
🖥️ `Test-HdvSyncScope.ps1` must PASS before anything is synchronised.

## 3. Obtain and start the installer (SYNC01)

1. Download the MSI **only** from the Microsoft Entra admin center (Microsoft: the Connect Sync
   .msi is exclusively available there).
2. Verify the signature and the version before running it:

   ```powershell
   Get-AuthenticodeSignature .\AzureADConnect.msi | Format-List Status, SignerCertificate
   ```

   Expect `Status: Valid` and a Microsoft signer. Version must be **≥ 2.6.84.0**.
3. Run the MSI and **stop at the Welcome page**. The ADSyncConfig module is now on disk.

## 4. Connector account (SYNC01, Enterprise Admin)

🖥️ `Set-HdvConnectorAccountPermissions.ps1 -WhatIf`, then with `-Apply -JournalPath <outside the repository>`
(type the lab domain DNS name). For the MVP it refuses the **whole** operation (zero changes) in any
forest that contains more than the lab domain, with or without Password Hash Sync.
Record the printed **SID**; it goes into the `HDV_EntraConnect` watchlist.

## 5. Wizard choices

| Page | Choice | Reason |
|---|---|---|
| Express settings | **Customize** | Express creates an `MSOL_` account with broad permissions and syncs the whole forest |
| Install required components | No custom SQL, no custom service account (default virtual service account), **do not import settings** | Clean, supported defaults |
| User sign-in | **Password Hash Synchronization**; Single sign-on off | ADR-0003 / hybrid-identity.md |
| Connect to Microsoft Entra ID | Cloud-only Hybrid Identity Administrator with MFA | Microsoft requirement |
| Connect your directories | **Use existing AD account** → the connector account from step 4 | Least privilege; known SID |
| Microsoft Entra sign-in configuration | Review UPN suffixes; a non-routable suffix syncs as `@<tenant>.onmicrosoft.com` | Discovery item D4 |
| Domain and OU filtering | **Sync selected domains and OUs** → select **only** the synced OU DNs from step 2 | Never synchronise Tier 0 or the connector account |
| Uniquely identifying your users | Defaults; source anchor ms-DS-ConsistencyGuid ("let Azure manage") | Requires the ConsistencyGuid permission granted in step 4 |
| Filter users and devices | Synchronize all users and devices (scope is set by the OUs) | Group filtering is a pilot feature |
| Optional features | **None** (no password, group or device writeback) | Smaller attack surface |
| Ready to configure | ✅ **Enable staging mode**; leave synchronisation start enabled | Imports and syncs, but exports nothing until verified |

## 6. Verify application-based authentication (SYNC01)

```powershell
Get-ADSyncEntraConnectorCredential
```

Expect `ConnectorIdentityType` = `Application`. If it shows `ServiceAccount`, use
*Additional tasks → Configure application-based authentication to Microsoft Entra ID* in the
wizard (Microsoft's documented switch). Copy the application (client) ID into
`EntraConnect.ApplicationId` in the local config.

## 7. Validate in staging mode (SYNC01)

🖥️ `Test-HdvSyncScope.ps1 -IncludeConnectConfiguration` and `Test-HdvEntraConnectConfiguration.ps1`
(with `ExpectStagingMode = $true`). In the Synchronization Service Manager, confirm that the
pending exports contain only the canary objects and other intended lab objects.
🖥️ `Export-HdvEntraConnectWatchlist.ps1 -OutputPath <outside the repository>`.

## 8. Go live and harden

1. Wizard → *Configure staging mode* → **disable** staging mode. Set `ExpectStagingMode = $false`.
2. 🖥️ Re-run `Test-HdvEntraConnectConfiguration.ps1`.
3. 🖥️ (MGMT) `Set-HdvHardMatchTakeoverBlock.ps1 -VerifyOnly`, then `-Apply` (type the lab tenant initial domain;
   grant admin consent for `Organization.Read.All` when prompted).
4. 🖥️ (MGMT) `Test-HdvEntraSyncState.ps1`: canary user and group present, connector account absent.
5. Entra admin center: change the Hybrid Identity Administrator assignment used for setup to a
   lower-privileged role (Microsoft recommends lowering it rather than deleting the account).
6. Copy the latest `%ProgramData%\AADConnect\Applied-SynchronizationPolicy-*.json` to a protected
   location **outside Git** (needed for a future rebuild; must not be edited).
7. Record the outcome in the lab-state history.

## 9. If something goes wrong

Enable staging mode first (stops all exports), then follow
[hybrid-identity-rollback.md](hybrid-identity-rollback.md). A run that printed `PARTIAL EXECUTION`
is recovered with §7 of that runbook.
