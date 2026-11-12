# Runbook: Module 2.1 rollback and recovery

> Operator runbook. **Not executed yet.** Nothing here is automated. HDV scripts never delete
> or roll back on their own, by design ([ADR-0013](../adr/0013-lab-state-cleanup-sweeper.md)).
> Run every command **only in the lab domain and lab tenant**, after confirming identity as in §1.
> Steps marked **(verify)** have not been checked against a real environment.

## 1. Before any rollback

1. Confirm you are in the lab, using the same values as the configuration file:

   ```powershell
   (Get-ADDomain) | Format-List DNSRoot, DomainSID, DistinguishedName
   ```

2. Mark the lab state **DIRTY** (reason: "rollback in progress").
3. If Entra Connect is installed: wizard → *Configure staging mode* → **enable**. This stops all
   exports to Entra ID while you work.
4. Keep the action journal (`-JournalPath`) of the run you are undoing. It lists every DONE
   change, in order. Undo in **reverse order**.

Placeholders used below: `<DOMAIN-DN>` (for example the configured `ActiveDirectory.DomainDN`),
`<NETBIOS>`, `<CONNECTOR>` (`svc-hdv-adsync`), `<CONNECTOR-DN>`, `<SYNCED-OU-DN>` (each synced OU).

## 2. Connector permissions rollback (synced OUs)

`Set-ADSyncBasicReadPermissions` and `Set-ADSyncMsDsConsistencyGuidPermissions` were applied
with `-ADobjectDN`, so they only touched the synced OUs. For **each** synced OU:

```powershell
dsacls "<SYNCED-OU-DN>" /R "<NETBIOS>\<CONNECTOR>"
```

`dsacls /R` removes all explicit permissions of that trustee on that object.

Verify that no ACE for the account remains:

```powershell
Show-ADSyncADObjectPermissions -ADobjectDN "<SYNCED-OU-DN>"
```

```powershell
(Get-Acl "AD:\<SYNCED-OU-DN>").Access | Where-Object { $_.IdentityReference -like "*\<CONNECTOR>" }
```

## 3. Domain replication permissions removal

`Set-ADSyncPasswordHashSyncPermissions` granted *Replicating Directory Changes* and
*Replicating Directory Changes All* at the domain root. That makes the account DCSync-capable.
In a single-domain forest (enforced by HDV) only one root is affected:

```powershell
dsacls "<DOMAIN-DN>" /R "<NETBIOS>\<CONNECTOR>"
```

Verify: no ACE of the account carries the replication extended rights
`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes) or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes-All):

```powershell
(Get-Acl "AD:\<DOMAIN-DN>").Access | Where-Object { $_.IdentityReference -like "*\<CONNECTOR>" } | Format-Table ActiveDirectoryRights, ObjectType
```

Removing these rights **stops Password Hash Sync** if Connect is still active (use staging mode
first, §1). `dsacls /R` on the domain root only removes that trustee's ACEs; it does not affect
other principals.

## 4. Connector account recovery

| Situation | Procedure |
|---|---|
| Password lost or must be rotated | As a Domain Admin: `Set-ADAccountPassword -Identity "<CONNECTOR-DN>" -Reset`. Then, as Microsoft documents: Synchronization Service Manager → **Connectors** → the AD connector → **Properties** → **Connect to Active Directory Forest** → new password → OK. Then restart the **Microsoft Entra ID Sync** service |
| Account must be taken out of service | `Disable-ADAccount -Identity "<CONNECTOR-DN>"` after §2–§3. Delete it only after Connect is uninstalled |
| Account was created but permission steps failed (partial run) | Do not reuse a half-configured account blindly: re-run the script with `-WhatIf` (§7). It reports the account as EXISTS and shows the remaining grants |
| `Set-HdvConnectorAccountPermissions.ps1` refuses the account (privileged or `adminCount=1`) | Create a **new** account. An account that was ever protected by AdminSDHolder keeps `adminCount=1` and a non-inheriting ACL |

## 5. OU and canary object cleanup

Delete objects in this order. Check each container is empty before removing it.

```powershell
Remove-ADUser  -Identity "CN=HDV Sync Canary,<first synced OU DN>"
```

```powershell
Remove-ADGroup -Identity "CN=HDV-Sync-Canary,<last synced OU DN>"
```

```powershell
Get-ADObject -SearchBase "<OU-DN>" -SearchScope OneLevel -Filter * | Select-Object DistinguishedName
```

```powershell
Set-ADOrganizationalUnit -Identity "<OU-DN>" -ProtectedFromAccidentalDeletion $false
```

```powershell
Remove-ADOrganizationalUnit -Identity "<OU-DN>"
```

Remove child OUs first, then `OU=HDV-Lab`. Never use `-Recursive`: an unexpected object inside
the lab OUs should be investigated, not deleted. Synchronised copies in Entra ID are deleted by the
next export only if Connect is active and out of staging mode. Otherwise they remain (§1).

## 6. Hard-match setting restoration

Leaving `BlockCloudObjectTakeoverThroughHardMatchEnabled = True` is recommended. To restore it
anyway (lab tenant only; scope `OnPremDirectorySynchronization.ReadWrite.All`):

```powershell
Connect-MgGraph -TenantId "<lab tenant ID>" -Scopes "OnPremDirectorySynchronization.ReadWrite.All", "Organization.Read.All"
```

```powershell
(Get-MgOrganization).VerifiedDomains | Where-Object IsInitial
```

```powershell
$sync = Get-MgDirectoryOnPremiseSynchronization; $sync.Features.BlockCloudObjectTakeoverThroughHardMatchEnabled = $false
```

```powershell
Update-MgDirectoryOnPremiseSynchronization -OnPremisesDirectorySynchronizationId $sync.Id -Features $sync.Features
```

```powershell
Disconnect-MgGraph
```

The first two commands confirm the tenant (same double check as the script). Do not continue
if the initial domain is not the lab's.

## 7. Partial execution recovery

A run that ends with **`PARTIAL EXECUTION`** (exit code 3) has made some changes and stopped at
the first failure. Nothing was rolled back automatically.

1. **Read the journal**: the console output, and the `-JournalPath` file if you used one. Every change
   is recorded as STARTED, then DONE or FAILED; the FAILED entry contains the error message. Entries never
   contain passwords or credentials.
2. **Fix the cause** reported in the FAILED entry (permissions, a missing OU, a typo in the config).
3. **Preview** with the same command and `-WhatIf`. Objects created earlier appear as EXISTS and
   are left unchanged. Remaining steps appear as WOULD.
4. **Re-run** with `-Apply` and the typed confirmation:
   - `New-HdvHybridLabObjects.ps1` is idempotent (create-only).
   - `Set-HdvConnectorAccountPermissions.ps1` skips the existing account and re-applies the
     ADSyncConfig grants. Re-applying an identical explicit ACE is normally merged by AD rather than
     duplicated **(verify on first run)**.
   - `Set-HdvHardMatchTakeoverBlock.ps1` skips the update if the value is already True.
5. **If you abandon instead**, undo each DONE entry in reverse order with §2–§6.
6. Record a manual recovery in the lab state (operator plus justification), then return it to CLEAN.

Never "half undo" by hand while also re-running the script: choose one path.

## 8. Inheritance restoration (`Set-ADSyncRestrictedPermissions`)

### What the cmdlet does (Microsoft documentation)

On the **connector account object only**, it:
- disables inheritance;
- removes all ACEs except those specific to SELF;
- adds explicit ACEs for SYSTEM, Enterprise Admins, Domain Admins and Administrators (Full Control),
  for Enterprise Domain Controllers (List Contents, Read All Properties, Read Permissions) and for
  Authenticated Users (List Contents).

### Security implications

| Effect | Implication |
|---|---|
| Inherited permissions removed | OU-level delegations (for example a help desk allowed to reset passwords in `OU=Tier0`) **no longer apply**, so they can't take over the DCSync-capable account. This is the purpose of the cmdlet |
| Inheritance disabled | **Future** OU-level hardening or delegations also stop applying to this object. Review it explicitly after every OU permission change |
| Explicit ACL | Anyone with *Modify permissions* on the object (Domain/Enterprise Admins, Administrators) still controls it. The account stays Tier 0 |
| Auditing | Whether the cmdlet also stops **SACL** (audit) inheritance is not documented **(verify)**. Check `(Get-Acl "AD:\<CONNECTOR-DN>" -Audit).AreAuditRulesProtected`; if true, add an explicit audit entry so that changes to the account (event 5136) are still logged |

### Restoration procedure (verify on a lab snapshot first)

1. Reset the DACL to the schema default for the user class:

   ```powershell
   dsacls "<CONNECTOR-DN>" /S
   ```

2. Re-enable inheritance (mark the object as not protected):

   ```powershell
   dsacls "<CONNECTOR-DN>" /P:N
   ```

3. Verify:

   ```powershell
   (Get-Acl "AD:\<CONNECTOR-DN>").AreAccessRulesProtected
   ```

   Expected: `False`. Then review `(Get-Acl "AD:\<CONNECTOR-DN>").Access` for inherited entries.

The GUI equivalent is Active Directory Users and Computers → *Advanced Features* → account →
Security → Advanced → **Enable inheritance**.

Restoring inheritance **re-opens** every inherited delegation path to the account. Do it only
when the account is being retired (after §2–§4), never while it still holds replication rights.
