# DCSync Detection Design (planned DET-AD-001)

> **Status:** design only. No query below has been executed against a workspace. Column names,
> XPath filters and event field formats are marked **(verify)** and must be confirmed in
> Phase 2 against real events from DC01 before the rule is written in Phase 3.

## 1. Why event 4662 alone is not enough

Event **4662** ("An operation was performed on an object") records **who** used replication
rights (`SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`) but **not from where**: it has no
source IP or workstation. The source is only available on the logon event **4624** that opened
the session. Both events are logged **on the same DC**, and logon IDs are only unique per
machine. The join key is therefore **(Computer, LogonId)**:

```
4662.Computer == 4624.Computer  AND  4662.SubjectLogonId == 4624.TargetLogonId
```

The 4624 can precede the 4662 by hours: replication clients such as the Entra Connect sync
engine reuse long-lived sessions. The logon lookback must be much longer than the replication
window, or the source is "unresolved".

## 2. Required telemetry on every domain controller

### Advanced Audit Policy (dedicated GPO linked to the Domain Controllers OU)

| Subcategory | Setting | Event | Note |
|---|---|---|---|
| DS Access → Audit Directory Service Access | Success | 4662 | Only produces events for objects whose SACL matches |
| Logon/Logoff → Audit Logon | Success | 4624 | Source attribution (LogonType 3 = network) |
| Security Options → "Audit: Force audit policy subcategory settings … to override audit policy category settings" | Enabled | — | Otherwise legacy category settings can silently win |

### SACL on the domain root object (for example `DC=lab,DC=example`)

| Principal | Type | Applies to | Permissions (extended rights) |
|---|---|---|---|
| Everyone | Success | This object only | Replicating Directory Changes; Replicating Directory Changes All; Replicating Directory Changes In Filtered Set |

**Do not overwrite existing configuration.** First read the current SACL and audit policy (read-only):

```powershell
(Get-Acl -Path ("AD:\" + (Get-ADDomain).DistinguishedName) -Audit).Audit | Format-Table IdentityReference, AuditFlags, ActiveDirectoryRights, ObjectType, InheritanceType
```

```powershell
auditpol /get /category:"DS Access","Logon/Logoff"
```

Phase 2 then **adds** the missing audit entries without replacing the ones already there.

### Well-known identifiers used by the detection

| Identifier | Meaning |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All (needed to read secrets) |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |
| `19195a5b-6da0-11d0-afd3-00c04fd930c9` | `domainDNS` object class (4662 `ObjectType`) |

## 3. Collection filters (DCR XPath) and their volume impact

Collect only what the detection needs (validate each XPath on DC01 first with
`Get-WinEvent -LogName Security -FilterXPath '<xpath>' -MaxEvents 5`):

```text
Security!*[System[(EventID=4662)] and EventData[Data[@Name='ObjectType']='%{19195a5b-6da0-11d0-afd3-00c04fd930c9}']]
Security!*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='3']]
```

The exact `ObjectType` value format in the event XML is **(verify)**. 4624 is the largest DC
stream this design adds. It was previously planned as "filter out" and is now required, but
only for LogonType 3. The cost impact is recalculated in [cost-and-licensing.md](cost-and-licensing.md#2-volume-model).

## 4. Tuning model: legitimate replication

Legitimate replicating principals are kept in two **watchlists** maintained from read-only
discovery output. They are never hard-coded in KQL:

| Watchlist | Content | Source |
|---|---|---|
| `HDV_DomainControllers` | SIDs of all DC computer accounts (members of *Domain Controllers*, RID 516; RODCs, RID 521, if any) and their IP addresses | `Get-ADDomainController -Filter *` |
| `HDV_EntraConnect` | SID of the Entra Connect **AD DS connector account** (`MSOL_*` for express installs, or the custom account) and the IP addresses of SYNC01 | Entra Connect configuration + `Get-ADUser` |

Classification of each replication request (4662 with replication GUIDs on `domainDNS`):

| # | Condition | Classification | Severity |
|---|---|---|---|
| 1 | Subject SID in `HDV_DomainControllers` | DC-to-DC replication | not alerted |
| 2 | Subject = connector SID **and** source IP ∈ SYNC01 IPs | Expected Password Hash Sync | not alerted |
| 3 | Subject = connector SID **and** source IP ∉ SYNC01 IPs | Connector credential used elsewhere | **High** |
| 4 | Subject = connector SID **and** source unresolved (no 4624 in lookback) | Unattributed connector replication | **Medium**; may also indicate a telemetry gap |
| 5 | Any other subject requesting Get-Changes-All or In-Filtered-Set | DCSync | **High** |
| 6 | Any other subject requesting Get-Changes only | Unusual replication (no secrets) | Low / hunting |

Excluding *all* computer accounts (`$` names) is explicitly **not** allowed: an attacker can
grant replication rights to a computer account they control. Only the DC SIDs are excluded.

## 5. Query sketch (NOT executed; column names to verify)

```kql
let ReplicationGuids = dynamic(["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"]);
let SecretGuids = dynamic(["1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"]);
let DcSids = _GetWatchlist("HDV_DomainControllers") | project Sid = tostring(SearchKey);
let Connect = _GetWatchlist("HDV_EntraConnect") | project ConnectorSid = tostring(SearchKey), SyncIps = todynamic(SyncIps);
let Replication = SecurityEvent
    | where TimeGenerated > ago(20m)                       // replication window (overlaps frequency for ingestion delay)
    | where EventID == 4662 and AccessMask == "0x100"
    | where ObjectType has "19195a5b-6da0-11d0-afd3-00c04fd930c9"
    | where Properties has_any (ReplicationGuids)
    | where SubjectUserSid !in (DcSids)
    | extend RequestsSecrets = Properties has_any (SecretGuids)
    | project ReplicationTime = TimeGenerated, Computer, SubjectUserSid, SubjectUserName, SubjectLogonId, RequestsSecrets;
let Logons = SecurityEvent
    | where TimeGenerated > ago(1d)                        // logon lookback; requires query_period >= P1D
    | where EventID == 4624 and LogonType == 3
    | project Computer, TargetLogonId, IpAddress;
Replication
| join kind=leftouter Logons on Computer, $left.SubjectLogonId == $right.TargetLogonId
| join kind=leftouter Connect on $left.SubjectUserSid == $right.ConnectorSid
| extend Source = iff(isempty(IpAddress), "unresolved", IpAddress)
| extend Classification = case(
    isnotempty(ConnectorSid) and set_has_element(SyncIps, IpAddress), "expected_connector",
    isnotempty(ConnectorSid) and Source == "unresolved", "connector_unattributed",
    isnotempty(ConnectorSid), "connector_unexpected_source",
    RequestsSecrets, "dcsync",
    "replication_without_secrets")
| where Classification != "expected_connector"
```

Rule parameters implied by the sketch: `query_frequency: PT10M`, `query_period: P1D` (so the
4624 lookback is in scope), suppression or grouping to absorb the overlap. With the WEF fallback
([ADR-0011](adr/0011-tier0-arc-isolation-wef-fallback.md)) the same events arrive in
`WindowsEvent` with a different shape, so a normalising KQL function is needed (Phase 3).

## 6. Validation

- **Positive scenario:** a dedicated lab account temporarily granted replication rights performs
  a DCSync-style replication request from WS01. Rights are removed in cleanup; the sweep removes
  any `HDV-` ACEs. Requires manual approval (high impact).
- **Negative scenario (`no_alert`):** a normal Entra Connect sync cycle from SYNC01 must not alert.
- **Unattributed path:** covered by restarting the log stream so that 4624 is outside the
  window. Expected classification `connector_unattributed`, not "expected".
