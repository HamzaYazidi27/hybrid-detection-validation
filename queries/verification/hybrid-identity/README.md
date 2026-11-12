# Verification queries: Module 2.1 (hybrid identity)

KQL used to **verify** that Module 2.1 produces the expected telemetry. These are not detection
rules (those live in `detections/`).

> **Status:** none of these queries has been executed. The tables they read are created by
> Modules 2.2–2.4. Column names follow Microsoft's published table schemas; any mismatch found
> on the first run is fixed and recorded in the header (`status: executed <date>`).

| ID | Purpose | Table | Licensing gate |
|---|---|---|---|
| HYB-V01 | Connect application sign-ins by source IP | `AADServicePrincipalSignInLogs` | LIC-003 |
| HYB-V02 | Credential changes on the Connect application | `AuditLogs` | LIC-001 |
| HYB-V03 | Directory changes initiated by Connect | `AuditLogs` | LIC-001 |
| HYB-V04 | Connect health events (WEF path) | `WindowsEvent` | none |
| HYB-V05 | Connect health events (direct AMA path) | `Event` | none |
| HYB-V06 | Connector-account replication requests (WEF path) | `WindowsEvent` | none |

All lab-specific values (Connect application ID, sync server name, connector SID) come from the
`HDV_EntraConnect` watchlist produced by `Export-HdvEntraConnectWatchlist.ps1`. Nothing is
hard-coded. Every file starts with a machine-checked header (`tests/test_verification_queries.py`):
tables must exist in the licensing matrix, and licensing gates must match it.
