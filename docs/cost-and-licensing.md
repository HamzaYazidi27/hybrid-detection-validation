# Cost Estimation and Licensing

> **Phase 0 cost: USD 0.** No Azure resource has been created.
> **Licensing** statements come from official Microsoft documentation sources recorded in
> [`tools/data/licensing-matrix.yml`](../tools/data/licensing-matrix.yml). Where sources
> conflict or are silent, the requirement is an **empirical gate**, not a conclusion.
> **Prices** were not retrieved from an official price list. Every price below is an
> unverified planning assumption; use the Azure Pricing Calculator before Phase 1.

## 1. Cost components

| Component | Billing model | Lab impact | Control |
|---|---|---|---|
| Azure Arc-enabled server connection | No charge for the connection itself; optional management services are billed per server | ≈ 0 | Do not enable optional services |
| Azure Monitor Agent | *"There's no cost to use the Azure Monitor Agent"*; ingestion is billed | 0 | — |
| Log Analytics ingestion (Analytics plan) | Per GB | **Main variable cost** | XPath filters, daily cap |
| Microsoft Sentinel | All data in a Sentinel-enabled workspace incurs Sentinel charges (in simplified pricing, billed together with Log Analytics) | Main variable cost | Same |
| Free tables | `AzureActivity`, `Heartbeat`, `Usage`, `Operation` are free to ingest (Azure Monitor). Sentinel billing also lists Azure Activity, Office 365 audit, Sentinel Health and security alerts as free **[search]**. **Raw Entra ID logs are paid** **[search]** | ≈ 0 | — |
| Retention | 31 days of analytics retention included in the ingestion price (Azure Monitor); 90 days when Sentinel is enabled **[search]** | ≈ 0 at default | Keep defaults |
| Entra ID P1/P2 | Per user per month, or trial | Depends on gates | Assign only where needed |
| VMware lab (incl. FW01, WEC01) | Local host | 0 cloud cost | — |
| GitHub Actions | Free for public repositories; included minutes for private ones | ≈ 0 | `timeout-minutes` on every job |

**[search]** = Microsoft Learn page seen only through search excerpts (learn.microsoft.com was
blocked in the build environment). Confirm directly before relying on it.

## 2. Volume model

Recalculated after the review: DCSync source attribution **requires** 4624 LogonType 3 on DCs.
Assumed average billed size: **1.5 KB per Windows event** (to be measured with `_BilledSize`).
`WindowsEvent` rows (WEF path) may be larger.

| Source | Events / day (assumption) | MB / day |
|---|---|---|
| DC01 4624 LogonType 3 | 2,000–30,000 | 3–45 |
| DC01 4662 on `domainDNS` (replication; PHS polls frequently) | 500–5,000 | 0.75–7.5 |
| DC01 4768 / 4769 / 4771 / 4776 | 1,000–20,000 | 1.5–30 |
| DC01 account/group management, 5136, 4719, 1102 | < 1,000 | < 1.5 |
| SYNC01 Security + Application (ADSync) | 2,000–20,000 | 3–30 |
| WS01 4688 (command line) + 4624 (optional) | 2,000–30,000 | 3–45 |
| Entra AuditLogs (if LIC-001 allows) | — | < 5 |
| Connect application sign-ins (if LIC-003 allows) | — | < 2 |
| SigninLogs (only with P1/P2) | — | < 10 |
| `Heartbeat`, `AzureActivity`, `SecurityAlert` | — | free |
| **Total billable** | | **≈ 15–180 MB/day ≈ 0.45–5.4 GB/month** |

**Formula:** `monthly_cost ≈ GB_per_month × P_GB`, where `P_GB` is the combined Log Analytics +
Sentinel pay-as-you-go price per GB in the chosen region (**not retrieved**). Illustrative only:
at an assumed `P_GB` of USD 4–6, this is roughly **USD 2–35 per month** after the trial.

Measure in Phase 2:

```kql
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize GB = sum(Quantity) / 1024 by DataType
| order by GB desc
```

## 3. Free trials

| Trial | Terms | Plan |
|---|---|---|
| Microsoft Sentinel | First **10 GB/day** on the Analytics plan free for **31 days** after enabling Sentinel on a workspace; limited to 20 workspaces per tenant **[search]** | Enable only when Phase 2 can onboard telemetry the same week, so the trial covers telemetry tuning **and** first validations |
| Entra ID P2 | 30-day trial when offered for the tenant **(verify availability)** | Start together with the Sentinel trial if sign-in detections are in scope |

## 4. Empirical licensing gates

### 4.1 Portal availability vs. Log Analytics export

| Log | Portal on Free | Portal on P1/P2 | Export to Log Analytics | Status |
|---|---|---|---|---|
| Audit logs | Yes, 7 days | Yes, 30 days | Unclear on Free | **Gate LIC-001** |
| Interactive sign-ins | Yes, 7 days | Yes, 30 days | **P1/P2 required** (Sentinel Entra ID connector) | Documented |
| Non-interactive user sign-ins | Yes (sign-in logs) | Yes | Not stated | **Gate LIC-002** |
| Service principal sign-ins | Yes (sign-in logs) | Yes | Not stated | **Gate LIC-003** |
| Managed identity sign-ins | Yes (sign-in logs) | Yes | Not stated | **Gate LIC-004** |
| Provisioning logs | **No** | Yes | Inferred P1/P2 | **Gate LIC-005** |
| Microsoft Graph activity logs | **No** | Yes | Inferred P1/P2 | **Gate LIC-006** |
| Risky users / risk events (ID Protection) | Limited | P1 limited; P2 full | Connector declares P1/P2; full data needs P2 | Documented |
| Risky service principals | — | — | Workload ID Premium | Documented |

### 4.2 Gate definitions

Each gate is a test on the lab tenant in Phase 2. The result is recorded here and in the
matrix, together with the date and the tenant's licence state.

| Gate | Question | Why it is open | Method | Result |
|---|---|---|---|---|
| LIC-001 | Can a Free tenant export **AuditLogs**? | The Entra integration page lists no licence requirement and the Sentinel connector flags only sign-in logs, but "Analyze activity logs with Log Analytics" lists a P1/P2 tenant as a prerequisite | Create a diagnostic setting with the AuditLogs category; make a benign directory change; query after 60 min | not run |
| LIC-002 | Can a Free tenant export **non-interactive sign-ins**? | No statement found | Try to enable the category; record whether rows arrive | not run |
| LIC-003 | Can a Free tenant export **service principal sign-ins**? | No statement found; needed for DET-HYB-001 | Enable the category; trigger a sync cycle; query for the Connect application | not run |
| LIC-004 | Can a Free tenant export **managed identity sign-ins**? | No statement found | Try to enable the category | not run |
| LIC-005 | Is **provisioning log** export possible without P1/P2? | Portal says No on Free; export inferred | Try to enable the category | not run |
| LIC-006 | Is **Graph activity log** export possible without P1/P2? | Portal says No on Free; export inferred | Try to enable the category | not run |

### 4.3 Licensing gates in the MVP

- A detection that depends on a gated table **must** list the gate in
  `prerequisites.licensing_gates` (validator-enforced).
- While a gate is open, the detection's runs are INCONCLUSIVE (`LICENSING_GATE_OPEN`).
- **Gate G-LIC (before Phase 3 Entra detections):** LIC-001 and LIC-003 have been run on the lab
  tenant and recorded. If LIC-001 fails on Free, the MVP's Entra detections require a P1/P2
  licence or trial. That is a scope decision for the owner, not something to work around.

## 5. Guardrails (to implement in Phase 1, before any ingestion)

- [ ] Subscription **budget** with alerts at 50 %, 80 % and 100 % of an amount set by the owner.
- [ ] Workspace **daily cap** (lab only; a cap produces INCONCLUSIVE results by design).
- [ ] DCRs with explicit **XPath** filters (including the 4662/4624 filters); never "All Security Events".
- [ ] No optional Arc services; no Defender plans.
- [ ] All resources tagged (`project=hdv`, `env=lab`) for cost analysis.
- [ ] Documented `terraform destroy` path.
