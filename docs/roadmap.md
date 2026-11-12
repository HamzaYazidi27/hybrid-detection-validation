# MVP Development Roadmap

> Each phase ends with **evidence**, not claims. A phase is complete only when its exit criteria
> are demonstrated and reviewed. Approval is required before each phase.

## Status

| Phase | Name | Status |
|---|---|---|
| 0 | Foundations: design, schemas, validator, safety core, CI | **In review (revision 2)** |
| 1 | Azure foundation (Terraform; plan only until approved) | Not started |
| 2 | Lab isolation, onboarding, telemetry, licensing gates | **In progress**: Module 2.1 package implemented (mock-tested, not run); 2.2–2.4 not started |
| 3 | Detection engineering | Not started |
| 4 | Validation engine | Not started (safety core done in Phase 0) |
| 5 | CI/CD with OIDC and regression | Not started |
| 6 | Post-MVP extensions | Not planned |

## Gates

| Gate | Condition | Required before |
|---|---|---|
| **G-NET** | FW01 deployed; isolation checks I1–I5 PASS | Any change in the lab beyond FW01; any scenario |
| **G-T0** | Owner decision: dedicated Tier 0 subscription (direct AMA) or WEF via WEC01 | Arc onboarding of any Tier 0 machine |
| **G-LIC** | Licensing gates LIC-001 and LIC-003 run and recorded | Entra / hybrid detections in Phase 3 |
| **G-CLEAN** | Lab state CLEAN (initialised with an attestation) | Every scenario run |
| **G-EXEC** | ADR-0009 accepted | Phase 4 execution features |

## Phase 0: Foundations

**Delivered (in review):**
- architecture, network isolation, DCSync design, data flow, threat model, safety, lab
  requirements, hybrid identity, cost and licensing documents;
- ADRs 0001–0014;
- detection and scenario schemas;
- hardened content validator with ATT&CK 20.1 and licensing-matrix checks;
- malicious fixtures;
- lab state, sweeper and maturity modules;
- Arc lockdown and isolation-check PowerShell scripts;
- CI (Python 3.12, hash-locked dependencies, actionlint, gitleaks, Dependabot).

**Exit criteria:** CI green on GitHub; owner review complete. ADR-0009 may remain Proposed.

**Not done:** no Azure resources, credentials, lab changes or simulations. No KQL executed.

## Phase 1: Azure foundation

**Deliverables:**
- Terraform for the workload subscription: resource groups, workspace, Sentinel (resource
  defined; enablement timed with the trial), Activity log export, budget + alerts, tags, RBAC
  (workspace-scoped CI roles defined but unused);
- optional separate root module for the Tier 0 subscription.

CI adds `terraform fmt -check`, `terraform validate`, `tflint` and a static IaC scan.

**Exit criteria:** `terraform plan` reviewed; **apply only after explicit approval**; budget
alerts tested.

## Phase 2: Lab isolation, onboarding, telemetry, licensing gates

**Deliverables (in this order):**
1. FW01 and G-NET.
2. Discovery inventory D1–D16.
3. G-T0 decision.
4. Dedicated audit GPO + SACL (additive, `-WhatIf` first).
5. WEF to WEC01, or Arc on DC01/SYNC01 (lockdown verified before connect).
6. DCRs.
7. Entra Connect ≥ 2.6.84.0 with application-based authentication (runbook; exports outside Git).
8. Entra diagnostic settings.
9. LIC-001…006 tests.
10. Lab state initialised.

**Exit criteria:**
- every required event ID observed from a benign manual action;
- `Heartbeat` from WEC01 (or the Arc servers);
- licensing gate results recorded;
- measured volume and latency replace the assumptions.

## Phase 3: Detection engineering

**Deliverables:**
- MVP detections in YAML;
- a normalising KQL function for `SecurityEvent` / `WindowsEvent`;
- KQL parse check in CI (`Kusto.Language`);
- watchlists for DCs and Entra Connect;
- rule deployment from YAML (approved, manual);
- verification of the Sentinel tactic mapping for ATT&CK's Stealth / Defense Impairment tactics.

**Exit criteria:** each detection fires on a documented manual reproduction. Status moves from
`draft` to `ready`. Maturity stays **unvalidated** until Phase 4 evidence exists.

| ID (planned) | Detection | ATT&CK (20.1) | Licensing |
|---|---|---|---|
| DET-AD-001 | DCSync by non-DC principal, or connector account from a non-SYNC01 source | T1003.006 | none |
| DET-AD-002 | Kerberoasting (RC4 service tickets) | T1558.003 | none |
| DET-AD-003 | Member added to a privileged AD group | T1098 | none |
| DET-ENTRA-001 | Credential added to an application / service principal | T1098.001 | gate LIC-001 |
| DET-ENTRA-002 | Privileged Entra role assigned | T1098.003 | gate LIC-001 |
| DET-ENTRA-003 | Password spraying against Entra ID | T1110.003 | P1/P2 |
| DET-HYB-001 | Entra Connect application signs in from a non-lab IP | T1078.004 | gate LIC-003 |
| DET-HYB-002 | Credential added to the Entra Connect application outside Connect's rotation | T1098.001 | gate LIC-001 |
| DET-AZ-001 | Diagnostic setting or DCR deleted or modified | T1685.002 | none |

## Phase 4: Validation engine

**Deliverables:**
- Python CLI (`plan`, `run`, `sweep`, `evaluate`, `report`) integrating the Phase 0 lab state
  and sweeper;
- fail-closed pre-flight;
- scenario, cleanup and sweep executors;
- three-layer evaluation plus the separate incident check;
- `AlertSource` adapters;
- SQLite persistence;
- Markdown/HTML reports with ATT&CK layer and maturity from evidence;
- unit tests with recorded API responses.

**Prerequisites:** G-EXEC, G-CLEAN.

**Exit criteria:**
- each MVP scenario has run end to end at least once, with evidence;
- a deliberately broken detection produces FAIL;
- a stopped telemetry source produces INCONCLUSIVE;
- a forced cleanup failure leaves the lab DIRTY and blocks the next run.

## Phase 5: CI/CD with OIDC and regression

**Deliverables:**
- federated credentials bound to GitHub environments (`hdv-evaluate`, `hdv-deploy`);
- workspace-scoped roles;
- evaluation workflow (schedule / dispatch), never on `pull_request`;
- rule deployment with manual approval;
- sanitised coverage report;
- PSScriptAnalyzer once a pinned version can be verified.

**Exit criteria:** a scheduled run produces a report; a PR that breaks a detection is caught.

## MVP definition of done

- Every MVP detection has at least one scenario, and is either validated end to end or reported
  as a licensing or telemetry gap.
- Reproducible Azure setup from Terraform; documented lab runbooks; isolation checks passing.
- Maturity derived from evidence across at least 3 runs per detection.
- Coverage report and ATT&CK layer generated from data, not hand-written.

## Phase 6: Post-MVP candidates (not committed)

FastAPI + PostgreSQL dashboard; Graph security adapter; Cloud Sync comparison lab; Defender for
Identity correlation; AD CS abuse; FQDN-based egress allow-list on FW01.
