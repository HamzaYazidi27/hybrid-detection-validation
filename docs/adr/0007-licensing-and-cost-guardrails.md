# ADR-0007: Licensing baseline, empirical licensing gates and cost guardrails

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

Licensing determines which telemetry exists at all. The Phase 0 review found that Microsoft's
documentation (a) distinguishes **portal availability** from **Log Analytics export**, and
(b) is contradictory or silent for several export cases. Guessing would either over-buy
licences or build detections on telemetry that never arrives.

## Decision

- **Licensing is data, not prose.** [`tools/data/licensing-matrix.yml`](../../tools/data/licensing-matrix.yml)
  records, per table: portal availability, the export requirement, a status
  (`documented` / `inferred` / `unresolved`) and the official sources.
- **Unresolved or inferred requirements are empirical tests** (gates LIC-001 to LIC-006),
  defined in the matrix and in [cost-and-licensing.md](../cost-and-licensing.md#4-empirical-licensing-gates).
  No conclusion is written until the test has run on the lab tenant.
- **Explicit MVP licensing gates:** a detection depending on a gated table must list the gate in
  `prerequisites.licensing_gates`. The validator enforces this. While a gate is open, the
  detection's verdicts are INCONCLUSIVE (`LICENSING_GATE_OPEN`), never PASS or FAIL.
- Declared licences must satisfy each table's documented export requirement (validator rule;
  P2 implies P1).
- **Phase 0 and Phase 1 planning create no paid resources.** Trials (Sentinel 31 days; Entra P2
  if used) start only when Phase 2 is ready to use them.
- Guardrails before any ingestion: budget alerts, workspace daily cap, XPath-filtered DCRs, no
  optional Arc services, documented teardown.

## Consequences

- Sign-in-based detections need P1/P2 for interactive sign-in export (documented by the
  Sentinel connector). Without it they remain a reported licensing gap.
- If LIC-001 fails (no AuditLogs export on Free), most Entra detections in the MVP are blocked
  until a licence or trial is available. This is the main licensing risk for the MVP.
