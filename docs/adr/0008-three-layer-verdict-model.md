# ADR-0008: Three-layer verdict model with run-marker correlation

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

"Did an alert fire?" alone is not a sound test. Missing telemetry (agent offline, DCR wrong,
audit policy off, daily cap, licensing) would be reported as a detection failure, and an
unrelated alert in the same time window would be reported as a success.

## Decision

Each scenario run is evaluated in three layers. Every layer stores its evidence: query text,
time window, matching row identifiers, adapter used. This is **planned** for Phase 4; nothing
is evaluated yet.

| Layer | Question | Evidence |
|---|---|---|
| L1 Telemetry | Did the expected raw events arrive? | Rows in `expected_telemetry` tables within the window |
| L2 Logic | Does the rule's KQL match those events? | Rule query executed ad hoc over the run window |
| L3 Alert | Did Sentinel produce the alert? | `SecurityAlert` row for the rule, correlated to the run |

Verdict for `expected_outcome: alert`:

| L1 | L2 | L3 | Verdict | Meaning |
|---|---|---|---|---|
| ✔ | ✔ | ✔ | **PASS** | Detection works end to end |
| ✔ | ✘ | – | **FAIL** | Detection logic gap |
| ✔ | ✔ | ✘ | **FAIL** | Rule deployment, schedule or configuration gap |
| ✘ | – | – | **INCONCLUSIVE** | Telemetry gap; says nothing about the detection |
| pre-flight failure, open licensing gate, lab not CLEAN, timeout, runner error | | | **INCONCLUSIVE** | With a reason code |

For `expected_outcome: no_alert` (negative tests): **PASS** when L1 is satisfied and no
correlated alert appears before the timeout; **FAIL** when one does; **INCONCLUSIVE** when L1
is not satisfied.

**Incident check (separate, optional):** when `validation.incident.expected` is true, the
engine also checks that an incident contains the alert. The result is reported separately and
**never changes the verdict** ([ADR-0006](0006-portal-independent-validation-engine.md)).

**Cleanup:** cleanup runs after every execution. Its failure does not change the verdict of that
run, but it marks the lab **DIRTY** and blocks all further runs ([ADR-0013](0013-lab-state-cleanup-sweeper.md)).

Correlation strategies (declared per detection):

- `run_marker`: a unique token `HDV-<run_id>` injected by the scenario must appear in declared
  alert columns. Strongest.
- `entity_and_time_window`: alert entities match the scenario's lab entities inside the run window.
- `time_window_only`: weakest. Allowed only with a written `justification` (schema-enforced),
  and reported as such.

## Consequences

- FAIL always means a defect in detection content or deployment. INCONCLUSIVE never counts as
  PASS, and maturity is derived from conclusive verdicts only ([ADR-0014](0014-maturity-derived-from-evidence.md)).
- L2 requires read access to the workspace, which also gives KQL integration tests (Phase 4).
- Observed latencies are recorded per run, replacing assumed values.
