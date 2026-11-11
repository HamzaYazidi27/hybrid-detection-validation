# ADR-0013: Fail-closed lab state, mandatory cleanup and an idempotent sweeper

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

Scenarios create artefacts (Entra application secrets, AD ACEs, Kerberos tickets). If cleanup
fails or the runner crashes, leftovers distort later verdicts and can leave real attack paths
open. VM snapshots do not revert Entra ID or Azure changes.

## Decision

1. **Lab state** is a local, atomically written file with three values:
   `UNINITIALISED` (no file), `CLEAN`, `DIRTY`. The runner calls `require_clean()` before
   **every** scenario. Any value other than `CLEAN`, or an unreadable file, blocks execution.
2. **Any failed or uncertain cleanup marks the lab DIRTY**: cleanup error, verification
   failure, runner crash or abort, timeout. This is not configurable per scenario.
3. **Recovery paths from DIRTY:**
   - a **verified sweep**: a real (non-dry-run) sweep whose verification pass finds no
     leftovers and has no errors; or
   - a **recorded manual recovery** with operator and justification. For example: snapshots
     restored **and** a cloud sweep run, because snapshots do not revert cloud objects.
4. **Sweeper:** every scenario with `cleanup.required: true` declares `cleanup.sweep`, an
   executor that removes all leftovers of that scenario from any run, selected by the `HDV-`
   marker prefix. The sweeper runs dry by default. In real mode it always runs a verification
   pass afterwards and must be idempotent: a second run finds nothing.
5. A **run lock** prevents two runners from executing against the same lab concurrently.

Implemented now (offline, tested): `validator/hdv/lab_state.py`, `validator/hdv/sweeper.py`.
Real sweep executors (Graph, AD, Azure) are Phase 4 work.

## Consequences

- A broken sweep executor keeps the lab blocked; the only override is a recorded manual recovery.
- Sweep selectors must only ever match `HDV-` prefixed or explicitly tagged lab objects. This is
  tested with a fake lab in which unrelated objects must survive.
- Snapshot restoration risks are documented in [safety.md](../safety.md#4-snapshot-restoration-risks).
