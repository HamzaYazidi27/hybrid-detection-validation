# ADR-0014: Detection maturity is derived from evidence, never declared

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

The first schema let authors set `status: stable` without any recorded run (review probe P10).
A self-declared maturity is exactly the kind of unverified claim this project exists to remove.

## Decision

- YAML `status` describes the **authoring lifecycle** only: detections are `draft`, `ready` or
  `deprecated`; scenarios are `draft`, `reviewed` or `retired`.
- **Maturity** is computed by `validator/hdv/maturity.py` from verdict records for the
  **current content version**:

| Maturity | Rule |
|---|---|
| unvalidated | No conclusive verdict (none, or INCONCLUSIVE only) |
| validated | At least one PASS with complete evidence; latest conclusive verdict is PASS |
| stable | Last 3 conclusive verdicts are PASS, on at least 2 different days, and every linked scenario has a PASS |
| failing | Latest conclusive verdict is FAIL and there was never a PASS |
| regressed | Latest conclusive verdict is FAIL after an earlier PASS |
| deprecated | Detection status is `deprecated` |

- INCONCLUSIVE never counts in either direction. A PASS without complete evidence (all layers
  recorded) is ignored. A new content version starts from `unvalidated`.

## Consequences

- Coverage reports show maturity from data. The repository cannot claim maturity it has not earned.
- Phase 0 has no verdict records, so every detection is, correctly, `unvalidated`.
