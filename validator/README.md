# Validation engine

A Python package (`validator/hdv/`) that will plan, run and evaluate scenarios using the
three-layer verdict model ([ADR-0008](../docs/adr/0008-three-layer-verdict-model.md)) and
portal-independent alert sources ([ADR-0006](../docs/adr/0006-portal-independent-validation-engine.md)).

| Module | Purpose | Status |
|---|---|---|
| `hdv/lab_state.py` | Fail-closed CLEAN / DIRTY / UNINITIALISED lab state, atomic writes, run lock ([ADR-0013](../docs/adr/0013-lab-state-cleanup-sweeper.md)) | **Implemented**, unit-tested |
| `hdv/sweeper.py` | Idempotent cleanup sweeper with verification pass and dry-run default | **Implemented** with injected executors; real Graph/AD/Azure executors are Phase 4 |
| `hdv/maturity.py` | Detection maturity derived from verdict evidence ([ADR-0014](../docs/adr/0014-maturity-derived-from-evidence.md)) | **Implemented**, unit-tested |
| CLI, executors, evaluation, persistence, reports | Validation loop | Planned (Phase 4) |

Design: [docs/architecture.md §5](../docs/architecture.md#5-validation-engine-design-phase-4-planned).

Not to be confused with [`tools/validate_content.py`](../tools/validate_content.py), which
statically validates YAML content in CI.
