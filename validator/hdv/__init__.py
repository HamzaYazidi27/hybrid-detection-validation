"""HDV validation engine (Phase 4, partially implemented).

Implemented in Phase 0 because they are safety-critical and testable offline:

- ``lab_state``: fail-closed CLEAN / DIRTY lab state that blocks scenario execution
  after a failed cleanup (ADR-0013).
- ``sweeper``: idempotent cleanup sweeper with verification pass (ADR-0013).
- ``maturity``: detection maturity derived from verdict evidence (ADR-0014).

Not implemented yet: scenario execution, telemetry/alert evaluation, persistence, reports.
"""

__all__ = ["lab_state", "sweeper", "maturity"]
