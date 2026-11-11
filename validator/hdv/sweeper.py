"""Idempotent cleanup sweeper (ADR-0013).

Each scenario with ``cleanup.required: true`` declares ``cleanup.sweep``: an executor that
finds and removes ALL leftovers of that scenario from any run (normally by the ``HDV-``
marker prefix). The sweeper:

1. Dry run (default): asks every sweep executor what it WOULD remove. Changes nothing.
2. Real run: removes leftovers, then runs a verification pass (dry run again). Any leftover
   found by the verification pass or any executor error marks the lab DIRTY.
3. Only a real run whose verification pass finds nothing may return the lab to CLEAN.

Executors are injected (``SweepExecutor``), so this module has no knowledge of AD, Graph or
Azure and is tested offline. Real executors are Phase 4 work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Protocol

from .lab_state import LabState, RecoveryMethod, State

MARKER_PREFIX = "HDV-"


@dataclass(frozen=True)
class SweepItem:
    scenario_id: str
    executor: Mapping[str, Any]
    selector: str
    marker_prefix: str = MARKER_PREFIX


@dataclass(frozen=True)
class SweepOutcome:
    """What one executor call observed. ``found`` counts leftovers present before acting."""

    found: int
    removed: int = 0
    errors: tuple[str, ...] = ()


class SweepExecutor(Protocol):
    def __call__(self, item: SweepItem, *, dry_run: bool) -> SweepOutcome: ...


@dataclass
class ItemReport:
    scenario_id: str
    found: int = 0
    removed: int = 0
    remaining: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class SweepReport:
    dry_run: bool
    items: list[ItemReport]

    @property
    def ok(self) -> bool:
        """True only for a real run with no errors and nothing left after verification."""
        return (not self.dry_run) and all(not i.errors and i.remaining == 0 for i in self.items)

    @property
    def total_found(self) -> int:
        return sum(i.found for i in self.items)


def plan(scenarios: Iterable[Mapping[str, Any]]) -> list[SweepItem]:
    """Build sweep items from scenario documents (already schema-validated)."""
    items = []
    for scenario in scenarios:
        cleanup = scenario.get("cleanup") or {}
        sweep = cleanup.get("sweep")
        if cleanup.get("required") and isinstance(sweep, Mapping):
            items.append(SweepItem(str(scenario["id"]), sweep["executor"], str(sweep["selector"])))
    return sorted(items, key=lambda item: item.scenario_id)


class Sweeper:
    def __init__(self, executors: Mapping[str, SweepExecutor], state: LabState) -> None:
        self._executors = dict(executors)
        self._state = state

    def _call(self, item: SweepItem, *, dry_run: bool) -> SweepOutcome:
        executor = self._executors.get(str(item.executor.get("type")))
        if executor is None:
            return SweepOutcome(found=0, errors=(f"no sweep executor registered for type {item.executor.get('type')!r}",))
        try:
            outcome = executor(item, dry_run=dry_run)
        except Exception as exc:  # noqa: BLE001 - any executor failure must be recorded, never raised
            return SweepOutcome(found=0, errors=(f"{type(exc).__name__}: {exc}",))
        if not isinstance(outcome, SweepOutcome) or outcome.found < 0 or outcome.removed < 0:
            return SweepOutcome(found=0, errors=("executor returned an invalid outcome",))
        if dry_run and outcome.removed:
            return SweepOutcome(found=outcome.found, errors=("executor removed items during a dry run",))
        return outcome

    def run(self, items: Iterable[SweepItem], *, dry_run: bool = True, operator: str = "") -> SweepReport:
        reports: list[ItemReport] = []
        for item in items:
            report = ItemReport(item.scenario_id)
            first = self._call(item, dry_run=dry_run)
            report.found, report.removed = first.found, first.removed
            report.errors.extend(first.errors)
            if dry_run:
                report.remaining = first.found
            else:
                verify = self._call(item, dry_run=True)
                report.errors.extend(verify.errors)
                report.remaining = verify.found
            reports.append(report)

        result = SweepReport(dry_run=dry_run, items=reports)
        if not dry_run:
            if result.ok:
                if self._state.read().state is State.DIRTY:
                    self._state.mark_clean(operator, RecoveryMethod.SWEEP, sweep_ok=True)
            else:
                failed = [i.scenario_id for i in reports if i.errors or i.remaining]
                self._state.mark_dirty(f"sweep incomplete for {', '.join(failed)}")
        return result
