"""Idempotent cleanup sweeper (ADR-0013), tested against an in-memory fake lab."""

from __future__ import annotations

from pathlib import Path

import pytest
import validate_content as vc
from hdv.lab_state import LabNotCleanError, LabState, State
from hdv.sweeper import SweepItem, SweepOutcome, Sweeper, plan

VALID_SCENARIOS = Path(__file__).resolve().parent / "fixtures" / "valid" / "scenarios"
ATTESTATION = "Snapshots taken 2026-11-11; lab verified isolated and empty."


class FakeLab:
    """Leftover objects per scenario. remove_fails simulates objects that cannot be deleted."""

    def __init__(self, leftovers: dict[str, set[str]], remove_fails: set[str] | None = None) -> None:
        self.leftovers = leftovers
        self.remove_fails = remove_fails or set()
        self.calls: list[tuple[str, bool]] = []

    def __call__(self, item: SweepItem, *, dry_run: bool) -> SweepOutcome:
        self.calls.append((item.scenario_id, dry_run))
        present = {o for o in self.leftovers.get(item.scenario_id, set()) if o.startswith(item.marker_prefix)}
        if dry_run:
            return SweepOutcome(found=len(present))
        removable = present - self.remove_fails
        self.leftovers.setdefault(item.scenario_id, set()).difference_update(removable)
        return SweepOutcome(found=len(present), removed=len(removable))


@pytest.fixture
def items() -> list[SweepItem]:
    return plan(vc.load_yaml(p) for p in sorted(VALID_SCENARIOS.glob("*.yml")))


@pytest.fixture
def dirty_lab(tmp_path: Path) -> LabState:
    lab = LabState(tmp_path / "lab-state.json")
    lab.initialise("operator", ATTESTATION)
    lab.mark_dirty("cleanup failed for SCN-ENTRA-001")
    return lab


def test_plan_reads_sweeps_from_scenarios(items: list[SweepItem]) -> None:
    assert [i.scenario_id for i in items] == ["SCN-AD-001", "SCN-ENTRA-001"]
    assert all(i.marker_prefix == "HDV-" for i in items)


def test_dry_run_changes_nothing(items: list[SweepItem], dirty_lab: LabState) -> None:
    fake = FakeLab({"SCN-ENTRA-001": {"HDV-1", "HDV-2", "unrelated-secret"}})
    report = Sweeper({"python": fake, "powershell": fake}, dirty_lab).run(items, dry_run=True)
    assert report.total_found == 2 and not report.ok
    assert fake.leftovers["SCN-ENTRA-001"] == {"HDV-1", "HDV-2", "unrelated-secret"}
    assert dirty_lab.read().state is State.DIRTY


def test_successful_sweep_is_verified_idempotent_and_cleans_lab(items: list[SweepItem], dirty_lab: LabState) -> None:
    fake = FakeLab({"SCN-ENTRA-001": {"HDV-1", "HDV-2", "unrelated-secret"}})
    sweeper = Sweeper({"python": fake, "powershell": fake}, dirty_lab)
    first = sweeper.run(items, dry_run=False, operator="operator")
    assert first.ok and first.total_found == 2
    assert fake.leftovers["SCN-ENTRA-001"] == {"unrelated-secret"}  # only HDV- objects are touched
    assert dirty_lab.read().state is State.CLEAN
    second = sweeper.run(items, dry_run=False, operator="operator")
    assert second.ok and second.total_found == 0  # idempotent
    # Every real call is followed by a verification dry run.
    assert ("SCN-ENTRA-001", False) in fake.calls and fake.calls.count(("SCN-ENTRA-001", True)) == 2


def test_leftovers_after_verification_keep_lab_dirty(items: list[SweepItem], dirty_lab: LabState) -> None:
    fake = FakeLab({"SCN-ENTRA-001": {"HDV-1", "HDV-stuck"}}, remove_fails={"HDV-stuck"})
    report = Sweeper({"python": fake, "powershell": fake}, dirty_lab).run(items, dry_run=False, operator="operator")
    assert not report.ok
    assert [i.remaining for i in report.items if i.scenario_id == "SCN-ENTRA-001"] == [1]
    with pytest.raises(LabNotCleanError):
        dirty_lab.require_clean()


def test_executor_exception_is_recorded_and_marks_dirty(items: list[SweepItem], tmp_path: Path) -> None:
    lab = LabState(tmp_path / "lab-state.json")
    lab.initialise("operator", ATTESTATION)

    def broken(item: SweepItem, *, dry_run: bool) -> SweepOutcome:
        raise ConnectionError("Graph unreachable")

    fake = FakeLab({})
    report = Sweeper({"python": broken, "powershell": fake}, lab).run(items, dry_run=False, operator="operator")
    assert not report.ok
    assert any("ConnectionError" in e for i in report.items for e in i.errors)
    assert lab.read().state is State.DIRTY


def test_missing_executor_is_an_error(items: list[SweepItem], dirty_lab: LabState) -> None:
    report = Sweeper({}, dirty_lab).run(items, dry_run=False, operator="operator")
    assert not report.ok and all(i.errors for i in report.items)


def test_executor_that_deletes_during_dry_run_is_rejected(items: list[SweepItem], dirty_lab: LabState) -> None:
    def rogue(item: SweepItem, *, dry_run: bool) -> SweepOutcome:
        return SweepOutcome(found=1, removed=1)

    report = Sweeper({"python": rogue, "powershell": rogue}, dirty_lab).run(items, dry_run=True)
    assert any("during a dry run" in e for i in report.items for e in i.errors)
