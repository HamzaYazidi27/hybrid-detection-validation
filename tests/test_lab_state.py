"""Fail-closed lab state (ADR-0013)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hdv.lab_state import (
    LabLockedError,
    LabNotCleanError,
    LabState,
    LabStateCorruptError,
    RecoveryMethod,
    State,
)

ATTESTATION = "Snapshots taken 2026-11-11; lab verified isolated and empty."
JUSTIFICATION = "Restored DC01/SYNC01 snapshots and ran the cloud sweep manually."


@pytest.fixture
def lab(tmp_path: Path) -> LabState:
    return LabState(tmp_path / ".hdv" / "lab-state.json")


def test_missing_state_is_uninitialised_and_blocks(lab: LabState) -> None:
    assert lab.read().state is State.UNINITIALISED
    with pytest.raises(LabNotCleanError, match="UNINITIALISED"):
        lab.require_clean()


def test_initialise_requires_real_attestation(lab: LabState) -> None:
    with pytest.raises(ValueError):
        lab.initialise("operator", "ok")
    lab.initialise("operator", ATTESTATION)
    lab.require_clean()
    with pytest.raises(ValueError, match="already initialised"):
        lab.initialise("operator", ATTESTATION)


def test_failed_cleanup_marks_dirty_and_blocks(lab: LabState) -> None:
    lab.initialise("operator", ATTESTATION)
    lab.mark_dirty("cleanup failed: secret HDV-123 still present", run_id="123", scenario_id="SCN-ENTRA-001")
    snapshot = lab.read()
    assert snapshot.state is State.DIRTY
    assert snapshot.history[-1].scenario_id == "SCN-ENTRA-001"
    with pytest.raises(LabNotCleanError, match="DIRTY"):
        lab.require_clean()


def test_dirty_cannot_be_cleared_without_verified_sweep_or_justification(lab: LabState) -> None:
    lab.initialise("operator", ATTESTATION)
    lab.mark_dirty("runner crashed")
    with pytest.raises(ValueError, match="successful"):
        lab.mark_clean("operator", RecoveryMethod.SWEEP, sweep_ok=False)
    with pytest.raises(ValueError, match="justification"):
        lab.mark_clean("operator", RecoveryMethod.MANUAL, justification="done")
    lab.mark_clean("operator", RecoveryMethod.MANUAL, justification=JUSTIFICATION)
    lab.require_clean()
    assert lab.read().history[-1].method == "manual_recovery"


def test_mark_clean_only_from_dirty(lab: LabState) -> None:
    lab.initialise("operator", ATTESTATION)
    with pytest.raises(ValueError, match="only valid from DIRTY"):
        lab.mark_clean("operator", RecoveryMethod.SWEEP, sweep_ok=True)


@pytest.mark.parametrize(
    "content",
    ["not json", json.dumps({"schema_version": 99, "state": "CLEAN"}), json.dumps({"schema_version": 1, "state": "MAYBE"}),
     json.dumps({"schema_version": 1, "state": "UNINITIALISED"})],
)
def test_corrupt_state_fails_closed(lab: LabState, content: str) -> None:
    lab.path.parent.mkdir(parents=True)
    lab.path.write_text(content, encoding="utf-8")
    with pytest.raises(LabStateCorruptError):
        lab.require_clean()
    lab.mark_dirty("state file was corrupt")  # failing safe must always be possible
    assert lab.read().state is State.DIRTY


def test_run_lock_is_exclusive(lab: LabState) -> None:
    with lab.run_lock():
        with pytest.raises(LabLockedError):
            with lab.run_lock():
                pass
    with lab.run_lock():  # released after use
        pass


def test_history_is_bounded(lab: LabState) -> None:
    lab.initialise("operator", ATTESTATION)
    for i in range(150):
        lab.mark_dirty(f"event {i}")
    assert len(lab.read().history) == 100
