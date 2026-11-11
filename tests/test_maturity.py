"""Detection maturity derived from verdict evidence (ADR-0014)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from hdv.maturity import Maturity, Verdict, VerdictRecord, derive_maturity

T0 = datetime(2027, 1, 10, 12, 0, tzinfo=timezone.utc)


def rec(verdict: str, day: int, *, version: str = "1.0.0", scenario: str = "SCN-AD-001", complete: bool = True) -> VerdictRecord:
    return VerdictRecord("DET-AD-001", version, scenario, f"run-{day}-{verdict}", Verdict(verdict), complete, T0 + timedelta(days=day))


def derive(records: list[VerdictRecord], *, status: str = "ready", scenarios: tuple[str, ...] = ("SCN-AD-001",)) -> Maturity:
    return derive_maturity("DET-AD-001", "1.0.0", status, scenarios, records)


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ([], Maturity.UNVALIDATED),
        ([rec("INCONCLUSIVE", 0), rec("INCONCLUSIVE", 1)], Maturity.UNVALIDATED),
        ([rec("PASS", 0, complete=False)], Maturity.UNVALIDATED),
        ([rec("PASS", 0)], Maturity.VALIDATED),
        ([rec("PASS", 0), rec("PASS", 0), rec("PASS", 0)], Maturity.VALIDATED),  # same day: not stable
        ([rec("PASS", 0), rec("PASS", 1), rec("PASS", 2)], Maturity.STABLE),
        ([rec("PASS", 0), rec("PASS", 1), rec("INCONCLUSIVE", 2), rec("PASS", 3)], Maturity.STABLE),
        ([rec("FAIL", 0)], Maturity.FAILING),
        ([rec("PASS", 0), rec("PASS", 1), rec("PASS", 2), rec("FAIL", 3)], Maturity.REGRESSED),
        ([rec("FAIL", 0), rec("PASS", 1)], Maturity.VALIDATED),
        ([rec("PASS", 0), rec("PASS", 1), rec("PASS", 2, version="0.9.0")], Maturity.VALIDATED),  # other version ignored
    ],
)
def test_maturity_from_evidence(records: list[VerdictRecord], expected: Maturity) -> None:
    assert derive(records) is expected


def test_stable_requires_every_linked_scenario() -> None:
    records = [rec("PASS", 0), rec("PASS", 1), rec("PASS", 2)]
    assert derive(records, scenarios=("SCN-AD-001", "SCN-AD-002")) is Maturity.VALIDATED


def test_deprecated_status_wins() -> None:
    assert derive([rec("PASS", 0)], status="deprecated") is Maturity.DEPRECATED
