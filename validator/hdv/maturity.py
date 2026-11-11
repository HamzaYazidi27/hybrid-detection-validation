"""Detection maturity derived from verdict evidence (ADR-0014).

Maturity is never declared in detection YAML. It is computed from verdict records produced
by the validation engine for the CURRENT content version of a detection:

    unvalidated - no conclusive verdict (only INCONCLUSIVE, or none at all)
    validated   - at least one PASS with complete evidence; latest conclusive verdict is PASS
    stable      - the last STABLE_STREAK conclusive verdicts are all PASS with complete
                  evidence, on at least STABLE_DISTINCT_DAYS different days, and every linked
                  scenario has at least one such PASS
    failing     - latest conclusive verdict is FAIL and there was never a PASS
    regressed   - latest conclusive verdict is FAIL after an earlier PASS
    deprecated  - detection status is deprecated

INCONCLUSIVE verdicts never count as evidence in either direction. A PASS without complete
evidence (all three layers recorded) is ignored.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable, Sequence

STABLE_STREAK = 3
STABLE_DISTINCT_DAYS = 2


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class Maturity(str, Enum):
    UNVALIDATED = "unvalidated"
    VALIDATED = "validated"
    STABLE = "stable"
    FAILING = "failing"
    REGRESSED = "regressed"
    DEPRECATED = "deprecated"


@dataclass(frozen=True)
class VerdictRecord:
    detection_id: str
    detection_version: str
    scenario_id: str
    run_id: str
    verdict: Verdict
    evidence_complete: bool
    finished_at: datetime


def derive_maturity(
    detection_id: str,
    detection_version: str,
    status: str,
    linked_scenarios: Sequence[str],
    records: Iterable[VerdictRecord],
) -> Maturity:
    if status == "deprecated":
        return Maturity.DEPRECATED

    relevant = sorted(
        (
            r
            for r in records
            if r.detection_id == detection_id
            and r.detection_version == detection_version
            and r.verdict is not Verdict.INCONCLUSIVE
            and not (r.verdict is Verdict.PASS and not r.evidence_complete)
        ),
        key=lambda r: r.finished_at,
    )
    if not relevant:
        return Maturity.UNVALIDATED

    latest = relevant[-1]
    ever_passed = any(r.verdict is Verdict.PASS for r in relevant)
    if latest.verdict is Verdict.FAIL:
        return Maturity.REGRESSED if ever_passed else Maturity.FAILING

    streak = relevant[-STABLE_STREAK:]
    passed_scenarios = {r.scenario_id for r in relevant if r.verdict is Verdict.PASS}
    if (
        len(streak) == STABLE_STREAK
        and all(r.verdict is Verdict.PASS for r in streak)
        and len({r.finished_at.date() for r in streak}) >= STABLE_DISTINCT_DAYS
        and set(linked_scenarios) <= passed_scenarios
    ):
        return Maturity.STABLE
    return Maturity.VALIDATED
