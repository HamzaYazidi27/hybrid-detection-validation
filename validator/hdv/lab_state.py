"""Fail-closed lab state (ADR-0013).

The lab is either CLEAN (scenarios may run) or DIRTY (leftovers may exist; every scenario
is blocked). A missing state file means UNINITIALISED, which also blocks: the operator must
attest that the lab is in a known state before the first run.

Transitions:

    UNINITIALISED --initialise(attestation)--> CLEAN
    CLEAN         --mark_dirty(reason)-------> DIRTY   (failed cleanup, runner crash, abort)
    DIRTY         --mark_clean(sweep ok)-----> CLEAN   (successful, verified sweep)
    DIRTY         --mark_clean(manual)-------> CLEAN   (recorded manual recovery + justification)

Writes are atomic (temporary file + os.replace). A run lock prevents two runners from
executing scenarios concurrently against the same lab.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 1
MAX_HISTORY = 100
MIN_JUSTIFICATION = 20


class State(str, Enum):
    UNINITIALISED = "UNINITIALISED"
    CLEAN = "CLEAN"
    DIRTY = "DIRTY"


class RecoveryMethod(str, Enum):
    SWEEP = "sweep"
    MANUAL = "manual_recovery"


class LabNotCleanError(RuntimeError):
    """Raised when a scenario would run while the lab is not CLEAN."""


class LabStateCorruptError(RuntimeError):
    """Raised when the state file cannot be trusted. Treated as blocking."""


class LabLockedError(RuntimeError):
    """Raised when another runner holds the run lock."""


@dataclass
class Transition:
    at: str
    to: str
    reason: str
    operator: str | None = None
    run_id: str | None = None
    scenario_id: str | None = None
    method: str | None = None


@dataclass
class Snapshot:
    state: State
    updated_at: str | None = None
    reason: str | None = None
    history: list[Transition] = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LabState:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    # -- reading ---------------------------------------------------------------
    def read(self) -> Snapshot:
        if not self.path.exists():
            return Snapshot(State.UNINITIALISED)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("schema_version") != SCHEMA_VERSION:
                raise ValueError(f"unsupported schema_version {raw.get('schema_version')!r}")
            state = State(raw["state"])
            if state is State.UNINITIALISED:
                raise ValueError("UNINITIALISED is never persisted")
            history = [Transition(**item) for item in raw.get("history", [])]
            return Snapshot(state, raw.get("updated_at"), raw.get("reason"), history)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise LabStateCorruptError(f"lab state file {self.path} cannot be trusted: {exc}") from exc

    def require_clean(self) -> None:
        """Gate called before ANY scenario execution. Fails closed."""
        snapshot = self.read()
        if snapshot.state is not State.CLEAN:
            raise LabNotCleanError(
                f"lab state is {snapshot.state.value}"
                + (f" ({snapshot.reason})" if snapshot.reason else "")
                + "; run the sweeper or record a manual recovery before executing scenarios"
            )

    # -- transitions -----------------------------------------------------------
    def initialise(self, operator: str, attestation: str) -> Snapshot:
        if self.read().state is not State.UNINITIALISED:
            raise ValueError("lab state is already initialised")
        _require_text("attestation", attestation)
        _require_text("operator", operator, minimum=1)
        return self._write(State.CLEAN, Transition(_now(), State.CLEAN.value, attestation, operator=operator))

    def mark_dirty(self, reason: str, run_id: str | None = None, scenario_id: str | None = None) -> Snapshot:
        """Always allowed (including from DIRTY/UNINITIALISED/corrupt): failing safe never fails."""
        _require_text("reason", reason, minimum=1)
        try:
            previous = self.read()
        except LabStateCorruptError:
            previous = Snapshot(State.DIRTY)
        transition = Transition(_now(), State.DIRTY.value, reason, run_id=run_id, scenario_id=scenario_id)
        return self._write(State.DIRTY, transition, previous.history)

    def mark_clean(
        self,
        operator: str,
        method: RecoveryMethod,
        *,
        justification: str | None = None,
        sweep_ok: bool = False,
    ) -> Snapshot:
        snapshot = self.read()
        if snapshot.state is not State.DIRTY:
            raise ValueError(f"mark_clean is only valid from DIRTY (current: {snapshot.state.value})")
        _require_text("operator", operator, minimum=1)
        if method is RecoveryMethod.SWEEP:
            if not sweep_ok:
                raise ValueError("a sweep recovery requires a successful, verified, non-dry-run sweep")
            reason = "verified sweep completed without leftovers or errors"
        elif method is RecoveryMethod.MANUAL:
            _require_text("justification", justification or "")
            reason = justification or ""
        else:  # pragma: no cover - Enum exhaustiveness
            raise ValueError(f"unknown recovery method {method!r}")
        transition = Transition(_now(), State.CLEAN.value, reason, operator=operator, method=method.value)
        return self._write(State.CLEAN, transition, snapshot.history)

    # -- run lock --------------------------------------------------------------
    @contextmanager
    def run_lock(self) -> Iterator[None]:
        """Exclusive lock for the duration of a run. A stale lock must be removed manually."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise LabLockedError(
                f"another run holds {self.lock_path}; if no runner is active, inspect and delete it manually"
            ) from None
        try:
            os.write(fd, json.dumps({"pid": os.getpid(), "at": _now()}).encode("utf-8"))
            os.close(fd)
            yield
        finally:
            self.lock_path.unlink(missing_ok=True)

    # -- persistence -----------------------------------------------------------
    def _write(self, state: State, transition: Transition, history: list[Transition] | None = None) -> Snapshot:
        entries = list(history or [])
        entries.append(transition)
        entries = entries[-MAX_HISTORY:]
        payload = {
            "schema_version": SCHEMA_VERSION,
            "state": state.value,
            "updated_at": transition.at,
            "reason": transition.reason,
            "history": [asdict(item) for item in entries],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name, suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return Snapshot(state, transition.at, transition.reason, entries)


def _require_text(name: str, value: str, minimum: int = MIN_JUSTIFICATION) -> None:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise ValueError(f"{name} must be at least {minimum} characters")
