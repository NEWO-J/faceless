"""Core data model for the OpSec-as-Code posture engine.

These types are the vocabulary of the standard: a :class:`CheckResult` per
control and an aggregate :class:`PostureReport`. The conformance rule lives here
in exactly one place so every consumer (CLI, JSON, SARIF, the shell hook) agrees
on what "conformant" means.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .errors import ExitCode


class State(str, Enum):
    """Outcome of evaluating a single control."""

    OK = "ok"                       # actual state matches desired
    DRIFT = "drift"                 # was/should be enforced, but has changed
    VIOLATION = "violation"         # a prohibited condition is present
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"                 # could not be evaluated
    NOT_ENFORCED = "not_enforced"   # skipped (e.g. fast mode, no provider)


#: States that count against conformance.
FAILING_STATES = frozenset({State.DRIFT, State.VIOLATION, State.ERROR})


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

#: Controls at or above this severity break conformance when failing.
CONFORMANCE_THRESHOLD = Severity.HIGH


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The result of observing one control."""

    control_id: str
    state: State
    severity: Severity
    summary: str
    detail: str = ""
    #: Canonical observed values, used for lock snapshots and drift-vs-lock.
    observed: dict[str, str] | None = None
    remediable: bool = False

    @property
    def failing(self) -> bool:
        return self.state in FAILING_STATES

    @property
    def counts_against_conformance(self) -> bool:
        return self.failing and self.severity.rank >= CONFORMANCE_THRESHOLD.rank

    def as_dict(self) -> dict[str, object]:
        return {
            "control": self.control_id,
            "state": self.state.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "detail": self.detail,
            "remediable": self.remediable,
            "observed": self.observed,
        }


@dataclass(frozen=True, slots=True)
class PostureReport:
    """Aggregate outcome of evaluating an entire desired-state config."""

    results: tuple[CheckResult, ...] = field(default_factory=tuple)

    @property
    def conformant(self) -> bool:
        """Conformant iff no control >= HIGH is in a failing state."""
        return not any(r.counts_against_conformance for r in self.results)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(r for r in self.results if r.counts_against_conformance)

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {s.value: 0 for s in State}
        for result in self.results:
            tally[result.state.value] += 1
        return tally

    def exit_code(self) -> int:
        return int(ExitCode.OK if self.conformant else ExitCode.NON_CONFORMANT)

    def as_dict(self, *, profile_name: str | None = None) -> dict[str, object]:
        counts = self.counts()
        return {
            "opsec_version": 1,
            "name": profile_name,
            "conformant": self.conformant,
            "summary": {
                "evaluated": len(self.results),
                "failing": len(self.failures),
                "by_state": counts,
            },
            "results": [r.as_dict() for r in self.results],
        }
