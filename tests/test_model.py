"""The conformance rule lives in one place; pin it down."""

from __future__ import annotations

from fle.model import CheckResult, PostureReport, Severity, State


def _r(state, severity):
    return CheckResult(control_id="X", state=state, severity=severity, summary="")


def test_high_violation_breaks_conformance():
    report = PostureReport(results=(_r(State.VIOLATION, Severity.HIGH),))
    assert not report.conformant
    assert report.exit_code() == 10


def test_low_drift_does_not_break_conformance():
    report = PostureReport(results=(_r(State.DRIFT, Severity.LOW),))
    assert report.conformant
    assert report.exit_code() == 0


def test_ok_and_not_applicable_are_conformant():
    report = PostureReport(results=(
        _r(State.OK, Severity.CRITICAL),
        _r(State.NOT_APPLICABLE, Severity.CRITICAL),
        _r(State.NOT_ENFORCED, Severity.CRITICAL),
    ))
    assert report.conformant


def test_error_at_high_breaks_conformance():
    report = PostureReport(results=(_r(State.ERROR, Severity.CRITICAL),))
    assert not report.conformant


def test_counts_tally_states():
    report = PostureReport(results=(_r(State.OK, Severity.LOW), _r(State.OK, Severity.LOW),
                                    _r(State.DRIFT, Severity.HIGH)))
    counts = report.counts()
    assert counts["ok"] == 2 and counts["drift"] == 1
