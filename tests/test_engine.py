"""Engine: evaluation, fast-path caching, drift-vs-lock, convergence."""

from __future__ import annotations

from fle.config import OpsecConfig
from fle.engine import converge, evaluate
from fle.model import CheckResult, Severity, State
from fle.providers import disk, git_identity


def _config(*controls, params=None):
    posture = []
    for c in controls:
        item = {"control": c}
        if params and c in params:
            item["params"] = params[c]
        posture.append(item)
    return OpsecConfig.from_mapping({
        "opsec_version": 1,
        "name": "t",
        "identity": {
            "persona": {"git_name": "ghost", "git_email": "ghost@x.example"},
            "real": {"emails": ["jane@real.example"]},
        },
        "posture": posture,
    })


def test_conformant_when_all_ok(monkeypatch):
    monkeypatch.setattr(disk, "_encryption_enabled", lambda: True)
    report = evaluate(_config("OPSEC-DISK-001"))
    assert report.conformant


def test_git_drift_makes_non_conformant(monkeypatch):
    monkeypatch.setattr(git_identity, "_git_get",
                        lambda k: "wrong" if k == "user.name" else "ghost@x.example")
    report = evaluate(_config("OPSEC-IDENTITY-101"))
    assert not report.conformant
    assert report.results[0].state is State.DRIFT


def test_fast_skips_expensive_without_cache():
    report = evaluate(_config("OPSEC-DISK-001"), fast=True, cache=None)
    assert report.results[0].state is State.NOT_ENFORCED


def test_fast_uses_cache_when_present():
    cached = {"OPSEC-DISK-001": CheckResult(
        control_id="OPSEC-DISK-001", state=State.OK, severity=Severity.HIGH, summary="cached")}
    report = evaluate(_config("OPSEC-DISK-001"), fast=True, cache=cached)
    assert report.results[0].state is State.OK
    assert report.results[0].summary == "cached"


def test_drift_from_lock(monkeypatch):
    monkeypatch.setattr(disk, "_encryption_enabled", lambda: True)  # observed encrypted=true
    lock = {"OPSEC-DISK-001": {"encrypted": "false"}}
    report = evaluate(_config("OPSEC-DISK-001"), lock=lock)
    assert report.results[0].state is State.DRIFT


def test_converge_remediates_git(monkeypatch):
    state = {"user.name": "wrong", "user.email": "ghost@x.example"}
    monkeypatch.setattr(git_identity, "_git_get", lambda k: state[k])
    monkeypatch.setattr(git_identity, "_git_set", lambda k, v: state.__setitem__(k, v))
    config = _config("OPSEC-IDENTITY-101")
    report = evaluate(config)
    assert not report.conformant
    outcomes = converge(config, report)
    assert state["user.name"] == "ghost"
    assert outcomes and outcomes[0].state is State.OK


def test_detect_only_controls_are_not_remediated(monkeypatch):
    monkeypatch.setattr(disk, "_encryption_enabled", lambda: False)  # violation, not remediable
    config = _config("OPSEC-DISK-001")
    report = evaluate(config)
    assert converge(config, report) == []
