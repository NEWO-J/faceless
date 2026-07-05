"""Declarative custom controls: parsing, evaluation, and engine integration."""

from __future__ import annotations

import sys

import pytest

from fle import custom
from fle.config import OpsecConfig
from fle.engine import evaluate
from fle.errors import ConfigError
from fle.model import State


def _cfg(controls, posture=None):
    doc = {"opsec_version": 1, "name": "t", "controls": controls,
           "posture": posture or [{"control": c["id"]} for c in controls]}
    return OpsecConfig.from_mapping(doc)


# -- parsing / validation --------------------------------------------------

def test_custom_control_parses_and_registers():
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "title": "x", "kind": "env",
                 "var": "PATH", "assert": {"exists": True}}])
    assert "FLE-CUSTOM-001" in cfg.custom_controls
    assert cfg.spec_for("FLE-CUSTOM-001").title == "x"


def test_bad_id_rejected():
    with pytest.raises(ConfigError):
        _cfg([{"id": "custom-1", "kind": "env", "var": "X", "assert": {"exists": True}}])


def test_collision_with_builtin_rejected():
    with pytest.raises(ConfigError):
        _cfg([{"id": "FLE-DISK-001", "kind": "env", "var": "X", "assert": {"exists": True}}])


def test_missing_kind_field_rejected():
    with pytest.raises(ConfigError):
        _cfg([{"id": "FLE-CUSTOM-001", "kind": "command", "assert": {"exit_zero": True}}])  # no run


def test_empty_assert_rejected():
    with pytest.raises(ConfigError):
        _cfg([{"id": "FLE-CUSTOM-001", "kind": "env", "var": "X", "assert": {}}])


def test_posture_can_reference_custom_control():
    cfg = _cfg(
        [{"id": "FLE-CUSTOM-050", "kind": "env", "var": "X", "assert": {"exists": True}}],
        posture=[{"control": "FLE-CUSTOM-050", "severity": "critical"}],
    )
    assert cfg.posture[0].control_id == "FLE-CUSTOM-050"
    assert cfg.posture[0].severity.value == "critical"


# -- evaluation ------------------------------------------------------------

def test_env_exists(monkeypatch):
    monkeypatch.setenv("FLE_TEST_VAR", "hi")
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "kind": "env", "var": "FLE_TEST_VAR",
                 "assert": {"exists": True}}])
    assert evaluate(cfg).results[0].state is State.OK


def test_env_absent_violation(monkeypatch):
    monkeypatch.delenv("FLE_MISSING", raising=False)
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "kind": "env", "var": "FLE_MISSING",
                 "assert": {"exists": True}}])
    assert evaluate(cfg).results[0].state is State.VIOLATION


def test_file_absent_ok(tmp_path):
    target = tmp_path / "nope.txt"
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "kind": "file", "path": str(target),
                 "assert": {"absent": True}}])
    assert evaluate(cfg).results[0].state is State.OK


def test_file_contains(tmp_path):
    target = tmp_path / "conf"
    target.write_text("PermitRootLogin no\n", encoding="utf-8")
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "kind": "file", "path": str(target),
                 "assert": {"contains": "PermitRootLogin no"}}])
    assert evaluate(cfg).results[0].state is State.OK


def test_command_content_and_max():
    py = sys.executable
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "kind": "command",
                 "run": [py, "-c", "print(42)"], "assert": {"max": 100}}])
    assert evaluate(cfg).results[0].state is State.OK
    cfg2 = _cfg([{"id": "FLE-CUSTOM-002", "kind": "command",
                  "run": [py, "-c", "print(999)"], "assert": {"max": 100}}])
    assert evaluate(cfg2).results[0].state is State.VIOLATION


def test_command_exit_zero():
    py = sys.executable
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "kind": "command",
                 "run": [py, "-c", "import sys; sys.exit(0)"], "assert": {"exit_zero": True}}])
    assert evaluate(cfg).results[0].state is State.OK


def test_sysctl_is_linux_gated(monkeypatch):
    monkeypatch.setattr(custom, "on_linux", lambda: False)
    cfg = _cfg([{"id": "FLE-CUSTOM-001", "kind": "sysctl",
                 "key": "net.ipv4.tcp_timestamps", "assert": {"equals": "0"}}])
    assert evaluate(cfg).results[0].state is State.NOT_APPLICABLE


def test_custom_control_counts_toward_conformance():
    cfg = _cfg(
        [{"id": "FLE-CUSTOM-001", "kind": "env", "var": "FLE_DEFINITELY_MISSING",
          "assert": {"exists": True}, "severity": "high"}],
    )
    report = evaluate(cfg)
    assert not report.conformant
