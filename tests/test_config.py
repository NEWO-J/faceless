"""Config loading + validation."""

from __future__ import annotations

import pytest

from fle.config import OpsecConfig
from fle.errors import ConfigError
from fle.model import Severity

VALID = {
    "opsec_version": 1,
    "name": "t",
    "identity": {
        "persona": {"git_name": "ghost", "git_email": "ghost@x.example"},
        "real": {"names": ["Jane Doe"], "emails": ["jane@real.example"]},
    },
    "posture": [
        {"control": "OPSEC-IDENTITY-101"},
        {"control": "OPSEC-SECRET-060", "params": {"forbidden_paths": ["~/.netrc"]}},
        {"control": "OPSEC-DISK-001", "severity": "critical"},
    ],
    "enforcement": {"on_command": "block", "auto_remediate": "full"},
}


def test_valid_config_parses():
    cfg = OpsecConfig.from_mapping(VALID)
    assert cfg.name == "t"
    assert len(cfg.posture) == 3
    assert cfg.enforcement.on_command == "block"
    assert cfg.identity.persona["git_email"] == "ghost@x.example"
    assert "jane@real.example" in cfg.identity.real_values()


def test_severity_override_applied():
    cfg = OpsecConfig.from_mapping(VALID)
    disk = next(i for i in cfg.posture if i.control_id == "OPSEC-DISK-001")
    assert disk.severity is Severity.CRITICAL


def test_bad_version_rejected():
    with pytest.raises(ConfigError):
        OpsecConfig.from_mapping({**VALID, "opsec_version": 2})


def test_unknown_control_rejected():
    with pytest.raises(ConfigError):
        OpsecConfig.from_mapping({**VALID, "posture": [{"control": "OPSEC-NOPE-999"}]})


def test_empty_posture_rejected():
    with pytest.raises(ConfigError):
        OpsecConfig.from_mapping({**VALID, "posture": []})


def test_duplicate_control_rejected():
    doc = {**VALID, "posture": [{"control": "OPSEC-DISK-001"}, {"control": "OPSEC-DISK-001"}]}
    with pytest.raises(ConfigError):
        OpsecConfig.from_mapping(doc)


def test_bad_enforcement_rejected():
    with pytest.raises(ConfigError):
        OpsecConfig.from_mapping({**VALID, "enforcement": {"on_command": "explode"}})
