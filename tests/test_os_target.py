"""OS-target detection, matching, and the FLE-OS-001 control."""

from __future__ import annotations

import pytest

from fle.catalog import BUNDLES, get_control
from fle.config import OpsecConfig
from fle.model import State
from fle.providers import os_target
from fle.providers.base import ProviderContext


def _ctx(expect):
    doc = {"opsec_version": 1, "name": "t",
           "os": {"expect": expect},
           "posture": [{"control": "FLE-OS-001"}]}
    cfg = OpsecConfig.from_mapping(doc)
    return ProviderContext(cfg, cfg.posture[0], get_control("FLE-OS-001"))


# -- detection -------------------------------------------------------------

def test_detect_tails(monkeypatch):
    monkeypatch.setattr(os_target, "_system", lambda: "Linux")
    monkeypatch.setattr(os_target, "_exists", lambda p: p == "/etc/amnesia")
    monkeypatch.setattr(os_target, "_os_release", lambda: {"ID": "debian"})
    assert os_target.detect_os() == "tails"


def test_detect_whonix_workstation(monkeypatch):
    monkeypatch.setattr(os_target, "_system", lambda: "Linux")
    monkeypatch.setattr(os_target, "_exists", lambda p: p == "/usr/share/anon-ws-base-files")
    monkeypatch.setattr(os_target, "_os_release", lambda: {"ID": "debian"})
    assert os_target.detect_os() == "whonix-workstation"


def test_detect_plain_distro(monkeypatch):
    monkeypatch.setattr(os_target, "_system", lambda: "Linux")
    monkeypatch.setattr(os_target, "_exists", lambda p: False)
    monkeypatch.setattr(os_target, "_os_release", lambda: {"ID": "ubuntu"})
    assert os_target.detect_os() == "ubuntu"


def test_detect_windows(monkeypatch):
    monkeypatch.setattr(os_target, "_system", lambda: "Windows")
    assert os_target.detect_os() == "windows"


# -- matching --------------------------------------------------------------

def test_umbrella_matching():
    assert os_target.os_matches("whonix", "whonix-workstation")
    assert os_target.os_matches("anonymity", "tails")
    assert os_target.os_matches("linux", "debian")
    assert not os_target.os_matches("tails", "ubuntu")


# -- control ---------------------------------------------------------------

def test_os_control_ok(monkeypatch):
    monkeypatch.setattr(os_target, "detect_os", lambda: "whonix-workstation")
    assert os_target.OsTargetProvider().observe(_ctx("whonix")).state is State.OK


def test_os_control_violation(monkeypatch):
    monkeypatch.setattr(os_target, "detect_os", lambda: "ubuntu")
    r = os_target.OsTargetProvider().observe(_ctx("tails"))
    assert r.state is State.VIOLATION
    assert r.observed["os"] == "ubuntu"


def test_os_control_list_expect(monkeypatch):
    monkeypatch.setattr(os_target, "detect_os", lambda: "tails")
    assert os_target.OsTargetProvider().observe(_ctx(["tails", "whonix"])).state is State.OK


def test_os_not_declared_is_not_applicable():
    doc = {"opsec_version": 1, "name": "t", "posture": [{"control": "FLE-OS-001"}]}
    cfg = OpsecConfig.from_mapping(doc)
    ctx = ProviderContext(cfg, cfg.posture[0], get_control("FLE-OS-001"))
    assert os_target.OsTargetProvider().observe(ctx).state is State.NOT_APPLICABLE


# -- config + bundles ------------------------------------------------------

def test_config_parses_os_string():
    cfg = OpsecConfig.from_mapping({"opsec_version": 1, "name": "t",
                                    "os": {"expect": "Whonix-Workstation"},
                                    "posture": [{"control": "FLE-OS-001"}]})
    assert cfg.os_policy.expected == ("whonix-workstation",)


def test_tails_and_whonix_bundles_exist_and_resolve():
    from fle.catalog import CATALOG
    for name in ("tails", "whonix"):
        assert name in BUNDLES
        for cid in BUNDLES[name]:
            assert cid in CATALOG
