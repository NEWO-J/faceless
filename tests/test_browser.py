"""Browser fingerprinting-resistance controls against mocked Firefox prefs."""

from __future__ import annotations

from fle.catalog import BUNDLES, get_control
from fle.config import OpsecConfig
from fle.model import State
from fle.providers import browser
from fle.providers.base import ProviderContext


def _ctx(control_id):
    doc = {"opsec_version": 1, "name": "t", "posture": [{"control": control_id}]}
    cfg = OpsecConfig.from_mapping(doc)
    return ProviderContext(cfg, cfg.posture[0], get_control(control_id))


def _prefs(monkeypatch, prefs):
    monkeypatch.setattr(browser, "_firefox_prefs", lambda: prefs)


def test_no_firefox_is_not_applicable(monkeypatch):
    _prefs(monkeypatch, None)
    assert browser.ResistFingerprintingProvider().observe(_ctx("FLE-BROWSER-001")).state is State.NOT_APPLICABLE


def test_resist_fingerprinting(monkeypatch):
    _prefs(monkeypatch, {"privacy.resistFingerprinting": "true"})
    assert browser.ResistFingerprintingProvider().observe(_ctx("FLE-BROWSER-001")).state is State.OK
    _prefs(monkeypatch, {"privacy.resistFingerprinting": "false"})
    assert browser.ResistFingerprintingProvider().observe(_ctx("FLE-BROWSER-001")).state is State.VIOLATION
    _prefs(monkeypatch, {})  # unset defaults to off
    assert browser.ResistFingerprintingProvider().observe(_ctx("FLE-BROWSER-001")).state is State.VIOLATION


def test_webrtc_disabled(monkeypatch):
    _prefs(monkeypatch, {"media.peerconnection.enabled": "false"})
    assert browser.WebrtcDisabledProvider().observe(_ctx("FLE-BROWSER-002")).state is State.OK
    _prefs(monkeypatch, {"media.peerconnection.enabled": "true"})
    assert browser.WebrtcDisabledProvider().observe(_ctx("FLE-BROWSER-002")).state is State.VIOLATION
    _prefs(monkeypatch, {})  # default enabled -> violation
    assert browser.WebrtcDisabledProvider().observe(_ctx("FLE-BROWSER-002")).state is State.VIOLATION


def test_canvas_webgl_either_way(monkeypatch):
    _prefs(monkeypatch, {"webgl.disabled": "true"})
    assert browser.CanvasWebglProvider().observe(_ctx("FLE-BROWSER-003")).state is State.OK
    _prefs(monkeypatch, {"privacy.resistFingerprinting": "true"})
    assert browser.CanvasWebglProvider().observe(_ctx("FLE-BROWSER-003")).state is State.OK
    _prefs(monkeypatch, {"webgl.disabled": "false"})
    assert browser.CanvasWebglProvider().observe(_ctx("FLE-BROWSER-003")).state is State.VIOLATION


def test_telemetry(monkeypatch):
    _prefs(monkeypatch, {"toolkit.telemetry.enabled": "false",
                         "datareporting.healthreport.uploadEnabled": "false"})
    assert browser.BrowserTelemetryProvider().observe(_ctx("FLE-BROWSER-004")).state is State.OK
    _prefs(monkeypatch, {"toolkit.telemetry.enabled": "true"})
    assert browser.BrowserTelemetryProvider().observe(_ctx("FLE-BROWSER-004")).state is State.VIOLATION


def test_letterboxing(monkeypatch):
    _prefs(monkeypatch, {"privacy.resistFingerprinting.letterboxing": "true"})
    assert browser.LetterboxingProvider().observe(_ctx("FLE-BROWSER-005")).state is State.OK
    _prefs(monkeypatch, {})
    assert browser.LetterboxingProvider().observe(_ctx("FLE-BROWSER-005")).state is State.VIOLATION


def test_pref_parser_reads_userpref_lines(tmp_path, monkeypatch):
    profile = tmp_path / "abcd.default"
    profile.mkdir()
    (profile / "prefs.js").write_text(
        'user_pref("privacy.resistFingerprinting", true);\n'
        'user_pref("media.peerconnection.enabled", false);\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(browser, "_profile_root", lambda: tmp_path)
    prefs = browser._firefox_prefs()
    assert prefs["privacy.resistFingerprinting"] == "true"
    assert prefs["media.peerconnection.enabled"] == "false"


def test_browser_bundle_resolves():
    from fle.catalog import CATALOG
    assert "browser-hardening" in BUNDLES
    for cid in BUNDLES["browser-hardening"]:
        assert cid in CATALOG
