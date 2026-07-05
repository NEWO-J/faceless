"""Browser fingerprinting-resistance controls (Firefox / Tor Browser).

The goal here is the community's goal: *uniformity*, not uniqueness. A hardened
browser makes you look like everyone else in the Tor Browser crowd (standardized
user agent, rounded window size, blocked canvas/WebGL, no WebRTC), which is what
actually shrinks your fingerprint. These controls verify that hardening is on;
they do not spoof or rotate anything.

Firefox is the tractable target: it exposes fingerprinting resistance through
prefs, and Tor Browser (shipped by Tails/Whonix) is Firefox-based with these on
by default. Cross-platform. Reports ``not_applicable`` when no Firefox profile is
found.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from ..model import State
from .base import Provider, ProviderContext
from .registry import register

_PREF_RE = re.compile(r'user_pref\(\s*"([^"]+)"\s*,\s*([^)]+?)\s*\)\s*;')


def _profile_root() -> Path:
    home = Path.home()
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", str(home))) / "Mozilla" / "Firefox" / "Profiles"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Firefox" / "Profiles"
    return home / ".mozilla" / "firefox"


def _firefox_prefs() -> dict[str, str] | None:
    """Merge user_pref entries across Firefox profiles. Overridable in tests."""
    root = _profile_root()
    if not root.is_dir():
        return None
    prefs: dict[str, str] = {}
    found = False
    for profile in root.iterdir():
        if not profile.is_dir():
            continue
        for name in ("prefs.js", "user.js"):
            path = profile / name
            if not path.is_file():
                continue
            found = True
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in _PREF_RE.finditer(text):
                prefs[match.group(1)] = match.group(2).strip().strip('"')
    return prefs if found else None


def _bool_pref(prefs: dict[str, str], key: str) -> bool | None:
    value = prefs.get(key)
    if value is None:
        return None
    return value.strip().lower() == "true"


class _FirefoxProvider(Provider):
    def _prefs(self, ctx: ProviderContext):
        prefs = _firefox_prefs()
        if prefs is None:
            return None, self.result(ctx, State.NOT_APPLICABLE, "no Firefox profile found")
        return prefs, None


class ResistFingerprintingProvider(_FirefoxProvider):
    control_id = "FLE-BROWSER-001"

    def observe(self, ctx: ProviderContext):
        prefs, na = self._prefs(ctx)
        if na:
            return na
        on = _bool_pref(prefs, "privacy.resistFingerprinting")
        observed = {"resistFingerprinting": str(on).lower()}
        if on:
            return self.result(ctx, State.OK, "resistFingerprinting is on (uniform fingerprint)",
                               observed=observed)
        return self.result(
            ctx, State.VIOLATION, "resistFingerprinting is off — your browser is uniquely trackable",
            detail="set privacy.resistFingerprinting=true (or use Tor Browser).", observed=observed,
        )


class WebrtcDisabledProvider(_FirefoxProvider):
    control_id = "FLE-BROWSER-002"

    def observe(self, ctx: ProviderContext):
        prefs, na = self._prefs(ctx)
        if na:
            return na
        enabled = _bool_pref(prefs, "media.peerconnection.enabled")
        observed = {"webrtc_enabled": str(enabled).lower()}
        if enabled is False:
            return self.result(ctx, State.OK, "WebRTC is disabled", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "WebRTC is enabled (can leak your real IP past the VPN)",
            detail="set media.peerconnection.enabled=false.", observed=observed,
        )


class CanvasWebglProvider(_FirefoxProvider):
    control_id = "FLE-BROWSER-003"

    def observe(self, ctx: ProviderContext):
        prefs, na = self._prefs(ctx)
        if na:
            return na
        rfp = _bool_pref(prefs, "privacy.resistFingerprinting")
        webgl_off = _bool_pref(prefs, "webgl.disabled")
        observed = {"resistFingerprinting": str(rfp).lower(), "webgl_disabled": str(webgl_off).lower()}
        if rfp or webgl_off:
            return self.result(ctx, State.OK, "canvas/WebGL fingerprinting is mitigated", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "canvas/WebGL fingerprinting is not mitigated",
            detail="enable privacy.resistFingerprinting or set webgl.disabled=true.", observed=observed,
        )


class BrowserTelemetryProvider(_FirefoxProvider):
    control_id = "FLE-BROWSER-004"

    def observe(self, ctx: ProviderContext):
        prefs, na = self._prefs(ctx)
        if na:
            return na
        telemetry = _bool_pref(prefs, "toolkit.telemetry.enabled")
        healthreport = _bool_pref(prefs, "datareporting.healthreport.uploadEnabled")
        observed = {"telemetry": str(telemetry).lower(), "healthreport": str(healthreport).lower()}
        if telemetry is False and healthreport is not True:
            return self.result(ctx, State.OK, "browser telemetry is disabled", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "browser telemetry is on (phones home usage data)",
            detail="set toolkit.telemetry.enabled=false and disable health-report upload.",
            observed=observed,
        )


class LetterboxingProvider(_FirefoxProvider):
    control_id = "FLE-BROWSER-005"

    def observe(self, ctx: ProviderContext):
        prefs, na = self._prefs(ctx)
        if na:
            return na
        on = _bool_pref(prefs, "privacy.resistFingerprinting.letterboxing")
        observed = {"letterboxing": str(on).lower()}
        if on:
            return self.result(ctx, State.OK, "RFP letterboxing rounds the window size", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "letterboxing is off — exact window size is a fingerprint",
            detail="set privacy.resistFingerprinting.letterboxing=true.", observed=observed,
        )


for _p in (ResistFingerprintingProvider(), WebrtcDisabledProvider(), CanvasWebglProvider(),
           BrowserTelemetryProvider(), LetterboxingProvider()):
    register(_p)
