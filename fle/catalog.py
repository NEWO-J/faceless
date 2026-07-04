"""The control catalog — the heart of the OpSec-as-Code standard.

Each control has a **stable ID** in a namespaced scheme (``OPSEC-<DOMAIN>-<NNN>``)
that a policy can cite and that survives across releases. The catalog is
data-only; the *how* of each check lives in a provider (``fle/providers``) keyed
by the same ID.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import ConfigError
from .model import Severity


@dataclass(frozen=True, slots=True)
class ControlSpec:
    id: str
    domain: str
    title: str
    default_severity: Severity
    remediable: bool
    rationale: str = ""
    #: True for checks too slow to run on every prompt; cached in fast mode.
    expensive: bool = False


CATALOG: dict[str, ControlSpec] = {
    "OPSEC-IDENTITY-101": ControlSpec(
        id="OPSEC-IDENTITY-101",
        domain="identity",
        title="Git identity matches persona and never the real identity",
        default_severity=Severity.CRITICAL,
        remediable=True,
        rationale=(
            "A forgotten git identity is the classic pseudonymity leak: one commit "
            "under your real name/email correlates the persona back to you."
        ),
    ),
    "OPSEC-SECRET-050": ControlSpec(
        id="OPSEC-SECRET-050",
        domain="secret",
        title="No secret-like values present in the environment",
        default_severity=Severity.HIGH,
        remediable=False,
        rationale="Secrets in env vars leak into child processes, logs, and crash dumps.",
    ),
    "OPSEC-SECRET-060": ControlSpec(
        id="OPSEC-SECRET-060",
        domain="secret",
        title="Declared plaintext secret files are absent",
        default_severity=Severity.HIGH,
        remediable=False,
        rationale="Long-lived plaintext credential files are a standing harvest target.",
    ),
    "OPSEC-EGRESS-001": ControlSpec(
        id="OPSEC-EGRESS-001",
        domain="egress",
        title="Declared VPN interface is present and carries the default route",
        default_severity=Severity.CRITICAL,
        remediable=False,
        rationale="A silently-dropped tunnel exposes real IP and cleartext metadata to the ISP.",
        expensive=True,
    ),
    "OPSEC-DISK-001": ControlSpec(
        id="OPSEC-DISK-001",
        domain="disk",
        title="System volume encryption is enabled",
        default_severity=Severity.HIGH,
        remediable=False,
        rationale="Without full-disk encryption, physical access defeats every other control.",
        expensive=True,
    ),
}


def get_control(control_id: str) -> ControlSpec:
    spec = CATALOG.get(control_id)
    if spec is None:
        raise ConfigError(
            f"unknown control {control_id!r}; known controls: {sorted(CATALOG)}"
        )
    return spec
