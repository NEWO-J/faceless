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
    # -- Network / egress leaks (Linux) ------------------------------------
    "OPSEC-EGRESS-002": ControlSpec(
        id="OPSEC-EGRESS-002", domain="egress",
        title="Default route rides the declared VPN interface",
        default_severity=Severity.CRITICAL, remediable=False,
        rationale="An up tunnel with the default route elsewhere still leaks all traffic.",
    ),
    "OPSEC-NET-001": ControlSpec(
        id="OPSEC-NET-001", domain="net",
        title="DNS resolvers are all on the allowlist",
        default_severity=Severity.HIGH, remediable=False,
        rationale="DNS to an ISP/unapproved resolver leaks every domain you visit.",
    ),
    "OPSEC-NET-002": ControlSpec(
        id="OPSEC-NET-002", domain="net",
        title="IPv6 is disabled or routed through the VPN",
        default_severity=Severity.HIGH, remediable=False,
        rationale="IPv6 commonly bypasses an IPv4-only tunnel and leaks the real address.",
    ),
    "OPSEC-NET-003": ControlSpec(
        id="OPSEC-NET-003", domain="net",
        title="Firewall denies by default on required chains",
        default_severity=Severity.HIGH, remediable=False,
        rationale="A default-deny egress policy is the kill-switch that stops leaks when the tunnel drops.",
        expensive=True,
    ),
    "OPSEC-NET-004": ControlSpec(
        id="OPSEC-NET-004", domain="net",
        title="No unexpected services listening on non-loopback",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="Every exposed port is attack surface and a potential fingerprint.",
        expensive=True,
    ),
    # -- System hardening / privesc (Linux) --------------------------------
    "OPSEC-PRIV-001": ControlSpec(
        id="OPSEC-PRIV-001", domain="privesc",
        title="No known-exploitable SUID binaries",
        default_severity=Severity.HIGH, remediable=False,
        rationale="SUID GTFOBins hand a local attacker an easy root shell.",
        expensive=True,
    ),
    "OPSEC-PRIV-002": ControlSpec(
        id="OPSEC-PRIV-002", domain="privesc",
        title="sudo requires a password (no NOPASSWD)",
        default_severity=Severity.HIGH, remediable=False,
        rationale="NOPASSWD turns any stolen session into instant root.",
    ),
    "OPSEC-PRIV-003": ControlSpec(
        id="OPSEC-PRIV-003", domain="privesc",
        title="No user-writable directories in PATH",
        default_severity=Severity.HIGH, remediable=False,
        rationale="A writable PATH dir lets an attacker shadow a trusted command.",
    ),
    "OPSEC-PRIV-004": ControlSpec(
        id="OPSEC-PRIV-004", domain="privesc",
        title="SSH does not permit direct root login",
        default_severity=Severity.HIGH, remediable=False,
        rationale="Direct root login removes the audit trail and invites brute force.",
    ),
    "OPSEC-PRIV-005": ControlSpec(
        id="OPSEC-PRIV-005", domain="privesc",
        title="ptrace scope hardening is enabled",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="ptrace_scope=0 lets any process read another's memory, including secrets.",
    ),
}

# Named bundles: expand to a set of control IDs so a config can pull a whole
# domain in one line while staying fully declarative.
BUNDLES: dict[str, list[str]] = {
    "linux-net": [
        "OPSEC-EGRESS-001", "OPSEC-EGRESS-002",
        "OPSEC-NET-001", "OPSEC-NET-002", "OPSEC-NET-003", "OPSEC-NET-004",
    ],
    "linux-privesc": [
        "OPSEC-PRIV-001", "OPSEC-PRIV-002", "OPSEC-PRIV-003",
        "OPSEC-PRIV-004", "OPSEC-PRIV-005",
    ],
}


def get_bundle(name: str) -> list[str]:
    bundle = BUNDLES.get(name)
    if bundle is None:
        raise ConfigError(f"unknown bundle {name!r}; known bundles: {sorted(BUNDLES)}")
    return list(bundle)


def get_control(control_id: str) -> ControlSpec:
    spec = CATALOG.get(control_id)
    if spec is None:
        raise ConfigError(
            f"unknown control {control_id!r}; known controls: {sorted(CATALOG)}"
        )
    return spec
