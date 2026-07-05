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
    "OPSEC-NET-005": ControlSpec(
        id="OPSEC-NET-005", domain="net",
        title="DNS is encrypted (DNS-over-TLS)",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="Cleartext DNS lets the resolver and every hop log what you look up.",
    ),
    "OPSEC-NET-006": ControlSpec(
        id="OPSEC-NET-006", domain="net",
        title="Resolver is not the LAN gateway (ISP router)",
        default_severity=Severity.HIGH, remediable=False,
        rationale="Using the router's DNS hands your full browsing history to the ISP.",
    ),
    "OPSEC-NET-007": ControlSpec(
        id="OPSEC-NET-007", domain="net",
        title="LLMNR is disabled",
        default_severity=Severity.HIGH, remediable=False,
        rationale="LLMNR broadcasts your hostname and enables Responder-style hash capture.",
    ),
    "OPSEC-NET-008": ControlSpec(
        id="OPSEC-NET-008", domain="net",
        title="mDNS is not broadcasting the host",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="Avahi/mDNS advertises your device name and services to the whole LAN.",
    ),
    "OPSEC-NET-009": ControlSpec(
        id="OPSEC-NET-009", domain="net",
        title="IPv6 privacy extensions are enabled",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="A stable IPv6 interface ID tracks you across every network you join.",
    ),
    "OPSEC-NET-010": ControlSpec(
        id="OPSEC-NET-010", domain="net",
        title="No MAC-derived (EUI-64) IPv6 address",
        default_severity=Severity.HIGH, remediable=False,
        rationale="An EUI-64 address embeds your MAC, a permanent hardware fingerprint.",
    ),
    "OPSEC-NET-011": ControlSpec(
        id="OPSEC-NET-011", domain="net",
        title="Wi-Fi MAC randomization is configured",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="A static MAC lets networks and trackers follow your device between locations.",
    ),
    "OPSEC-NET-012": ControlSpec(
        id="OPSEC-NET-012", domain="net",
        title="Captive-portal connectivity check is disabled",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="NetworkManager pings a check URL on every join, phoning home your presence.",
    ),
    "OPSEC-NET-013": ControlSpec(
        id="OPSEC-NET-013", domain="net",
        title="TCP timestamps are disabled",
        default_severity=Severity.LOW, remediable=False,
        rationale="TCP timestamps leak system uptime, a passive fingerprint.",
    ),
    "OPSEC-NET-014": ControlSpec(
        id="OPSEC-NET-014", domain="net",
        title="Public egress IP is not a forbidden (real) address",
        default_severity=Severity.CRITICAL, remediable=False,
        rationale="The definitive leak test: prove the outside world does not see your real IP.",
        expensive=True,
    ),
}

# Named bundles: expand to a set of control IDs so a config can pull a whole
# domain in one line while staying fully declarative.
BUNDLES: dict[str, list[str]] = {
    "linux-net": [
        "OPSEC-EGRESS-001", "OPSEC-EGRESS-002",
        "OPSEC-NET-001", "OPSEC-NET-002", "OPSEC-NET-003", "OPSEC-NET-004",
        "OPSEC-NET-005", "OPSEC-NET-006", "OPSEC-NET-007", "OPSEC-NET-008",
        "OPSEC-NET-009", "OPSEC-NET-010", "OPSEC-NET-011", "OPSEC-NET-012",
        "OPSEC-NET-013",
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
