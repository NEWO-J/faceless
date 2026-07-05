"""The control catalog — the heart of the OpSec-as-Code standard.

Each control has a **stable ID** in a namespaced scheme (``FLE-<DOMAIN>-<NNN>``)
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
    "FLE-IDENTITY-101": ControlSpec(
        id="FLE-IDENTITY-101",
        domain="identity",
        title="Git identity matches persona and never the real identity",
        default_severity=Severity.CRITICAL,
        remediable=True,
        rationale=(
            "A forgotten git identity is the classic pseudonymity leak: one commit "
            "under your real name/email correlates the persona back to you."
        ),
    ),
    "FLE-SECRET-050": ControlSpec(
        id="FLE-SECRET-050",
        domain="secret",
        title="No secret-like values present in the environment",
        default_severity=Severity.HIGH,
        remediable=False,
        rationale="Secrets in env vars leak into child processes, logs, and crash dumps.",
    ),
    "FLE-SECRET-060": ControlSpec(
        id="FLE-SECRET-060",
        domain="secret",
        title="Declared plaintext secret files are absent",
        default_severity=Severity.HIGH,
        remediable=False,
        rationale="Long-lived plaintext credential files are a standing harvest target.",
    ),
    "FLE-EGRESS-001": ControlSpec(
        id="FLE-EGRESS-001",
        domain="egress",
        title="Declared VPN interface is present and carries the default route",
        default_severity=Severity.CRITICAL,
        remediable=False,
        rationale="A silently-dropped tunnel exposes real IP and cleartext metadata to the ISP.",
        expensive=True,
    ),
    "FLE-DISK-001": ControlSpec(
        id="FLE-DISK-001",
        domain="disk",
        title="System volume encryption is enabled",
        default_severity=Severity.HIGH,
        remediable=False,
        rationale="Without full-disk encryption, physical access defeats every other control.",
        expensive=True,
    ),
    # -- Network / egress leaks (Linux) ------------------------------------
    "FLE-EGRESS-002": ControlSpec(
        id="FLE-EGRESS-002", domain="egress",
        title="Default route rides the declared VPN interface",
        default_severity=Severity.CRITICAL, remediable=False,
        rationale="An up tunnel with the default route elsewhere still leaks all traffic.",
    ),
    "FLE-NET-001": ControlSpec(
        id="FLE-NET-001", domain="net",
        title="DNS resolvers are all on the allowlist",
        default_severity=Severity.HIGH, remediable=False,
        rationale="DNS to an ISP/unapproved resolver leaks every domain you visit.",
    ),
    "FLE-NET-002": ControlSpec(
        id="FLE-NET-002", domain="net",
        title="IPv6 is disabled or routed through the VPN",
        default_severity=Severity.HIGH, remediable=False,
        rationale="IPv6 commonly bypasses an IPv4-only tunnel and leaks the real address.",
    ),
    "FLE-NET-003": ControlSpec(
        id="FLE-NET-003", domain="net",
        title="Firewall denies by default on required chains",
        default_severity=Severity.HIGH, remediable=False,
        rationale="A default-deny egress policy is the kill-switch that stops leaks when the tunnel drops.",
        expensive=True,
    ),
    "FLE-NET-004": ControlSpec(
        id="FLE-NET-004", domain="net",
        title="No unexpected services listening on non-loopback",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="Every exposed port is attack surface and a potential fingerprint.",
        expensive=True,
    ),
    "FLE-NET-005": ControlSpec(
        id="FLE-NET-005", domain="net",
        title="DNS is encrypted (DNS-over-TLS)",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="Cleartext DNS lets the resolver and every hop log what you look up.",
    ),
    "FLE-NET-006": ControlSpec(
        id="FLE-NET-006", domain="net",
        title="Resolver is not the LAN gateway (ISP router)",
        default_severity=Severity.HIGH, remediable=False,
        rationale="Using the router's DNS hands your full browsing history to the ISP.",
    ),
    "FLE-NET-007": ControlSpec(
        id="FLE-NET-007", domain="net",
        title="LLMNR is disabled",
        default_severity=Severity.HIGH, remediable=False,
        rationale="LLMNR broadcasts your hostname and enables Responder-style hash capture.",
    ),
    "FLE-NET-008": ControlSpec(
        id="FLE-NET-008", domain="net",
        title="mDNS is not broadcasting the host",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="Avahi/mDNS advertises your device name and services to the whole LAN.",
    ),
    "FLE-NET-009": ControlSpec(
        id="FLE-NET-009", domain="net",
        title="IPv6 privacy extensions are enabled",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="A stable IPv6 interface ID tracks you across every network you join.",
    ),
    "FLE-NET-010": ControlSpec(
        id="FLE-NET-010", domain="net",
        title="No MAC-derived (EUI-64) IPv6 address",
        default_severity=Severity.HIGH, remediable=False,
        rationale="An EUI-64 address embeds your MAC, a permanent hardware fingerprint.",
    ),
    "FLE-NET-011": ControlSpec(
        id="FLE-NET-011", domain="net",
        title="Wi-Fi MAC randomization is configured",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="A static MAC lets networks and trackers follow your device between locations.",
    ),
    "FLE-NET-012": ControlSpec(
        id="FLE-NET-012", domain="net",
        title="Captive-portal connectivity check is disabled",
        default_severity=Severity.MEDIUM, remediable=False,
        rationale="NetworkManager pings a check URL on every join, phoning home your presence.",
    ),
    "FLE-NET-013": ControlSpec(
        id="FLE-NET-013", domain="net",
        title="TCP timestamps are disabled",
        default_severity=Severity.LOW, remediable=False,
        rationale="TCP timestamps leak system uptime, a passive fingerprint.",
    ),
    "FLE-NET-014": ControlSpec(
        id="FLE-NET-014", domain="net",
        title="Public egress IP is not a forbidden (real) address",
        default_severity=Severity.CRITICAL, remediable=False,
        rationale="The definitive leak test: prove the outside world does not see your real IP.",
        expensive=True,
    ),
    # -- Operating-system target -------------------------------------------
    "FLE-OS-001": ControlSpec(
        id="FLE-OS-001", domain="os",
        title="Running the declared target operating system",
        default_severity=Severity.CRITICAL, remediable=False,
        rationale="Doing sensitive work on the wrong OS (host instead of Tails/Whonix) "
                  "voids the entire threat model.",
    ),
}

# Named bundles: expand to a set of control IDs so a config can pull a whole
# domain in one line while staying fully declarative.
BUNDLES: dict[str, list[str]] = {
    "linux-net": [
        "FLE-EGRESS-001", "FLE-EGRESS-002",
        "FLE-NET-001", "FLE-NET-002", "FLE-NET-003", "FLE-NET-004",
        "FLE-NET-005", "FLE-NET-006", "FLE-NET-007", "FLE-NET-008",
        "FLE-NET-009", "FLE-NET-010", "FLE-NET-011", "FLE-NET-012",
        "FLE-NET-013",
    ],
    # Anonymity-OS presets: verify the OS, plus the leak checks that matter most
    # on Tails/Whonix (IPv6 off, no MAC-derived address, MAC randomization).
    "tails": ["FLE-OS-001", "FLE-NET-002", "FLE-NET-010", "FLE-NET-011"],
    "whonix": ["FLE-OS-001", "FLE-NET-002", "FLE-NET-010", "FLE-NET-011"],
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
