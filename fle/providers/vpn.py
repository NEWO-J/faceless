"""OPSEC-EGRESS-001 — declared VPN interface is present.

A silently-dropped tunnel is the highest-consequence drift: your real IP and
cleartext metadata are suddenly exposed to the ISP while you believe you're
covered. This provider checks that the declared interface exists. Presence is a
cheap, reliable proxy for "the tunnel is up"; a full route-table assertion is a
future refinement. Marked *expensive* so the per-command hot path uses a cached
result. Detect-only (bringing a tunnel up is out of scope for the engine).
"""

from __future__ import annotations

import platform
import subprocess

from ..model import State
from .base import Provider, ProviderContext
from .registry import register


def _list_interfaces() -> set[str]:
    """Return the set of network interface names. Overridable in tests."""
    try:
        import psutil  # type: ignore

        return set(psutil.net_if_addrs().keys())
    except Exception:
        pass

    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=15, check=False,
            ).stdout
            return {line.strip() for line in out.splitlines() if line.strip()}
        # Linux / macOS: /sys or `ip`/`ifconfig`
        from pathlib import Path

        sysnet = Path("/sys/class/net")
        if sysnet.is_dir():
            return {p.name for p in sysnet.iterdir()}
        out = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
        return {line.split(":")[1].strip() for line in out.splitlines() if ":" in line}
    except (OSError, subprocess.SubprocessError):
        return set()


class VpnInterfaceProvider(Provider):
    control_id = "OPSEC-EGRESS-001"

    def observe(self, ctx: ProviderContext):
        interface = str(ctx.params.get("interface", "")).strip()
        if not interface:
            return self.result(
                ctx, State.NOT_APPLICABLE,
                "no `interface` param declared for the egress control",
            )
        interfaces = _list_interfaces()
        if not interfaces:
            return self.result(
                ctx, State.ERROR,
                "could not enumerate network interfaces",
                detail="install `psutil` or ensure the platform tool is available.",
            )
        present = interface in interfaces
        observed = {"interface": interface, "present": str(present).lower()}
        if present:
            return self.result(
                ctx, State.OK, f"VPN interface {interface!r} is present",
                observed=observed,
            )
        return self.result(
            ctx, State.VIOLATION,
            f"VPN interface {interface!r} is MISSING — tunnel may be down",
            detail=f"present interfaces: {sorted(interfaces)}",
            observed=observed,
        )


register(VpnInterfaceProvider())
