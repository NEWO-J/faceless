"""Network / egress-leak controls (Linux).

These check that traffic actually leaves the way you declared: the default route
rides the VPN, DNS isn't leaking to a resolver you didn't authorize, IPv6 isn't
sneaking around the tunnel, the firewall denies by default, and nothing
unexpected is listening. Each control is Linux-only and reports
``not_applicable`` elsewhere.
"""

from __future__ import annotations

import re

from ..model import State
from . import linux
from .base import Provider, ProviderContext
from .registry import register


# -- observation seams (mockable) -----------------------------------------

def _default_route_iface(v6: bool = False) -> str | None:
    out = linux.run(["ip", "-o", "-6" if v6 else "-4", "route", "show", "default"])
    if not out:
        return None
    match = re.search(r"\bdev\s+(\S+)", out)
    return match.group(1) if match else None


def _nameservers() -> list[str]:
    text = linux.read("/etc/resolv.conf") or ""
    return [m.group(1) for m in re.finditer(r"(?m)^\s*nameserver\s+(\S+)", text)]


def _ipv6_disabled() -> bool:
    return linux.sysctl("net.ipv6.conf.all.disable_ipv6") == "1"


def _firewall_policies() -> dict[str, str] | None:
    """Return default chain policies, e.g. {'INPUT': 'DROP', 'OUTPUT': 'ACCEPT'}."""
    out = linux.run(["iptables", "-S"])
    if not out:
        return None
    policies: dict[str, str] = {}
    for match in re.finditer(r"(?m)^-P\s+(\w+)\s+(\w+)", out):
        policies[match.group(1).upper()] = match.group(2).upper()
    return policies or None


def _listening_ports() -> list[int] | None:
    """Ports bound on non-loopback addresses."""
    out = linux.run(["ss", "-tulnH"])
    if out is None:
        return None
    ports: set[int] = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        local = cols[4]
        addr, _, port = local.rpartition(":")
        if addr in ("127.0.0.1", "[::1]", "::1"):
            continue
        if port.isdigit():
            ports.add(int(port))
    return sorted(ports)


# -- providers -------------------------------------------------------------

class _LinuxProvider(Provider):
    def _guard(self, ctx: ProviderContext):
        if not linux.on_linux():
            return self.result(ctx, State.NOT_APPLICABLE, "Linux-only control")
        return None


class EgressRouteProvider(_LinuxProvider):
    control_id = "OPSEC-EGRESS-002"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        iface = str(ctx.params.get("interface", "")).strip()
        if not iface:
            return self.result(ctx, State.NOT_APPLICABLE, "declare an `interface` param")
        current = _default_route_iface()
        observed = {"default_route_iface": current or ""}
        if current == iface:
            return self.result(ctx, State.OK, f"default route rides {iface}", observed=observed)
        return self.result(
            ctx, State.VIOLATION,
            f"default route is via {current!r}, not the VPN {iface!r}",
            detail="traffic is not being forced through the tunnel.", observed=observed,
        )


class DnsLeakProvider(_LinuxProvider):
    control_id = "OPSEC-NET-001"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        allowed = {str(a) for a in ctx.params.get("allowed_resolvers", [])}
        if not allowed:
            return self.result(ctx, State.NOT_APPLICABLE, "declare `allowed_resolvers`")
        servers = _nameservers()
        leaking = [s for s in servers if s not in allowed]
        observed = {"nameservers": ",".join(servers)}
        if leaking:
            return self.result(
                ctx, State.VIOLATION,
                f"DNS resolver(s) not on the allowlist: {leaking}",
                detail=f"allowed={sorted(allowed)}", observed=observed,
            )
        return self.result(ctx, State.OK, "DNS resolvers are all allowlisted", observed=observed)


class Ipv6LeakProvider(_LinuxProvider):
    control_id = "OPSEC-NET-002"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        if _ipv6_disabled():
            return self.result(ctx, State.OK, "IPv6 is disabled", observed={"ipv6": "disabled"})
        iface = str(ctx.params.get("interface", "")).strip()
        route6 = _default_route_iface(v6=True)
        observed = {"ipv6": "enabled", "v6_route_iface": route6 or ""}
        if iface and route6 == iface:
            return self.result(ctx, State.OK, f"IPv6 routed via {iface}", observed=observed)
        return self.result(
            ctx, State.VIOLATION,
            "IPv6 is enabled and not routed through the VPN (leak risk)",
            detail="disable IPv6 or force its default route through the tunnel.",
            observed=observed,
        )


class FirewallPolicyProvider(_LinuxProvider):
    control_id = "OPSEC-NET-003"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        require = [str(c).upper() for c in ctx.params.get("default_deny", ["OUTPUT"])]
        policies = _firewall_policies()
        if policies is None:
            return self.result(
                ctx, State.ERROR, "could not read iptables policy (root may be required)"
            )
        offenders = [c for c in require if policies.get(c) != "DROP"]
        observed = {c.lower(): policies.get(c, "?") for c in require}
        if offenders:
            return self.result(
                ctx, State.VIOLATION,
                f"firewall chain(s) not default-deny: {offenders}",
                detail=f"policies={policies}", observed=observed,
            )
        return self.result(ctx, State.OK, "firewall denies by default on required chains", observed=observed)


class ListeningPortsProvider(_LinuxProvider):
    control_id = "OPSEC-NET-004"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        allowed = {int(p) for p in ctx.params.get("allowed_ports", [])}
        ports = _listening_ports()
        if ports is None:
            return self.result(ctx, State.ERROR, "could not enumerate listening ports (need `ss`)")
        offenders = [p for p in ports if p not in allowed]
        observed = {"listening": ",".join(map(str, ports))}
        if offenders:
            return self.result(
                ctx, State.VIOLATION,
                f"unexpected service(s) listening on: {offenders}",
                detail=f"allowed_ports={sorted(allowed)}", observed=observed,
            )
        return self.result(ctx, State.OK, "no unexpected listening ports", observed=observed)


for _p in (EgressRouteProvider(), DnsLeakProvider(), Ipv6LeakProvider(),
           FirewallPolicyProvider(), ListeningPortsProvider()):
    register(_p)
