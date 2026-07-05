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


# ==========================================================================
# Deep network / leak controls (community-driven: DNS/IPv6/WebRTC leaks,
# LLMNR/mDNS, IPv6 privacy addresses, MAC randomization, egress-IP proof).
# ==========================================================================

def _default_gateway() -> str | None:
    out = linux.run(["ip", "-o", "-4", "route", "show", "default"])
    if not out:
        return None
    match = re.search(r"\bvia\s+(\S+)", out)
    return match.group(1) if match else None


def _resolvectl_status() -> str | None:
    return linux.run(["resolvectl", "status"])


def _resolved_protocol(flag: str) -> bool | None:
    """Tri-state read of a systemd-resolved protocol flag (LLMNR/mDNS/DNSOverTLS)."""
    status = _resolvectl_status()
    if not status:
        return None
    if f"+{flag}" in status:
        return True
    if f"-{flag}" in status:
        return False
    return None


def _service_active(name: str) -> bool | None:
    out = linux.run(["systemctl", "is-active", name])
    if out is None:
        return None
    return out.strip() == "active"


def _global_ipv6_addrs() -> list[str]:
    out = linux.run(["ip", "-o", "-6", "addr", "show", "scope", "global"]) or ""
    return re.findall(r"inet6\s+([0-9a-f:]+)/", out)


def _sysctl_int(key: str) -> int | None:
    value = linux.sysctl(key)
    if value is None:
        return None
    value = value.strip()
    return int(value) if value.lstrip("-").isdigit() else None


def _use_tempaddr() -> int | None:
    return _sysctl_int("net.ipv6.conf.all.use_tempaddr")


def _nm_print_config() -> str | None:
    return linux.run(["NetworkManager", "--print-config"])


def _public_ip() -> str | None:
    """Fetch the egress IP as seen by the outside world. Overridable in tests."""
    import urllib.request

    for url in ("https://api.ipify.org", "https://ifconfig.co/ip"):
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:  # noqa: S310
                ip = resp.read().decode("utf-8", "replace").strip()
                if ip:
                    return ip
        except Exception:  # noqa: BLE001 - any failure => unknown
            continue
    return None


class EncryptedDnsProvider(_LinuxProvider):
    control_id = "OPSEC-NET-005"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        state = _resolved_protocol("DNSOverTLS")
        if state is None:
            return self.result(ctx, State.NOT_APPLICABLE, "systemd-resolved not detected")
        if state:
            return self.result(ctx, State.OK, "DNS-over-TLS is on", observed={"dot": "on"})
        return self.result(
            ctx, State.VIOLATION, "DNS is unencrypted (DNS-over-TLS off)",
            detail="your resolver and network can read every domain you look up.",
            observed={"dot": "off"},
        )


class ResolverIsGatewayProvider(_LinuxProvider):
    control_id = "OPSEC-NET-006"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        gateway = _default_gateway()
        servers = _nameservers()
        if not servers:
            return self.result(ctx, State.NOT_APPLICABLE, "no resolvers configured")
        if gateway and gateway in servers:
            return self.result(
                ctx, State.VIOLATION,
                "DNS is pointed at the LAN gateway (ISP router) — classic leak",
                detail=f"gateway {gateway} is in your resolver list.",
                observed={"gateway": gateway, "nameservers": ",".join(servers)},
            )
        return self.result(ctx, State.OK, "resolver is not the LAN gateway",
                           observed={"nameservers": ",".join(servers)})


class LlmnrProvider(_LinuxProvider):
    control_id = "OPSEC-NET-007"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        state = _resolved_protocol("LLMNR")
        if state is None:
            return self.result(ctx, State.NOT_APPLICABLE, "LLMNR state unknown")
        if state:
            return self.result(
                ctx, State.VIOLATION, "LLMNR is enabled (name broadcast + hash capture)",
                detail="LLMNR broadcasts your hostname and enables Responder-style poisoning.",
                observed={"llmnr": "on"},
            )
        return self.result(ctx, State.OK, "LLMNR is disabled", observed={"llmnr": "off"})


class MdnsProvider(_LinuxProvider):
    control_id = "OPSEC-NET-008"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        resolved_mdns = _resolved_protocol("mDNS")
        avahi = _service_active("avahi-daemon")
        broadcasting = resolved_mdns is True or avahi is True
        observed = {"resolved_mdns": str(resolved_mdns).lower(), "avahi": str(avahi).lower()}
        if broadcasting:
            return self.result(
                ctx, State.VIOLATION, "mDNS is broadcasting your hostname on the LAN",
                detail="disable Avahi and set MulticastDNS=no to stop advertising the device.",
                observed=observed,
            )
        return self.result(ctx, State.OK, "mDNS is not broadcasting", observed=observed)


class Ipv6PrivacyProvider(_LinuxProvider):
    control_id = "OPSEC-NET-009"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        if _ipv6_disabled():
            return self.result(ctx, State.NOT_APPLICABLE, "IPv6 is disabled")
        value = _use_tempaddr()
        if value is None:
            return self.result(ctx, State.NOT_APPLICABLE, "use_tempaddr not readable")
        observed = {"use_tempaddr": str(value)}
        if value >= 2:
            return self.result(ctx, State.OK, "IPv6 privacy addresses are preferred", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "IPv6 privacy extensions are off (stable address tracks you)",
            detail="set net.ipv6.conf.all.use_tempaddr=2 (RFC 8981 temporary addresses).",
            observed=observed,
        )


class Ipv6Eui64Provider(_LinuxProvider):
    control_id = "OPSEC-NET-010"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        addrs = _global_ipv6_addrs()
        if not addrs:
            return self.result(ctx, State.NOT_APPLICABLE, "no global IPv6 addresses")
        leaking = [a for a in addrs if "ff:fe" in a]
        observed = {"eui64_addrs": ",".join(leaking)}
        if leaking:
            return self.result(
                ctx, State.VIOLATION, "IPv6 address embeds your MAC (EUI-64)",
                detail=f"MAC-derived addresses track your hardware across networks: {leaking}",
                observed=observed,
            )
        return self.result(ctx, State.OK, "no MAC-derived IPv6 addresses", observed=observed)


class MacRandomizationProvider(_LinuxProvider):
    control_id = "OPSEC-NET-011"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        config = _nm_print_config()
        if config is None:
            return self.result(ctx, State.NOT_APPLICABLE, "NetworkManager config not readable")
        scan_random = "wifi.scan-rand-mac-address=yes" in config.replace(" ", "")
        cloned = re.search(r"cloned-mac-address\s*=\s*(random|stable)", config)
        observed = {"scan_random": str(scan_random).lower(), "cloned": bool(cloned) and "yes" or "no"}
        if scan_random and cloned:
            return self.result(ctx, State.OK, "MAC randomization is configured", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "Wi-Fi MAC randomization is not fully configured",
            detail="set wifi.scan-rand-mac-address=yes and cloned-mac-address=random|stable.",
            observed=observed,
        )


class ConnectivityCheckProvider(_LinuxProvider):
    control_id = "OPSEC-NET-012"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        config = _nm_print_config()
        if config is None:
            return self.result(ctx, State.NOT_APPLICABLE, "NetworkManager config not readable")
        disabled = re.search(r"connectivity[\s\S]{0,200}?enabled\s*=\s*false", config)
        if disabled:
            return self.result(ctx, State.OK, "captive-portal connectivity check is disabled",
                               observed={"connectivity_check": "off"})
        return self.result(
            ctx, State.VIOLATION, "NetworkManager phones home for connectivity checks",
            detail="set [connectivity] enabled=false so the OS stops pinging a check URL on every join.",
            observed={"connectivity_check": "on"},
        )


class TcpTimestampsProvider(_LinuxProvider):
    control_id = "OPSEC-NET-013"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        value = _sysctl_int("net.ipv4.tcp_timestamps")
        if value is None:
            return self.result(ctx, State.NOT_APPLICABLE, "tcp_timestamps not readable")
        observed = {"tcp_timestamps": str(value)}
        if value == 0:
            return self.result(ctx, State.OK, "TCP timestamps disabled (no uptime fingerprint)", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "TCP timestamps expose your system uptime (fingerprint)",
            detail="set net.ipv4.tcp_timestamps=0.", observed=observed,
        )


class PublicIpProvider(Provider):
    """Cross-platform egress-IP proof: does the outside world see a forbidden IP?"""

    control_id = "OPSEC-NET-014"

    def observe(self, ctx: ProviderContext):
        forbidden = {str(ip) for ip in ctx.params.get("forbidden_ips", [])}
        if not forbidden:
            return self.result(
                ctx, State.NOT_APPLICABLE,
                "declare `forbidden_ips` (e.g. your real ISP address) to enable",
            )
        ip = _public_ip()
        if ip is None:
            return self.result(ctx, State.ERROR, "could not determine the public egress IP")
        observed = {"public_ip": ip}
        if ip in forbidden:
            return self.result(
                ctx, State.VIOLATION,
                "egress IP is a forbidden (real) address — you are exposed",
                detail=f"the internet sees {ip}, which you flagged as your real IP.",
                observed=observed,
            )
        return self.result(ctx, State.OK, f"egress IP {ip} is not a forbidden address", observed=observed)


for _p in (EncryptedDnsProvider(), ResolverIsGatewayProvider(), LlmnrProvider(),
           MdnsProvider(), Ipv6PrivacyProvider(), Ipv6Eui64Provider(),
           MacRandomizationProvider(), ConnectivityCheckProvider(),
           TcpTimestampsProvider(), PublicIpProvider()):
    register(_p)
