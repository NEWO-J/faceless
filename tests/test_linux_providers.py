"""Linux network providers against mocked system state."""

from __future__ import annotations

import pytest

from fle.catalog import get_control
from fle.config import OpsecConfig
from fle.model import State
from fle.providers import linux, network
from fle.providers.base import ProviderContext


@pytest.fixture(autouse=True)
def _pretend_linux(monkeypatch):
    monkeypatch.setattr(linux, "on_linux", lambda: True)


def _ctx(control_id, params=None):
    doc = {"opsec_version": 1, "name": "t",
           "posture": [{"control": control_id, **({"params": params} if params else {})}]}
    cfg = OpsecConfig.from_mapping(doc)
    return ProviderContext(cfg, cfg.posture[0], get_control(control_id))


def test_egress_route_ok(monkeypatch):
    monkeypatch.setattr(network, "_default_route_iface", lambda v6=False: "wg0")
    r = network.EgressRouteProvider().observe(_ctx("OPSEC-EGRESS-002", {"interface": "wg0"}))
    assert r.state is State.OK


def test_egress_route_violation(monkeypatch):
    monkeypatch.setattr(network, "_default_route_iface", lambda v6=False: "eth0")
    r = network.EgressRouteProvider().observe(_ctx("OPSEC-EGRESS-002", {"interface": "wg0"}))
    assert r.state is State.VIOLATION


def test_dns_leak(monkeypatch):
    monkeypatch.setattr(network, "_nameservers", lambda: ["192.168.1.1"])
    ctx = _ctx("OPSEC-NET-001", {"allowed_resolvers": ["10.0.0.1"]})
    assert network.DnsLeakProvider().observe(ctx).state is State.VIOLATION
    monkeypatch.setattr(network, "_nameservers", lambda: ["10.0.0.1"])
    assert network.DnsLeakProvider().observe(ctx).state is State.OK


def test_ipv6_disabled_is_ok(monkeypatch):
    monkeypatch.setattr(network, "_ipv6_disabled", lambda: True)
    assert network.Ipv6LeakProvider().observe(_ctx("OPSEC-NET-002")).state is State.OK


def test_ipv6_enabled_not_tunneled_is_violation(monkeypatch):
    monkeypatch.setattr(network, "_ipv6_disabled", lambda: False)
    monkeypatch.setattr(network, "_default_route_iface", lambda v6=False: "eth0")
    ctx = _ctx("OPSEC-NET-002", {"interface": "wg0"})
    assert network.Ipv6LeakProvider().observe(ctx).state is State.VIOLATION


def test_firewall_default_deny(monkeypatch):
    monkeypatch.setattr(network, "_firewall_policies", lambda: {"OUTPUT": "DROP"})
    assert network.FirewallPolicyProvider().observe(_ctx("OPSEC-NET-003")).state is State.OK
    monkeypatch.setattr(network, "_firewall_policies", lambda: {"OUTPUT": "ACCEPT"})
    assert network.FirewallPolicyProvider().observe(_ctx("OPSEC-NET-003")).state is State.VIOLATION
    monkeypatch.setattr(network, "_firewall_policies", lambda: None)
    assert network.FirewallPolicyProvider().observe(_ctx("OPSEC-NET-003")).state is State.ERROR


def test_listening_ports(monkeypatch):
    monkeypatch.setattr(network, "_listening_ports", lambda: [22, 8080])
    ctx = _ctx("OPSEC-NET-004", {"allowed_ports": [22]})
    r = network.ListeningPortsProvider().observe(ctx)
    assert r.state is State.VIOLATION and "8080" in r.observed["listening"]


def test_non_linux_is_not_applicable(monkeypatch):
    monkeypatch.setattr(linux, "on_linux", lambda: False)
    r = network.FirewallPolicyProvider().observe(_ctx("OPSEC-NET-003"))
    assert r.state is State.NOT_APPLICABLE


# -- deep network controls -------------------------------------------------

def test_encrypted_dns(monkeypatch):
    monkeypatch.setattr(network, "_resolved_protocol", lambda f: {"DNSOverTLS": True}.get(f))
    assert network.EncryptedDnsProvider().observe(_ctx("OPSEC-NET-005")).state is State.OK
    monkeypatch.setattr(network, "_resolved_protocol", lambda f: {"DNSOverTLS": False}.get(f))
    assert network.EncryptedDnsProvider().observe(_ctx("OPSEC-NET-005")).state is State.VIOLATION


def test_resolver_is_gateway(monkeypatch):
    monkeypatch.setattr(network, "_default_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(network, "_nameservers", lambda: ["192.168.1.1"])
    assert network.ResolverIsGatewayProvider().observe(_ctx("OPSEC-NET-006")).state is State.VIOLATION
    monkeypatch.setattr(network, "_nameservers", lambda: ["10.64.0.1"])
    assert network.ResolverIsGatewayProvider().observe(_ctx("OPSEC-NET-006")).state is State.OK


def test_llmnr(monkeypatch):
    monkeypatch.setattr(network, "_resolved_protocol", lambda f: True if f == "LLMNR" else None)
    assert network.LlmnrProvider().observe(_ctx("OPSEC-NET-007")).state is State.VIOLATION
    monkeypatch.setattr(network, "_resolved_protocol", lambda f: False if f == "LLMNR" else None)
    assert network.LlmnrProvider().observe(_ctx("OPSEC-NET-007")).state is State.OK


def test_mdns_broadcasting(monkeypatch):
    monkeypatch.setattr(network, "_resolved_protocol", lambda f: None)
    monkeypatch.setattr(network, "_service_active", lambda n: True)
    assert network.MdnsProvider().observe(_ctx("OPSEC-NET-008")).state is State.VIOLATION
    monkeypatch.setattr(network, "_service_active", lambda n: False)
    assert network.MdnsProvider().observe(_ctx("OPSEC-NET-008")).state is State.OK


def test_ipv6_privacy(monkeypatch):
    monkeypatch.setattr(network, "_ipv6_disabled", lambda: False)
    monkeypatch.setattr(network, "_use_tempaddr", lambda: 2)
    assert network.Ipv6PrivacyProvider().observe(_ctx("OPSEC-NET-009")).state is State.OK
    monkeypatch.setattr(network, "_use_tempaddr", lambda: 0)
    assert network.Ipv6PrivacyProvider().observe(_ctx("OPSEC-NET-009")).state is State.VIOLATION


def test_ipv6_eui64_leak(monkeypatch):
    monkeypatch.setattr(network, "_global_ipv6_addrs", lambda: ["2001:db8::211:22ff:fe33:4455"])
    assert network.Ipv6Eui64Provider().observe(_ctx("OPSEC-NET-010")).state is State.VIOLATION
    monkeypatch.setattr(network, "_global_ipv6_addrs", lambda: ["2001:db8::dead:beef:cafe:1234"])
    assert network.Ipv6Eui64Provider().observe(_ctx("OPSEC-NET-010")).state is State.OK


def test_mac_randomization(monkeypatch):
    monkeypatch.setattr(network, "_nm_print_config",
                        lambda: "wifi.scan-rand-mac-address=yes\ncloned-mac-address=random\n")
    assert network.MacRandomizationProvider().observe(_ctx("OPSEC-NET-011")).state is State.OK
    monkeypatch.setattr(network, "_nm_print_config", lambda: "wifi.powersave=2\n")
    assert network.MacRandomizationProvider().observe(_ctx("OPSEC-NET-011")).state is State.VIOLATION


def test_connectivity_check(monkeypatch):
    monkeypatch.setattr(network, "_nm_print_config", lambda: "[connectivity]\nenabled=false\n")
    assert network.ConnectivityCheckProvider().observe(_ctx("OPSEC-NET-012")).state is State.OK
    monkeypatch.setattr(network, "_nm_print_config", lambda: "[connectivity]\nuri=http://x/check\n")
    assert network.ConnectivityCheckProvider().observe(_ctx("OPSEC-NET-012")).state is State.VIOLATION


def test_tcp_timestamps(monkeypatch):
    monkeypatch.setattr(network, "_sysctl_int", lambda k: 0)
    assert network.TcpTimestampsProvider().observe(_ctx("OPSEC-NET-013")).state is State.OK
    monkeypatch.setattr(network, "_sysctl_int", lambda k: 1)
    assert network.TcpTimestampsProvider().observe(_ctx("OPSEC-NET-013")).state is State.VIOLATION


def test_public_ip_leak(monkeypatch):
    # opt-in: no forbidden_ips => not applicable
    assert network.PublicIpProvider().observe(_ctx("OPSEC-NET-014")).state is State.NOT_APPLICABLE
    monkeypatch.setattr(network, "_public_ip", lambda: "203.0.113.9")
    ctx = _ctx("OPSEC-NET-014", {"forbidden_ips": ["203.0.113.9"]})
    assert network.PublicIpProvider().observe(ctx).state is State.VIOLATION
    ctx_ok = _ctx("OPSEC-NET-014", {"forbidden_ips": ["203.0.113.9"]})
    monkeypatch.setattr(network, "_public_ip", lambda: "45.10.20.30")
    assert network.PublicIpProvider().observe(ctx_ok).state is State.OK
