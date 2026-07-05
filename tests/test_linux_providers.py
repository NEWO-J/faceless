"""Linux network + privesc providers against mocked system state."""

from __future__ import annotations

import pytest

from fle.catalog import get_control
from fle.config import OpsecConfig
from fle.model import State
from fle.providers import hardening, linux, network
from fle.providers.base import ProviderContext


@pytest.fixture(autouse=True)
def _pretend_linux(monkeypatch):
    monkeypatch.setattr(linux, "on_linux", lambda: True)


def _ctx(control_id, params=None):
    doc = {"opsec_version": 1, "name": "t",
           "posture": [{"control": control_id, **({"params": params} if params else {})}]}
    cfg = OpsecConfig.from_mapping(doc)
    return ProviderContext(cfg, cfg.posture[0], get_control(control_id))


# -- network ---------------------------------------------------------------

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


# -- privesc ---------------------------------------------------------------

def test_dangerous_suid(monkeypatch):
    monkeypatch.setattr(hardening, "_suid_binaries", lambda: ["/usr/bin/find", "/usr/bin/passwd"])
    r = hardening.DangerousSuidProvider().observe(_ctx("OPSEC-PRIV-001"))
    assert r.state is State.VIOLATION and "find" in r.observed["dangerous_suid"]


def test_suid_allowlisted(monkeypatch):
    monkeypatch.setattr(hardening, "_suid_binaries", lambda: ["/usr/bin/find"])
    ctx = _ctx("OPSEC-PRIV-001", {"allow_suid": ["/usr/bin/find"]})
    assert hardening.DangerousSuidProvider().observe(ctx).state is State.OK


def test_sudo_nopasswd(monkeypatch):
    monkeypatch.setattr(hardening, "_sudo_nopasswd", lambda: True)
    assert hardening.SudoNoPasswdProvider().observe(_ctx("OPSEC-PRIV-002")).state is State.VIOLATION
    monkeypatch.setattr(hardening, "_sudo_nopasswd", lambda: False)
    assert hardening.SudoNoPasswdProvider().observe(_ctx("OPSEC-PRIV-002")).state is State.OK


def test_writable_path(monkeypatch):
    monkeypatch.setattr(hardening, "_writable_path_dirs", lambda: ["/tmp/evil"])
    assert hardening.WritablePathProvider().observe(_ctx("OPSEC-PRIV-003")).state is State.VIOLATION
    monkeypatch.setattr(hardening, "_writable_path_dirs", lambda: [])
    assert hardening.WritablePathProvider().observe(_ctx("OPSEC-PRIV-003")).state is State.OK


def test_ssh_root_login(monkeypatch):
    monkeypatch.setattr(hardening, "_sshd_config", lambda: {"permitrootlogin": "yes"})
    assert hardening.SshRootLoginProvider().observe(_ctx("OPSEC-PRIV-004")).state is State.VIOLATION
    monkeypatch.setattr(hardening, "_sshd_config", lambda: {"permitrootlogin": "no"})
    assert hardening.SshRootLoginProvider().observe(_ctx("OPSEC-PRIV-004")).state is State.OK


def test_ptrace_scope(monkeypatch):
    monkeypatch.setattr(hardening, "_ptrace_scope", lambda: 0)
    assert hardening.PtraceScopeProvider().observe(_ctx("OPSEC-PRIV-005")).state is State.VIOLATION
    monkeypatch.setattr(hardening, "_ptrace_scope", lambda: 1)
    assert hardening.PtraceScopeProvider().observe(_ctx("OPSEC-PRIV-005")).state is State.OK


def test_non_linux_is_not_applicable(monkeypatch):
    monkeypatch.setattr(linux, "on_linux", lambda: False)
    r = hardening.PtraceScopeProvider().observe(_ctx("OPSEC-PRIV-005"))
    assert r.state is State.NOT_APPLICABLE
