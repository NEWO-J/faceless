"""Provider behavior against mocked system state."""

from __future__ import annotations

from fle.config import OpsecConfig
from fle.model import State
from fle.providers import git_identity, environment, filesystem, vpn, disk
from fle.providers.base import ProviderContext
from fle.catalog import get_control


def _ctx(control_id: str, doc_overrides=None, params=None):
    doc = {
        "opsec_version": 1,
        "name": "t",
        "identity": {
            "persona": {"git_name": "ghost", "git_email": "ghost@x.example"},
            "real": {"names": ["Jane Doe"], "emails": ["jane@real.example"]},
        },
        "posture": [{"control": control_id, **({"params": params} if params else {})}],
    }
    if doc_overrides:
        doc.update(doc_overrides)
    config = OpsecConfig.from_mapping(doc)
    item = config.posture[0]
    return ProviderContext(config=config, item=item, spec=get_control(control_id))


# -- git identity ----------------------------------------------------------

def test_git_identity_ok(monkeypatch):
    monkeypatch.setattr(git_identity, "_git_get",
                        lambda k: {"user.name": "ghost", "user.email": "ghost@x.example"}[k])
    r = git_identity.GitIdentityProvider().observe(_ctx("OPSEC-IDENTITY-101"))
    assert r.state is State.OK


def test_git_identity_drift(monkeypatch):
    monkeypatch.setattr(git_identity, "_git_get",
                        lambda k: {"user.name": "someoneelse", "user.email": "ghost@x.example"}[k])
    r = git_identity.GitIdentityProvider().observe(_ctx("OPSEC-IDENTITY-101"))
    assert r.state is State.DRIFT


def test_git_identity_real_leak_is_violation(monkeypatch):
    monkeypatch.setattr(git_identity, "_git_get",
                        lambda k: {"user.name": "Jane Doe", "user.email": "jane@real.example"}[k])
    r = git_identity.GitIdentityProvider().observe(_ctx("OPSEC-IDENTITY-101"))
    assert r.state is State.VIOLATION


def test_git_identity_enforce_sets_persona(monkeypatch):
    calls = {}
    monkeypatch.setattr(git_identity, "_git_set", lambda k, v: calls.__setitem__(k, v))
    monkeypatch.setattr(git_identity, "_git_get", lambda k: "ghost" if k == "user.name" else "ghost@x.example")
    r = git_identity.GitIdentityProvider().enforce(_ctx("OPSEC-IDENTITY-101"))
    assert calls == {"user.name": "ghost", "user.email": "ghost@x.example"}
    assert r.state is State.OK


# -- environment secrets ---------------------------------------------------

def test_environment_clean(monkeypatch):
    monkeypatch.setattr(environment, "_get_environ", lambda: {"PATH": "/usr/bin", "EDITOR": "vim"})
    r = environment.EnvironmentSecretProvider().observe(_ctx("OPSEC-SECRET-050"))
    assert r.state is State.OK


def test_environment_detects_secret_value(monkeypatch):
    monkeypatch.setattr(environment, "_get_environ",
                        lambda: {"AWS": "AKIAIOSFODNN7EXAMPLE"})
    r = environment.EnvironmentSecretProvider().observe(_ctx("OPSEC-SECRET-050"))
    assert r.state is State.VIOLATION
    assert "AWS" in r.observed["offenders"]


def test_environment_detects_suspect_name(monkeypatch):
    monkeypatch.setattr(environment, "_get_environ",
                        lambda: {"DB_PASSWORD": "hunter2hunter2"})
    r = environment.EnvironmentSecretProvider().observe(_ctx("OPSEC-SECRET-050"))
    assert r.state is State.VIOLATION


# -- forbidden files -------------------------------------------------------

def test_forbidden_files_absent(monkeypatch):
    monkeypatch.setattr(filesystem, "_exists", lambda p: False)
    ctx = _ctx("OPSEC-SECRET-060", params={"forbidden_paths": ["~/.netrc"]})
    r = filesystem.ForbiddenFilesProvider().observe(ctx)
    assert r.state is State.OK


def test_forbidden_files_present(monkeypatch):
    monkeypatch.setattr(filesystem, "_exists", lambda p: True)
    ctx = _ctx("OPSEC-SECRET-060", params={"forbidden_paths": ["~/.aws/credentials"]})
    r = filesystem.ForbiddenFilesProvider().observe(ctx)
    assert r.state is State.VIOLATION


# -- vpn interface ---------------------------------------------------------

def test_vpn_present(monkeypatch):
    monkeypatch.setattr(vpn, "_list_interfaces", lambda: {"eth0", "wg0"})
    ctx = _ctx("OPSEC-EGRESS-001", params={"interface": "wg0"})
    r = vpn.VpnInterfaceProvider().observe(ctx)
    assert r.state is State.OK


def test_vpn_missing_is_violation(monkeypatch):
    monkeypatch.setattr(vpn, "_list_interfaces", lambda: {"eth0"})
    ctx = _ctx("OPSEC-EGRESS-001", params={"interface": "wg0"})
    r = vpn.VpnInterfaceProvider().observe(ctx)
    assert r.state is State.VIOLATION


# -- disk encryption -------------------------------------------------------

def test_disk_encrypted(monkeypatch):
    monkeypatch.setattr(disk, "_encryption_enabled", lambda: True)
    r = disk.DiskEncryptionProvider().observe(_ctx("OPSEC-DISK-001"))
    assert r.state is State.OK


def test_disk_unencrypted_is_violation(monkeypatch):
    monkeypatch.setattr(disk, "_encryption_enabled", lambda: False)
    r = disk.DiskEncryptionProvider().observe(_ctx("OPSEC-DISK-001"))
    assert r.state is State.VIOLATION


def test_disk_unknown_is_error(monkeypatch):
    monkeypatch.setattr(disk, "_encryption_enabled", lambda: None)
    r = disk.DiskEncryptionProvider().observe(_ctx("OPSEC-DISK-001"))
    assert r.state is State.ERROR
