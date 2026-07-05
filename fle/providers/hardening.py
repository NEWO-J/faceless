"""System hardening / privilege-escalation controls (Linux).

The winPEAS/linPEAS-style checks: dangerous SUID binaries, passwordless sudo,
writable PATH entries (hijack), permissive SSH, and kernel hardening. Linux-only;
reports ``not_applicable`` elsewhere.
"""

from __future__ import annotations

import os
import re

from ..model import State
from . import linux
from .base import Provider, ProviderContext
from .registry import register

# GTFOBins that grant a shell / file read-write when SUID. Not exhaustive; the
# high-signal subset that most often means game-over.
DANGEROUS_SUID = frozenset({
    "bash", "sh", "dash", "zsh", "vim", "vi", "view", "nano", "less", "more",
    "man", "awk", "gawk", "find", "nmap", "perl", "python", "python3", "ruby",
    "gdb", "env", "tar", "zip", "cp", "docker", "dmesg", "systemctl", "tmux",
})


# -- observation seams (mockable) -----------------------------------------

def _suid_binaries() -> list[str] | None:
    out = linux.run(["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
                     "-perm", "-4000", "-type", "f"], timeout=30)
    if out is None:
        return None
    return [line.strip() for line in out.splitlines() if line.strip()]


def _sudo_nopasswd() -> bool | None:
    out = linux.run(["sudo", "-n", "-l"])
    if out is None:
        return None
    return "NOPASSWD" in out


def _writable_path_dirs() -> list[str]:
    dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    return [d for d in dirs if os.path.isdir(d) and os.access(d, os.W_OK)]


def _sshd_config() -> dict[str, str]:
    text = linux.read("/etc/ssh/sshd_config") or ""
    config: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1].strip().lower()  # last wins
    return config


def _ptrace_scope() -> int | None:
    value = linux.sysctl("kernel.yama.ptrace_scope")
    if value is None or not value.isdigit():
        return None
    return int(value)


# -- providers -------------------------------------------------------------

class _LinuxProvider(Provider):
    def _guard(self, ctx: ProviderContext):
        if not linux.on_linux():
            return self.result(ctx, State.NOT_APPLICABLE, "Linux-only control")
        return None


class DangerousSuidProvider(_LinuxProvider):
    control_id = "OPSEC-PRIV-001"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        allow = {str(p) for p in ctx.params.get("allow_suid", [])}
        found = _suid_binaries()
        if found is None:
            return self.result(ctx, State.ERROR, "could not scan for SUID binaries")
        dangerous = [
            p for p in found
            if os.path.basename(p) in DANGEROUS_SUID and p not in allow
        ]
        observed = {"dangerous_suid": ",".join(sorted(dangerous))}
        if dangerous:
            return self.result(
                ctx, State.VIOLATION,
                f"{len(dangerous)} exploitable SUID binary(ies) present",
                detail="privesc via: " + ", ".join(dangerous), observed=observed,
            )
        return self.result(ctx, State.OK, "no known-dangerous SUID binaries", observed=observed)


class SudoNoPasswdProvider(_LinuxProvider):
    control_id = "OPSEC-PRIV-002"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        value = _sudo_nopasswd()
        if value is None:
            return self.result(ctx, State.NOT_APPLICABLE, "sudo not available / no rules")
        if value:
            return self.result(
                ctx, State.VIOLATION, "sudo is configured with NOPASSWD",
                detail="a stolen session escalates to root without a password.",
                observed={"nopasswd": "true"},
            )
        return self.result(ctx, State.OK, "sudo requires a password", observed={"nopasswd": "false"})


class WritablePathProvider(_LinuxProvider):
    control_id = "OPSEC-PRIV-003"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        writable = _writable_path_dirs()
        observed = {"writable_path_dirs": ",".join(writable)}
        if writable:
            return self.result(
                ctx, State.VIOLATION,
                f"{len(writable)} PATH directory(ies) are user-writable (hijack risk)",
                detail="writable: " + ", ".join(writable), observed=observed,
            )
        return self.result(ctx, State.OK, "no writable directories in PATH", observed=observed)


class SshRootLoginProvider(_LinuxProvider):
    control_id = "OPSEC-PRIV-004"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        config = _sshd_config()
        if not config:
            return self.result(ctx, State.NOT_APPLICABLE, "no sshd_config found")
        permit = config.get("permitrootlogin", "prohibit-password")
        observed = {"permitrootlogin": permit}
        if permit == "yes":
            return self.result(
                ctx, State.VIOLATION, "SSH permits direct root login",
                detail="set `PermitRootLogin no` in sshd_config.", observed=observed,
            )
        return self.result(ctx, State.OK, f"SSH root login restricted ({permit})", observed=observed)


class PtraceScopeProvider(_LinuxProvider):
    control_id = "OPSEC-PRIV-005"

    def observe(self, ctx: ProviderContext):
        na = self._guard(ctx)
        if na:
            return na
        scope = _ptrace_scope()
        if scope is None:
            return self.result(ctx, State.NOT_APPLICABLE, "ptrace_scope not readable")
        observed = {"ptrace_scope": str(scope)}
        if scope >= 1:
            return self.result(ctx, State.OK, f"ptrace hardening on (scope={scope})", observed=observed)
        return self.result(
            ctx, State.VIOLATION, "ptrace_scope=0 lets any process read another's memory",
            detail="set kernel.yama.ptrace_scope=1 or higher.", observed=observed,
        )


for _p in (DangerousSuidProvider(), SudoNoPasswdProvider(), WritablePathProvider(),
           SshRootLoginProvider(), PtraceScopeProvider()):
    register(_p)
