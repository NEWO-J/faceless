"""FLE-DISK-001 — system volume encryption is enabled.

Without full-disk encryption, physical access defeats every other control. This
provider reports a tri-state: encrypted (ok), not encrypted (violation), or
undeterminable (error). Marked *expensive*; the hot path uses a cached result.
Detect-only.
"""

from __future__ import annotations

import platform
import subprocess

from ..model import State
from .base import Provider, ProviderContext
from .registry import register


def _encryption_enabled() -> bool | None:
    """Tri-state encryption status. Overridable in tests.

    Returns True/False if determinable, else None.
    """
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-BitLockerVolume -MountPoint $env:SystemDrive)"
                 ".ProtectionStatus"],
                capture_output=True, text=True, timeout=20, check=False,
            ).stdout.strip()
            if not out:
                return None
            # ProtectionStatus: On / Off (or 1 / 0)
            return out.lower() in {"on", "1"}
        if system == "Darwin":
            out = subprocess.run(
                ["fdesetup", "status"], capture_output=True, text=True,
                timeout=15, check=False,
            ).stdout.lower()
            if "filevault is on" in out:
                return True
            if "filevault is off" in out:
                return False
            return None
        if system == "Linux":
            out = subprocess.run(
                ["lsblk", "-o", "TYPE", "-n"], capture_output=True, text=True,
                timeout=10, check=False,
            ).stdout
            return "crypt" in out.split() if out else None
    except (OSError, subprocess.SubprocessError):
        return None
    return None


class DiskEncryptionProvider(Provider):
    control_id = "FLE-DISK-001"

    def observe(self, ctx: ProviderContext):
        status = _encryption_enabled()
        if status is None:
            return self.result(
                ctx, State.ERROR,
                "could not determine disk-encryption status",
                observed={"encrypted": "unknown"},
            )
        if status:
            return self.result(
                ctx, State.OK, "system volume encryption is enabled",
                observed={"encrypted": "true"},
            )
        return self.result(
            ctx, State.VIOLATION,
            "system volume is NOT encrypted",
            observed={"encrypted": "false"},
        )


register(DiskEncryptionProvider())
