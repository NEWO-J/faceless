"""Shared Linux system-access helpers for providers.

Every function is a mockable seam: providers call these, and tests monkeypatch
them (or the per-control observation functions built on top). Nothing here
raises; failures return ``None`` so a provider can report ``error``/``n/a``
rather than crash the whole evaluation.
"""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path


def on_linux() -> bool:
    return platform.system() == "Linux"


def run(args: list[str], *, timeout: float = 15.0) -> str | None:
    """Run a command and return stdout, or None on any failure."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 and not result.stdout:
        return None
    return result.stdout


def read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def sysctl(key: str) -> str | None:
    """Read a sysctl value via /proc/sys, falling back to the sysctl binary."""
    proc_path = "/proc/sys/" + key.replace(".", "/")
    value = read(proc_path)
    if value is not None:
        return value.strip()
    out = run(["sysctl", "-n", key])
    return out.strip() if out else None
