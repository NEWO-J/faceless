"""Read/write ``opsec.lock.yaml`` — the known-good posture snapshot.

Locking pins the observed values of every OK control. Afterwards, "it works" is
defined precisely as "matches the lock"; any change to a locked value surfaces as
drift, even if the new value would otherwise look fine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

import yaml

from .model import PostureReport, State


def write_lock(report: PostureReport, path: str | Path) -> dict[str, dict[str, str]]:
    """Snapshot observed values of OK controls to the lock file."""
    snapshot: dict[str, dict[str, str]] = {
        r.control_id: dict(r.observed)
        for r in report.results
        if r.state is State.OK and r.observed is not None
    }
    Path(path).write_text(
        yaml.safe_dump({"opsec_version": 1, "locked": snapshot}, sort_keys=True),
        encoding="utf-8",
    )
    return snapshot


def read_lock(path: str | Path) -> dict[str, dict[str, str]] | None:
    """Return the locked snapshot, or None if no lock exists."""
    lock_path = Path(path)
    if not lock_path.is_file():
        return None
    try:
        document = yaml.safe_load(lock_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return None
    locked = document.get("locked", {})
    if not isinstance(locked, Mapping):
        return None
    return {str(k): dict(v) for k, v in locked.items()}
