"""Tiny result cache for the per-command fast path.

Expensive controls (disk encryption, interface enumeration) are too slow to run
at every shell prompt. A full ``fle verify`` writes its results here; ``--fast``
reuses them until they age out, so the prompt reflects the last real check
instead of paying the cost every time.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .model import CheckResult, Severity, State


def default_cache_path(config_path: Path | None) -> Path:
    base = config_path.parent if config_path else Path.cwd()
    return base / ".fle-cache.json"


def save(results: tuple[CheckResult, ...] | list[CheckResult], path: Path) -> None:
    payload = {
        "saved_at": time.time(),
        "results": {r.control_id: r.as_dict() for r in results},
    }
    try:
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass  # cache is best-effort; never fail a verify over it


def load(path: Path, ttl_seconds: float) -> dict[str, CheckResult]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if time.time() - float(payload.get("saved_at", 0)) > ttl_seconds:
        return {}
    out: dict[str, CheckResult] = {}
    for control_id, data in payload.get("results", {}).items():
        try:
            out[control_id] = CheckResult(
                control_id=data["control"],
                state=State(data["state"]),
                severity=Severity(data["severity"]),
                summary=data.get("summary", ""),
                detail=data.get("detail", ""),
                observed=data.get("observed"),
                remediable=data.get("remediable", False),
            )
        except (KeyError, ValueError):
            continue
    return out
