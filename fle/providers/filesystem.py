"""OPSEC-SECRET-060 — declared plaintext secret files are absent.

Long-lived plaintext credential files (``~/.aws/credentials``, ``~/.netrc``, …)
are a standing harvest target. This provider fails if any path the config
declares forbidden currently exists. Detect-only.
"""

from __future__ import annotations

from pathlib import Path

from ..model import State
from .base import Provider, ProviderContext
from .registry import register


def _exists(path: Path) -> bool:
    """Overridable in tests."""
    return path.exists()


class ForbiddenFilesProvider(Provider):
    control_id = "OPSEC-SECRET-060"

    def observe(self, ctx: ProviderContext):
        declared = list(ctx.params.get("forbidden_paths", []))
        if not declared:
            return self.result(
                ctx, State.NOT_APPLICABLE, "no forbidden_paths declared"
            )
        present = [p for p in declared if _exists(Path(p).expanduser())]
        if present:
            return self.result(
                ctx, State.VIOLATION,
                f"{len(present)} forbidden plaintext secret file(s) present",
                detail="present: " + ", ".join(present),
                observed={"present": ",".join(sorted(present))},
            )
        return self.result(
            ctx, State.OK, "no forbidden secret files present",
            observed={"present": ""},
        )


register(ForbiddenFilesProvider())
