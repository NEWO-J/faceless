"""FLE-SECRET-050 — no secret-like values in the environment.

Secrets in environment variables leak into every child process, crash dump, and
CI log. This provider scans the *values* of the current environment for
high-signal credential patterns and reports the offending variable *names* only
(never the secret itself). Detect-only.
"""

from __future__ import annotations

import os
import re
from typing import Mapping

from ..model import State
from .base import Provider, ProviderContext
from .registry import register

# High-signal patterns only, to keep false positives near zero on env values.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),          # AWS access key id
    re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),                # GitHub PAT
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),       # Slack token
    re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),           # Stripe live key
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)

# Names that are secrets by convention even without a recognizable value shape.
_SUSPECT_NAME = re.compile(r"(?i)(secret|token|password|passwd|api[_-]?key|private[_-]?key)")


def _get_environ() -> Mapping[str, str]:
    """Return the environment to scan. Overridable in tests."""
    return dict(os.environ)


class EnvironmentSecretProvider(Provider):
    control_id = "FLE-SECRET-050"

    def observe(self, ctx: ProviderContext):
        allow = {str(n) for n in ctx.params.get("allow", [])}
        offenders: list[str] = []
        for name, value in _get_environ().items():
            if name in allow or not value:
                continue
            if any(p.search(value) for p in _SECRET_PATTERNS):
                offenders.append(name)
            elif _SUSPECT_NAME.search(name) and len(value) >= 8:
                offenders.append(name)
        offenders = sorted(set(offenders))
        if offenders:
            return self.result(
                ctx, State.VIOLATION,
                f"{len(offenders)} environment variable(s) hold secret-like values",
                detail="offending names: " + ", ".join(offenders),
                observed={"offenders": ",".join(offenders)},
            )
        return self.result(
            ctx, State.OK, "no secret-like values found in the environment",
            observed={"offenders": ""},
        )


register(EnvironmentSecretProvider())
