"""OPSEC-IDENTITY-101 — git identity matches persona, never the real identity.

The classic pseudonymity leak: you set up a persona once, then a tired late-night
commit goes out under your real name because git config drifted back. This
provider observes the effective global git identity and, being remediable, can
reset it to the declared persona.
"""

from __future__ import annotations

import shutil
import subprocess

from ..model import CheckResult, State
from .base import Provider, ProviderContext
from .registry import register


def _git_get(key: str) -> str | None:
    """Read a global git config value, or None. Overridable in tests."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        result = subprocess.run(
            [git, "config", "--global", "--get", key],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value or None


def _git_set(key: str, value: str) -> None:
    """Set a global git config value. Overridable in tests."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git not found on PATH")
    subprocess.run(
        [git, "config", "--global", key, value],
        capture_output=True, text=True, timeout=10, check=True,
    )


class GitIdentityProvider(Provider):
    control_id = "OPSEC-IDENTITY-101"

    def _observed(self) -> dict[str, str]:
        return {
            "user.name": _git_get("user.name") or "",
            "user.email": _git_get("user.email") or "",
        }

    def observe(self, ctx: ProviderContext) -> CheckResult:
        persona = ctx.identity.persona
        want_name = persona.get("git_name")
        want_email = persona.get("git_email")
        if not want_name and not want_email:
            return self.result(
                ctx, State.NOT_APPLICABLE,
                "no persona git identity declared; nothing to enforce",
            )

        observed = self._observed()
        cur_name, cur_email = observed["user.name"], observed["user.email"]

        real_values = {v.lower() for v in ctx.identity.real_values()}
        leaked = [
            v for v in (cur_name, cur_email) if v and v.lower() in real_values
        ]
        if leaked:
            return self.result(
                ctx, State.VIOLATION,
                "git identity exposes your real identity",
                detail=f"git config currently reads {leaked}; expected the persona.",
                observed=observed,
            )

        mismatched = (want_name and cur_name != want_name) or (
            want_email and cur_email != want_email
        )
        if mismatched:
            return self.result(
                ctx, State.DRIFT,
                "git identity has drifted from the declared persona",
                detail=f"have name={cur_name!r} email={cur_email!r}; "
                f"want name={want_name!r} email={want_email!r}.",
                observed=observed,
            )
        return self.result(
            ctx, State.OK, "git identity matches the persona", observed=observed
        )

    def enforce(self, ctx: ProviderContext) -> CheckResult:
        persona = ctx.identity.persona
        if persona.get("git_name"):
            _git_set("user.name", persona["git_name"])
        if persona.get("git_email"):
            _git_set("user.email", persona["git_email"])
        return self.result(
            ctx, State.OK, "reset git identity to the persona",
            observed=self._observed(),
        )


register(GitIdentityProvider())
