from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .model import CheckResult, State
from .providers.base import Provider, ProviderContext
from .providers.linux import on_linux, sysctl


def _num(value: str) -> float | None:
    try:
        return float(str(value).strip().strip('"').strip("'"))
    except (ValueError, TypeError):
        return None


def _content_assertion(assertion: dict, value: str) -> tuple[bool, str]:
    """Apply content assertions (equals/contains/matches/min/max). All must hold."""
    checks: list[tuple[bool, str]] = []
    if "equals" in assertion:
        checks.append((value.strip() == str(assertion["equals"]).strip(),
                       f"equals {assertion['equals']!r}"))
    if "contains" in assertion:
        checks.append((str(assertion["contains"]) in value, f"contains {assertion['contains']!r}"))
    if "matches" in assertion:
        checks.append((re.search(str(assertion["matches"]), value) is not None,
                       f"matches /{assertion['matches']}/"))
    if "max" in assertion:
        num = _num(value)
        checks.append((num is not None and num <= float(assertion["max"]), f"<= {assertion['max']}"))
    if "min" in assertion:
        num = _num(value)
        checks.append((num is not None and num >= float(assertion["min"]), f">= {assertion['min']}"))
    if not checks:
        return True, "no content assertion"
    failed = [desc for ok, desc in checks if not ok]
    return not failed, ("; ".join(failed) if failed else "content ok")


def _presence(assertion: dict, present: bool) -> tuple[bool, str] | None:
    if "exists" in assertion:
        want = bool(assertion["exists"])
        return present == want, f"exists={present} (want {want})"
    if "absent" in assertion:
        want_absent = bool(assertion["absent"])
        return (not present if want_absent else present), f"present={present} (want absent={want_absent})"
    return None


def _ok(state_ok: bool, reason: str, observed: dict) -> tuple[State, str, str, dict]:
    if state_ok:
        return State.OK, "check passed", "", observed
    return State.VIOLATION, f"check failed: {reason}", "", observed


# -- kind handlers ---------------------------------------------------------

def _eval_command(cc) -> tuple[State, str, str, dict]:
    run = [str(x) for x in cc.spec.get("run", [])]
    try:
        result = subprocess.run(
            run, capture_output=True, text=True,
            timeout=float(cc.spec.get("timeout", 20)), check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return State.ERROR, f"command failed to run: {exc}", "", {}
    out = (result.stdout or "").strip()
    observed = {"exit": str(result.returncode), "stdout": out[:120]}
    if "exit_zero" in cc.assertion:
        ok = (result.returncode == 0) == bool(cc.assertion["exit_zero"])
        return _ok(ok, f"exit code {result.returncode}", observed)
    ok, reason = _content_assertion(cc.assertion, out)
    return _ok(ok, reason, observed)


def _eval_file(cc) -> tuple[State, str, str, dict]:
    path = Path(str(cc.spec.get("path", ""))).expanduser()
    present = path.exists()
    observed = {"path": str(path), "present": str(present).lower()}
    presence = _presence(cc.assertion, present)
    if presence is not None:
        return _ok(*presence, observed)
    if not present:
        return State.VIOLATION, "check failed: file does not exist", "", observed
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return State.ERROR, f"cannot read file: {exc}", "", observed
    ok, reason = _content_assertion(cc.assertion, text)
    return _ok(ok, reason, observed)


def _eval_env(cc) -> tuple[State, str, str, dict]:
    var = str(cc.spec.get("var", ""))
    value = os.environ.get(var)
    present = value is not None
    observed = {"var": var, "present": str(present).lower()}
    presence = _presence(cc.assertion, present)
    if presence is not None:
        return _ok(*presence, observed)
    if not present:
        return State.VIOLATION, f"check failed: env var {var} is not set", "", observed
    ok, reason = _content_assertion(cc.assertion, value)
    return _ok(ok, reason, observed)


def _eval_sysctl(cc) -> tuple[State, str, str, dict]:
    if not on_linux():
        return State.NOT_APPLICABLE, "sysctl is Linux-only", "", {}
    key = str(cc.spec.get("key", ""))
    value = sysctl(key)
    if value is None:
        return State.NOT_APPLICABLE, f"sysctl {key} not readable", "", {}
    observed = {"sysctl": key, "value": value}
    ok, reason = _content_assertion(cc.assertion, value)
    return _ok(ok, reason, observed)


_HANDLERS = {
    "command": _eval_command,
    "file": _eval_file,
    "env": _eval_env,
    "sysctl": _eval_sysctl,
}


def evaluate_custom(cc) -> tuple[State, str, str, dict]:
    handler = _HANDLERS.get(cc.kind)
    if handler is None:
        return State.ERROR, f"unknown custom kind {cc.kind!r}", "", {}
    return handler(cc)


class CustomCheckProvider(Provider):
    """Evaluates any declarative custom control, keyed by the posture item's id."""

    control_id = "FLE-CUSTOM"  # placeholder; never registered in the registry

    def observe(self, ctx: ProviderContext) -> CheckResult:
        cc = ctx.config.custom_controls.get(ctx.item.control_id)
        if cc is None:
            return CheckResult(ctx.item.control_id, State.ERROR, ctx.severity,
                               "custom control definition not found")
        state, summary, detail, observed = evaluate_custom(cc)
        return CheckResult(
            control_id=cc.id, state=state, severity=ctx.severity,
            summary=summary, detail=detail, observed=observed or None, remediable=False,
        )


CUSTOM_PROVIDER = CustomCheckProvider()

CUSTOM_KINDS = frozenset(_HANDLERS)
