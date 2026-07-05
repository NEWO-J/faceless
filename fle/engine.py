"""The evaluation loop: desired state → observed state → posture report.

``evaluate`` runs each declared control's provider and compares the result to
the desired state and, if a lock is present, to the last known-good snapshot.
``converge`` runs remediation on the failing, remediable controls.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Mapping

from .config import OpsecConfig
from .custom import CUSTOM_PROVIDER
from .model import CheckResult, PostureReport, Severity, State
from .providers import ProviderContext, get_provider, load_builtin_providers


def _resolve_provider(config: OpsecConfig, control_id: str):
    """Built-in provider, or the shared custom-check provider for YAML controls."""
    provider = get_provider(control_id)
    if provider is None and control_id in config.custom_controls:
        return CUSTOM_PROVIDER
    return provider


def _not_enforced(control_id: str, severity: Severity, summary: str) -> CheckResult:
    return CheckResult(
        control_id=control_id, state=State.NOT_ENFORCED,
        severity=severity, summary=summary,
    )


def _apply_lock(
    result: CheckResult, lock: Mapping[str, dict[str, str]] | None
) -> CheckResult:
    """Flag drift-from-lock: an OK control whose observed values changed."""
    if lock is None or result.state is not State.OK or result.observed is None:
        return result
    locked = lock.get(result.control_id)
    if locked is not None and dict(locked) != dict(result.observed):
        return replace(
            result,
            state=State.DRIFT,
            summary="drift from the locked known-good state",
            detail=f"locked={locked}; now={result.observed}",
        )
    return result


def evaluate(
    config: OpsecConfig,
    *,
    fast: bool = False,
    lock: Mapping[str, dict[str, str]] | None = None,
    cache: Mapping[str, CheckResult] | None = None,
) -> PostureReport:
    load_builtin_providers()
    results: list[CheckResult] = []

    for item in config.posture:
        spec = config.spec_for(item.control_id)
        provider = _resolve_provider(config, item.control_id)
        if provider is None:
            results.append(_not_enforced(item.control_id, item.severity, "no provider registered"))
            continue

        if fast and spec.expensive:
            cached = (cache or {}).get(item.control_id)
            if cached is not None:
                results.append(cached)
            else:
                results.append(_not_enforced(
                    item.control_id, item.severity, "skipped on fast path (expensive; not yet cached)"
                ))
            continue

        ctx = ProviderContext(config=config, item=item, spec=spec)
        try:
            result = provider.observe(ctx)
        except Exception as exc:  # noqa: BLE001 - provider faults must not crash verify
            result = CheckResult(
                control_id=item.control_id, state=State.ERROR,
                severity=item.severity, summary="provider raised an error",
                detail=str(exc),
            )
        results.append(_apply_lock(result, lock))

    return PostureReport(results=tuple(results))


def converge(config: OpsecConfig, report: PostureReport, *, full: bool = False) -> list[CheckResult]:
    """Enforce failing, remediable controls. Returns the enforcement results.

    ``full`` is reserved for controls flagged destructive; none exist in v1, so
    it currently behaves like the safe subset (all remediable controls are safe).
    """
    load_builtin_providers()
    outcomes: list[CheckResult] = []
    for result in report.results:
        if not (result.failing and result.remediable):
            continue
        item = next((i for i in config.posture if i.control_id == result.control_id), None)
        provider = _resolve_provider(config, result.control_id)
        if item is None or provider is None:
            continue
        spec = config.spec_for(result.control_id)
        ctx = ProviderContext(config=config, item=item, spec=spec)
        try:
            outcomes.append(provider.enforce(ctx))
        except Exception as exc:  # noqa: BLE001
            outcomes.append(CheckResult(
                control_id=result.control_id, state=State.ERROR,
                severity=item.severity, summary="remediation failed", detail=str(exc),
            ))
    return outcomes
