"""Provider framework — the single extension point of the engine.

A provider backs exactly one control ID. It ``observe()``s actual system state
and returns a :class:`~fle.model.CheckResult`; if the control is remediable it
also implements ``enforce()``. Providers must be cheap to construct and must not
perform I/O at import time.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping

from ..catalog import ControlSpec
from ..config import Identity, OpsecConfig, PostureItem
from ..errors import NotRemediable
from ..model import CheckResult, Severity, State


@dataclass(frozen=True, slots=True)
class ProviderContext:
    """Everything a provider needs to evaluate one posture item."""

    config: OpsecConfig
    item: PostureItem
    spec: ControlSpec

    @property
    def params(self) -> Mapping[str, Any]:
        return self.item.params

    @property
    def identity(self) -> Identity:
        return self.config.identity

    @property
    def severity(self) -> Severity:
        return self.item.severity


class Provider(ABC):
    control_id: str

    @abstractmethod
    def observe(self, ctx: ProviderContext) -> CheckResult:
        """Return the current state of this control."""

    def enforce(self, ctx: ProviderContext) -> CheckResult:
        """Converge actual state toward desired. Detect-only by default."""
        raise NotRemediable(f"{self.control_id} is detect-only")

    # -- convenience -------------------------------------------------------

    def result(
        self,
        ctx: ProviderContext,
        state: State,
        summary: str,
        *,
        detail: str = "",
        observed: dict[str, str] | None = None,
    ) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            state=state,
            severity=ctx.severity,
            summary=summary,
            detail=detail,
            observed=observed,
            remediable=ctx.spec.remediable,
        )
