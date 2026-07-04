"""Rendering and export for posture reports.

Rich tables/panels for humans; ``to_json`` and ``to_sarif`` for machines;
``status_line`` for the shell prompt. Human output goes to stderr so JSON on
stdout stays pipeable.
"""

from __future__ import annotations

import json
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .model import CheckResult, PostureReport, State

console = Console(stderr=True)

_STATE_STYLE = {
    State.OK: "green",
    State.DRIFT: "bold yellow",
    State.VIOLATION: "bold white on red",
    State.ERROR: "bold red",
    State.NOT_APPLICABLE: "dim",
    State.NOT_ENFORCED: "dim cyan",
}

_STATE_GLYPH = {
    State.OK: "OK",
    State.DRIFT: "DRIFT",
    State.VIOLATION: "VIOLATION",
    State.ERROR: "ERROR",
    State.NOT_APPLICABLE: "n/a",
    State.NOT_ENFORCED: "skipped",
}


def render_report(report: PostureReport, *, name: str | None = None) -> None:
    table = Table(show_header=True, header_style="bold", expand=True, box=None)
    table.add_column("STATE", no_wrap=True)
    table.add_column("CONTROL", no_wrap=True)
    table.add_column("SEV", no_wrap=True)
    table.add_column("SUMMARY", overflow="fold")

    for result in _ordered(report.results):
        table.add_row(
            Text(_STATE_GLYPH[result.state], style=_STATE_STYLE[result.state]),
            result.control_id,
            result.severity.value,
            result.summary,
        )

    counts = report.counts()
    if report.conformant:
        header = Text("CONFORMANT", style="bold green")
        border = "green"
    else:
        header = Text(f"NON-CONFORMANT — {len(report.failures)} failing", style="bold red")
        border = "red"
    subtitle = (
        f"ok={counts['ok']} drift={counts['drift']} violation={counts['violation']} "
        f"error={counts['error']} n/a={counts['not_applicable']} skipped={counts['not_enforced']}"
    )
    title = f"FLE · POSTURE" + (f" · {name}" if name else "")
    console.print(Panel(_stack(header, table, Text(subtitle, style="dim")),
                        title=f"[bold]{title}[/]", border_style=border, expand=True))


def render_detail(results: Sequence[CheckResult]) -> None:
    """Print the detail lines for failing controls, if any."""
    failing = [r for r in results if r.failing]
    if not failing:
        return
    for r in failing:
        if r.detail:
            console.print(f"  [dim]{r.control_id}:[/] {r.detail}")


def render_enforcement(outcomes: Sequence[CheckResult]) -> None:
    if not outcomes:
        console.print("[dim]nothing to remediate.[/]")
        return
    for r in outcomes:
        style = "green" if r.state is State.OK else "yellow"
        console.print(f"  [{style}]{_STATE_GLYPH[r.state]}[/] {r.control_id}: {r.summary}")


def status_line(report: PostureReport) -> str:
    """Compact one-line status for the shell prompt."""
    if report.conformant:
        return "opsec:ok"
    failing = report.failures
    worst = failing[0].control_id if failing else "?"
    return f"opsec:FAIL({len(failing)}:{worst})"


def to_json(report: PostureReport, *, name: str | None = None) -> str:
    return json.dumps(report.as_dict(profile_name=name), indent=2)


def to_sarif(report: PostureReport, *, name: str | None = None) -> str:
    """Minimal SARIF 2.1.0 export for tool interoperability."""
    level = {
        State.VIOLATION: "error", State.ERROR: "error",
        State.DRIFT: "warning", State.OK: "none",
        State.NOT_APPLICABLE: "none", State.NOT_ENFORCED: "none",
    }
    results = [
        {
            "ruleId": r.control_id,
            "level": level[r.state],
            "message": {"text": f"[{r.state.value}] {r.summary}. {r.detail}".strip()},
        }
        for r in report.results
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "fle", "informationUri": "https://faceless-engine.dev",
                                "rules": [{"id": cid} for cid in {r.control_id for r in report.results}]}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


# -- helpers ---------------------------------------------------------------


def _ordered(results: Sequence[CheckResult]) -> list[CheckResult]:
    order = {State.VIOLATION: 0, State.ERROR: 1, State.DRIFT: 2,
             State.OK: 3, State.NOT_ENFORCED: 4, State.NOT_APPLICABLE: 5}
    return sorted(results, key=lambda r: (order.get(r.state, 9), r.control_id))


def _stack(*renderables: object):
    from rich.console import Group

    return Group(*renderables)
