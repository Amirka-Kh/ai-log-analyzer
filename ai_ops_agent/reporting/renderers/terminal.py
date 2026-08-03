"""Terminal renderer for Report using rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ai_ops_agent.reporting.models import SEVERITY_RANK, Report, Severity

SEVERITY_STYLE = {
    Severity.sev1: "bold white on red",
    Severity.sev2: "bold black on dark_orange",
    Severity.sev3: "bold black on yellow",
    Severity.info: "bold white on grey37",
}

VERDICT_LABEL = {
    "real_incident": "REAL INCIDENT",
    "false_positive": "FALSE POSITIVE",
    "noisy_rule": "NOISY RULE",
    "expected_maintenance": "EXPECTED MAINTENANCE",
    "needs_human": "NEEDS HUMAN",
    "no_incident": "NO INCIDENT",
}


def render_report(report: Report, console: Console | None = None, verbose: bool = False) -> None:
    console = console or Console()

    banner = Text()
    banner.append(f" {VERDICT_LABEL.get(report.verdict.value, report.verdict.value)} ",
                  style=SEVERITY_STYLE[report.severity])
    banner.append(f"  {report.severity.value.upper()}")
    if report.engine.llm_used:
        banner.append(f"  confidence {report.confidence:.0%}")
    console.print(Panel(banner, title=report.title or "Analysis", subtitle=report.source))

    if report.summary:
        console.print(report.summary, style="bold")
        console.print()

    if report.probable_cause.statement:
        console.print("[bold]Probable cause:[/bold]", report.probable_cause.statement)
        for ev in report.probable_cause.evidence:
            console.print(f"  [dim]{ev.source.value} | {ev.query}[/dim] {ev.excerpt}")
        console.print()

    if report.findings:
        table = Table(title=f"Findings ({len(report.findings)})", expand=True)
        table.add_column("Sev", width=5)
        table.add_column("Count", width=7, justify="right")
        table.add_column("Finding", overflow="fold")
        table.add_column("Lines", width=14)
        for f in sorted(report.findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True):
            lines = ",".join(str(n) for n in f.line_refs[:3]) or "-"
            table.add_row(f.severity.value, str(f.count), f.title, lines)
        console.print(table)
        if verbose:
            for f in report.findings:
                for ev in f.evidence:
                    console.print(f"  [dim]{f.title[:50]} | {ev.query}:[/dim] {ev.excerpt}")

    if report.recommended_actions:
        console.print("\n[bold]Suggested actions (for a human to review):[/bold]")
        for i, action in enumerate(report.recommended_actions, 1):
            cmd = f"  [cyan]{action.command}[/cyan]" if action.command else ""
            console.print(f"  {i}. {action.step} [dim](risk: {action.risk})[/dim]{cmd}")

    if report.unknowns:
        console.print("\n[bold]Unknowns:[/bold]")
        for u in report.unknowns:
            console.print(f"  - {u}")

    stats = report.stats
    footer = (
        f"{stats.total_lines} lines / {stats.parsed_records} records / "
        f"{stats.template_count} templates / {stats.error_count} errors"
    )
    if stats.first_ts and stats.last_ts:
        footer += f" | {stats.first_ts.isoformat()} .. {stats.last_ts.isoformat()}"
    footer += f" | format: {stats.detected_format}"
    if report.engine.llm_used:
        footer += f" | model: {report.engine.model} (prompt {report.engine.prompt_version})"
    else:
        footer += " | deterministic (no LLM)"
    if report.engine.degraded:
        footer += f" | DEGRADED: {report.engine.degraded_reason}"
    if stats.sampling_note:
        footer += f" | note: {stats.sampling_note}"
    console.print(Panel(footer, style="dim"))
