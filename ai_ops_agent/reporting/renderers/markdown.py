"""Markdown renderer for Report (used for --output markdown and, later, as the
full-report attachment posted to Mattermost)."""

from __future__ import annotations

from ai_ops_agent.reporting.models import Report


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# {report.title or 'Analysis report'}")
    lines.append("")
    lines.append(
        f"**Verdict:** {report.verdict.value} | **Severity:** {report.severity.value}"
        + (f" | **Confidence:** {report.confidence:.0%}" if report.engine.llm_used else "")
    )
    lines.append(f"**Source:** `{report.source}` | **Report ID:** `{report.id}`")
    lines.append("")
    if report.summary:
        lines.append(report.summary)
        lines.append("")

    if report.timeline:
        lines.append("## Timeline")
        for event in report.timeline:
            lines.append(f"- `{event.ts}` — {event.event}")
        lines.append("")

    if report.probable_cause.statement:
        lines.append("## Probable cause")
        lines.append(report.probable_cause.statement)
        for ev in report.probable_cause.evidence:
            lines.append(f"> `{ev.source.value}` ({ev.query}): {ev.excerpt}")
        if report.probable_cause.alternatives_considered:
            lines.append("")
            lines.append("**Alternatives considered:**")
            for alt in report.probable_cause.alternatives_considered:
                lines.append(f"- {alt.hypothesis} — rejected: {alt.why_rejected}")
        lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("| Severity | Count | Finding | Lines |")
        lines.append("|---|---|---|---|")
        for f in report.findings:
            refs = ", ".join(str(n) for n in f.line_refs[:5]) or "-"
            title = f.title.replace("|", "\\|")
            lines.append(f"| {f.severity.value} | {f.count} | {title} | {refs} |")
        lines.append("")

    if report.recommended_actions:
        lines.append("## Suggested actions")
        for i, action in enumerate(report.recommended_actions, 1):
            cmd = f" — `{action.command}`" if action.command else ""
            lines.append(f"{i}. {action.step} (risk: {action.risk}){cmd}")
        lines.append("")

    if report.false_positive_reasoning:
        lines.append("## False-positive reasoning")
        lines.append(report.false_positive_reasoning)
        lines.append("")

    if report.unknowns:
        lines.append("## Unknowns")
        for u in report.unknowns:
            lines.append(f"- {u}")
        lines.append("")

    stats = report.stats
    lines.append("## Stats")
    lines.append(
        f"- {stats.total_lines} lines, {stats.parsed_records} records, "
        f"{stats.template_count} templates, {stats.error_count} errors "
        f"({stats.detected_format} format)"
    )
    if stats.first_ts and stats.last_ts:
        lines.append(f"- Span: {stats.first_ts.isoformat()} .. {stats.last_ts.isoformat()}")
    if report.engine.llm_used:
        lines.append(
            f"- Model: {report.engine.model}, prompt {report.engine.prompt_version}"
        )
    else:
        lines.append("- Deterministic analysis (no LLM)")
    if report.engine.degraded:
        lines.append(f"- **Degraded output:** {report.engine.degraded_reason}")
    if stats.sampling_note:
        lines.append(f"- Note: {stats.sampling_note}")
    return "\n".join(lines)
