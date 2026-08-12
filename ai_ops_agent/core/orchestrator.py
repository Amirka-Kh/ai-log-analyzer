"""The analysis engine shared by every entry point.

`ai-ops analyze`, `ai-ops watch` escalations, and (in later phases) the
webhook/Mattermost paths all feed records through this engine and get the same
:class:`Report` back. No analysis logic lives in the CLI layer.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from datetime import datetime, timedelta

from ai_ops_agent.config import AppConfig
from ai_ops_agent.core.redaction import Redactor
from ai_ops_agent.core.signals import (
    AnalysisSignals,
    SignalsCollector,
    build_deterministic_findings,
    summarize_timeline,
)
from ai_ops_agent.llm.client import LLMClient, LLMError, LLMResult
from ai_ops_agent.llm.prompt_loader import load_prompt
from ai_ops_agent.llm.schemas import LLMVerdict
from ai_ops_agent.reporting.models import (
    Alternative,
    AnalysisStats,
    Evidence,
    EvidenceSource,
    Finding,
    ProbableCause,
    RecommendedAction,
    Report,
    Severity,
    TimelineEvent,
    Verdict,
)
from ai_ops_agent.streaming.parsing import LogRecord, parse_stream
from ai_ops_agent.streaming.templates import TemplateStore

logger = logging.getLogger(__name__)

_SINCE_RE = re.compile(r"^(\d+)([smhd])$")
_SINCE_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_since(since: str) -> timedelta:
    m = _SINCE_RE.match(since.strip())
    if not m:
        raise ValueError(f"invalid --since value {since!r}; expected e.g. 30m, 2h, 1d")
    return timedelta(**{_SINCE_UNITS[m.group(2)]: int(m.group(1))})


class AnalysisEngine:
    def __init__(self, config: AppConfig, llm_client: LLMClient | None = None) -> None:
        self.config = config
        self.llm_client = llm_client
        self.redactor = Redactor(enabled=config.redact, redact_ips=config.redact_ips)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def analyze_lines(
        self,
        lines: Iterable[str],
        source: str,
        since: str | None = None,
        focus: str | None = None,
        fmt: str | None = None,
    ) -> Report:
        cutoff: datetime | None = None
        if since:
            cutoff = datetime.now() - parse_since(since)

        templates = TemplateStore()
        collector = SignalsCollector(gap_threshold_s=self.config.analyze.gap_threshold_s)
        detected_fmt = fmt or "auto"
        skipped_old = 0

        for record in parse_stream(lines, fmt=fmt):
            if cutoff is not None and record.ts is not None:
                ts = record.ts.replace(tzinfo=None) if record.ts.tzinfo else record.ts
                if ts < cutoff:
                    skipped_old += 1
                    continue
            templates.add(record)
            collector.add(record)

        signals = collector.finalize()
        return self._build_report(
            signals=signals,
            templates=templates,
            source=source,
            focus=focus,
            detected_fmt=detected_fmt,
            skipped_old=skipped_old,
        )

    def analyze_records(
        self, records: Iterable[LogRecord], source: str, focus: str | None = None
    ) -> Report:
        """Same engine, pre-parsed records (used by watch escalations)."""
        templates = TemplateStore()
        collector = SignalsCollector(gap_threshold_s=self.config.analyze.gap_threshold_s)
        for record in records:
            templates.add(record)
            collector.add(record)
        signals = collector.finalize()
        return self._build_report(
            signals=signals, templates=templates, source=source, focus=focus, detected_fmt="stream"
        )

    # ------------------------------------------------------------------
    # Report assembly
    # ------------------------------------------------------------------

    def _build_report(
        self,
        signals: AnalysisSignals,
        templates: TemplateStore,
        source: str,
        focus: str | None,
        detected_fmt: str,
        skipped_old: int = 0,
    ) -> Report:
        findings = self._deterministic_findings(signals, templates)
        stats = AnalysisStats(
            total_lines=signals.total_lines,
            parsed_records=signals.records,
            template_count=len(templates),
            error_count=signals.error_count,
            warning_count=signals.level_counts.get("warning", 0),
            first_ts=signals.first_ts,
            last_ts=signals.last_ts,
            detected_format=detected_fmt,
        )
        notes = []
        if skipped_old:
            notes.append(f"{skipped_old} records older than --since were skipped")
        if templates.overflowed:
            notes.append("template store overflowed; rare templates merged into <overflow>")
        stats.sampling_note = "; ".join(notes) or None

        report = Report(source=source, findings=findings, stats=stats)

        if self.llm_client is not None and signals.records > 0:
            self._run_llm(report, signals, templates, focus)
        else:
            self._deterministic_verdict(report, signals)
        stats.redaction_hits = self.redactor.hits
        return report

    def _deterministic_findings(
        self, signals: AnalysisSignals, templates: TemplateStore
    ) -> list[Finding]:
        raw = build_deterministic_findings(
            signals, templates, top_n=min(10, self.config.analyze.top_templates)
        )
        findings = []
        for item in raw:
            evidence = [
                Evidence(
                    source=EvidenceSource.logs,
                    query=f"line {line_no}",
                    excerpt=self.redactor.redact(text),
                )
                for line_no, text in item["exemplars"]
            ]
            findings.append(
                Finding(
                    severity=Severity(item["severity"]),
                    title=self.redactor.redact(item["title"]),
                    detail=item["detail"],
                    evidence=evidence,
                    line_refs=[line_no for line_no, _ in item["exemplars"]],
                    count=item["count"],
                )
            )
        return findings

    def _deterministic_verdict(self, report: Report, signals: AnalysisSignals) -> None:
        if signals.records == 0:
            report.verdict = Verdict.needs_human
            report.severity = Severity.info
            report.title = "No log records parsed"
            report.summary = "The source produced no parseable log records."
            return
        sev = report.max_finding_severity()
        if signals.fatal_hits or sev in (Severity.sev1, Severity.sev2):
            report.verdict = Verdict.needs_human
            report.severity = sev if sev != Severity.info else Severity.sev3
            report.title = "Deterministic signals found issues that need a human look"
        elif signals.error_rate > 0.10 or sev == Severity.sev3:
            report.verdict = Verdict.needs_human
            report.severity = Severity.sev3
            report.title = "Elevated errors detected (deterministic analysis only)"
        else:
            report.verdict = Verdict.no_incident
            report.severity = Severity.info
            report.title = "No significant issues detected"
        report.summary = (
            f"Deterministic analysis of {signals.records} records "
            f"({signals.error_count} errors, {signals.error_rate:.1%} error rate); "
            f"{len(report.findings)} findings. LLM analysis was not used."
        )

    # ------------------------------------------------------------------
    # LLM path
    # ------------------------------------------------------------------

    def _run_llm(
        self,
        report: Report,
        signals: AnalysisSignals,
        templates: TemplateStore,
        focus: str | None,
    ) -> None:
        prompt = load_prompt("analyze_system")
        context = self.build_context(signals, templates, report.source, focus)
        report.engine.prompt_version = prompt.version

        assert self.llm_client is not None
        result: LLMResult | None = None
        error_note = ""
        for attempt in range(2):
            user = context if not error_note else f"{context}\n\n{error_note}"
            try:
                candidate = self.llm_client.generate_verdict(prompt.text, user)
            except LLMError as exc:
                report.engine.degraded = True
                report.engine.degraded_reason = str(exc)
                logger.warning("LLM call failed: %s", exc)
                self._deterministic_verdict(report, signals)
                report.summary += " (LLM unavailable — degraded to deterministic output.)"
                return
            bad = validate_evidence(candidate.verdict, context)
            if not bad:
                result = candidate
                break
            error_note = (
                "VALIDATION ERROR: the following evidence excerpts were not found "
                "verbatim in the summary above; quote excerpts exactly as given:\n- "
                + "\n- ".join(bad[:5])
            )
            logger.warning("evidence validation failed (attempt %d): %d bad excerpts",
                           attempt + 1, len(bad))

        if result is None:
            report.engine.degraded = True
            report.engine.degraded_reason = "evidence validation failed after retry"
            self._deterministic_verdict(report, signals)
            report.summary += " (LLM output failed evidence validation — degraded output.)"
            return

        self._merge_llm_verdict(report, result)

    def build_context(
        self,
        signals: AnalysisSignals,
        templates: TemplateStore,
        source: str,
        focus: str | None,
    ) -> str:
        """Render the compact, redacted summary the model sees."""
        cfg = self.config.analyze
        red = self.redactor.redact
        parts: list[str] = []
        parts.append(f"Log source: {source}")
        if focus:
            parts.append(f"Operator focus: {focus}")
        span = ""
        if signals.first_ts and signals.last_ts:
            span = f" spanning {signals.first_ts.isoformat()} .. {signals.last_ts.isoformat()}"
        parts.append(
            f"Records: {signals.records} ({signals.error_count} errors, "
            f"{signals.error_rate:.1%} error rate){span}"
        )
        parts.append(
            "Level histogram: "
            + ", ".join(f"{k}={v}" for k, v in signals.level_counts.most_common())
        )

        parts.append("\n<untrusted-log-data>")

        top = templates.top(cfg.top_templates)
        if top:
            parts.append("## Top templates by volume (template | count | level | exemplar)")
            for t in top:
                parts.append(
                    f"- [{t.count}x, {t.dominant_level}, first line {t.first_line}] "
                    f"{red(t.template)}\n  exemplar: {red(t.exemplar)}"
                )

        emerging = templates.emerging(signals.total_lines, cfg.emerging_tail_fraction)
        if emerging:
            parts.append("## Templates first appearing near the end of the input")
            for t in emerging[:15]:
                parts.append(f"- [{t.count}x, {t.dominant_level}] {red(t.template)}")

        if signals.exception_types:
            parts.append("## Exception types")
            for exc, count in signals.exception_types.most_common(10):
                parts.append(f"- {exc}: {count}x")

        if signals.security_hits:
            parts.append("## Security signal matches")
            for hit in signals.security_hits.values():
                parts.append(f"- {hit.title}: {hit.count}x")
                for line_no, text in hit.exemplars:
                    parts.append(f"  line {line_no}: {red(text)}")

        if signals.fatal_hits:
            parts.append("## Fatal/panic/OOM markers")
            for line_no, text in signals.fatal_hits[:10]:
                parts.append(f"- line {line_no}: {red(text)}")

        timeline = summarize_timeline(signals, cfg.max_timeline_buckets)
        if timeline:
            parts.append("## Error timeline (bucket start | total | errors)")
            for bucket in timeline[-120:]:
                parts.append(f"- {bucket.start.isoformat()} | {bucket.total} | {bucket.errors}")

        if signals.gaps:
            parts.append("## Logging gaps (silent periods)")
            for start, end in signals.gaps:
                parts.append(f"- {start.isoformat()} .. {end.isoformat()}")

        parts.append("</untrusted-log-data>")

        context = "\n".join(parts)
        limit = self.config.llm.max_context_chars
        if len(context) > limit:
            context = context[:limit] + "\n[context truncated at char budget]"
        return context

    def _merge_llm_verdict(self, report: Report, result: LLMResult) -> None:
        v = result.verdict
        report.verdict = Verdict(v.verdict)
        report.confidence = v.confidence
        report.severity = Severity(v.severity)
        report.title = v.title
        report.summary = v.summary
        report.timeline = [TimelineEvent(ts=e.ts, event=e.event) for e in v.timeline]
        report.probable_cause = ProbableCause(
            statement=v.probable_cause.statement,
            evidence=[
                Evidence(source=EvidenceSource(e.source), query=e.query, excerpt=e.excerpt)
                for e in v.probable_cause.evidence
            ],
            alternatives_considered=[
                Alternative(hypothesis=a.hypothesis, why_rejected=a.why_rejected)
                for a in v.probable_cause.alternatives_considered
            ],
        )
        report.blast_radius.services = v.blast_radius.services
        report.blast_radius.users_affected = v.blast_radius.users_affected
        report.recommended_actions = [
            RecommendedAction(
                step=a.step, command=a.command, risk=a.risk, reversible=a.reversible
            )
            for a in v.recommended_actions
        ]
        report.false_positive_reasoning = v.false_positive_reasoning
        report.unknowns = v.unknowns
        report.links = {
            k: val for k, val in v.links.model_dump().items() if val is not None
        }
        report.engine.llm_used = True
        report.engine.model = result.model
        report.engine.input_tokens = result.input_tokens
        report.engine.output_tokens = result.output_tokens


_WS_RE = re.compile(r"\s+")


def _norm(text: str) -> str:
    return _WS_RE.sub(" ", text).strip().lower()


def validate_evidence(verdict: LLMVerdict, context: str) -> list[str]:
    """Anti-hallucination check: every evidence excerpt must appear (modulo
    whitespace/case) in the context we supplied. Returns the offending excerpts.
    """
    haystack = _norm(context)
    bad = []
    for ev in verdict.probable_cause.evidence:
        needle = _norm(ev.excerpt)
        if len(needle) < 4 or needle not in haystack:
            bad.append(ev.excerpt[:120])
    incident = verdict.verdict not in ("no_incident", "needs_human")
    if incident and not verdict.probable_cause.evidence:
        bad.append("<probable_cause.evidence is empty>")
    return bad
