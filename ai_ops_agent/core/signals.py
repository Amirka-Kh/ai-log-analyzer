"""Deterministic signal computation over a stream of LogRecords.

Runs with no LLM involved; its output feeds both the `--no-llm` report and the
compact context handed to the model.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from ai_ops_agent.core.security import FATAL_MARKERS, SECURITY_PATTERNS
from ai_ops_agent.streaming.parsing import LogRecord
from ai_ops_agent.streaming.templates import TemplateStore


@dataclass
class SecurityHit:
    name: str
    title: str
    severity: str
    count: int = 0
    exemplars: list[tuple[int, str]] = field(default_factory=list)  # (line_no, text)


@dataclass
class TimeBucket:
    start: datetime
    total: int = 0
    errors: int = 0


@dataclass
class AnalysisSignals:
    total_lines: int = 0
    records: int = 0
    level_counts: Counter = field(default_factory=Counter)
    exception_types: Counter = field(default_factory=Counter)
    security_hits: dict[str, SecurityHit] = field(default_factory=dict)
    fatal_hits: list[tuple[int, str]] = field(default_factory=list)
    timeline: list[TimeBucket] = field(default_factory=list)
    gaps: list[tuple[datetime, datetime]] = field(default_factory=list)
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    @property
    def error_count(self) -> int:
        return self.level_counts.get("error", 0) + self.level_counts.get("critical", 0)

    @property
    def error_rate(self) -> float:
        return self.error_count / self.records if self.records else 0.0


class SignalsCollector:
    def __init__(self, gap_threshold_s: float = 300.0, max_exemplars: int = 3) -> None:
        self.signals = AnalysisSignals()
        self._minute_buckets: dict[datetime, TimeBucket] = {}
        self.gap_threshold_s = gap_threshold_s
        self.max_exemplars = max_exemplars

    def add(self, record: LogRecord) -> None:
        sig = self.signals
        sig.records += 1
        sig.total_lines += 1 + len(record.extra_lines)
        sig.level_counts[record.level or "unknown"] += 1

        exc = record.exception_type()
        if exc:
            sig.exception_types[exc] += 1

        text = record.full_text
        for pattern in SECURITY_PATTERNS:
            if pattern.pattern.search(text):
                hit = sig.security_hits.setdefault(
                    pattern.name,
                    SecurityHit(pattern.name, pattern.title, pattern.severity.value),
                )
                hit.count += 1
                if len(hit.exemplars) < self.max_exemplars:
                    hit.exemplars.append((record.line_no, record.message[:200]))

        if FATAL_MARKERS.search(text) and len(sig.fatal_hits) < 20:
            sig.fatal_hits.append((record.line_no, record.message[:200]))

        ts = record.ts
        if ts is not None:
            naive = ts.replace(tzinfo=None) if ts.tzinfo else ts
            if sig.first_ts is None or naive < sig.first_ts:
                sig.first_ts = naive
            if sig.last_ts is None or naive > sig.last_ts:
                sig.last_ts = naive
            minute = naive.replace(second=0, microsecond=0)
            bucket = self._minute_buckets.setdefault(minute, TimeBucket(start=minute))
            bucket.total += 1
            if record.is_error:
                bucket.errors += 1

    def finalize(self) -> AnalysisSignals:
        sig = self.signals
        sig.timeline = [self._minute_buckets[k] for k in sorted(self._minute_buckets)]
        # Silent-period detection: consecutive active minutes further apart
        # than the gap threshold.
        prev: datetime | None = None
        for bucket in sig.timeline:
            if prev is not None:
                delta = (bucket.start - prev).total_seconds()
                if delta > self.gap_threshold_s:
                    sig.gaps.append((prev, bucket.start))
            prev = bucket.start
        sig.gaps = sorted(
            sig.gaps, key=lambda g: (g[1] - g[0]).total_seconds(), reverse=True
        )[:5]
        return sig


def summarize_timeline(signals: AnalysisSignals, max_buckets: int = 500) -> list[TimeBucket]:
    """Coarsen the per-minute timeline if it exceeds ``max_buckets``."""
    timeline = signals.timeline
    if len(timeline) <= max_buckets:
        return timeline
    factor = (len(timeline) + max_buckets - 1) // max_buckets
    merged: list[TimeBucket] = []
    for i in range(0, len(timeline), factor):
        chunk = timeline[i : i + factor]
        merged.append(
            TimeBucket(
                start=chunk[0].start,
                total=sum(b.total for b in chunk),
                errors=sum(b.errors for b in chunk),
            )
        )
    return merged


def top_error_minutes(signals: AnalysisSignals, n: int = 5) -> list[TimeBucket]:
    return sorted(signals.timeline, key=lambda b: b.errors, reverse=True)[:n]


def build_deterministic_findings(
    signals: AnalysisSignals, templates: TemplateStore, top_n: int = 10
) -> list[dict]:
    """Raw finding dicts from deterministic signals (converted to Finding by the
    orchestrator, which owns redaction)."""
    findings: list[dict] = []

    for hit in sorted(signals.security_hits.values(), key=lambda h: h.count, reverse=True):
        findings.append(
            {
                "severity": hit.severity,
                "title": f"{hit.title} ({hit.count}x)",
                "detail": "Matched a deterministic security signal pattern.",
                "exemplars": hit.exemplars,
                "count": hit.count,
            }
        )

    if signals.fatal_hits:
        findings.append(
            {
                "severity": "sev2",
                "title": f"Fatal/panic/OOM markers present ({len(signals.fatal_hits)}x)",
                "detail": "Lines matched fatal, panic, OOM, segfault, or stack-trace markers.",
                "exemplars": signals.fatal_hits[:3],
                "count": len(signals.fatal_hits),
            }
        )

    for exc, count in signals.exception_types.most_common(5):
        findings.append(
            {
                "severity": "sev3",
                "title": f"Exception {exc} ({count}x)",
                "detail": "Recurring exception type extracted from stack traces.",
                "exemplars": [],
                "count": count,
            }
        )

    error_templates = templates.top(top_n, level_filter={"error", "critical"})
    for t in error_templates:
        findings.append(
            {
                "severity": "sev3",
                "title": f"Error template ({t.count}x): {t.template[:120]}",
                "detail": "High-volume error-level log template.",
                "exemplars": [(t.first_line, t.exemplar)],
                "count": t.count,
            }
        )

    for start, end in signals.gaps:
        minutes = (end - start).total_seconds() / 60
        findings.append(
            {
                "severity": "info",
                "title": (
                    f"Logging gap of {minutes:.0f} min "
                    f"({start.isoformat()} → {end.isoformat()})"
                ),
                "detail": "No log lines observed during this period (possible outage or rotation).",
                "exemplars": [],
                "count": 1,
            }
        )

    return findings
