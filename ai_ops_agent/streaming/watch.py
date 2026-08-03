"""Watch session: the control loop for `ai-ops watch`, decoupled from I/O.

The CLI feeds raw lines in with a caller-supplied clock; this module owns
parsing, clustering, the baseline phase, windowing, trigger evaluation,
cooldown / rate limiting, and the session summary. No asyncio in here, so the
whole state machine is unit-testable with a fake clock and scripted lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ai_ops_agent.config import WatchConfig
from ai_ops_agent.reporting.models import SEVERITY_RANK, Severity
from ai_ops_agent.streaming.parsing import LogRecord, parse_plain_line, parse_stream
from ai_ops_agent.streaming.state import Baseline
from ai_ops_agent.streaming.templates import TemplateStore
from ai_ops_agent.streaming.triggers import Trigger, evaluate_window
from ai_ops_agent.streaming.windowing import Window


@dataclass
class Notification:
    """A finding worth telling the human about."""

    at: float
    severity: Severity
    reasons: list[str]
    detail: str
    window_lines: int
    window_errors: int
    exemplars: list[str]
    suppressed_repeats: int = 0
    related_to_previous: bool = False


@dataclass
class SessionSummary:
    duration_s: float
    total_lines: int
    total_errors: int
    template_count: int
    notifications: int
    suppressed: int
    top_templates: list[tuple[str, int]] = field(default_factory=list)


class WatchSession:
    def __init__(self, config: WatchConfig, fmt: str | None = None) -> None:
        self.config = config
        self.fmt = fmt
        self.templates = TemplateStore()
        self.baseline = Baseline(duration_s=config.baseline_seconds)
        self.window: Window | None = None
        self.started_at: float | None = None
        self.total_lines = 0
        self.total_errors = 0
        self.notifications: list[Notification] = []
        self.suppressed = 0
        self._last_notified_at: float | None = None
        self._notify_times: list[float] = []
        self._last_reasons: set[str] = set()

    # ------------------------------------------------------------------

    def ingest_line(self, raw_line: str, now: float) -> list[Notification]:
        """Feed one raw line; returns any notifications emitted (window close)."""
        if self.started_at is None:
            self.started_at = now
            self.baseline.start(now)
        line = raw_line.rstrip("\n")
        if not line.strip():
            return []
        record = self._parse(line)
        self.total_lines += 1
        if record.is_error:
            self.total_errors += 1

        template, is_new = self.templates.add(record)
        if not self.baseline.finished:
            self.baseline.observe(template, record.is_error)
            self.baseline.maybe_finish(now)
            return []

        if self.window is None:
            self.window = Window(start=now)
        self.window.add(record, template, is_new)
        if self.window.is_full(now, self.config.window_seconds, self.config.window_max_lines):
            return self.close_window(now)
        return []

    def tick(self, now: float) -> list[Notification]:
        """Called periodically even when no lines arrive, so time-based window
        closes still happen on a quiet stream."""
        if self.baseline.maybe_finish(now):
            return []
        if self.window is not None and self.window.is_full(
            now, self.config.window_seconds, self.config.window_max_lines
        ):
            return self.close_window(now)
        return []

    def process_exit(self, returncode: int, now: float) -> Notification | None:
        """Non-zero process exit is always escalated (not rate-limited)."""
        pending = self.close_window(now)
        if returncode == 0:
            return None
        note = Notification(
            at=now,
            severity=Severity.sev2,
            reasons=["process_exit"],
            detail=f"watched process exited with code {returncode}",
            window_lines=0,
            window_errors=0,
            exemplars=[],
        )
        self.notifications.append(note)
        return note if not pending else note

    # ------------------------------------------------------------------

    def close_window(self, now: float) -> list[Notification]:
        window, self.window = self.window, None
        if window is None or window.count == 0:
            return []
        triggers = evaluate_window(window, self.baseline, self.config)
        if not triggers:
            return []
        return self._emit(window, triggers, now)

    def _emit(self, window: Window, triggers: list[Trigger], now: float) -> list[Notification]:
        reasons = {t.reason for t in triggers}
        # Cooldown: identical reasons within the cooldown window are counted,
        # not re-notified — a crash loop yields one escalating thread, not 100.
        if (
            self._last_notified_at is not None
            and now - self._last_notified_at < self.config.cooldown_seconds
            and reasons <= self._last_reasons
        ):
            self.suppressed += 1
            if self.notifications:
                self.notifications[-1].suppressed_repeats += 1
            return []

        # Global rate limit.
        self._notify_times = [t for t in self._notify_times if now - t < 3600]
        if len(self._notify_times) >= self.config.max_alerts_per_hour:
            self.suppressed += 1
            return []

        severity = max((t.severity for t in triggers), key=lambda s: SEVERITY_RANK[s])
        exemplars: list[str] = []
        for record in window.records:
            if record.is_error and len(exemplars) < 5:
                exemplars.append(f"line ~{record.line_no}: {record.message[:200]}")
        if not exemplars:
            exemplars = [f"{r.message[:200]}" for r in window.records[:3]]
        note = Notification(
            at=now,
            severity=severity,
            reasons=sorted(reasons),
            detail=" | ".join(t.detail for t in triggers),
            window_lines=window.count,
            window_errors=window.errors,
            exemplars=exemplars,
            related_to_previous=bool(reasons & self._last_reasons),
        )
        self.notifications.append(note)
        self._last_notified_at = now
        self._last_reasons = reasons
        self._notify_times.append(now)
        return [note]

    # ------------------------------------------------------------------

    def summary(self, now: float) -> SessionSummary:
        duration = (now - self.started_at) if self.started_at is not None else 0.0
        return SessionSummary(
            duration_s=duration,
            total_lines=self.total_lines,
            total_errors=self.total_errors,
            template_count=len(self.templates),
            notifications=len(self.notifications),
            suppressed=self.suppressed,
            top_templates=[(t.template, t.count) for t in self.templates.top(5)],
        )

    def recent_records(self) -> list[LogRecord]:
        return list(self.window.records) if self.window else []

    def _parse(self, line: str) -> LogRecord:
        # Reuse the analyze parsers one line at a time; parse_stream on a single
        # line handles format-specific extraction, plain fallback included.
        records = list(parse_stream([line], fmt=self.fmt, sample_size=1))
        return records[0] if records else parse_plain_line(1, line)
