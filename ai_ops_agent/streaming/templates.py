"""Drain-style log template clustering.

Variable parts of a message (UUIDs, IPs, numbers, paths, durations, hex ids)
are normalized into placeholders so millions of lines collapse into a few
hundred templates with counts, first/last seen, and one exemplar each. This is
the core cost control: the LLM sees templates and exemplars, never the raw
firehose.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from ai_ops_agent.streaming.parsing import LogRecord

_NORMALIZERS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
        "<ts>",
    ),
    (
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
        "<uuid>",
    ),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<email>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\b\d+(?:\.\d+)?\s?(?:ns|us|µs|ms|s|m|h)\b"), "<dur>"),
    (re.compile(r"\b\d+(?:\.\d+)?\s?(?:B|KB|MB|GB|TB|KiB|MiB|GiB)\b"), "<size>"),
    (re.compile(r"(?<=[\s\"'=:(\[])(/[\w.\-]+){2,}"), "<path>"),
    (re.compile(r"\b\d+\b"), "<n>"),
]


def normalize_message(message: str) -> str:
    text = message.strip()
    for pattern, placeholder in _NORMALIZERS:
        text = pattern.sub(placeholder, text)
    # Collapse runs of identical placeholders/whitespace so lists of ids merge.
    text = re.sub(r"(<\w+>)(,\s*<\w+>)+", r"\1...", text)
    text = re.sub(r"\s+", " ", text)
    return text[:500]


@dataclass
class TemplateStats:
    template: str
    count: int = 0
    first_line: int = 0
    last_line: int = 0
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    exemplar: str = ""
    levels: Counter = field(default_factory=Counter)

    @property
    def dominant_level(self) -> str:
        return self.levels.most_common(1)[0][0] if self.levels else "info"


class TemplateStore:
    """Incremental clustering of records into normalized templates."""

    def __init__(self, max_templates: int = 10_000) -> None:
        self._templates: dict[str, TemplateStats] = {}
        self.max_templates = max_templates
        self.overflowed = False

    def add(self, record: LogRecord) -> tuple[str, bool]:
        """Add a record; returns (template, is_new)."""
        tmpl = normalize_message(record.message)
        stats = self._templates.get(tmpl)
        is_new = stats is None
        if stats is None:
            if len(self._templates) >= self.max_templates:
                self.overflowed = True
                tmpl = "<overflow>"
                stats = self._templates.setdefault(tmpl, TemplateStats(template=tmpl))
                is_new = False
            else:
                stats = TemplateStats(
                    template=tmpl,
                    first_line=record.line_no,
                    first_ts=record.ts,
                    exemplar=record.message[:400],
                )
                self._templates[tmpl] = stats
        stats.count += 1
        stats.last_line = record.line_no
        if record.ts is not None:
            stats.last_ts = record.ts
            if stats.first_ts is None:
                stats.first_ts = record.ts
        stats.levels[record.level or "info"] += 1
        return tmpl, is_new

    def __len__(self) -> int:
        return len(self._templates)

    def __contains__(self, template: str) -> bool:
        return template in self._templates

    def get(self, template: str) -> TemplateStats | None:
        return self._templates.get(template)

    def all(self) -> list[TemplateStats]:
        return list(self._templates.values())

    def top(self, n: int, level_filter: set[str] | None = None) -> list[TemplateStats]:
        items = self.all()
        if level_filter:
            items = [t for t in items if t.dominant_level in level_filter]
        return sorted(items, key=lambda t: t.count, reverse=True)[:n]

    def emerging(
        self, total_lines: int, tail_fraction: float = 0.2, n: int = 20
    ) -> list[TemplateStats]:
        """Templates first seen in the final ``tail_fraction`` of the input."""
        if total_lines <= 0:
            return []
        threshold = total_lines * (1.0 - tail_fraction)
        items = [t for t in self.all() if t.first_line >= threshold]
        return sorted(items, key=lambda t: t.count, reverse=True)[:n]
