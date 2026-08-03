"""Rolling window accumulation for `watch`."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ai_ops_agent.streaming.parsing import LogRecord


@dataclass
class Window:
    start: float  # monotonic-ish seconds supplied by the caller
    records: list[LogRecord] = field(default_factory=list)
    templates: Counter = field(default_factory=Counter)
    new_templates: list[str] = field(default_factory=list)
    new_template_levels: dict[str, str] = field(default_factory=dict)
    errors: int = 0

    def add(self, record: LogRecord, template: str, is_new: bool) -> None:
        self.records.append(record)
        self.templates[template] += 1
        if is_new:
            self.new_templates.append(template)
            self.new_template_levels[template] = record.level or "info"
        if record.is_error:
            self.errors += 1

    @property
    def count(self) -> int:
        return len(self.records)

    @property
    def error_rate(self) -> float:
        return self.errors / self.count if self.count else 0.0

    def is_full(self, now: float, max_seconds: float, max_lines: int) -> bool:
        return self.count >= max_lines or (now - self.start) >= max_seconds
