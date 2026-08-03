"""Rolling baseline learned during the initial watch phase."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Baseline:
    duration_s: float
    started_at: float | None = None
    finished: bool = False
    lines: int = 0
    errors: int = 0
    template_counts: Counter = field(default_factory=Counter)
    # Templates considered "known good" once the baseline closes.
    known_templates: set[str] = field(default_factory=set)

    def start(self, now: float) -> None:
        if self.started_at is None:
            self.started_at = now

    def observe(self, template: str, is_error: bool) -> None:
        self.lines += 1
        if is_error:
            self.errors += 1
        self.template_counts[template] += 1

    def maybe_finish(self, now: float) -> bool:
        """Close the baseline once its duration has elapsed. Returns True the
        one time the transition happens."""
        if self.finished or self.started_at is None:
            return False
        if now - self.started_at >= self.duration_s:
            self.finished = True
            self.known_templates = set(self.template_counts)
            return True
        return False

    @property
    def error_rate(self) -> float:
        return self.errors / self.lines if self.lines else 0.0

    def summary(self) -> str:
        top = ", ".join(t for t, _ in self.template_counts.most_common(5))
        return (
            f"baseline: {self.lines} lines, {self.error_rate:.1%} error rate, "
            f"{len(self.template_counts)} templates; most common: {top}"
        )
