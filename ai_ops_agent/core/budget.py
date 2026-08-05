"""Per-investigation budgets: tool calls and wall clock (spec §4.4)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Budget:
    max_tool_calls: int = 12
    max_wall_clock_s: float = 90.0
    clock: object = time.monotonic  # injectable for tests
    started_at: float | None = None
    tool_calls_used: int = 0
    exhausted_reason: str | None = field(default=None)

    def start(self) -> None:
        if self.started_at is None:
            self.started_at = self.clock()  # type: ignore[operator]

    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        return self.clock() - self.started_at  # type: ignore[operator]

    def allow_tool_call(self) -> bool:
        self.start()
        if self.tool_calls_used >= self.max_tool_calls:
            self.exhausted_reason = f"tool-call budget exhausted ({self.max_tool_calls})"
            return False
        if self.elapsed() >= self.max_wall_clock_s:
            self.exhausted_reason = f"wall-clock budget exhausted ({self.max_wall_clock_s:.0f}s)"
            return False
        return True

    def record_tool_call(self) -> None:
        self.tool_calls_used += 1

    @property
    def exhausted(self) -> bool:
        return self.exhausted_reason is not None
