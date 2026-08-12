"""Tool protocol, JSON schema, and typed result envelope (spec §6).

Every tool exposes a JSON schema to the LLM, returns a
``{ok, data, truncated, error, latency_ms}`` envelope, truncates to a char
budget, and is audit-logged by the agent loop. Tools are read-only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolResult:
    ok: bool
    data: str = ""
    truncated: bool = False
    error: str | None = None
    latency_ms: float = 0.0

    def to_model_text(self) -> str:
        if not self.ok:
            return f"[tool error] {self.error}"
        suffix = "\n[...truncated...]" if self.truncated else ""
        return self.data + suffix


class Tool(Protocol):
    name: str
    description: str

    def input_schema(self) -> dict[str, Any]: ...

    def run(self, **kwargs: Any) -> ToolResult: ...


@dataclass
class ToolSpec:
    """Wraps a callable as an auditable tool with schema + result truncation."""

    name: str
    description: str
    schema: dict[str, Any]
    func: Any  # (**kwargs) -> str   (raises for errors)
    max_result_chars: int = 8000
    redactor: Any = None  # optional ai_ops_agent.core.redaction.Redactor

    def input_schema(self) -> dict[str, Any]:
        return self.schema

    def run(self, **kwargs: Any) -> ToolResult:
        started = time.monotonic()
        try:
            raw = self.func(**kwargs)
        except ToolError as exc:
            return ToolResult(ok=False, error=str(exc),
                              latency_ms=(time.monotonic() - started) * 1000)
        except Exception as exc:  # noqa: BLE001 - surface as a tool error, never crash the loop
            return ToolResult(ok=False, error=f"{type(exc).__name__}: {exc}",
                              latency_ms=(time.monotonic() - started) * 1000)
        text = raw if isinstance(raw, str) else str(raw)
        if self.redactor is not None:
            text = self.redactor.redact(text)
        truncated = len(text) > self.max_result_chars
        if truncated:
            text = text[: self.max_result_chars]
        return ToolResult(
            ok=True, data=text, truncated=truncated,
            latency_ms=(time.monotonic() - started) * 1000,
        )


class ToolError(Exception):
    """Expected tool failure (bad input, backend rejection) — surfaced to the
    model as a tool error rather than crashing the loop."""


@dataclass
class ToolRegistry:
    tools: dict[str, ToolSpec] = field(default_factory=dict)

    def add(self, spec: ToolSpec) -> None:
        self.tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self.tools.get(name)

    def openai_schema(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.schema,
                },
            }
            for spec in self.tools.values()
        ]

    def anthropic_schema(self) -> list[dict]:
        return [
            {"name": spec.name, "description": spec.description, "input_schema": spec.schema}
            for spec in self.tools.values()
        ]

    def __len__(self) -> int:
        return len(self.tools)
