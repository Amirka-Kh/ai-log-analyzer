"""VictoriaMetrics / PromQL tools over the vmselect HTTP API (spec §6).

Read-only: only the ``/query`` and ``/query_range`` and ``/label`` endpoints
are used; write/admin endpoints are never called. Step count and series
returned are capped.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ai_ops_agent.config import MetricsConfig
from ai_ops_agent.tools.base import ToolError, ToolSpec

# Guard against a query string that smuggles in a write/admin path.
_FORBIDDEN = ("/api/v1/admin", "/api/v1/import", "delete_series", "/write")


class MetricsClient:
    def __init__(self, config: MetricsConfig, transport: httpx.BaseTransport | None = None) -> None:
        if not config.configured:
            raise ToolError("VictoriaMetrics is not configured (AI_OPS_METRICS_URL unset)")
        self.config = config
        headers = {}
        if config.bearer_token:
            headers["Authorization"] = f"Bearer {config.bearer_token}"
        auth = None
        if config.username:
            auth = (config.username, config.password or "")
        self._client = httpx.Client(
            base_url=config.url.rstrip("/"),  # type: ignore[union-attr]
            headers=headers,
            auth=auth,
            timeout=config.request_timeout_s,
            transport=transport,
        )

    def _get(self, path: str, params: dict[str, Any]) -> dict:
        if any(bad in path for bad in _FORBIDDEN):
            raise ToolError("refused: only read endpoints are permitted")
        try:
            resp = self._client.get(path, params=params)
        except httpx.HTTPError as exc:
            raise ToolError(f"metrics request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise ToolError(f"metrics API {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        if data.get("status") != "success":
            raise ToolError(f"query error: {data.get('error', 'unknown')}")
        return data

    def instant_query(self, query: str) -> str:
        data = self._get("/api/v1/query", {"query": query})
        return _format_result(data.get("data", {}), self.config.max_series)

    def range_query(self, query: str, minutes: int = 120, step: str = "60s") -> str:
        end = int(time.time())
        start = end - minutes * 60
        step_s = _step_seconds(step)
        if step_s and (end - start) / step_s > self.config.max_range_steps:
            step_s = max(1, (end - start) // self.config.max_range_steps)
            step = f"{step_s}s"
        data = self._get(
            "/api/v1/query_range",
            {"query": query, "start": start, "end": end, "step": step},
        )
        return _format_result(data.get("data", {}), self.config.max_series, is_range=True)

    def list_series(self, match: str, minutes: int = 120) -> str:
        end = int(time.time())
        start = end - minutes * 60
        data = self._get("/api/v1/series", {"match[]": match, "start": start, "end": end})
        series = data.get("data", [])[: self.config.max_series]
        if not series:
            return "no matching series"
        return "\n".join(str(s) for s in series)


def _step_seconds(step: str) -> int:
    units = {"s": 1, "m": 60, "h": 3600}
    if step and step[-1] in units and step[:-1].isdigit():
        return int(step[:-1]) * units[step[-1]]
    return 60


def _format_result(data: dict, max_series: int, is_range: bool = False) -> str:
    result = data.get("result", [])
    if not result:
        return "empty result (no data points)"
    lines: list[str] = []
    for series in result[:max_series]:
        metric = series.get("metric", {})
        label_str = "{" + ",".join(f"{k}={v}" for k, v in sorted(metric.items())) + "}"
        if is_range:
            values = series.get("values", [])
            if values:
                first_v = values[0][1]
                last_v = values[-1][1]
                sample = f"first={first_v} last={last_v} points={len(values)}"
            else:
                sample = "no points"
            lines.append(f"{label_str} {sample}")
        else:
            value = series.get("value", ["", ""])
            lines.append(f"{label_str} = {value[1]}")
    if len(result) > max_series:
        lines.append(f"[... {len(result) - max_series} more series omitted ...]")
    return "\n".join(lines)


def build_metrics_tools(config: MetricsConfig, redactor: Any = None,
                        client: MetricsClient | None = None) -> list[ToolSpec]:
    """Construct the metrics tool specs, or [] if metrics are unconfigured."""
    if not config.configured:
        return []
    mc = client or MetricsClient(config)
    return [
        ToolSpec(
            name="metrics_instant_query",
            description="Run an instant PromQL/MetricsQL query against VictoriaMetrics. "
            "Returns the current value per series. Read-only.",
            schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "PromQL/MetricsQL expression"}
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            func=lambda query: mc.instant_query(query),
            max_result_chars=config.max_result_chars,
            redactor=redactor,
        ),
        ToolSpec(
            name="metrics_range_query",
            description="Run a range PromQL query over the last N minutes; returns "
            "first/last value and point count per series (step is capped).",
            schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "minutes": {"type": "integer", "description": "lookback window, default 120"},
                    "step": {"type": "string", "description": "e.g. 60s, 5m; default 60s"},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            func=lambda query, minutes=120, step="60s": mc.range_query(query, minutes, step),
            max_result_chars=config.max_result_chars,
            redactor=redactor,
        ),
        ToolSpec(
            name="metrics_list_series",
            description="Discover label values / series matching a selector so you "
            "stop guessing metric names. Capped cardinality.",
            schema={
                "type": "object",
                "properties": {
                    "match": {"type": "string", "description": "series selector, e.g. "
                              "'{__name__=~\"container_.*\", namespace=\"prod\"}'"},
                    "minutes": {"type": "integer"},
                },
                "required": ["match"],
                "additionalProperties": False,
            },
            func=lambda match, minutes=120: mc.list_series(match, minutes),
            max_result_chars=config.max_result_chars,
            redactor=redactor,
        ),
    ]
