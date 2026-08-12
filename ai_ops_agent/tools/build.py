"""Assemble the tool registry + deterministic context pre-fetch from config.

Tools that lack config are simply not registered — the model never sees them
(spec §5a: degrade, don't crash). CLI mode reuses the same builder; whichever
backends are configured become available.
"""

from __future__ import annotations

from typing import Any

from ai_ops_agent.config import AppConfig
from ai_ops_agent.core.alert import Alert
from ai_ops_agent.core.redaction import Redactor
from ai_ops_agent.tools.base import ToolRegistry
from ai_ops_agent.tools.kubernetes import K8sClient, build_k8s_tools
from ai_ops_agent.tools.metrics import MetricsClient, build_metrics_tools


def build_registry(
    config: AppConfig,
    metrics_client: MetricsClient | None = None,
    k8s_client: K8sClient | None = None,
) -> tuple[ToolRegistry, list[tuple[str, Any]]]:
    """Return (registry, prefetch) — prefetch is a list of (label, fn(alert))."""
    redactor = Redactor(enabled=config.redact, redact_ips=config.redact_ips)
    registry = ToolRegistry()

    mc = metrics_client
    if config.metrics.configured and mc is None:
        mc = MetricsClient(config.metrics)
    if config.metrics.configured:
        for spec in build_metrics_tools(config.metrics, redactor=redactor, client=mc):
            registry.add(spec)

    kc = k8s_client
    if config.k8s.configured and kc is None:
        kc = K8sClient(config.k8s)
    if config.k8s.configured:
        for spec in build_k8s_tools(config.k8s, redactor=redactor, client=kc):
            registry.add(spec)

    prefetch = _build_prefetch(mc, kc)
    return registry, prefetch


def _build_prefetch(mc: MetricsClient | None, kc: K8sClient | None) -> list[tuple[str, Any]]:
    """Deterministic turn-1 context so the model starts informed (spec §4.4)."""
    prefetch: list[tuple[str, Any]] = []

    if kc is not None:
        def pod_state(alert: Alert) -> str:
            if not (alert.namespace and alert.workload):
                return "no namespace/workload label on the alert"
            return kc.get_resource("pods", alert.workload, alert.namespace)

        def recent_events(alert: Alert) -> str:
            if not alert.namespace:
                return "no namespace label on the alert"
            return kc.describe_events(alert.namespace)

        def recent_logs(alert: Alert) -> str:
            if not (alert.namespace and alert.workload):
                return "no namespace/workload label on the alert"
            return kc.get_logs(alert.workload, alert.namespace)

        prefetch += [
            ("Affected pod/workload state", pod_state),
            ("Recent namespace events (last 30m)", recent_events),
            ("Last container log lines", recent_logs),
        ]

    if mc is not None:
        def alert_expr(alert: Alert) -> str:
            expr = alert.annotations.get("expr") or alert.annotations.get("expression")
            if not expr:
                return "alert carried no PromQL expression to evaluate"
            return mc.instant_query(expr)

        prefetch.append(("Alert expression current value", alert_expr))

    return prefetch
