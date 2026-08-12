"""Canonical Alert model + normalizers for incoming webhook payloads.

Alertmanager/vmalert v4 and Grafana unified-alerting payloads are both mapped
onto the same :class:`Alert` so the gating, task store, and agent loop never
see a provider-specific shape.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class Alert(BaseModel):
    fingerprint: str
    name: str
    severity: str = "unknown"
    status: str = "firing"  # firing | resolved
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    generator_url: str | None = None
    runbook_url: str | None = None

    # Convenience projections from labels (populated during normalization).
    cluster: str | None = None
    namespace: str | None = None
    workload: str | None = None
    node: str | None = None

    @property
    def is_resolved(self) -> bool:
        return self.status == "resolved"

    def group_key(self) -> str:
        """Correlate alerts firing on the same cluster/namespace/node."""
        return "|".join(
            [self.cluster or "", self.namespace or "", self.node or ""]
        )


def _parse_ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    v = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _fingerprint(labels: dict[str, str], name: str) -> str:
    basis = name + "".join(f"{k}={v}" for k, v in sorted(labels.items()))
    return hashlib.sha1(basis.encode()).hexdigest()[:16]


_WORKLOAD_LABELS = (
    "workload",
    "deployment",
    "daemonset",
    "statefulset",
    "job",
    "pod",
    "job_name",
)


def _project(alert: Alert) -> Alert:
    labels = alert.labels
    alert.cluster = labels.get("cluster") or labels.get("cluster_name")
    alert.namespace = labels.get("namespace") or labels.get("exported_namespace")
    alert.node = labels.get("node") or labels.get("instance")
    for key in _WORKLOAD_LABELS:
        if key in labels:
            alert.workload = labels[key]
            break
    if alert.severity == "unknown":
        alert.severity = labels.get("severity", "unknown")
    if not alert.runbook_url:
        alert.runbook_url = alert.annotations.get("runbook_url") or alert.annotations.get(
            "runbook"
        )
    return alert


def normalize_alertmanager(payload: dict) -> list[Alert]:
    """Alertmanager / vmalert v4 webhook payload -> list of Alerts."""
    alerts: list[Alert] = []
    for raw in payload.get("alerts", []):
        labels = {k: str(v) for k, v in (raw.get("labels") or {}).items()}
        annotations = {k: str(v) for k, v in (raw.get("annotations") or {}).items()}
        name = labels.get("alertname", "unknown")
        fingerprint = raw.get("fingerprint") or _fingerprint(labels, name)
        alert = Alert(
            fingerprint=fingerprint,
            name=name,
            status=raw.get("status", "firing"),
            starts_at=_parse_ts(raw.get("startsAt")),
            ends_at=_parse_ts(raw.get("endsAt")),
            labels=labels,
            annotations=annotations,
            generator_url=raw.get("generatorURL"),
        )
        alerts.append(_project(alert))
    return alerts


def normalize_grafana(payload: dict) -> list[Alert]:
    """Grafana unified-alerting webhook payload -> list of Alerts."""
    alerts: list[Alert] = []
    for raw in payload.get("alerts", []):
        labels = {k: str(v) for k, v in (raw.get("labels") or {}).items()}
        annotations = {k: str(v) for k, v in (raw.get("annotations") or {}).items()}
        name = labels.get("alertname") or payload.get("title", "unknown")
        fingerprint = raw.get("fingerprint") or _fingerprint(labels, name)
        alert = Alert(
            fingerprint=fingerprint,
            name=name,
            status=raw.get("status", "firing"),
            starts_at=_parse_ts(raw.get("startsAt")),
            ends_at=_parse_ts(raw.get("endsAt")),
            labels=labels,
            annotations=annotations,
            generator_url=raw.get("generatorURL") or raw.get("panelURL"),
        )
        alert.runbook_url = raw.get("dashboardURL") or annotations.get("runbook_url")
        alerts.append(_project(alert))
    return alerts


def alert_from_manual(
    name: str,
    namespace: str | None = None,
    workload: str | None = None,
    pod: str | None = None,
    cluster: str | None = None,
    node: str | None = None,
    severity: str = "unknown",
) -> Alert:
    """Build an Alert for an ad-hoc `ai-ops investigate` request."""
    labels: dict[str, str] = {"alertname": name, "severity": severity}
    for key, value in (
        ("namespace", namespace),
        ("workload", workload),
        ("pod", pod),
        ("cluster", cluster),
        ("node", node),
    ):
        if value:
            labels[key] = value
    alert = Alert(
        fingerprint=_fingerprint(labels, name),
        name=name,
        severity=severity,
        status="firing",
        starts_at=datetime.now(UTC),
        labels=labels,
    )
    if pod and not workload:
        alert.workload = pod
    return _project(alert)
