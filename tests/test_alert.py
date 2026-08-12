from __future__ import annotations

from ai_ops_agent.core.alert import (
    alert_from_manual,
    normalize_alertmanager,
    normalize_grafana,
)


def test_normalize_alertmanager():
    payload = {
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "HighMemoryUsage",
                    "severity": "warning",
                    "namespace": "prod",
                    "pod": "api-7d9f-xk2",
                    "cluster": "prod-1",
                    "node": "node-3",
                },
                "annotations": {"runbook_url": "https://rb/mem", "expr": "mem > 90"},
                "startsAt": "2026-08-01T10:00:00Z",
                "generatorURL": "https://vm/graph",
                "fingerprint": "abc123",
            }
        ]
    }
    alerts = normalize_alertmanager(payload)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.name == "HighMemoryUsage"
    assert a.severity == "warning"
    assert a.namespace == "prod"
    assert a.workload == "api-7d9f-xk2"
    assert a.cluster == "prod-1"
    assert a.node == "node-3"
    assert a.runbook_url == "https://rb/mem"
    assert a.fingerprint == "abc123"
    assert a.starts_at is not None


def test_fingerprint_derived_when_absent():
    payload = {"alerts": [{"labels": {"alertname": "X", "a": "1"}}]}
    a1 = normalize_alertmanager(payload)[0]
    a2 = normalize_alertmanager(payload)[0]
    assert a1.fingerprint == a2.fingerprint  # deterministic
    assert len(a1.fingerprint) == 16


def test_normalize_grafana():
    payload = {
        "title": "grafana alert",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "DiskFull", "namespace": "stage"},
                "annotations": {},
                "dashboardURL": "https://grafana/d/1",
            }
        ],
    }
    alerts = normalize_grafana(payload)
    assert alerts[0].name == "DiskFull"
    assert alerts[0].namespace == "stage"
    assert alerts[0].runbook_url == "https://grafana/d/1"


def test_group_key():
    a = alert_from_manual("X", namespace="prod", cluster="c1", node="n1")
    assert a.group_key() == "c1|prod|n1"


def test_alert_from_manual_pod_becomes_workload():
    a = alert_from_manual("investigate", namespace="prod", pod="api-xk2")
    assert a.workload == "api-xk2"
    assert a.status == "firing"
    assert a.starts_at is not None
