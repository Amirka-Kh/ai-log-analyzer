from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ai_ops_agent.api.app import create_app
from ai_ops_agent.config import AppConfig
from ai_ops_agent.core.alert import Alert
from ai_ops_agent.core.service import AlertService
from ai_ops_agent.core.task_store import TaskStore


class RecordingService(AlertService):
    """AlertService that records handled alerts instead of investigating."""

    def __init__(self, config):
        super().__init__(config, TaskStore(":memory:"), None, None)  # type: ignore[arg-type]
        self.handled: list[tuple[Alert, bool]] = []

    def handle_alert(self, alert: Alert, force: bool = False):
        self.handled.append((alert, force))
        from ai_ops_agent.core.task_store import GateDecision

        return GateDecision("investigate", "recorded")


@pytest.fixture
def client_and_service():
    config = AppConfig()
    config.server.webhook_secret = "s3cr3t"
    service = RecordingService(config)
    app = create_app(config, service=service)
    return TestClient(app), service


ALERTMANAGER_PAYLOAD = {
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "HighMem", "namespace": "prod", "pod": "api-xk2"},
            "annotations": {"expr": "mem > 90"},
            "fingerprint": "fp-1",
        }
    ]
}


def test_healthz(client_and_service):
    client, _ = client_and_service
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_webhook_requires_token(client_and_service):
    client, service = client_and_service
    resp = client.post("/webhook/alertmanager", json=ALERTMANAGER_PAYLOAD)
    assert resp.status_code == 401
    assert service.handled == []


def test_webhook_wrong_token_rejected(client_and_service):
    client, _ = client_and_service
    resp = client.post(
        "/webhook/alertmanager", json=ALERTMANAGER_PAYLOAD,
        headers={"X-AIOps-Token": "wrong"},
    )
    assert resp.status_code == 401


def test_webhook_accepts_and_processes(client_and_service):
    client, service = client_and_service
    resp = client.post(
        "/webhook/alertmanager", json=ALERTMANAGER_PAYLOAD,
        headers={"X-AIOps-Token": "s3cr3t"},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1
    # Background task ran (TestClient runs them synchronously on response).
    assert len(service.handled) == 1
    alert, force = service.handled[0]
    assert alert.name == "HighMem"
    assert alert.namespace == "prod"
    assert not force


def test_grafana_webhook(client_and_service):
    client, service = client_and_service
    payload = {"alerts": [{"status": "firing", "labels": {"alertname": "Disk"}}]}
    resp = client.post(
        "/webhook/grafana", json=payload, headers={"X-AIOps-Token": "s3cr3t"}
    )
    assert resp.status_code == 202
    assert service.handled[0][0].name == "Disk"


def test_manual_investigate_forced(client_and_service):
    client, service = client_and_service
    resp = client.post(
        "/investigate",
        json={"alert_name": "HighMem", "namespace": "prod", "pod": "api-xk2"},
        headers={"X-AIOps-Token": "s3cr3t"},
    )
    assert resp.status_code == 202
    alert, force = service.handled[0]
    assert force is True
    assert alert.workload == "api-xk2"


def test_metrics_endpoint(client_and_service):
    client, _ = client_and_service
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "aiops_queue_depth" in resp.text


def test_auth_disabled_when_no_secret():
    config = AppConfig()  # no webhook_secret
    service = RecordingService(config)
    app = create_app(config, service=service)
    client = TestClient(app)
    resp = client.post("/webhook/alertmanager", json=ALERTMANAGER_PAYLOAD)
    assert resp.status_code == 202  # accepted without a token in dev mode
