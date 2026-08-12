"""FastAPI app: webhook receivers, ad-hoc investigate, health, metrics.

Webhooks authenticate via a shared secret header, validate the payload with
pydantic, respond 202 immediately, and process the alert out of band in a
background task (spec §4.1).
"""

from __future__ import annotations

import hmac
import logging

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

from ai_ops_agent.config import AppConfig, load_config
from ai_ops_agent.core.alert import (
    alert_from_manual,
    normalize_alertmanager,
    normalize_grafana,
)
from ai_ops_agent.core.service import AlertService
from ai_ops_agent.core.task_store import TaskStore
from ai_ops_agent.llm.client import make_client
from ai_ops_agent.tools.build import build_registry

logger = logging.getLogger(__name__)


def _check_auth(config: AppConfig, token: str | None) -> None:
    secret = config.server.webhook_secret
    if not secret:
        return  # auth disabled (dev only)
    if not token or not hmac.compare_digest(token, secret):
        raise HTTPException(status_code=401, detail="invalid or missing webhook token")


def create_app(
    config: AppConfig | None = None,
    service: AlertService | None = None,
) -> FastAPI:
    config = config or load_config()
    app = FastAPI(title="AI Ops Agent", version="0.1.0")

    if service is None:
        store = TaskStore(config.server.db_path)
        llm_client = make_client(config.llm)
        registry, prefetch = build_registry(config)
        notifier = _build_notifier(config)
        service = AlertService(config, store, llm_client, registry, prefetch, notifier)
    app.state.config = config
    app.state.service = service

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "queue_depth": service.store.queue_depth()}

    @app.get("/metrics")
    def metrics() -> str:
        stats = service.store.accuracy_stats()
        lines = [
            "# HELP aiops_queue_depth Investigations in progress",
            "# TYPE aiops_queue_depth gauge",
            f"aiops_queue_depth {service.store.queue_depth()}",
            "# HELP aiops_feedback_total Human feedback records",
            "# TYPE aiops_feedback_total counter",
            f"aiops_feedback_total {stats['feedback_count']}",
        ]
        if stats["accuracy"] is not None:
            lines += [
                "# HELP aiops_verdict_accuracy Agreement between agent and human verdicts",
                "# TYPE aiops_verdict_accuracy gauge",
                f"aiops_verdict_accuracy {stats['accuracy']:.4f}",
            ]
        return "\n".join(lines) + "\n"

    @app.post("/webhook/alertmanager", status_code=202)
    async def webhook_alertmanager(
        request: Request,
        background: BackgroundTasks,
        x_aiops_token: str | None = Header(default=None),
    ) -> dict:
        _check_auth(config, x_aiops_token)
        payload = await request.json()
        alerts = normalize_alertmanager(payload)
        for alert in alerts:
            background.add_task(_safe_handle, service, alert)
        return {"accepted": len(alerts)}

    @app.post("/webhook/grafana", status_code=202)
    async def webhook_grafana(
        request: Request,
        background: BackgroundTasks,
        x_aiops_token: str | None = Header(default=None),
    ) -> dict:
        _check_auth(config, x_aiops_token)
        payload = await request.json()
        alerts = normalize_grafana(payload)
        for alert in alerts:
            background.add_task(_safe_handle, service, alert)
        return {"accepted": len(alerts)}

    @app.post("/investigate", status_code=202)
    async def investigate(
        request: Request,
        background: BackgroundTasks,
        x_aiops_token: str | None = Header(default=None),
    ) -> dict:
        _check_auth(config, x_aiops_token)
        body = await request.json()
        alert = alert_from_manual(
            name=body.get("alert_name") or body.get("name", "manual-investigation"),
            namespace=body.get("namespace"),
            workload=body.get("workload"),
            pod=body.get("pod"),
            cluster=body.get("cluster"),
            node=body.get("node"),
            severity=body.get("severity", "unknown"),
        )
        background.add_task(_safe_handle, service, alert, True)
        return {"accepted": True, "fingerprint": alert.fingerprint}

    return app


def _safe_handle(service: AlertService, alert, force: bool = False) -> None:
    try:
        service.handle_alert(alert, force=force)
    except Exception:  # noqa: BLE001 - background task must never propagate
        logger.exception("failed handling alert %s", getattr(alert, "fingerprint", "?"))


def _build_notifier(config: AppConfig):
    if not config.mattermost.configured:
        return None
    from ai_ops_agent.mattermost.client import MattermostClient, MattermostError
    from ai_ops_agent.mattermost.notify import MattermostNotifier

    try:
        client = MattermostClient(config.mattermost)
    except MattermostError:
        return None
    return MattermostNotifier(client, config.mattermost)
