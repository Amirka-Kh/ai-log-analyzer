"""AlertService: the out-of-band pipeline behind the webhook.

normalize (done by caller) → record → gate → (investigate) → persist → notify.
Shared by the webhook API and the CLI `investigate` command so both produce the
same Report through the same path.
"""

from __future__ import annotations

import logging

from ai_ops_agent.config import AppConfig
from ai_ops_agent.core.alert import Alert
from ai_ops_agent.core.investigator import AuditLog, Investigator
from ai_ops_agent.core.task_store import GateDecision, TaskStore
from ai_ops_agent.llm.client import LLMClient
from ai_ops_agent.reporting.models import Report, Verdict
from ai_ops_agent.tools.base import ToolRegistry

logger = logging.getLogger(__name__)


class AlertService:
    def __init__(
        self,
        config: AppConfig,
        store: TaskStore,
        llm_client: LLMClient | None,
        tools: ToolRegistry,
        prefetch: list | None = None,
        notifier=None,
    ) -> None:
        self.config = config
        self.store = store
        self.llm_client = llm_client
        self.tools = tools
        self.prefetch = prefetch or []
        self.notifier = notifier

    def handle_alert(self, alert: Alert, force: bool = False) -> GateDecision:
        """Gate and, if warranted, investigate. Runs synchronously — the API
        wraps this in a background task so the webhook can return 202 fast."""
        self.store.record_alert(alert)
        srv = self.config.server
        if force:
            decision = GateDecision("investigate", "forced (ad-hoc investigate)")
        else:
            decision = self.store.gate(
                alert,
                cooldown_minutes=srv.cooldown_minutes,
                flap_transitions=srv.flap_transitions,
                flap_window_minutes=srv.flap_window_minutes,
            )
        logger.info("alert %s [%s] gate: %s (%s)",
                    alert.name, alert.fingerprint, decision.action, decision.reason)

        if decision.action == "skip":
            self._notify_filtered(alert, decision)
            return decision
        if decision.action == "attach":
            if decision.investigation_id:
                self.store.attach(decision.investigation_id)
            return decision

        # Grouping: correlated alerts on the same cluster/namespace/node.
        group_id = self.store.find_group(alert.group_key(), srv.group_window_seconds)
        if group_id and not force:
            self.store.attach(group_id)
            return GateDecision("attach", "grouped with a correlated investigation", group_id)

        report, audit = self.investigate(alert)
        return GateDecision("investigate", f"investigated -> {report.verdict.value}")

    def investigate(self, alert: Alert) -> tuple[Report, AuditLog]:
        import uuid

        inv_id = uuid.uuid4().hex[:12]
        self.store.create_investigation(inv_id, alert)
        investigator = Investigator(self.config, self.llm_client, self.tools, self.prefetch)
        try:
            report, audit = investigator.investigate(alert)
        except Exception:  # noqa: BLE001 - never let one alert crash the worker
            logger.exception("investigation %s crashed", inv_id)
            self.store.complete_investigation(
                inv_id, "error", "info", "{}", status="error"
            )
            raise
        report.id = inv_id
        root_post_id = self._notify_report(alert, report)
        self.store.complete_investigation(
            inv_id, report.verdict.value, report.severity.value,
            report.model_dump_json(), root_post_id=root_post_id,
        )
        return report, audit

    # ------------------------------------------------------------------

    def _notify_report(self, alert: Alert, report: Report) -> str | None:
        if self.notifier is None:
            return None
        try:
            return self.notifier.post_report(report, fingerprint=alert.fingerprint)
        except Exception as exc:  # noqa: BLE001 - notification never blocks the pipeline
            logger.warning("notification failed: %s", exc)
            return None

    def _notify_filtered(self, alert: Alert, decision: GateDecision) -> None:
        """Log filtered alerts to the noise channel — the agent's 'I filtered
        this for you' trail where accuracy is validated (spec §8)."""
        if self.notifier is None:
            return
        channel = self.config.mattermost.noise_channel or self.config.mattermost.default_channel
        try:
            self.notifier.post_text(
                channel,
                f"Filtered alert **{alert.name}** ({alert.fingerprint}): {decision.reason}",
                fingerprint=f"filtered:{alert.fingerprint}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("noise-channel notification failed: %s", exc)


def report_is_actionable(report: Report) -> bool:
    return report.verdict not in (
        Verdict.false_positive, Verdict.noisy_rule, Verdict.no_incident,
    )
