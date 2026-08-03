"""Report → Mattermost card rendering, channel routing, and threading.

Core UX rule (spec §8): one investigation = one root post; follow-ups thread
under it, and the root post's status field is updated in place rather than
spamming the channel. The card stays scannable in ~10s; the full markdown
report rides along as a threaded file attachment.
"""

from __future__ import annotations

import logging

from ai_ops_agent.config import MattermostConfig
from ai_ops_agent.mattermost.client import MattermostClient, MattermostError
from ai_ops_agent.reporting.models import SEVERITY_RANK, Report, Severity, Verdict
from ai_ops_agent.reporting.renderers.markdown import render_markdown

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    Severity.sev1: "#d24b4b",
    Severity.sev2: "#e8a33d",
    Severity.sev3: "#4b8bd2",
    Severity.info: "#5a5a5a",
}

NOISE_VERDICTS = {Verdict.false_positive, Verdict.noisy_rule, Verdict.expected_maintenance}

STATUS_INVESTIGATING = "🔍 investigating"
STATUS_RESOLVED = "✅ resolved"


def route_channel(report: Report, config: MattermostConfig) -> tuple[str, str | None]:
    """Return (channel, mention) for a report per the routing rules."""
    if report.verdict in NOISE_VERDICTS:
        return config.noise_channel or config.default_channel, None
    if report.severity == Severity.sev1:
        return config.alerts_channel or config.default_channel, config.mention_sev1 or None
    if report.severity == Severity.sev2:
        return config.alerts_channel or config.default_channel, None
    return config.default_channel, None


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_card(report: Report, status: str = STATUS_INVESTIGATING) -> dict:
    """Message-attachment card: colored severity bar, one-liner title, summary,
    probable cause, top-3 actions, footer with source + report id."""
    fields: list[dict] = [
        {"short": True, "title": "Verdict", "value": report.verdict.value},
        {"short": True, "title": "Severity", "value": report.severity.value},
        {"short": True, "title": "Status", "value": status},
    ]
    if report.engine.llm_used:
        fields.append(
            {"short": True, "title": "Confidence", "value": f"{report.confidence:.0%}"}
        )
    if report.summary:
        fields.append({"short": False, "title": "Summary", "value": _truncate(report.summary, 600)})
    if report.probable_cause.statement:
        fields.append(
            {
                "short": False,
                "title": "Probable cause",
                "value": _truncate(report.probable_cause.statement, 600),
            }
        )
    if report.findings:
        top = sorted(report.findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)[:3]
        listing = "\n".join(f"{i}. [{f.severity.value}] {_truncate(f.title, 140)}"
                            for i, f in enumerate(top, 1))
        fields.append({"short": False, "title": "Top findings", "value": listing})
    if report.recommended_actions:
        listing = "\n".join(
            f"{i}. {_truncate(a.step, 140)} (risk: {a.risk})"
            for i, a in enumerate(report.recommended_actions[:3], 1)
        )
        fields.append({"short": False, "title": "Suggested actions", "value": listing})

    footer_bits = [f"source: {report.source}", f"report: {report.id}"]
    if report.engine.llm_used:
        footer_bits.append(f"model: {report.engine.model}")
    if report.engine.degraded:
        footer_bits.append("DEGRADED output")
    for name, url in report.links.items():
        footer_bits.append(f"{name}: {url}")

    return {
        "color": SEVERITY_COLORS[report.severity],
        "title": _truncate(report.title or "Analysis report", 200),
        "fields": fields,
        "footer": " | ".join(footer_bits),
    }


class MattermostNotifier:
    """Stateful poster: tracks thread roots per fingerprint so repeat findings
    thread under one investigation post."""

    def __init__(self, client: MattermostClient, config: MattermostConfig) -> None:
        self.client = client
        self.config = config
        # fingerprint -> (root post id, channel)
        self._threads: dict[str, tuple[str, str]] = {}

    def post_report(
        self,
        report: Report,
        fingerprint: str | None = None,
        channel: str | None = None,
        attach_full_report: bool = True,
    ) -> str | None:
        """Post a report card; returns the root post id (None if queued/webhook).

        A repeat ``fingerprint`` threads under the existing root instead of
        creating a new channel post.
        """
        routed_channel, mention = route_channel(report, self.config)
        channel = channel or routed_channel
        card = build_card(report)
        text = f"{mention} {report.title}" if mention else report.title

        root_id: str | None = None
        if fingerprint and fingerprint in self._threads:
            root_id, channel = self._threads[fingerprint]

        post_id = self.client.safe_post(
            channel, text, root_id=root_id, props={"attachments": [card]}
        )
        if post_id is None:
            return None
        thread_root = root_id or post_id
        if fingerprint and fingerprint not in self._threads and post_id:
            self._threads[fingerprint] = (post_id, channel)

        if attach_full_report and self.client.api_mode:
            try:
                markdown = render_markdown(report).encode()
                file_id = self.client.upload_file(channel, f"report-{report.id}.md", markdown)
                if file_id:
                    self.client.create_post(
                        channel,
                        "Full report attached.",
                        root_id=thread_root or None,
                        file_ids=[file_id],
                    )
            except MattermostError as exc:
                logger.warning("could not attach full report: %s", exc)
        return thread_root

    def update_status(self, root_id: str, report: Report, status: str) -> None:
        """Update the root post's card in place (🔍 investigating → ✅ resolved)."""
        card = build_card(report, status=status)
        try:
            self.client.update_post(root_id, report.title, props={"attachments": [card]})
        except MattermostError as exc:
            logger.warning("could not update root post %s: %s", root_id, exc)

    def post_text(self, channel: str, message: str, fingerprint: str | None = None) -> str | None:
        """Plain threaded text message (watch status lines, session summaries)."""
        root_id: str | None = None
        if fingerprint and fingerprint in self._threads:
            root_id, channel = self._threads[fingerprint]
        post_id = self.client.safe_post(channel, message, root_id=root_id)
        if post_id and fingerprint and fingerprint not in self._threads:
            self._threads[fingerprint] = (post_id, channel)
        return root_id or post_id
