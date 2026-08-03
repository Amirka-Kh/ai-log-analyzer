from __future__ import annotations

import json

import httpx
import pytest

from ai_ops_agent.config import MattermostConfig
from ai_ops_agent.mattermost.client import MattermostClient, MattermostError, _split_message
from ai_ops_agent.mattermost.notify import (
    STATUS_RESOLVED,
    MattermostNotifier,
    build_card,
    route_channel,
)
from ai_ops_agent.reporting.models import (
    Evidence,
    Finding,
    ProbableCause,
    RecommendedAction,
    Report,
    Severity,
    Verdict,
)


class FakeServer:
    """Mock Mattermost API: records requests, configurable failures."""

    def __init__(self, fail_times: int = 0, fail_status: int = 500):
        self.posts: list[dict] = []
        self.updates: list[dict] = []
        self.uploads: list[dict] = []
        self.webhook_bodies: list[dict] = []
        self.fail_times = fail_times
        self.fail_status = fail_status
        self._post_counter = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if self.fail_times > 0:
            self.fail_times -= 1
            headers = {"Retry-After": "0"} if self.fail_status == 429 else {}
            return httpx.Response(self.fail_status, text="boom", headers=headers)
        if path.startswith("/api/v4/teams/name/"):
            return httpx.Response(200, json={"id": "team-1"})
        if "/channels/name/" in path:
            name = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={"id": f"chan-{name}"})
        if path == "/api/v4/posts" and request.method == "POST":
            body = json.loads(request.content)
            self._post_counter += 1
            body["id"] = f"post-{self._post_counter}"
            self.posts.append(body)
            return httpx.Response(201, json={"id": body["id"]})
        if path.startswith("/api/v4/posts/") and request.method == "PUT":
            self.updates.append(json.loads(request.content))
            return httpx.Response(200, json={})
        if path == "/api/v4/files":
            self.uploads.append({"filename": request.url.params.get("filename")})
            return httpx.Response(201, json={"file_infos": [{"id": "file-1"}]})
        if path == "/hooks/abc":
            self.webhook_bodies.append(json.loads(request.content))
            return httpx.Response(200, text="ok")
        return httpx.Response(404, text=f"unhandled {path}")


def make_config(tmp_path, **overrides) -> MattermostConfig:
    defaults = dict(
        url="http://mm.test",
        token="pat-token",
        team="ops",
        default_channel="ops-alerts",
        noise_channel="ops-noise",
        queue_path=str(tmp_path / "queue.jsonl"),
        backoff_base_s=0.0,
    )
    defaults.update(overrides)
    return MattermostConfig(**defaults)


def make_client(tmp_path, server: FakeServer, **overrides) -> MattermostClient:
    config = make_config(tmp_path, **overrides)
    return MattermostClient(
        config, transport=httpx.MockTransport(server.handler), sleep=lambda s: None
    )


def make_report(**overrides) -> Report:
    defaults = dict(
        source="app.log",
        verdict=Verdict.real_incident,
        severity=Severity.sev2,
        title="Connection pool exhaustion led to OOM",
        summary="Pool exhausted, worker OOM-killed.",
        probable_cause=ProbableCause(
            statement="Pool exhaustion escalated into memory pressure.",
            evidence=[Evidence(excerpt="connection pool exhausted")],
        ),
        findings=[
            Finding(severity=Severity.info, title="minor note"),
            Finding(severity=Severity.sev2, title="OOM markers present"),
        ],
        recommended_actions=[
            RecommendedAction(step="Check pool sizing", risk="low"),
            RecommendedAction(step="Restart worker", risk="medium"),
        ],
    )
    defaults.update(overrides)
    return Report(**defaults)


# ---------------------------------------------------------------------------
# Card structure and routing
# ---------------------------------------------------------------------------


def test_card_structure():
    card = build_card(make_report())
    assert card["color"] == "#e8a33d"  # sev2
    assert card["title"].startswith("Connection pool")
    titles = [f["title"] for f in card["fields"]]
    assert {"Verdict", "Severity", "Status", "Summary", "Probable cause"} <= set(titles)
    findings_field = next(f for f in card["fields"] if f["title"] == "Top findings")
    # Most severe first, not alphabetical by value.
    assert findings_field["value"].splitlines()[0].startswith("1. [sev2]")
    actions = next(f for f in card["fields"] if f["title"] == "Suggested actions")
    assert len(actions["value"].splitlines()) <= 3
    assert "source: app.log" in card["footer"]


def test_severity_colors():
    assert build_card(make_report(severity=Severity.sev1))["color"] == "#d24b4b"
    assert build_card(make_report(severity=Severity.sev3))["color"] == "#4b8bd2"
    assert build_card(make_report(severity=Severity.info))["color"] == "#5a5a5a"


def test_routing(tmp_path):
    config = make_config(tmp_path)
    channel, mention = route_channel(make_report(severity=Severity.sev1), config)
    assert channel == "ops-alerts" and mention == "@here"
    channel, mention = route_channel(make_report(severity=Severity.sev2), config)
    assert channel == "ops-alerts" and mention is None
    channel, _ = route_channel(
        make_report(verdict=Verdict.false_positive, severity=Severity.sev3), config
    )
    assert channel == "ops-noise"


# ---------------------------------------------------------------------------
# Posting, threading, splitting
# ---------------------------------------------------------------------------


def test_post_report_card_and_attachment(tmp_path):
    server = FakeServer()
    client = make_client(tmp_path, server)
    notifier = MattermostNotifier(client, client.config)
    root = notifier.post_report(make_report())
    assert root == "post-1"
    card_post = server.posts[0]
    assert card_post["channel_id"] == "chan-ops-alerts"
    assert card_post["props"]["attachments"][0]["color"] == "#e8a33d"
    # Full report uploaded and threaded under the root.
    assert server.uploads and server.uploads[0]["filename"].endswith(".md")
    attach_post = server.posts[1]
    assert attach_post["root_id"] == "post-1"
    assert attach_post["file_ids"] == ["file-1"]


def test_thread_reuse_for_repeat_fingerprint(tmp_path):
    server = FakeServer()
    client = make_client(tmp_path, server)
    notifier = MattermostNotifier(client, client.config)
    notifier.post_report(make_report(), fingerprint="fp-1", attach_full_report=False)
    notifier.post_report(make_report(), fingerprint="fp-1", attach_full_report=False)
    assert len(server.posts) == 2
    assert "root_id" not in server.posts[0]
    assert server.posts[1]["root_id"] == "post-1"


def test_sev1_mention(tmp_path):
    server = FakeServer()
    client = make_client(tmp_path, server)
    notifier = MattermostNotifier(client, client.config)
    notifier.post_report(make_report(severity=Severity.sev1), attach_full_report=False)
    assert server.posts[0]["message"].startswith("@here ")


def test_long_message_split_into_thread(tmp_path):
    server = FakeServer()
    client = make_client(tmp_path, server)
    long_message = "\n".join(f"line {i} " + "x" * 80 for i in range(200))
    assert len(long_message) > 2 * client.config.max_message_chars
    client.create_post("ops-alerts", long_message)
    assert len(server.posts) >= 3
    for continuation in server.posts[1:]:
        assert continuation["root_id"] == "post-1"
    reassembled = "\n".join(p["message"] for p in server.posts)
    assert "line 0" in reassembled and "line 199" in reassembled


def test_split_message_respects_limit():
    chunks = _split_message("a" * 10_000, 3800)
    assert all(len(c) <= 3800 for c in chunks)
    assert "".join(chunks) == "a" * 10_000


def test_update_status(tmp_path):
    server = FakeServer()
    client = make_client(tmp_path, server)
    notifier = MattermostNotifier(client, client.config)
    root = notifier.post_report(make_report(), attach_full_report=False)
    notifier.update_status(root, make_report(), STATUS_RESOLVED)
    card = server.updates[0]["props"]["attachments"][0]
    status = next(f for f in card["fields"] if f["title"] == "Status")
    assert status["value"] == STATUS_RESOLVED


# ---------------------------------------------------------------------------
# Retries, rate limits, outage queue
# ---------------------------------------------------------------------------


def test_retry_on_server_error(tmp_path):
    server = FakeServer(fail_times=2, fail_status=500)
    client = make_client(tmp_path, server)
    post_id = client.create_post("ops-alerts", "hello")
    assert post_id == "post-1"


def test_rate_limit_backoff(tmp_path):
    server = FakeServer(fail_times=1, fail_status=429)
    sleeps: list[float] = []
    config = make_config(tmp_path)
    client = MattermostClient(
        config, transport=httpx.MockTransport(server.handler), sleep=sleeps.append
    )
    client.create_post("ops-alerts", "hello")
    assert sleeps  # Retry-After honored


def test_exhausted_retries_raise(tmp_path):
    server = FakeServer(fail_times=99, fail_status=500)
    client = make_client(tmp_path, server)
    with pytest.raises(MattermostError):
        client.create_post("ops-alerts", "hello")


def test_outage_queues_then_flushes(tmp_path):
    down = FakeServer(fail_times=99, fail_status=500)
    client = make_client(tmp_path, down)
    assert client.safe_post("ops-alerts", "incident during outage") is None
    assert client.queue_path.exists()
    queued = [json.loads(ln) for ln in client.queue_path.read_text().splitlines()]
    assert queued[0]["message"] == "incident during outage"

    up = FakeServer()
    client2 = make_client(tmp_path, up)
    assert client2.flush_queue() == 1
    assert not client2.queue_path.exists()
    assert up.posts[0]["message"] == "incident during outage"


# ---------------------------------------------------------------------------
# Webhook fallback
# ---------------------------------------------------------------------------


def test_webhook_fallback_mode(tmp_path):
    server = FakeServer()
    config = make_config(tmp_path, url=None, token=None, webhook_url="http://mm.test/hooks/abc")
    client = MattermostClient(
        config, transport=httpx.MockTransport(server.handler), sleep=lambda s: None
    )
    assert not client.api_mode
    notifier = MattermostNotifier(client, config)
    notifier.post_report(make_report(), attach_full_report=False)
    body = server.webhook_bodies[0]
    assert body["channel"] == "ops-alerts"
    assert body["attachments"][0]["color"] == "#e8a33d"
    # Feature loss: no uploads, no updates in webhook mode.
    assert client.upload_file("ops-alerts", "x.md", b"data") is None


def test_unconfigured_raises(tmp_path):
    with pytest.raises(MattermostError):
        MattermostClient(MattermostConfig(queue_path=str(tmp_path / "q.jsonl")))
