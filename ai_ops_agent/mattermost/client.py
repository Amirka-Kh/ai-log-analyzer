"""Mattermost API client (bot account + Personal Access Token).

Handles the API properly per spec §8: rate limits with backoff, retries on
5xx, a persistent retry queue so an outage doesn't lose an incident, and a
log-to-stderr fallback. An incoming-webhook mode exists for the simplest
deployments (no threading, no updates, no uploads — feature loss documented
in the README).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from ai_ops_agent.config import MattermostConfig

logger = logging.getLogger(__name__)


class MattermostError(Exception):
    """Unrecoverable Mattermost API failure (after retries)."""


class MattermostClient:
    """Thin, synchronous API v4 client.

    ``transport`` and ``sleep`` are injectable for tests.
    """

    def __init__(
        self,
        config: MattermostConfig,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not config.configured:
            raise MattermostError(
                "Mattermost is not configured: set AI_OPS_MATTERMOST_URL + "
                "AI_OPS_MATTERMOST_TOKEN (or AI_OPS_MATTERMOST_WEBHOOK_URL)"
            )
        self.config = config
        self._sleep = sleep
        headers = {}
        if config.token:
            headers["Authorization"] = f"Bearer {config.token}"
        self._client = httpx.Client(
            base_url=(config.url or "").rstrip("/"),
            headers=headers,
            timeout=config.request_timeout_s,
            transport=transport,
        )
        self._channel_ids: dict[str, str] = {}
        self._team_id: str | None = None
        self.queue_path = Path(config.queue_path).expanduser()

    @property
    def api_mode(self) -> bool:
        """True when using the full API (PAT); False for webhook-only mode."""
        return bool(self.config.url and self.config.token)

    # ------------------------------------------------------------------
    # Low-level request with backoff
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                resp = self._client.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                last_error = exc
                self._sleep(self.config.backoff_base_s * (2**attempt))
                continue
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "1") or 1)
                self._sleep(retry_after)
                last_error = MattermostError("rate limited (429)")
                continue
            if resp.status_code >= 500:
                last_error = MattermostError(f"server error {resp.status_code}")
                self._sleep(self.config.backoff_base_s * (2**attempt))
                continue
            if resp.status_code >= 400:
                raise MattermostError(f"{method} {path} -> {resp.status_code}: {resp.text[:200]}")
            return resp.json() if resp.content else {}
        raise MattermostError(f"{method} {path} failed after retries: {last_error}")

    # ------------------------------------------------------------------
    # API operations
    # ------------------------------------------------------------------

    def channel_id(self, channel_name: str) -> str:
        name = channel_name.lstrip("#")
        if name in self._channel_ids:
            return self._channel_ids[name]
        if self._team_id is None:
            if not self.config.team:
                raise MattermostError("AI_OPS_MATTERMOST_TEAM is required to resolve channels")
            team = self._request("GET", f"/api/v4/teams/name/{self.config.team}")
            self._team_id = team["id"]
        channel = self._request("GET", f"/api/v4/teams/{self._team_id}/channels/name/{name}")
        self._channel_ids[name] = channel["id"]
        return channel["id"]

    def create_post(
        self,
        channel: str,
        message: str,
        root_id: str | None = None,
        props: dict | None = None,
        file_ids: list[str] | None = None,
    ) -> str:
        """Create a post; returns the post id. Long messages are split into a
        root post plus threaded continuations (4000-char API cap)."""
        if not self.api_mode:
            self._post_webhook(channel, message, props)
            return ""
        chunks = _split_message(message, self.config.max_message_chars)
        payload: dict[str, Any] = {
            "channel_id": self.channel_id(channel),
            "message": chunks[0],
        }
        if root_id:
            payload["root_id"] = root_id
        if props:
            payload["props"] = props
        if file_ids:
            payload["file_ids"] = file_ids
        post = self._request("POST", "/api/v4/posts", json=payload)
        post_id = post.get("id", "")
        thread_root = root_id or post_id
        for chunk in chunks[1:]:
            self._request(
                "POST",
                "/api/v4/posts",
                json={
                    "channel_id": payload["channel_id"],
                    "message": chunk,
                    "root_id": thread_root,
                },
            )
        return post_id

    def update_post(self, post_id: str, message: str, props: dict | None = None) -> None:
        if not self.api_mode:
            return  # webhooks cannot update posts
        body: dict[str, Any] = {"id": post_id, "message": message[: self.config.max_message_chars]}
        if props:
            body["props"] = props
        self._request("PUT", f"/api/v4/posts/{post_id}", json=body)

    def upload_file(self, channel: str, filename: str, content: bytes) -> str | None:
        if not self.api_mode:
            return None  # webhooks cannot upload files
        result = self._request(
            "POST",
            "/api/v4/files",
            params={"channel_id": self.channel_id(channel), "filename": filename},
            files={"files": (filename, content)},
        )
        infos = result.get("file_infos", [])
        return infos[0]["id"] if infos else None

    def _post_webhook(self, channel: str, message: str, props: dict | None) -> None:
        assert self.config.webhook_url is not None
        body: dict[str, Any] = {"text": message, "channel": channel.lstrip("#")}
        if props and "attachments" in props:
            body["attachments"] = props["attachments"]
        resp = self._client.post(self.config.webhook_url, json=body)
        if resp.status_code >= 400:
            raise MattermostError(f"webhook post failed: {resp.status_code}")

    # ------------------------------------------------------------------
    # Durable delivery: enqueue on failure, flush later
    # ------------------------------------------------------------------

    def safe_post(
        self,
        channel: str,
        message: str,
        root_id: str | None = None,
        props: dict | None = None,
        file_ids: list[str] | None = None,
    ) -> str | None:
        """Post; on failure persist to the retry queue and log to stderr.

        Returns the post id, or None if the message was queued instead.
        """
        self.flush_queue()
        try:
            return self.create_post(channel, message, root_id=root_id, props=props,
                                    file_ids=file_ids)
        except MattermostError as exc:
            logger.error("Mattermost delivery failed (%s); queuing message for retry", exc)
            self._enqueue(
                {"channel": channel, "message": message, "root_id": root_id, "props": props}
            )
            return None

    def _enqueue(self, item: dict) -> None:
        try:
            self.queue_path.parent.mkdir(parents=True, exist_ok=True)
            with self.queue_path.open("a") as fh:
                fh.write(json.dumps(item) + "\n")
        except OSError as exc:  # last-resort fallback: at least keep it in logs
            logger.error("could not persist queued Mattermost message: %s\n%s", exc, item)

    def flush_queue(self) -> int:
        """Attempt delivery of previously queued messages; returns count sent."""
        if not self.queue_path.exists():
            return 0
        try:
            lines = self.queue_path.read_text().splitlines()
        except OSError:
            return 0
        remaining: list[str] = []
        sent = 0
        for line in lines:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                self.create_post(
                    item["channel"],
                    item["message"],
                    root_id=item.get("root_id"),
                    props=item.get("props"),
                )
                sent += 1
            except MattermostError:
                remaining.append(line)
            except (json.JSONDecodeError, KeyError):
                logger.warning("dropping malformed queued message: %.120s", line)
        try:
            if remaining:
                self.queue_path.write_text("\n".join(remaining) + "\n")
            else:
                self.queue_path.unlink(missing_ok=True)
        except OSError as exc:
            logger.error("could not rewrite Mattermost queue: %s", exc)
        return sent


def _split_message(message: str, limit: int) -> list[str]:
    if len(message) <= limit:
        return [message]
    chunks: list[str] = []
    remaining = message
    while remaining:
        if len(remaining) <= limit:
            chunks.append(remaining)
            break
        cut = remaining.rfind("\n", 0, limit)
        if cut < limit // 2:
            cut = limit
        chunks.append(remaining[:cut])
        remaining = remaining[cut:].lstrip("\n")
    return chunks
