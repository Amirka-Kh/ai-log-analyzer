"""SQLite-backed task store: idempotency, dedupe, flap detection, cooldowns,
grouping, and investigation/feedback persistence (spec §3, §4.3).

Single-file store so a single-replica deployment needs no external database;
the schema is small enough to swap for Postgres later.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ai_ops_agent.core.alert import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    received_at TEXT NOT NULL,
    labels TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_events_fp ON alert_events(fingerprint, received_at);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    group_key TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL,           -- investigating | done | error
    verdict TEXT,
    severity TEXT,
    report_json TEXT,
    root_post_id TEXT,
    attach_count INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_inv_fp ON investigations(fingerprint, created_at);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    agent_verdict TEXT,
    human_verdict TEXT NOT NULL,
    actor TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS silences (
    fingerprint TEXT PRIMARY KEY,
    until TEXT NOT NULL,
    actor TEXT,
    created_at TEXT NOT NULL
);
"""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse(dt: str) -> datetime:
    return datetime.fromisoformat(dt)


@dataclass
class GateDecision:
    action: str  # investigate | attach | skip
    reason: str
    investigation_id: str | None = None


class TaskStore:
    def __init__(self, db_path: str | Path) -> None:
        path = Path(db_path).expanduser()
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # Alert bookkeeping + gating
    # ------------------------------------------------------------------

    def record_alert(self, alert: Alert) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alert_events (fingerprint, status, received_at, labels) "
                "VALUES (?, ?, ?, ?)",
                (alert.fingerprint, alert.status, _iso(_now()), json.dumps(alert.labels)),
            )
            self._conn.commit()

    def gate(
        self,
        alert: Alert,
        cooldown_minutes: int,
        flap_transitions: int,
        flap_window_minutes: int,
        ignore_list: set[str] | None = None,
    ) -> GateDecision:
        """Decide whether to investigate, attach, or skip (spec §4.3).

        ``record_alert`` must be called before ``gate`` so flap/dedupe windows
        include this event.
        """
        fp = alert.fingerprint
        if ignore_list and alert.name in ignore_list:
            return GateDecision("skip", f"alert '{alert.name}' is on the ignore list")

        if self.is_silenced(fp):
            return GateDecision("skip", "fingerprint is silenced / in a maintenance window")

        # Resolved for something never investigated -> park it.
        if alert.is_resolved:
            recent = self._recent_investigation(fp, cooldown_minutes)
            if recent is None:
                return GateDecision("skip", "resolved alert with no active investigation")
            return GateDecision(
                "attach", "resolved — attaching to existing investigation", recent
            )

        # Flapping: N transitions within M minutes.
        if self._transition_count(fp, flap_window_minutes) >= flap_transitions:
            return GateDecision(
                "skip",
                f"flapping ({flap_transitions}+ transitions in {flap_window_minutes}m) — "
                "likely a noisy alert rule",
            )

        # Cooldown: same fingerprint investigated recently -> attach.
        recent = self._recent_investigation(fp, cooldown_minutes)
        if recent is not None:
            return GateDecision(
                "attach", f"within {cooldown_minutes}m cooldown of an existing investigation",
                recent,
            )

        return GateDecision("investigate", "new alert outside cooldown")

    def _transition_count(self, fingerprint: str, window_minutes: int) -> int:
        cutoff = _iso(_now() - timedelta(minutes=window_minutes))
        cur = self._conn.execute(
            "SELECT status FROM alert_events WHERE fingerprint = ? AND received_at >= ? "
            "ORDER BY received_at",
            (fingerprint, cutoff),
        )
        statuses = [row["status"] for row in cur.fetchall()]
        transitions = sum(1 for a, b in zip(statuses, statuses[1:], strict=False) if a != b)
        return transitions

    def _recent_investigation(self, fingerprint: str, cooldown_minutes: int) -> str | None:
        cutoff = _iso(_now() - timedelta(minutes=cooldown_minutes))
        cur = self._conn.execute(
            "SELECT id FROM investigations WHERE fingerprint = ? AND created_at >= ? "
            "ORDER BY created_at DESC LIMIT 1",
            (fingerprint, cutoff),
        )
        row = cur.fetchone()
        return row["id"] if row else None

    def find_group(self, group_key: str, window_seconds: float) -> str | None:
        """Return the id of a recent investigation for the same
        cluster/namespace/node group, for correlation."""
        if not group_key.strip("|"):
            return None
        cutoff = _iso(_now() - timedelta(seconds=window_seconds))
        cur = self._conn.execute(
            "SELECT id FROM investigations WHERE group_key = ? AND created_at >= ? "
            "AND status = 'investigating' ORDER BY created_at DESC LIMIT 1",
            (group_key, cutoff),
        )
        row = cur.fetchone()
        return row["id"] if row else None

    # ------------------------------------------------------------------
    # Investigations
    # ------------------------------------------------------------------

    def create_investigation(self, inv_id: str, alert: Alert) -> None:
        now = _iso(_now())
        with self._lock:
            self._conn.execute(
                "INSERT INTO investigations (id, fingerprint, group_key, created_at, "
                "updated_at, status) VALUES (?, ?, ?, ?, ?, 'investigating')",
                (inv_id, alert.fingerprint, alert.group_key(), now, now),
            )
            self._conn.commit()

    def complete_investigation(
        self, inv_id: str, verdict: str, severity: str, report_json: str,
        status: str = "done", root_post_id: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE investigations SET status = ?, verdict = ?, severity = ?, "
                "report_json = ?, root_post_id = ?, updated_at = ? WHERE id = ?",
                (status, verdict, severity, report_json, root_post_id, _iso(_now()), inv_id),
            )
            self._conn.commit()

    def attach(self, inv_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE investigations SET attach_count = attach_count + 1, updated_at = ? "
                "WHERE id = ?",
                (_iso(_now()), inv_id),
            )
            self._conn.commit()

    def get_investigation(self, inv_id: str) -> dict | None:
        cur = self._conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_root_post_id(self, inv_id: str) -> str | None:
        inv = self.get_investigation(inv_id)
        return inv.get("root_post_id") if inv else None

    # ------------------------------------------------------------------
    # Feedback + accuracy + silences
    # ------------------------------------------------------------------

    def record_feedback(
        self, investigation_id: str, fingerprint: str, agent_verdict: str | None,
        human_verdict: str, actor: str | None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO feedback (investigation_id, fingerprint, agent_verdict, "
                "human_verdict, actor, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (investigation_id, fingerprint, agent_verdict, human_verdict, actor, _iso(_now())),
            )
            self._conn.commit()

    def accuracy_stats(self) -> dict:
        cur = self._conn.execute(
            "SELECT agent_verdict, human_verdict FROM feedback WHERE agent_verdict IS NOT NULL"
        )
        rows = cur.fetchall()
        total = len(rows)
        agree = sum(1 for r in rows if r["agent_verdict"] == r["human_verdict"])
        return {
            "feedback_count": total,
            "agreement": agree,
            "accuracy": (agree / total) if total else None,
        }

    def silence(self, fingerprint: str, minutes: float, actor: str | None = None) -> None:
        until = _iso(_now() + timedelta(minutes=minutes))
        with self._lock:
            self._conn.execute(
                "INSERT INTO silences (fingerprint, until, actor, created_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET until=excluded.until",
                (fingerprint, until, actor, _iso(_now())),
            )
            self._conn.commit()

    def is_silenced(self, fingerprint: str) -> bool:
        cur = self._conn.execute(
            "SELECT until FROM silences WHERE fingerprint = ?", (fingerprint,)
        )
        row = cur.fetchone()
        if row is None:
            return False
        return _parse(row["until"]) > _now()

    def queue_depth(self) -> int:
        cur = self._conn.execute(
            "SELECT COUNT(*) AS n FROM investigations WHERE status = 'investigating'"
        )
        return cur.fetchone()["n"]
