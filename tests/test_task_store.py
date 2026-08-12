from __future__ import annotations

from ai_ops_agent.core.alert import alert_from_manual
from ai_ops_agent.core.task_store import TaskStore


def make_store() -> TaskStore:
    return TaskStore(":memory:")


def gate(store, alert):
    store.record_alert(alert)
    return store.gate(alert, cooldown_minutes=30, flap_transitions=4, flap_window_minutes=10)


def test_new_alert_investigates():
    store = make_store()
    a = alert_from_manual("HighMem", namespace="prod")
    d = gate(store, a)
    assert d.action == "investigate"


def test_cooldown_attaches():
    store = make_store()
    a = alert_from_manual("HighMem", namespace="prod")
    gate(store, a)
    store.create_investigation("inv-1", a)
    d = gate(store, a)
    assert d.action == "attach"
    assert d.investigation_id == "inv-1"


def test_resolved_without_investigation_skipped():
    store = make_store()
    a = alert_from_manual("HighMem", namespace="prod")
    a.status = "resolved"
    d = gate(store, a)
    assert d.action == "skip"
    assert "resolved" in d.reason


def test_resolved_attaches_to_open_investigation():
    store = make_store()
    a = alert_from_manual("HighMem", namespace="prod")
    gate(store, a)
    store.create_investigation("inv-1", a)
    a.status = "resolved"
    d = gate(store, a)
    assert d.action == "attach"


def test_flapping_skipped():
    store = make_store()
    a = alert_from_manual("Flappy", namespace="prod")
    # firing<->resolved churn ending on 'firing' (4 transitions in-window), so the
    # flap check — not the resolved-skip branch — is what fires.
    d = None
    for status in ["firing", "resolved", "firing", "resolved", "firing"]:
        a.status = status
        d = gate(store, a)
    assert d.action == "skip"
    assert "flapping" in d.reason


def test_ignore_list():
    store = make_store()
    a = alert_from_manual("Watchdog", namespace="prod")
    store.record_alert(a)
    d = store.gate(a, 30, 4, 10, ignore_list={"Watchdog"})
    assert d.action == "skip"
    assert "ignore list" in d.reason


def test_silence():
    store = make_store()
    a = alert_from_manual("HighMem", namespace="prod")
    store.silence(a.fingerprint, minutes=60, actor="alice")
    assert store.is_silenced(a.fingerprint)
    d = gate(store, a)
    assert d.action == "skip"


def test_grouping():
    store = make_store()
    a = alert_from_manual("A", namespace="prod", cluster="c1", node="n1")
    store.create_investigation("inv-1", a)
    b = alert_from_manual("B", namespace="prod", cluster="c1", node="n1")
    assert a.group_key() == b.group_key()
    assert store.find_group(b.group_key(), window_seconds=300) == "inv-1"


def test_feedback_and_accuracy():
    store = make_store()
    a = alert_from_manual("HighMem", namespace="prod")
    store.create_investigation("inv-1", a)
    store.record_feedback("inv-1", a.fingerprint, "real_incident", "real_incident", "alice")
    store.record_feedback("inv-1", a.fingerprint, "real_incident", "false_positive", "bob")
    stats = store.accuracy_stats()
    assert stats["feedback_count"] == 2
    assert stats["agreement"] == 1
    assert stats["accuracy"] == 0.5


def test_queue_depth():
    store = make_store()
    a = alert_from_manual("HighMem", namespace="prod")
    store.create_investigation("inv-1", a)
    assert store.queue_depth() == 1
    store.complete_investigation("inv-1", "real_incident", "sev2", "{}")
    assert store.queue_depth() == 0
