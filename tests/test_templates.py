from __future__ import annotations

from ai_ops_agent.streaming.parsing import LogRecord
from ai_ops_agent.streaming.templates import TemplateStore, normalize_message


def rec(line_no: int, message: str, level: str = "info") -> LogRecord:
    return LogRecord(line_no=line_no, raw=message, message=message, level=level)


def test_normalize_merges_variable_parts():
    a = normalize_message("connection pool exhausted: waited 5000ms for a connection")
    b = normalize_message("connection pool exhausted: waited 5001ms for a connection")
    assert a == b
    assert "<dur>" in a


def test_normalize_placeholders():
    msg = (
        "user 550e8400-e29b-41d4-a716-446655440000 from 10.0.0.5:443 read "
        "/var/log/app/x.log in 12ms at 2026-08-01T10:00:00Z code 0xdeadbeef bob@example.com"
    )
    norm = normalize_message(msg)
    for placeholder in ("<uuid>", "<ip>", "<path>", "<dur>", "<ts>", "<hex>", "<email>"):
        assert placeholder in norm, f"{placeholder} missing from {norm!r}"


def test_store_counts_and_exemplar():
    store = TemplateStore()
    for i in range(5):
        tmpl, is_new = store.add(rec(i + 1, f"request {i} failed after {i}ms", "error"))
        assert is_new == (i == 0)
    assert len(store) == 1
    stats = store.top(1)[0]
    assert stats.count == 5
    assert stats.exemplar.startswith("request 0 failed")
    assert stats.dominant_level == "error"
    assert stats.first_line == 1 and stats.last_line == 5


def test_emerging_templates():
    store = TemplateStore()
    for i in range(1, 81):
        store.add(rec(i, "steady state heartbeat ok"))
    for i in range(81, 101):
        store.add(rec(i, "BRAND NEW failure mode xyz", "error"))
    emerging = store.emerging(total_lines=100, tail_fraction=0.2)
    assert len(emerging) == 1
    assert "BRAND NEW" in emerging[0].template


def test_overflow_cap():
    store = TemplateStore(max_templates=10)
    for i in range(50):
        # Words differ so normalization can't merge them.
        msg = f"unique message variant number{'x' * (i % 7)} kind_{chr(65 + i % 26)}{'y' * i}"
        store.add(rec(i + 1, msg))
    assert len(store) <= 11  # 10 + <overflow>
    assert store.overflowed
