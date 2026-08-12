from __future__ import annotations

from ai_ops_agent.core.signals import SignalsCollector
from ai_ops_agent.streaming.parsing import parse_stream
from tests.conftest import read_fixture_lines


def collect(name: str):
    collector = SignalsCollector()
    for record in parse_stream(read_fixture_lines(name)):
        collector.add(record)
    return collector.finalize()


def test_level_counts_and_error_rate():
    signals = collect("json_lines.log")
    assert signals.level_counts["error"] == 4
    assert signals.level_counts["critical"] == 1
    assert signals.error_count == 5
    assert 0 < signals.error_rate < 1


def test_security_hits_nginx():
    signals = collect("nginx_access.log")
    assert "path_scan" in signals.security_hits
    assert signals.security_hits["path_scan"].count >= 2
    assert "sqli" in signals.security_hits
    hit = signals.security_hits["sqli"]
    assert hit.exemplars and hit.exemplars[0][0] > 0


def test_ssh_failures_syslog():
    signals = collect("syslog.log")
    assert "ssh_auth_failure" in signals.security_hits
    assert signals.security_hits["ssh_auth_failure"].count == 3
    assert "sudo_usage" in signals.security_hits


def test_fatal_markers():
    signals = collect("json_lines.log")
    assert signals.fatal_hits  # OOMKilled line
    assert any("OOMKilled" in text or "Out of memory" in text for _, text in signals.fatal_hits)


def test_exception_types():
    signals = collect("java_stacktrace.log")
    assert signals.exception_types["java.lang.NullPointerException"] == 2


def test_timeline_and_span():
    signals = collect("json_lines.log")
    assert signals.first_ts is not None and signals.last_ts is not None
    assert signals.first_ts <= signals.last_ts
    assert signals.timeline
    peak = max(signals.timeline, key=lambda b: b.errors)
    assert peak.errors >= 4  # the 10:05 error burst


def test_gap_detection():
    lines = [
        "2026-08-01T10:00:00Z INFO ok\n",
        "2026-08-01T10:01:00Z INFO ok\n",
        "2026-08-01T10:30:00Z INFO back after silence\n",
    ]
    collector = SignalsCollector(gap_threshold_s=300)
    for record in parse_stream(lines):
        collector.add(record)
    signals = collector.finalize()
    assert len(signals.gaps) == 1
    start, end = signals.gaps[0]
    assert (end - start).total_seconds() == 29 * 60
