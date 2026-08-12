from __future__ import annotations

from ai_ops_agent.streaming.parsing import (
    detect_format,
    parse_stream,
    parse_timestamp,
)
from tests.conftest import read_fixture_lines


def test_detect_json_format():
    lines = read_fixture_lines("json_lines.log")
    assert detect_format(lines) == "json"


def test_detect_access_format():
    lines = read_fixture_lines("nginx_access.log")
    assert detect_format(lines) == "access"


def test_detect_syslog_format():
    lines = read_fixture_lines("syslog.log")
    assert detect_format(lines) == "syslog"


def test_detect_plain_fallback():
    assert detect_format(["hello world\n", "just some text\n"]) == "plain"


def test_json_records():
    records = list(parse_stream(read_fixture_lines("json_lines.log")))
    assert len(records) == 12
    first = records[0]
    assert first.level == "info"
    assert first.message == "server started on port 8080"
    assert first.ts is not None and first.ts.hour == 10
    crit = [r for r in records if r.level == "critical"]
    assert len(crit) == 1 and "OOMKilled" in crit[0].message


def test_access_records_status_levels():
    records = list(parse_stream(read_fixture_lines("nginx_access.log")))
    assert len(records) == 10
    errors = [r for r in records if r.level == "error"]
    warnings = [r for r in records if r.level == "warning"]
    assert len(errors) == 2  # the two 500s
    assert len(warnings) == 4  # the 404s / 400


def test_syslog_records():
    records = list(parse_stream(read_fixture_lines("syslog.log")))
    assert len(records) == 8
    assert records[0].fields["program"] == "sshd"
    assert records[0].ts is not None


def test_java_stacktrace_grouping():
    records = list(parse_stream(read_fixture_lines("java_stacktrace.log")))
    # 5 timestamped records; exception heads and stack frames fold into the
    # ERROR records that logged them.
    assert len(records) == 5
    err = records[2]
    assert err.level == "error"
    assert any("NullPointerException" in ln for ln in err.extra_lines)
    assert any("Caused by" in ln for ln in err.extra_lines)
    assert err.exception_type() == "java.lang.NullPointerException"


def test_python_traceback_grouping():
    records = list(parse_stream(read_fixture_lines("python_traceback.log")))
    assert len(records) == 5
    crashed = records[2]
    assert "Traceback (most recent call last):" in crashed.extra_lines[0]
    # The closing "KeyError: 'total'" line is absorbed too.
    assert crashed.extra_lines[-1].startswith("KeyError")
    assert crashed.exception_type() == "KeyError"
    # The record after the traceback parses independently.
    assert records[3].message.startswith("picked up job")


def test_parse_timestamp_formats():
    assert parse_timestamp("2026-08-01T10:00:00Z") is not None
    assert parse_timestamp("2026-08-01 10:00:00,123") is not None
    assert parse_timestamp("01/Aug/2026:10:00:01 +0000") is not None
    assert parse_timestamp("Aug  1 10:00:01") is not None
    assert parse_timestamp("not a date") is None


def test_blank_lines_skipped():
    records = list(parse_stream(["\n", "hello INFO world\n", "\n"]))
    assert len(records) == 1
    assert records[0].level == "info"
