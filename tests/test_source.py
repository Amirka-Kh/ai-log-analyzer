from __future__ import annotations

import gzip

import pytest

from ai_ops_agent.streaming.source import SourceError, iter_lines, resolve_source


def test_resolve_file(fixtures_dir):
    resolved = resolve_source(str(fixtures_dir / "clean.log"))
    assert resolved.kind == "file"
    assert len(list(iter_lines(resolved))) == 6


def test_resolve_glob(fixtures_dir):
    resolved = resolve_source(str(fixtures_dir / "*.log"))
    assert resolved.kind == "file"
    assert len(resolved.paths) >= 5


def test_gzip_transparent(tmp_path):
    path = tmp_path / "app.log.gz"
    with gzip.open(path, "wt") as fh:
        fh.write("line one\nline two\n")
    resolved = resolve_source(str(path))
    assert [ln.strip() for ln in iter_lines(resolved)] == ["line one", "line two"]


def test_command_source():
    resolved = resolve_source("echo hello world")
    assert resolved.kind == "command"
    assert resolved.argv == ["echo", "hello", "world"]
    lines = list(iter_lines(resolved))
    assert lines[0].strip() == "hello world"


def test_missing_source_raises():
    with pytest.raises(SourceError):
        resolve_source("/nonexistent/path/definitely_missing.log")


def test_command_not_found_raises():
    resolved = resolve_source("definitely-not-a-command-xyz --flag")
    with pytest.raises(SourceError):
        list(iter_lines(resolved))


def test_journalctl_source():
    resolved = resolve_source("journalctl:nginx", since="1h")
    assert resolved.kind == "journalctl"
    assert resolved.argv[:3] == ["journalctl", "-u", "nginx"]
    assert "--since" in resolved.argv
