from __future__ import annotations

import json

from typer.testing import CliRunner

from ai_ops_agent.cli import app

runner = CliRunner()


def test_analyze_clean_exit_zero(fixtures_dir):
    result = runner.invoke(
        app, ["analyze", "--source", str(fixtures_dir / "clean.log"), "--no-llm"]
    )
    assert result.exit_code == 0
    assert "NO INCIDENT" in result.output


def test_analyze_incident_exit_one(fixtures_dir):
    result = runner.invoke(
        app, ["analyze", "--source", str(fixtures_dir / "json_lines.log"), "--no-llm"]
    )
    assert result.exit_code == 1  # sev2 fatal-marker finding >= default fail-on sev2


def test_fail_on_threshold_relaxed(fixtures_dir):
    result = runner.invoke(
        app,
        [
            "analyze",
            "--source",
            str(fixtures_dir / "json_lines.log"),
            "--no-llm",
            "--fail-on",
            "sev1",
        ],
    )
    assert result.exit_code == 0


def test_json_output_parses(fixtures_dir):
    result = runner.invoke(
        app,
        [
            "analyze",
            "--source",
            str(fixtures_dir / "nginx_access.log"),
            "--no-llm",
            "--output",
            "json",
            "--fail-on",
            "sev1",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["stats"]["parsed_records"] == 10
    assert payload["verdict"] in ("needs_human", "no_incident")
    assert any("Path scanning" in f["title"] for f in payload["findings"])


def test_markdown_output(fixtures_dir):
    result = runner.invoke(
        app,
        [
            "analyze",
            "--source",
            str(fixtures_dir / "syslog.log"),
            "--no-llm",
            "--output",
            "markdown",
            "--fail-on",
            "sev1",
        ],
    )
    assert result.exit_code == 0
    assert "## Findings" in result.stdout


def test_stdin_source(fixtures_dir):
    content = (fixtures_dir / "clean.log").read_text()
    result = runner.invoke(app, ["analyze", "--source", "-", "--no-llm"], input=content)
    assert result.exit_code == 0


def test_missing_source_exit_two():
    result = runner.invoke(app, ["analyze", "--source", "/no/such/file.log", "--no-llm"])
    assert result.exit_code == 2


def test_bad_since_exit_two(fixtures_dir):
    result = runner.invoke(
        app,
        ["analyze", "--source", str(fixtures_dir / "clean.log"), "--no-llm", "--since", "nope"],
    )
    assert result.exit_code == 2


def test_bad_fail_on_exit_two(fixtures_dir):
    result = runner.invoke(
        app,
        ["analyze", "--source", str(fixtures_dir / "clean.log"), "--no-llm", "--fail-on", "high"],
    )
    assert result.exit_code == 2


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
