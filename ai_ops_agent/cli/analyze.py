"""`ai-ops analyze` — one-shot analysis of a finite source."""

from __future__ import annotations

import sys

import typer
from rich.console import Console

from ai_ops_agent.config import load_config
from ai_ops_agent.core.orchestrator import AnalysisEngine, parse_since
from ai_ops_agent.llm.client import LLMError, make_client
from ai_ops_agent.reporting.models import Severity
from ai_ops_agent.reporting.renderers.markdown import render_markdown
from ai_ops_agent.reporting.renderers.terminal import render_report
from ai_ops_agent.streaming.source import SourceError, iter_lines, resolve_source

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def analyze_command(
    source: str | None = typer.Option(
        None,
        "--source",
        "-s",
        help="File path, glob, '-' for stdin, 'journalctl:<unit>', or a command string to run.",
    ),
    since: str | None = typer.Option(
        None, "--since", help="Only consider records newer than e.g. 30m, 2h, 1d."
    ),
    focus: str | None = typer.Option(
        None, "--focus", help="Hint for the model, e.g. 'errors' or 'auth failures'."
    ),
    output: str = typer.Option("text", "--output", "-o", help="text | json | markdown."),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Deterministic collectors only; no API key needed."
    ),
    redact: bool = typer.Option(
        True, "--redact/--no-redact", help="Redact secrets/PII before the LLM and reports."
    ),
    fail_on: str = typer.Option(
        "sev2", "--fail-on", help="Exit 1 when findings at or above this severity exist."
    ),
    model: str | None = typer.Option(None, "--model", help="Override the LLM model id."),
    provider: str | None = typer.Option(
        None,
        "--provider",
        help="LLM provider: anthropic | openai (openai also covers self-hosted "
        "OpenAI-compatible endpoints via AI_OPS_LLM_OPENAI_BASE_URL).",
    ),
    fmt: str | None = typer.Option(
        None, "--format", help="Force input format: json|logfmt|access|syslog|plain."
    ),
    config_file: str | None = typer.Option(None, "--config", help="YAML config file."),
    notify: str = typer.Option(
        "none", "--notify", help="none | mattermost — post the report after analysis."
    ),
    channel: str | None = typer.Option(
        None, "--channel", help="Mattermost channel override (with --notify mattermost)."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Analyze a log file, stdin, or command output and produce a report."""
    err = Console(stderr=True)
    try:
        config = load_config(config_file)
        config.redact = redact
        if model:
            config.llm.model = model
        if provider:
            config.llm.provider = provider
        try:
            fail_threshold = Severity(fail_on)
        except ValueError:
            raise SourceError(f"invalid --fail-on {fail_on!r}; use sev1|sev2|sev3|info") from None
        if since:
            parse_since(since)  # validate early
        if notify not in ("none", "mattermost"):
            raise SourceError(f"invalid --notify {notify!r}; use none|mattermost")
        notifier = build_notifier(config) if notify == "mattermost" else None
        resolved = resolve_source(source, since=since)
        llm_client = None if no_llm else make_client(config.llm)
    except (SourceError, ValueError, LLMError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    engine = AnalysisEngine(config, llm_client=llm_client)

    try:
        report = engine.analyze_lines(
            iter_lines(resolved),
            source=resolved.description,
            since=since,
            focus=focus,
            fmt=fmt,
        )
    except SourceError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    if output == "json":
        sys.stdout.write(report.model_dump_json(indent=2) + "\n")
    elif output == "markdown":
        sys.stdout.write(render_markdown(report) + "\n")
    else:
        render_report(report, verbose=verbose)

    if notifier is not None:
        # Delivery failures never change the analysis exit code — the client
        # queues undeliverable messages and logs to stderr.
        notifier.post_report(report, channel=channel)

    if report.fails_threshold(fail_threshold):
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_OK)


def build_notifier(config):
    """Construct a MattermostNotifier or raise SourceError if unconfigured."""
    from ai_ops_agent.mattermost.client import MattermostClient, MattermostError
    from ai_ops_agent.mattermost.notify import MattermostNotifier

    try:
        client = MattermostClient(config.mattermost)
    except MattermostError as exc:
        raise SourceError(str(exc)) from None
    return MattermostNotifier(client, config.mattermost)
