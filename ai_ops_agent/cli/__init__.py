"""`ai-ops` CLI entry point.

The CLI is glue only: it resolves sources, wires the shared AnalysisEngine /
WatchSession, and renders. Exit codes: 0 clean, 1 findings at or above
--fail-on, 2 tool/config error.
"""

from __future__ import annotations

import logging
import sys

import typer

from ai_ops_agent import __version__
from ai_ops_agent.cli.analyze import analyze_command
from ai_ops_agent.cli.watch import watch_command

app = typer.Typer(
    name="ai-ops",
    help="AI Ops Agent — analyze log files and watch live streams with an LLM-backed engine.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)

app.command("analyze")(analyze_command)
app.command("watch")(watch_command)


@app.command("version")
def version() -> None:
    """Print the ai-ops version."""
    typer.echo(__version__)


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)
