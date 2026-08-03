"""`ai-ops watch` — follow a live command or file, escalate on triggers.

The command string is supplied by the human operator (never the model), parsed
with shlex and executed without a shell. The asyncio plumbing lives here; all
analysis state is in :class:`WatchSession`.
"""

from __future__ import annotations

import asyncio
import contextlib
import shlex
import time
from pathlib import Path

import typer
from rich.console import Console

from ai_ops_agent.config import load_config
from ai_ops_agent.core.orchestrator import AnalysisEngine
from ai_ops_agent.llm.client import make_client
from ai_ops_agent.reporting.renderers.terminal import SEVERITY_STYLE, render_report
from ai_ops_agent.streaming.watch import Notification, WatchSession

EXIT_ERROR = 2


def watch_command(
    command: str | None = typer.Argument(
        None, help="Command to spawn and follow, e.g. \"docker logs -f my-api\"."
    ),
    source: str | None = typer.Option(
        None, "--source", help="File to follow instead of a command (tail -F semantics)."
    ),
    window: float = typer.Option(60.0, "--window", help="Window size in seconds."),
    window_lines: int = typer.Option(500, "--window-lines", help="Max lines per window."),
    baseline: float = typer.Option(
        300.0, "--baseline", help="Baseline learning period in seconds (emits nothing)."
    ),
    cooldown: float = typer.Option(120.0, "--cooldown", help="Cooldown between similar alerts."),
    max_alerts: int = typer.Option(10, "--max-alerts-per-hour"),
    restart: bool = typer.Option(False, "--restart", help="Respawn the command if it exits."),
    no_llm: bool = typer.Option(True, "--llm/--no-llm", help="Explain escalations with the LLM."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the status line."),
    fmt: str | None = typer.Option(None, "--format", help="Force input format."),
    config_file: str | None = typer.Option(None, "--config"),
) -> None:
    """Continuously watch a stream; learn a baseline, then alert on anomalies."""
    err = Console(stderr=True)
    if command is None and source is None:
        err.print("[red]error:[/red] give a command argument or --source FILE")
        raise typer.Exit(EXIT_ERROR)
    config = load_config(config_file)
    config.watch.window_seconds = window
    config.watch.window_max_lines = window_lines
    config.watch.baseline_seconds = baseline
    config.watch.cooldown_seconds = cooldown
    config.watch.max_alerts_per_hour = max_alerts

    llm_client = None if no_llm else make_client(config.llm)
    engine = AnalysisEngine(config, llm_client=llm_client) if llm_client else None

    try:
        asyncio.run(
            _run_watch(
                command=command,
                source=source,
                config=config,
                engine=engine,
                fmt=fmt,
                restart=restart,
                quiet=quiet,
            )
        )
    except KeyboardInterrupt:
        pass


async def _run_watch(
    command: str | None,
    source: str | None,
    config,
    engine: AnalysisEngine | None,
    fmt: str | None,
    restart: bool,
    quiet: bool,
) -> None:
    console = Console()
    session = WatchSession(config.watch, fmt=fmt)
    stop = asyncio.Event()

    async def pump() -> None:
        while not stop.is_set():
            if command is not None:
                code = await _pump_command(command, session, console, engine, quiet)
                if not restart or stop.is_set():
                    if code is not None:
                        note = session.process_exit(code, time.monotonic())
                        if note:
                            _print_notification(console, note)
                    return
                console.print("[dim]process exited; restarting in 2s (--restart)[/dim]")
                await asyncio.sleep(2)
            else:
                assert source is not None
                await _pump_file(Path(source), session, console, engine, quiet, stop)
                return

    ticker = asyncio.create_task(_tick_loop(session, console, engine, quiet, stop))
    try:
        if not quiet:
            console.print(
                f"[dim]watching; learning baseline for {config.watch.baseline_seconds:.0f}s "
                f"(no alerts during baseline)[/dim]"
            )
        await pump()
    finally:
        stop.set()
        ticker.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ticker
        _print_summary(console, session)


async def _pump_command(
    command: str, session: WatchSession, console: Console, engine, quiet: bool
) -> int | None:
    argv = shlex.split(command)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        console.print(f"[red]error:[/red] command not found: {argv[0]}")
        raise typer.Exit(EXIT_ERROR) from None
    assert proc.stdout is not None
    try:
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            for note in session.ingest_line(raw.decode(errors="replace"), time.monotonic()):
                _handle_notification(console, note, session, engine, quiet)
    finally:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        await proc.wait()
    return proc.returncode


async def _pump_file(
    path: Path, session: WatchSession, console: Console, engine, quiet: bool, stop: asyncio.Event
) -> None:
    """Follow a file (tail -F-ish: seek to end, poll for new lines)."""
    try:
        fh = path.open("r", errors="replace")
    except OSError as exc:
        console.print(f"[red]error:[/red] cannot open {path}: {exc}")
        raise typer.Exit(EXIT_ERROR) from None
    fh.seek(0, 2)
    try:
        while not stop.is_set():
            line = fh.readline()
            if line:
                for note in session.ingest_line(line, time.monotonic()):
                    _handle_notification(console, note, session, engine, quiet)
            else:
                await asyncio.sleep(0.5)
    finally:
        fh.close()


async def _tick_loop(
    session: WatchSession, console: Console, engine, quiet: bool, stop: asyncio.Event
) -> None:
    last_status = 0.0
    while not stop.is_set():
        await asyncio.sleep(1.0)
        now = time.monotonic()
        for note in session.tick(now):
            _handle_notification(console, note, session, engine, quiet)
        if not quiet and now - last_status >= 30:
            last_status = now
            s = session.summary(now)
            phase = "baseline" if not session.baseline.finished else "watching"
            console.print(
                f"[dim][{phase}] {s.total_lines} lines, {s.total_errors} errors, "
                f"{s.template_count} templates, {s.notifications} alerts "
                f"({s.suppressed} suppressed)[/dim]"
            )


def _handle_notification(
    console: Console, note: Notification, session: WatchSession, engine, quiet: bool
) -> None:
    _print_notification(console, note)
    if engine is not None:
        # Escalate through the same analysis engine: triggering window records
        # plus baseline context, previous findings folded into the focus hint.
        records = session.recent_records()
        focus = (
            f"live watch escalation; triggers: {', '.join(note.reasons)}; "
            f"{session.baseline.summary()}; "
            f"{len(session.notifications) - 1} previous findings this session"
        )
        try:
            report = engine.analyze_records(records, source="watch stream", focus=focus)
            render_report(report, console=console)
        except Exception as exc:  # noqa: BLE001 - keep the watch alive
            console.print(f"[red]LLM escalation failed:[/red] {exc}")


def _print_notification(console: Console, note: Notification) -> None:
    style = SEVERITY_STYLE.get(note.severity, "bold")
    related = " (related to previous finding)" if note.related_to_previous else ""
    console.print(
        f"[{style}] {note.severity.value.upper()} [/{style}] "
        f"{', '.join(note.reasons)}{related}: {note.detail}"
    )
    for line in note.exemplars[:3]:
        console.print(f"    [dim]{line}[/dim]")


def _print_summary(console: Console, session: WatchSession) -> None:
    s = session.summary(time.monotonic())
    console.print()
    console.print("[bold]watch session summary[/bold]")
    console.print(
        f"  duration: {s.duration_s:.0f}s | lines: {s.total_lines} | errors: {s.total_errors} "
        f"| templates: {s.template_count}"
    )
    console.print(f"  alerts: {s.notifications} emitted, {s.suppressed} suppressed")
    for tmpl, count in s.top_templates:
        console.print(f"  [dim]{count:>8}x  {tmpl[:100]}[/dim]")
