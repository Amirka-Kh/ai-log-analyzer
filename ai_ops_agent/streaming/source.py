"""Source resolution for `analyze`: file, glob, stdin, command, journalctl.

Everything streams — files are read line by line (``.gz`` transparently), and
command sources are spawned via ``shlex`` + exec (never ``shell=True``). The
command string comes from the human operator, not the model; no tool that
spawns processes is ever exposed to the LLM.
"""

from __future__ import annotations

import glob as globlib
import gzip
import shlex
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


class SourceError(Exception):
    """Configuration/tool error resolving or reading a source (exit code 2)."""


@dataclass
class ResolvedSource:
    kind: str  # file | stdin | command | journalctl
    description: str
    paths: list[Path] | None = None
    argv: list[str] | None = None


def resolve_source(source: str | None, since: str | None = None) -> ResolvedSource:
    if source is None or source == "-":
        if source is None and sys.stdin.isatty():
            raise SourceError("no --source given and stdin is a TTY; nothing to analyze")
        return ResolvedSource(kind="stdin", description="stdin")

    if source.startswith("journalctl:"):
        unit = source.split(":", 1)[1]
        if not unit:
            raise SourceError("journalctl source requires a unit, e.g. journalctl:nginx")
        argv = ["journalctl", "-u", unit, "--no-pager", "-o", "short-iso"]
        if since:
            argv += ["--since", _journalctl_since(since)]
        return ResolvedSource(kind="journalctl", description=source, argv=argv)

    path = Path(source)
    if path.exists() and path.is_file():
        return ResolvedSource(kind="file", description=str(path), paths=[path])

    matches = sorted(globlib.glob(source))
    file_matches = [Path(p) for p in matches if Path(p).is_file()]
    if file_matches:
        return ResolvedSource(
            kind="file", description=f"{source} ({len(file_matches)} files)", paths=file_matches
        )

    if " " in source:
        argv = shlex.split(source)
        return ResolvedSource(kind="command", description=source, argv=argv)

    raise SourceError(f"source not found: {source!r} (not a file, glob match, or command)")


def _journalctl_since(since: str) -> str:
    """Translate our relative '--since 2h' into journalctl's syntax."""
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    if since and since[-1] in units and since[:-1].isdigit():
        return f"-{since[:-1]} {units[since[-1]]}"
    return since


def iter_lines(resolved: ResolvedSource) -> Iterator[str]:
    if resolved.kind == "stdin":
        yield from sys.stdin
        return
    if resolved.kind == "file":
        assert resolved.paths is not None
        for path in resolved.paths:
            yield from _iter_file(path)
        return
    # command / journalctl
    assert resolved.argv is not None
    try:
        proc = subprocess.Popen(
            resolved.argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise SourceError(f"command not found: {resolved.argv[0]}") from exc
    assert proc.stdout is not None
    try:
        yield from proc.stdout
    finally:
        proc.stdout.close()
        proc.wait()


def _iter_file(path: Path) -> Iterator[str]:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", errors="replace") as fh:
                yield from fh
        else:
            with open(path, errors="replace") as fh:
                yield from fh
    except OSError as exc:
        raise SourceError(f"cannot read {path}: {exc}") from exc
