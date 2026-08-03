"""Log parsing: format detection, per-line parsers, multi-line grouping.

Supported formats: JSON lines, logfmt, nginx/apache combined access logs,
syslog, and plain text with best-effort timestamp/level extraction. Multi-line
exception blocks (Java/Python stack traces) are folded into the record that
started them.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime

LEVEL_ALIASES = {
    "trace": "debug",
    "debug": "debug",
    "info": "info",
    "notice": "info",
    "warn": "warning",
    "warning": "warning",
    "err": "error",
    "error": "error",
    "crit": "critical",
    "critical": "critical",
    "fatal": "critical",
    "panic": "critical",
    "alert": "critical",
    "emerg": "critical",
}

ERROR_LEVELS = {"error", "critical"}


@dataclass
class LogRecord:
    line_no: int  # 1-based line number of the first line of the record
    raw: str  # first raw line
    message: str
    level: str | None = None
    ts: datetime | None = None
    fields: dict[str, str] = field(default_factory=dict)
    extra_lines: list[str] = field(default_factory=list)  # continuation lines

    @property
    def is_error(self) -> bool:
        return (self.level or "") in ERROR_LEVELS

    @property
    def full_text(self) -> str:
        if not self.extra_lines:
            return self.raw
        return "\n".join([self.raw, *self.extra_lines])

    def exception_type(self) -> str | None:
        for line in [self.raw, *self.extra_lines]:
            m = _EXC_RE.match(line.strip())
            if m:
                return m.group(1)
        return None


_EXC_RE = re.compile(
    r"^(?:Caused by:\s*)?([A-Za-z_][\w.$]*(?:Error|Exception|Fault|Throwable|Interrupt))\b"
)

_LEVEL_TOKEN_RE = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRIT(?:ICAL)?|FATAL|PANIC|ALERT|EMERG)\b",
    re.IGNORECASE,
)

_ISO_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)

_ACCESS_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+\"(?P<request>[^\"]*)\"\s+"
    r"(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+\"(?P<referer>[^\"]*)\"\s+\"(?P<agent>[^\"]*)\")?"
)

_LOGFMT_RE = re.compile(r"(\w[\w.]*)=(\"(?:[^\"\\]|\\.)*\"|\S+)")

_CONTINUATION_RE = re.compile(
    r"^(\s+|Caused by:|Traceback \(most recent call last\)"
    r"|\.\.\.\s*\d+\s+(?:more|common frames)"
    # Exception head lines ("java.lang.NullPointerException: ...", "KeyError: ...")
    # belong to the record that logged them.
    r"|(?:[A-Za-z_][\w$]*\.)*[A-Za-z_]\w*(?:Error|Exception):)"
)

TS_JSON_KEYS = ("timestamp", "time", "ts", "@timestamp", "datetime")
LEVEL_JSON_KEYS = ("level", "severity", "lvl", "loglevel", "log.level")
MSG_JSON_KEYS = ("message", "msg", "event", "log")


def normalize_level(value: str | None) -> str | None:
    if not value:
        return None
    return LEVEL_ALIASES.get(value.strip().lower())


def parse_timestamp(value: str) -> datetime | None:
    value = value.strip()
    m = _ISO_TS_RE.match(value)
    if m:
        s = m.group(1).replace(",", ".").replace(" ", "T")
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            pass
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    # Syslog format has no year; pin to the current year.
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now().year)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Per-format parsers: return a LogRecord or None if the line doesn't match.
# ---------------------------------------------------------------------------


def parse_json_line(line_no: int, line: str) -> LogRecord | None:
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        obj = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    ts = None
    for key in TS_JSON_KEYS:
        if key in obj:
            v = obj[key]
            if isinstance(v, (int, float)):
                try:
                    ts = datetime.fromtimestamp(v if v < 1e11 else v / 1000)
                except (ValueError, OSError, OverflowError):
                    ts = None
            elif isinstance(v, str):
                ts = parse_timestamp(v)
            break
    level = None
    for key in LEVEL_JSON_KEYS:
        if key in obj and isinstance(obj[key], str):
            level = normalize_level(obj[key])
            break
    message = ""
    for key in MSG_JSON_KEYS:
        if key in obj and isinstance(obj[key], str):
            message = obj[key]
            break
    if not message:
        message = stripped
    fields = {k: str(v) for k, v in obj.items() if isinstance(v, (str, int, float, bool))}
    return LogRecord(line_no=line_no, raw=line, message=message, level=level, ts=ts, fields=fields)


def parse_logfmt_line(line_no: int, line: str) -> LogRecord | None:
    pairs = _LOGFMT_RE.findall(line)
    if len(pairs) < 2:
        return None
    fields = {k: v.strip('"') for k, v in pairs}
    if not ({"level", "lvl", "severity"} & fields.keys()) and not (
        {"msg", "message"} & fields.keys()
    ):
        return None
    level = normalize_level(fields.get("level") or fields.get("lvl") or fields.get("severity"))
    ts = None
    for key in ("time", "ts", "timestamp"):
        if key in fields:
            ts = parse_timestamp(fields[key])
            break
    message = fields.get("msg") or fields.get("message") or line.strip()
    return LogRecord(line_no=line_no, raw=line, message=message, level=level, ts=ts, fields=fields)


def parse_access_line(line_no: int, line: str) -> LogRecord | None:
    m = _ACCESS_RE.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    if status >= 500:
        level = "error"
    elif status >= 400:
        level = "warning"
    else:
        level = "info"
    fields = {k: v for k, v in m.groupdict().items() if v is not None}
    message = f"{m.group('request')} -> {status}"
    return LogRecord(
        line_no=line_no,
        raw=line,
        message=message,
        level=level,
        ts=parse_timestamp(m.group("ts")),
        fields=fields,
    )


def parse_syslog_line(line_no: int, line: str) -> LogRecord | None:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    msg = m.group("msg")
    level = normalize_level(_extract_level_token(msg))
    return LogRecord(
        line_no=line_no,
        raw=line,
        message=msg,
        level=level,
        ts=parse_timestamp(m.group("ts")),
        fields={"host": m.group("host"), "program": m.group("prog")},
    )


_LEADING_LEVEL_RE = re.compile(
    r"^(?:TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRIT(?:ICAL)?|FATAL|PANIC|ALERT|EMERG)"
    r"\b[\s:\-\]|]*",
    re.IGNORECASE,
)


def parse_plain_line(line_no: int, line: str) -> LogRecord:
    ts = None
    m = _ISO_TS_RE.search(line[:64])
    if m:
        ts = parse_timestamp(m.group(1))
    level = normalize_level(_extract_level_token(line))
    message = line.strip()
    if m:
        message = message.replace(m.group(1), "", 1).strip(" -[]|")
    if level:
        message = _LEADING_LEVEL_RE.sub("", message, count=1) or message
    return LogRecord(line_no=line_no, raw=line, message=message or line.strip(), level=level, ts=ts)


def _extract_level_token(text: str) -> str | None:
    m = _LEVEL_TOKEN_RE.search(text[:160])
    return m.group(1) if m else None


PARSERS = {
    "json": parse_json_line,
    "logfmt": parse_logfmt_line,
    "access": parse_access_line,
    "syslog": parse_syslog_line,
}


def detect_format(sample: list[str]) -> str:
    """Pick the parser with the highest match ratio over a sample of lines."""
    lines = [ln for ln in sample if ln.strip()][:100]
    if not lines:
        return "plain"
    best_name, best_score = "plain", 0.0
    for name, parser in PARSERS.items():
        matched = sum(1 for i, ln in enumerate(lines) if parser(i + 1, ln) is not None)
        score = matched / len(lines)
        if score > best_score:
            best_name, best_score = name, score
    return best_name if best_score >= 0.5 else "plain"


def is_continuation(line: str) -> bool:
    return bool(line) and bool(_CONTINUATION_RE.match(line))


def parse_stream(
    lines: Iterable[str], fmt: str | None = None, sample_size: int = 100
) -> Iterator[LogRecord]:
    """Parse an iterable of raw lines into LogRecords, streaming.

    Buffers up to ``sample_size`` lines for format detection when ``fmt`` is
    None, then streams. Continuation lines (stack frames etc.) are attached to
    the preceding record; a Python ``Traceback`` header additionally absorbs
    the closing exception line.
    """
    iterator = iter(lines)
    buffer: list[str] = []
    if fmt is None:
        for line in iterator:
            buffer.append(line)
            if len(buffer) >= sample_size:
                break
        fmt = detect_format(buffer)

    parser = PARSERS.get(fmt or "plain")
    current: LogRecord | None = None
    in_traceback = False
    line_no = 0

    def make_record(no: int, line: str) -> LogRecord:
        rec = parser(no, line) if parser else None
        return rec if rec is not None else parse_plain_line(no, line)

    def flush() -> LogRecord | None:
        nonlocal current, in_traceback
        rec, current, in_traceback = current, None, False
        return rec

    for line in _chain(buffer, iterator):
        line_no += 1
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if current is not None and is_continuation(line):
            current.extra_lines.append(line)
            if "Traceback (most recent call last)" in line:
                in_traceback = True
            elif not line[:1].isspace():
                # An exception-head line ("KeyError: ...") closes the traceback.
                in_traceback = False
            continue
        if current is not None and in_traceback and not line[:1].isspace():
            # The final "SomeError: message" line of a Python traceback.
            current.extra_lines.append(line)
            in_traceback = False
            continue
        if line.startswith("Traceback (most recent call last)") and current is not None:
            current.extra_lines.append(line)
            in_traceback = True
            continue
        prev = flush()
        if prev is not None:
            yield prev
        current = make_record(line_no, line)
        # A record that *is* a traceback header starts multi-line absorption.
        if line.startswith("Traceback (most recent call last)"):
            in_traceback = True
    last = flush()
    if last is not None:
        yield last


def _chain(buffer: list[str], rest: Iterator[str]) -> Iterator[str]:
    yield from buffer
    yield from rest
