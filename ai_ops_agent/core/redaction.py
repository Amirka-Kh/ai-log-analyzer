"""Redaction pipeline.

Applied to every excerpt, exemplar, and context blob *before* it reaches the
LLM or a rendered report. Raw log lines are processed in-memory only; nothing
unredacted leaves the process when redaction is enabled (the default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class RedactionRule:
    name: str
    pattern: re.Pattern[str]
    replacement: str


def _rule(name: str, pattern: str, flags: int = 0) -> RedactionRule:
    return RedactionRule(name, re.compile(pattern, flags), f"[REDACTED:{name}]")


DEFAULT_RULES: list[RedactionRule] = [
    _rule(
        "private_key",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    _rule("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    _rule("aws_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _rule("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    _rule(
        "conn_string",
        r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@]+@",
        re.IGNORECASE,
    ),
    _rule(
        "kv_secret",
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth)\s*[=:]\s*[^\s,;\"']+",
    ),
    _rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
]

IP_RULE = _rule("ip", r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")


@dataclass
class Redactor:
    enabled: bool = True
    redact_ips: bool = False
    extra_rules: list[RedactionRule] = field(default_factory=list)
    hits: int = 0

    def _rules(self) -> list[RedactionRule]:
        rules = list(DEFAULT_RULES) + self.extra_rules
        if self.redact_ips:
            rules.append(IP_RULE)
        return rules

    def redact(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        for rule in self._rules():
            text, n = rule.pattern.subn(rule.replacement, text)
            self.hits += n
        return text
