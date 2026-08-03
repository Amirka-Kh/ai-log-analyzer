"""Deterministic security-signal patterns (subset of the night-audit set that
applies to raw log content). Matched against full record text; each hit is
counted with a few exemplar line references.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_ops_agent.reporting.models import Severity


@dataclass(frozen=True)
class SecurityPattern:
    name: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]


def _p(name: str, title: str, severity: Severity, pattern: str) -> SecurityPattern:
    return SecurityPattern(name, title, severity, re.compile(pattern, re.IGNORECASE))


SECURITY_PATTERNS: list[SecurityPattern] = [
    _p(
        "path_scan",
        "Path scanning / probe attempts",
        Severity.sev3,
        r"(/\.env\b|/wp-admin|/wp-login|/phpmyadmin|/\.git\b|/etc/passwd|\.\./\.\.|%2e%2e%2f)",
    ),
    _p(
        "sqli",
        "SQL-injection-like payloads",
        Severity.sev2,
        r"(union(?:\s|%20|\+)+select|'\s*or\s+1\s*=\s*1|%27\s*or\s*1%3D1|information_schema"
        r"|sleep\(\d+\)|;--\s|xp_cmdshell)",
    ),
    _p(
        "xss",
        "XSS-like payloads",
        Severity.sev3,
        r"(<script[\s>]|javascript:\s*\w|onerror\s*=)",
    ),
    _p(
        "ssh_auth_failure",
        "SSH authentication failures",
        Severity.sev3,
        r"(failed password for|authentication failure|invalid user \w+ from)",
    ),
    _p(
        "sudo_usage",
        "sudo invocations",
        Severity.info,
        r"\bsudo(?:\[\d+\])?:\s+\w+\s*:.*COMMAND=",
    ),
    _p(
        "privilege_error",
        "Permission / access denied errors",
        Severity.info,
        r"(permission denied|access denied|forbidden by rule)",
    ),
]

# Health-critical markers used by both analyze and the watch trigger policy.
FATAL_MARKERS = re.compile(
    r"(\bpanic\b|\bfatal\b|OOMKilled|Out of memory|oom-killer|segfault|"
    r"core dumped|stack overflow|Traceback \(most recent call last\)|OutOfMemoryError)",
    re.IGNORECASE,
)
