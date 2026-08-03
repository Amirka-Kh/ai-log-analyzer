"""Trigger policy: decide whether a closed window is worth escalating.

The LLM is never called per window — only when one of these deterministic
triggers fires, and then still subject to the cooldown / rate limits enforced
by the watch session.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_ops_agent.config import WatchConfig
from ai_ops_agent.core.security import FATAL_MARKERS, SECURITY_PATTERNS
from ai_ops_agent.reporting.models import Severity
from ai_ops_agent.streaming.state import Baseline
from ai_ops_agent.streaming.windowing import Window


@dataclass
class Trigger:
    reason: str
    severity: Severity
    detail: str


def evaluate_window(window: Window, baseline: Baseline, config: WatchConfig) -> list[Trigger]:
    triggers: list[Trigger] = []
    if window.count == 0:
        return triggers

    # 1. Never-seen-before templates, weighted by level.
    novel_errors = [
        t for t in window.new_templates
        if window.new_template_levels.get(t) in ("error", "critical")
    ]
    if novel_errors:
        triggers.append(
            Trigger(
                reason="new_error_template",
                severity=Severity.sev2,
                detail=f"{len(novel_errors)} new error template(s): "
                + "; ".join(novel_errors[:3]),
            )
        )

    # 2. Error rate exceeding the learned baseline by a configurable factor.
    rate = window.error_rate
    baseline_rate = max(baseline.error_rate, 0.001)
    if rate >= config.min_error_rate and rate / baseline_rate >= config.error_rate_factor:
        triggers.append(
            Trigger(
                reason="error_rate_spike",
                severity=Severity.sev2,
                detail=f"window error rate {rate:.1%} vs baseline {baseline.error_rate:.1%}",
            )
        )

    # 3. Fatal / panic / OOM / stack-trace markers.
    fatal_lines = [r for r in window.records if FATAL_MARKERS.search(r.full_text)]
    if fatal_lines:
        triggers.append(
            Trigger(
                reason="fatal_marker",
                severity=Severity.sev1,
                detail=f"{len(fatal_lines)} fatal marker line(s); first: "
                + fatal_lines[0].message[:160],
            )
        )

    # 4. Security-signal pattern matches.
    for pattern in SECURITY_PATTERNS:
        if pattern.severity == Severity.info:
            continue
        matched = [r for r in window.records if pattern.pattern.search(r.full_text)]
        if matched:
            triggers.append(
                Trigger(
                    reason=f"security:{pattern.name}",
                    severity=pattern.severity,
                    detail=f"{pattern.title}: {len(matched)} line(s); first: "
                    + matched[0].message[:160],
                )
            )

    return triggers
