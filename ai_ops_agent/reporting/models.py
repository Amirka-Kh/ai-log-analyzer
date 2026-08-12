"""Canonical Report / Finding / Evidence models.

Every entry point (CLI analyze, CLI watch, and — in later phases — webhook
alerts and Mattermost commands) produces the same :class:`Report`; renderers
only differ in how they present it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    sev1 = "sev1"
    sev2 = "sev2"
    sev3 = "sev3"
    info = "info"


# Higher = more severe, used for --fail-on comparisons.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.sev1: 3,
    Severity.sev2: 2,
    Severity.sev3: 1,
    Severity.info: 0,
}


class Verdict(StrEnum):
    real_incident = "real_incident"
    false_positive = "false_positive"
    noisy_rule = "noisy_rule"
    expected_maintenance = "expected_maintenance"
    needs_human = "needs_human"
    # CLI-mode addition: a plain log file with nothing wrong in it. The alert
    # path never emits this, but "everything is fine" is a first-class outcome
    # for `ai-ops analyze`.
    no_incident = "no_incident"


class EvidenceSource(StrEnum):
    metrics = "metrics"
    k8s = "k8s"
    logs = "logs"
    ssh = "ssh"
    local = "local"


class Evidence(BaseModel):
    source: EvidenceSource = EvidenceSource.logs
    query: str = ""
    excerpt: str


class TimelineEvent(BaseModel):
    ts: str
    event: str


class Alternative(BaseModel):
    hypothesis: str
    why_rejected: str


class ProbableCause(BaseModel):
    statement: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    alternatives_considered: list[Alternative] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    step: str
    command: str | None = None
    risk: str = "low"
    reversible: bool = True


class BlastRadius(BaseModel):
    services: list[str] = Field(default_factory=list)
    users_affected: str = "unknown"


class Finding(BaseModel):
    severity: Severity
    title: str
    detail: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    # Where a human can jump to in the source (1-based line numbers).
    line_refs: list[int] = Field(default_factory=list)
    count: int = 1


class AnalysisStats(BaseModel):
    total_lines: int = 0
    parsed_records: int = 0
    template_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    detected_format: str = "plain"
    sampling_note: str | None = None
    redaction_hits: int = 0


class EngineMeta(BaseModel):
    llm_used: bool = False
    model: str | None = None
    prompt_version: str | None = None
    degraded: bool = False
    degraded_reason: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


class Report(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = ""

    verdict: Verdict = Verdict.no_incident
    confidence: float = 0.0
    severity: Severity = Severity.info
    title: str = ""
    summary: str = ""
    timeline: list[TimelineEvent] = Field(default_factory=list)
    probable_cause: ProbableCause = Field(default_factory=ProbableCause)
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    false_positive_reasoning: str | None = None
    unknowns: list[str] = Field(default_factory=list)
    links: dict[str, str] = Field(default_factory=dict)

    findings: list[Finding] = Field(default_factory=list)
    stats: AnalysisStats = Field(default_factory=AnalysisStats)
    engine: EngineMeta = Field(default_factory=EngineMeta)

    def max_finding_severity(self) -> Severity:
        best = self.severity
        for f in self.findings:
            if SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]:
                best = f.severity
        return best

    def fails_threshold(self, fail_on: Severity) -> bool:
        return SEVERITY_RANK[self.max_finding_severity()] >= SEVERITY_RANK[fail_on]
