"""Structured-output schema the model must produce (spec §4)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class LLMEvidence(BaseModel):
    source: Literal["metrics", "k8s", "logs", "ssh", "local"]
    query: str
    excerpt: str


class LLMTimelineEvent(BaseModel):
    ts: str
    event: str


class LLMAlternative(BaseModel):
    hypothesis: str
    why_rejected: str


class LLMProbableCause(BaseModel):
    statement: str
    evidence: list[LLMEvidence]
    alternatives_considered: list[LLMAlternative] = Field(default_factory=list)


class LLMBlastRadius(BaseModel):
    services: list[str] = Field(default_factory=list)
    users_affected: Literal["unknown", "none", "partial", "full"] = "unknown"


class LLMRecommendedAction(BaseModel):
    step: str
    command: str | None = None
    risk: Literal["low", "medium", "high"] = "low"
    reversible: bool = True


class LLMLinks(BaseModel):
    dashboard: str | None = None
    runbook: str | None = None
    logs: str | None = None


class LLMVerdict(BaseModel):
    verdict: Literal[
        "real_incident",
        "false_positive",
        "noisy_rule",
        "expected_maintenance",
        "needs_human",
        "no_incident",
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Literal["sev1", "sev2", "sev3", "info"]
    title: str
    summary: str
    timeline: list[LLMTimelineEvent] = Field(default_factory=list)
    probable_cause: LLMProbableCause
    blast_radius: LLMBlastRadius = Field(default_factory=LLMBlastRadius)
    recommended_actions: list[LLMRecommendedAction] = Field(default_factory=list)
    false_positive_reasoning: str | None = None
    unknowns: list[str] = Field(default_factory=list)
    links: LLMLinks = Field(default_factory=LLMLinks)
