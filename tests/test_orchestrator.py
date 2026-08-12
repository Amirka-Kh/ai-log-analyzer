from __future__ import annotations

import tracemalloc

from ai_ops_agent.config import AppConfig
from ai_ops_agent.core.orchestrator import AnalysisEngine, validate_evidence
from ai_ops_agent.llm.client import LLMError, LLMResult
from ai_ops_agent.llm.schemas import (
    LLMEvidence,
    LLMProbableCause,
    LLMVerdict,
)
from ai_ops_agent.reporting.models import Severity, Verdict
from tests.conftest import read_fixture_lines


def make_verdict(excerpt: str, verdict: str = "real_incident") -> LLMVerdict:
    return LLMVerdict(
        verdict=verdict,
        confidence=0.8,
        severity="sev2",
        title="Connection pool exhaustion led to OOM",
        summary="The api service exhausted its DB connection pool and a worker was OOM-killed.",
        probable_cause=LLMProbableCause(
            statement="Pool exhaustion escalated into memory pressure.",
            evidence=[LLMEvidence(source="logs", query="template", excerpt=excerpt)],
        ),
    )


class FakeLLM:
    def __init__(self, verdicts=None, error: LLMError | None = None):
        self.verdicts = list(verdicts or [])
        self.error = error
        self.calls: list[str] = []

    def generate_verdict(self, system: str, user: str) -> LLMResult:
        self.calls.append(user)
        if self.error:
            raise self.error
        verdict = self.verdicts.pop(0)
        return LLMResult(verdict=verdict, model="fake-model", input_tokens=100, output_tokens=50)


def analyze(name: str, llm=None, config: AppConfig | None = None):
    config = config or AppConfig()
    engine = AnalysisEngine(config, llm_client=llm)
    return engine.analyze_lines(read_fixture_lines(name), source=name)


def test_deterministic_clean_log():
    report = analyze("clean.log")
    assert report.verdict == Verdict.no_incident
    assert report.severity == Severity.info
    assert not report.engine.llm_used
    assert report.stats.parsed_records == 6


def test_deterministic_incident_log():
    report = analyze("json_lines.log")
    assert report.verdict == Verdict.needs_human
    assert report.findings
    titles = " ".join(f.title for f in report.findings)
    assert "Fatal" in titles or "Error template" in titles


def test_deterministic_security_findings():
    report = analyze("nginx_access.log")
    titles = " ".join(f.title for f in report.findings)
    assert "Path scanning" in titles
    assert "SQL-injection" in titles
    sqli = next(f for f in report.findings if "SQL-injection" in f.title)
    assert sqli.severity == Severity.sev2
    assert sqli.line_refs


def test_llm_happy_path():
    # Excerpt copied verbatim from a template exemplar in the context.
    llm = FakeLLM(verdicts=[make_verdict("connection pool exhausted: waited")])
    report = analyze("json_lines.log", llm=llm)
    assert report.engine.llm_used
    assert report.verdict == Verdict.real_incident
    assert report.confidence == 0.8
    assert report.engine.model == "fake-model"
    assert not report.engine.degraded
    assert len(llm.calls) == 1


def test_llm_hallucinated_evidence_retries_then_degrades():
    bad = make_verdict("this excerpt was never in any log line at all zzz")
    llm = FakeLLM(verdicts=[bad, bad])
    report = analyze("json_lines.log", llm=llm)
    assert len(llm.calls) == 2  # one retry with the validation error appended
    assert "VALIDATION ERROR" in llm.calls[1]
    assert report.engine.degraded
    assert report.verdict == Verdict.needs_human  # degraded to deterministic


def test_llm_retry_recovers():
    bad = make_verdict("never appeared xyz123")
    good = make_verdict("connection pool exhausted: waited")
    llm = FakeLLM(verdicts=[bad, good])
    report = analyze("json_lines.log", llm=llm)
    assert not report.engine.degraded
    assert report.verdict == Verdict.real_incident


def test_llm_unavailable_degrades():
    llm = FakeLLM(error=LLMError("no api key"))
    report = analyze("json_lines.log", llm=llm)
    assert report.engine.degraded
    assert "no api key" in (report.engine.degraded_reason or "")
    assert report.verdict == Verdict.needs_human


def test_context_wraps_untrusted_data_and_redacts():
    config = AppConfig()
    engine = AnalysisEngine(config, llm_client=None)
    from ai_ops_agent.core.signals import SignalsCollector
    from ai_ops_agent.streaming.parsing import parse_stream
    from ai_ops_agent.streaming.templates import TemplateStore

    templates = TemplateStore()
    collector = SignalsCollector()
    lines = read_fixture_lines("prompt_injection.log") + [
        "2026-08-01T10:00:20Z ERROR login failed password=Hunter2Secret\n"
    ]
    for record in parse_stream(lines):
        templates.add(record)
        collector.add(record)
    context = engine.build_context(collector.finalize(), templates, "test", None)
    assert "<untrusted-log-data>" in context and "</untrusted-log-data>" in context
    # Injection content is inside the delimiters, secrets are redacted.
    assert "Hunter2Secret" not in context
    body = context.split("<untrusted-log-data>")[1]
    assert "ignore previous instructions" in body


def test_evidence_validation_whitespace_insensitive():
    verdict = make_verdict("Connection   Pool exhausted:  waited")
    assert validate_evidence(verdict, "blah connection pool exhausted: waited 5000ms") == []


def test_evidence_required_for_incident_verdicts():
    verdict = make_verdict("x")
    verdict.probable_cause.evidence = []
    bad = validate_evidence(verdict, "anything")
    assert bad == ["<probable_cause.evidence is empty>"]


def test_streaming_memory_stays_flat():
    """A large synthetic input must not be materialized in memory."""

    def lines():
        for i in range(100_000):
            level = "ERROR" if i % 50 == 0 else "INFO"
            yield (
                f"2026-08-01T10:{(i // 6000) % 60:02d}:{(i // 100) % 60:02d}Z "
                f"{level} request {i} handled in {i % 90}ms\n"
            )

    engine = AnalysisEngine(AppConfig(), llm_client=None)
    tracemalloc.start()
    report = engine.analyze_lines(lines(), source="synthetic")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert report.stats.parsed_records == 100_000
    # 100k lines of ~70 bytes would be ~7MB if buffered; templates collapse them.
    assert peak < 40 * 1024 * 1024
    assert report.stats.template_count < 100
