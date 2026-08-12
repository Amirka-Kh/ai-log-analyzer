from __future__ import annotations

from ai_ops_agent.config import AppConfig
from ai_ops_agent.core.alert import alert_from_manual
from ai_ops_agent.core.budget import Budget
from ai_ops_agent.core.investigator import Investigator
from ai_ops_agent.llm.client import AgentStep, LLMResult, ToolCall
from ai_ops_agent.llm.schemas import LLMEvidence, LLMProbableCause, LLMVerdict
from ai_ops_agent.tools.base import ToolRegistry, ToolSpec


class ScriptedLLM:
    """Fake LLM: emits a scripted sequence of agent steps, then a verdict."""

    def __init__(self, steps: list[AgentStep], verdict: LLMVerdict):
        self._steps = list(steps)
        self._verdict = verdict
        self.step_calls = 0
        self.verdict_calls = 0
        self.last_verdict_user = ""

    def agent_step(self, system, messages, tools) -> AgentStep:
        self.step_calls += 1
        step = self._steps.pop(0)
        # Thread the incoming messages through so the loop's history is coherent.
        return AgentStep(step.tool_calls, step.text, [*messages,
                         {"role": "assistant", "content": step.text,
                          **({"tool_calls": step.tool_calls} if step.tool_calls else {})}])

    def generate_verdict(self, system, user) -> LLMResult:
        self.verdict_calls += 1
        self.last_verdict_user = user
        return LLMResult(verdict=self._verdict, model="fake", input_tokens=10, output_tokens=5)


def make_registry() -> tuple[ToolRegistry, list]:
    reg = ToolRegistry()
    reg.add(ToolSpec(
        name="k8s_get", description="get pod",
        schema={"type": "object", "properties": {"name": {"type": "string"}}},
        func=lambda name="": "phase=Running restarts=7 reason=CrashLoopBackOff",
    ))
    return reg, []


def verdict_citing(excerpt: str, verdict="real_incident") -> LLMVerdict:
    return LLMVerdict(
        verdict=verdict, confidence=0.8, severity="sev2",
        title="CrashLoopBackOff on api", summary="Pod is crash looping.",
        probable_cause=LLMProbableCause(
            statement="Pod crash loops.",
            evidence=[LLMEvidence(source="k8s", query="k8s_get", excerpt=excerpt)],
        ),
    )


def test_investigation_uses_tools_then_verdict():
    reg, pf = make_registry()
    llm = ScriptedLLM(
        steps=[
            AgentStep([ToolCall("c1", "k8s_get", {"name": "api-xk2"})], "", []),
            AgentStep([], "The pod is crash looping with 7 restarts.", []),
        ],
        verdict=verdict_citing("CrashLoopBackOff"),
    )
    inv = Investigator(AppConfig(), llm, reg, pf)
    report, audit = inv.investigate(alert_from_manual("Crash", namespace="prod", pod="api-xk2"))
    assert report.verdict.value == "real_incident"
    assert report.engine.llm_used
    assert not report.engine.degraded
    assert audit.tool_calls() == 1
    # Tool observation is present in the transcript given to the verdict step.
    assert "CrashLoopBackOff" in llm.last_verdict_user


def test_hallucinated_evidence_degrades():
    reg, pf = make_registry()
    llm = ScriptedLLM(
        steps=[AgentStep([], "done", [])],
        verdict=verdict_citing("this text was never in any tool output"),
    )
    inv = Investigator(AppConfig(), llm, reg, pf)
    report, _ = inv.investigate(alert_from_manual("Crash", namespace="prod", pod="api-xk2"))
    assert report.engine.degraded
    assert report.verdict.value == "needs_human"
    assert llm.verdict_calls == 2  # retried once


def test_no_tools_degrades_to_needs_human():
    llm = ScriptedLLM(steps=[], verdict=verdict_citing("x"))
    inv = Investigator(AppConfig(), llm, ToolRegistry(), [])
    report, _ = inv.investigate(alert_from_manual("Crash", namespace="prod"))
    assert report.verdict.value == "needs_human"
    assert report.engine.degraded
    assert llm.step_calls == 0  # no tools -> no agent loop


def test_prefetch_runs_and_is_audited():
    reg, _ = make_registry()
    pf = [("Pod state", lambda alert: "phase=Running restarts=7")]
    llm = ScriptedLLM(
        steps=[AgentStep([], "looks fine", [])],
        verdict=verdict_citing("restarts=7", verdict="no_incident"),
    )
    inv = Investigator(AppConfig(), llm, reg, pf)
    report, audit = inv.investigate(alert_from_manual("Crash", namespace="prod", pod="api-xk2"))
    prefetch_entries = [e for e in audit.entries if e.kind == "prefetch"]
    assert len(prefetch_entries) == 1
    assert "restarts=7" in llm.last_verdict_user


def test_budget_stops_tool_calls():
    budget = Budget(max_tool_calls=2, max_wall_clock_s=1000)
    assert budget.allow_tool_call()
    budget.record_tool_call()
    assert budget.allow_tool_call()
    budget.record_tool_call()
    assert not budget.allow_tool_call()
    assert "tool-call budget" in budget.exhausted_reason


def test_links_populated_from_alert():
    reg, pf = make_registry()
    llm = ScriptedLLM(steps=[AgentStep([], "done", [])], verdict=verdict_citing("restarts=7"))
    inv = Investigator(AppConfig(), llm, reg, pf)
    alert = alert_from_manual("Crash", namespace="prod", pod="api-xk2")
    alert.generator_url = "https://vm/graph"
    alert.runbook_url = "https://rb/crash"
    report, _ = inv.investigate(alert)
    assert report.links["dashboard"] == "https://vm/graph"
    assert report.links["runbook"] == "https://rb/crash"
