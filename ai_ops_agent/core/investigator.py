"""The reactive agent loop: alert → context pre-fetch → tool-using
investigation → structured verdict → Report (spec §4).

Read-only throughout. Budget-bounded (tool calls + wall clock). Every tool
call and LLM turn is recorded in an immutable audit log on the Report's
engine metadata / the returned AuditLog.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from ai_ops_agent.config import AppConfig
from ai_ops_agent.core.alert import Alert
from ai_ops_agent.core.budget import Budget
from ai_ops_agent.core.orchestrator import AnalysisEngine
from ai_ops_agent.core.redaction import Redactor
from ai_ops_agent.llm.client import LLMClient, LLMError
from ai_ops_agent.llm.prompt_loader import load_prompt
from ai_ops_agent.reporting.models import Report, Severity, Verdict
from ai_ops_agent.tools.base import ToolRegistry, ToolResult

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    kind: str  # tool_call | llm_turn | prefetch
    name: str
    detail: str
    ok: bool = True
    latency_ms: float = 0.0


@dataclass
class AuditLog:
    entries: list[AuditEntry] = field(default_factory=list)

    def add(self, entry: AuditEntry) -> None:
        self.entries.append(entry)

    def tool_calls(self) -> int:
        return sum(1 for e in self.entries if e.kind == "tool_call")


class Investigator:
    """Runs one alert investigation end to end."""

    def __init__(
        self,
        config: AppConfig,
        llm_client: LLMClient | None,
        tools: ToolRegistry,
        prefetch: list | None = None,
    ) -> None:
        self.config = config
        self.llm_client = llm_client
        self.tools = tools
        self.redactor = Redactor(enabled=config.redact, redact_ips=config.redact_ips)
        # Reuse the analysis engine's verdict-merging + evidence validation.
        self._engine = AnalysisEngine(config, llm_client=None)
        # prefetch is a list of (label, callable(alert) -> str) run deterministically.
        self._prefetch = prefetch or []

    def investigate(self, alert: Alert) -> tuple[Report, AuditLog]:
        audit = AuditLog()
        report = Report(source=f"alert:{alert.name}")
        report.links = {}
        if alert.generator_url:
            report.links["dashboard"] = alert.generator_url
        if alert.runbook_url:
            report.links["runbook"] = alert.runbook_url

        context = self._build_initial_context(alert, audit)

        if self.llm_client is None or not self.tools.tools:
            # No LLM or no tools: emit a needs_human report from the alert + prefetch.
            self._degrade(report, alert, context, "no LLM client or no tools available")
            return report, audit

        transcript = self._run_agent_loop(alert, context, audit)
        self._finalize_verdict(report, transcript, audit)
        return report, audit

    # ------------------------------------------------------------------

    def _build_initial_context(self, alert: Alert, audit: AuditLog) -> str:
        red = self.redactor.redact
        parts = [
            f"Alert: {alert.name}",
            f"Severity: {alert.severity} | Status: {alert.status}",
            f"Cluster: {alert.cluster or '-'} | Namespace: {alert.namespace or '-'} | "
            f"Workload: {alert.workload or '-'} | Node: {alert.node or '-'}",
        ]
        if alert.annotations:
            parts.append("Annotations:")
            for k, v in alert.annotations.items():
                parts.append(f"  {k}: {red(v)}")
        parts.append("Labels: " + ", ".join(f"{k}={red(v)}" for k, v in alert.labels.items()))

        parts.append("\n<untrusted-data>")
        for label, fn in self._prefetch:
            try:
                result = fn(alert)
            except Exception as exc:  # noqa: BLE001 - prefetch is best-effort
                result = f"(prefetch failed: {exc})"
            ok = not str(result).startswith("(prefetch failed")
            audit.add(AuditEntry(kind="prefetch", name=label, detail=str(result)[:200], ok=ok))
            parts.append(f"## {label}\n{red(str(result))}")
        parts.append("</untrusted-data>")
        return "\n".join(parts)

    def _run_agent_loop(self, alert: Alert, context: str, audit: AuditLog) -> str:
        prompt = load_prompt("investigate_system")
        budget = Budget(max_tool_calls=12, max_wall_clock_s=90.0)
        tool_schema = (
            self.tools.anthropic_schema()
            if self.config.llm.provider == "anthropic"
            else self.tools.openai_schema()
        )
        messages: list[dict] = [{"role": "user", "content": context}]
        final_text = ""
        assert self.llm_client is not None

        while True:
            try:
                step = self.llm_client.agent_step(prompt.text, messages, tool_schema)
            except LLMError as exc:
                audit.add(AuditEntry("llm_turn", "agent_step", str(exc), ok=False))
                logger.warning("agent step failed: %s", exc)
                break
            messages = step.messages
            audit.add(AuditEntry(
                "llm_turn", "agent_step",
                f"{len(step.tool_calls)} tool call(s)" if step.tool_calls else "final text",
            ))
            if not step.tool_calls:
                final_text = step.text
                break
            # Execute each requested tool, budget-gated.
            results: list[dict] = []
            stop = False
            for call in step.tool_calls:
                if not budget.allow_tool_call():
                    results.append(self._tool_result_msg(
                        call.id, f"[budget] {budget.exhausted_reason}; stop calling tools "
                        "and give your conclusion now."))
                    stop = True
                    continue
                result = self._execute_tool(call.name, call.arguments, audit)
                budget.record_tool_call()
                results.append(self._tool_result_msg(call.id, result.to_model_text()))
            messages = self._append_tool_results(messages, results)
            if stop:
                # One more turn to let the model conclude, then done.
                try:
                    step = self.llm_client.agent_step(prompt.text, messages, tool_schema)
                    final_text = step.text
                except LLMError:
                    pass
                break

        # Full transcript = context + everything the model saw, for evidence
        # validation and the final verdict prompt.
        notes = self._transcript_text(messages, final_text)
        return context + "\n\n## Investigation notes\n" + notes

    def _execute_tool(self, name: str, args: dict, audit: AuditLog) -> ToolResult:
        spec = self.tools.get(name)
        if spec is None:
            audit.add(AuditEntry("tool_call", name, "unknown tool", ok=False))
            return ToolResult(ok=False, error=f"unknown tool '{name}'")
        result = spec.run(**args)
        audit.add(AuditEntry(
            "tool_call", name,
            f"args={json.dumps(args)[:120]} -> {'ok' if result.ok else result.error}",
            ok=result.ok, latency_ms=result.latency_ms,
        ))
        return result

    def _finalize_verdict(self, report: Report, transcript: str, audit: AuditLog) -> None:
        prompt = load_prompt("analyze_system")
        report.engine.prompt_version = prompt.version
        assert self.llm_client is not None
        error_note = ""
        from ai_ops_agent.core.orchestrator import validate_evidence

        for _attempt in range(2):
            user = transcript if not error_note else f"{transcript}\n\n{error_note}"
            try:
                result = self.llm_client.generate_verdict(prompt.text, user)
            except LLMError as exc:
                audit.add(AuditEntry("llm_turn", "generate_verdict", str(exc), ok=False))
                self._degrade(report, None, transcript, str(exc))
                return
            bad = validate_evidence(result.verdict, transcript)
            if not bad:
                self._engine._merge_llm_verdict(report, result)
                audit.add(AuditEntry("llm_turn", "generate_verdict",
                                     f"verdict={result.verdict.verdict}"))
                return
            error_note = (
                "VALIDATION ERROR: these evidence excerpts were not found verbatim in "
                "the investigation notes above; quote tool output exactly:\n- "
                + "\n- ".join(bad[:5])
            )
        report.engine.degraded = True
        report.engine.degraded_reason = "evidence validation failed after retry"
        self._degrade(report, None, transcript, report.engine.degraded_reason)

    def _degrade(self, report: Report, alert: Alert | None, context: str, reason: str) -> None:
        report.verdict = Verdict.needs_human
        report.severity = Severity.sev3 if report.severity == Severity.info else report.severity
        report.title = report.title or "Investigation incomplete — needs human review"
        report.summary = (
            report.summary or "Automated investigation could not reach a validated verdict."
        ) + f" (degraded: {reason})"
        report.engine.degraded = True
        report.engine.degraded_reason = reason
        report.unknowns = report.unknowns or ["automated investigation did not complete"]

    # ------------------------------------------------------------------
    # Small message helpers (provider-neutral)
    # ------------------------------------------------------------------

    @staticmethod
    def _tool_result_msg(call_id: str, content: str) -> dict:
        return {"call_id": call_id, "content": content}

    @staticmethod
    def _append_tool_results(messages: list[dict], results: list[dict]) -> list[dict]:
        for r in results:
            messages.append(
                {"role": "tool", "tool_call_id": r["call_id"], "content": r["content"]}
            )
        return messages

    @staticmethod
    def _transcript_text(messages: list[dict], final_text: str) -> str:
        lines: list[str] = []
        for msg in messages:
            if msg["role"] == "tool":
                lines.append(f"[tool result] {msg['content']}")
            elif msg["role"] == "assistant" and msg.get("content"):
                lines.append(f"[agent] {msg['content']}")
        if final_text and (not lines or final_text not in lines[-1]):
            lines.append(f"[agent conclusion] {final_text}")
        return "\n".join(lines)
