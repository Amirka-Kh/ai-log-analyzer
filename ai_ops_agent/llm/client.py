"""Provider-agnostic LLM client.

Two implementations behind one protocol:

- ``AnthropicLLMClient`` (default) uses ``client.messages.parse`` with the
  pydantic verdict schema so responses are validated at the API layer.
- ``OpenAILLMClient`` speaks the Chat Completions API with a JSON-schema
  ``response_format``, which also covers self-hosted OpenAI-compatible
  servers (vLLM, Ollama, LiteLLM) via ``openai_base_url``.

The orchestrator only sees the protocol; provider selection happens in
``make_client``.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from pydantic import ValidationError

from ai_ops_agent.config import LLMConfig
from ai_ops_agent.llm.schemas import LLMVerdict


class LLMError(Exception):
    """Any failure talking to the model (auth, network, refusal, bad output)."""


@dataclass
class LLMResult:
    verdict: LLMVerdict
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class AgentStep:
    """One turn of the agent loop: either tool calls to execute, or final text.

    ``messages`` carries the provider-neutral history to feed back on the next
    step (assistant turn + any tool calls already appended).
    """

    tool_calls: list[ToolCall]
    text: str
    messages: list[dict[str, Any]]


class LLMClient(Protocol):
    def generate_verdict(self, system: str, user: str) -> LLMResult: ...

    def agent_step(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AgentStep:
        """Run one model turn with tools. ``messages`` is a provider-neutral
        history (roles: user/assistant/tool). Returns requested tool calls or
        the final text, plus the updated message history."""
        ...


class AnthropicLLMClient:
    """Anthropic Messages API client with structured output."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self._client: Any = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover
                raise LLMError(
                    "the 'anthropic' package is not installed; "
                    "install it or run with --no-llm"
                ) from exc
            self._client = anthropic.Anthropic(timeout=self.config.request_timeout_s)
        return self._client

    def generate_verdict(self, system: str, user: str) -> LLMResult:
        import anthropic

        client = self._get_client()
        try:
            response = client.messages.parse(
                model=self.config.model,
                max_tokens=self.config.max_output_tokens,
                system=[
                    {
                        "type": "text",
                        "text": system,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user}],
                output_format=LLMVerdict,
            )
        except anthropic.AuthenticationError as exc:
            raise LLMError(
                "authentication failed — set ANTHROPIC_API_KEY (or run with --no-llm)"
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError(f"cannot reach the LLM API: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"LLM API error {exc.status_code}: {exc.message}") from exc

        if response.stop_reason == "refusal":
            raise LLMError("the model declined this request (stop_reason=refusal)")
        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            raise LLMError("model response did not match the verdict schema")
        usage = getattr(response, "usage", None)
        return LLMResult(
            verdict=parsed,
            model=response.model,
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
        )

    def agent_step(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AgentStep:
        import anthropic

        client = self._get_client()
        anthropic_tools = [
            {"name": t["name"], "description": t["description"],
             "input_schema": t["parameters"] if "parameters" in t else t["input_schema"]}
            for t in tools
        ]
        try:
            response = client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_output_tokens,
                system=system,
                messages=_neutral_to_anthropic(messages),
                tools=anthropic_tools,
            )
        except anthropic.AuthenticationError as exc:
            raise LLMError(
                "authentication failed — set ANTHROPIC_API_KEY (or run with --no-llm)"
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError(f"cannot reach the LLM API: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"LLM API error {exc.status_code}: {exc.message}") from exc

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(id=block.id, name=block.name, arguments=dict(block.input))
                )
        assistant_msg: dict[str, Any] = {"role": "assistant", "content": " ".join(text_parts)}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        return AgentStep(
            tool_calls=tool_calls, text=" ".join(text_parts),
            messages=[*messages, assistant_msg],
        )


def _neutral_to_anthropic(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pending_results: list[dict[str, Any]] = []

    def flush_results() -> None:
        nonlocal pending_results
        if pending_results:
            out.append({"role": "user", "content": pending_results})
            pending_results = []

    for msg in messages:
        role = msg["role"]
        if role == "tool":
            pending_results.append(
                {"type": "tool_result", "tool_use_id": msg["tool_call_id"],
                 "content": msg["content"]}
            )
            continue
        flush_results()
        if role == "user":
            out.append({"role": "user", "content": [{"type": "text", "text": msg["content"]}]})
        elif role == "assistant":
            blocks: list[dict[str, Any]] = []
            if msg.get("content"):
                blocks.append({"type": "text", "text": msg["content"]})
            for tc in msg.get("tool_calls", []):
                blocks.append(
                    {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments}
                )
            out.append({"role": "assistant", "content": blocks})
    flush_results()
    return out


class OpenAILLMClient:
    """OpenAI Chat Completions client (works with self-hosted compatible APIs).

    ``transport`` is injectable for tests.
    """

    def __init__(self, config: LLMConfig, transport: httpx.BaseTransport | None = None) -> None:
        self.config = config
        api_key = config.openai_api_key or os.environ.get("OPENAI_API_KEY", "")
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.Client(
            base_url=config.openai_base_url.rstrip("/"),
            headers=headers,
            timeout=config.request_timeout_s,
            transport=transport,
        )

    def generate_verdict(self, system: str, user: str) -> LLMResult:
        schema = LLMVerdict.model_json_schema()
        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_completion_tokens": self.config.max_output_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "ops_verdict", "schema": schema},
            },
        }
        data = self._post_with_compat(payload)

        try:
            choice = data["choices"][0]["message"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"malformed Chat Completions response: {exc}") from exc
        if choice.get("refusal"):
            raise LLMError(f"the model declined this request: {choice['refusal'][:200]}")
        content = choice.get("content") or ""
        try:
            verdict = LLMVerdict.model_validate(json.loads(_strip_code_fences(content)))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise LLMError(f"model response did not match the verdict schema: {exc}") from exc

        usage = data.get("usage") or {}
        return LLMResult(
            verdict=verdict,
            model=data.get("model", self.config.model),
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )

    def agent_step(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AgentStep:
        wire_messages = [{"role": "system", "content": system}]
        wire_messages.extend(_neutral_to_openai(messages))
        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_completion_tokens": self.config.max_output_tokens,
            "messages": wire_messages,
            "tools": tools,
        }
        data = self._post_with_compat(payload)
        try:
            choice = data["choices"][0]["message"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"malformed Chat Completions response: {exc}") from exc

        text = choice.get("content") or ""
        tool_calls: list[ToolCall] = []
        for raw in choice.get("tool_calls") or []:
            fn = raw.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(id=raw["id"], name=fn.get("name", ""), arguments=args))

        assistant_msg: dict[str, Any] = {"role": "assistant", "content": text}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        return AgentStep(
            tool_calls=tool_calls, text=text, messages=[*messages, assistant_msg]
        )

    def _post_with_compat(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST /chat/completions, degrading gracefully for older
        OpenAI-compatible servers that reject newer parameters."""
        for _ in range(3):
            try:
                resp = self._client.post("/chat/completions", json=payload)
            except httpx.HTTPError as exc:
                raise LLMError(f"cannot reach the LLM API: {exc}") from exc
            if resp.status_code == 400:
                text = resp.text
                # Older servers: max_completion_tokens -> max_tokens.
                if "max_completion_tokens" in text and "max_completion_tokens" in payload:
                    payload["max_tokens"] = payload.pop("max_completion_tokens")
                    continue
                # Servers without structured-output support: drop the schema
                # (the system prompt still demands JSON; we validate ourselves).
                if "response_format" in text and "response_format" in payload:
                    payload.pop("response_format")
                    continue
            if resp.status_code == 401:
                raise LLMError(
                    "authentication failed — set OPENAI_API_KEY / "
                    "AI_OPS_LLM_OPENAI_API_KEY (or run with --no-llm)"
                )
            if resp.status_code >= 400:
                raise LLMError(f"LLM API error {resp.status_code}: {resp.text[:200]}")
            return resp.json()
        raise LLMError("LLM API rejected the request after compatibility retries")


def _neutral_to_openai(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages:
        role = msg["role"]
        if role == "tool":
            out.append(
                {"role": "tool", "tool_call_id": msg["tool_call_id"], "content": msg["content"]}
            )
        elif role == "assistant":
            entry: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or None}
            if msg.get("tool_calls"):
                entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in msg["tool_calls"]
                ]
            out.append(entry)
        else:
            out.append({"role": "user", "content": msg["content"]})
    return out


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _strip_code_fences(text: str) -> str:
    return _FENCE_RE.sub("", text.strip()).strip()


def make_client(config: LLMConfig) -> LLMClient:
    if config.provider == "anthropic":
        return AnthropicLLMClient(config)
    if config.provider == "openai":
        return OpenAILLMClient(config)
    raise LLMError(f"unknown LLM provider {config.provider!r}; use 'anthropic' or 'openai'")
