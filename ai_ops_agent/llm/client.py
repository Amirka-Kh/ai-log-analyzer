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


class LLMClient(Protocol):
    def generate_verdict(self, system: str, user: str) -> LLMResult: ...


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


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _strip_code_fences(text: str) -> str:
    return _FENCE_RE.sub("", text.strip()).strip()


def make_client(config: LLMConfig) -> LLMClient:
    if config.provider == "anthropic":
        return AnthropicLLMClient(config)
    if config.provider == "openai":
        return OpenAILLMClient(config)
    raise LLMError(f"unknown LLM provider {config.provider!r}; use 'anthropic' or 'openai'")
