"""Provider-agnostic LLM client.

The Anthropic implementation uses ``client.messages.parse`` with the pydantic
verdict schema so responses are validated at the API layer. The interface is a
small protocol so a self-hosted / OpenAI-compatible backend can be added
without touching the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

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


def make_client(config: LLMConfig) -> LLMClient:
    return AnthropicLLMClient(config)
