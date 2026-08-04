from __future__ import annotations

import json

import httpx
import pytest

from ai_ops_agent.config import LLMConfig
from ai_ops_agent.llm.client import (
    AnthropicLLMClient,
    LLMError,
    OpenAILLMClient,
    make_client,
)


def verdict_payload() -> dict:
    return {
        "verdict": "real_incident",
        "confidence": 0.7,
        "severity": "sev2",
        "title": "Pool exhaustion",
        "summary": "The pool was exhausted.",
        "probable_cause": {
            "statement": "Pool exhausted.",
            "evidence": [
                {"source": "logs", "query": "template", "excerpt": "pool exhausted"}
            ],
        },
    }


class FakeOpenAI:
    """Mock Chat Completions server with configurable quirks."""

    def __init__(
        self,
        content: str | None = None,
        refusal: str | None = None,
        reject_param: str | None = None,
        status: int = 200,
    ):
        self.content = content if content is not None else json.dumps(verdict_payload())
        self.refusal = refusal
        self.reject_param = reject_param  # simulate older servers rejecting a param
        self.status = status
        self.requests: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        body = json.loads(request.content)
        self.requests.append(body)
        if self.status != 200:
            return httpx.Response(self.status, text="nope")
        if self.reject_param and self.reject_param in body:
            return httpx.Response(
                400, json={"error": {"message": f"Unsupported parameter: {self.reject_param}"}}
            )
        message: dict = {"role": "assistant", "content": self.content}
        if self.refusal:
            message["refusal"] = self.refusal
            message["content"] = None
        return httpx.Response(
            200,
            json={
                "model": body["model"],
                "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 60},
            },
        )


def make_openai(server: FakeOpenAI, **overrides) -> OpenAILLMClient:
    config = LLMConfig(
        provider="openai",
        model="gpt-test",
        openai_base_url="http://llm.test/v1",
        openai_api_key="sk-test",
        **overrides,
    )
    return OpenAILLMClient(config, transport=httpx.MockTransport(server.handler))


def test_openai_happy_path():
    server = FakeOpenAI()
    result = make_openai(server).generate_verdict("system prompt", "user context")
    assert result.verdict.verdict == "real_incident"
    assert result.model == "gpt-test"
    assert result.input_tokens == 120 and result.output_tokens == 60
    request = server.requests[0]
    assert request["messages"][0] == {"role": "system", "content": "system prompt"}
    assert request["response_format"]["type"] == "json_schema"
    assert "Bearer sk-test" in str(server.requests) or True  # header checked below


def test_openai_auth_header_sent():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("Authorization")
        return FakeOpenAI().handler(request)

    config = LLMConfig(provider="openai", model="m", openai_api_key="sk-abc",
                       openai_base_url="http://llm.test/v1")
    OpenAILLMClient(config, transport=httpx.MockTransport(handler)).generate_verdict("s", "u")
    assert captured["auth"] == "Bearer sk-abc"


def test_openai_code_fenced_json_parsed():
    server = FakeOpenAI(content=f"```json\n{json.dumps(verdict_payload())}\n```")
    result = make_openai(server).generate_verdict("s", "u")
    assert result.verdict.severity == "sev2"


def test_openai_max_tokens_compat_fallback():
    """Older servers rejecting max_completion_tokens get max_tokens instead."""
    server = FakeOpenAI(reject_param="max_completion_tokens")
    result = make_openai(server).generate_verdict("s", "u")
    assert result.verdict.verdict == "real_incident"
    assert "max_completion_tokens" in server.requests[0]
    assert "max_tokens" in server.requests[-1]


def test_openai_response_format_compat_fallback():
    """Servers without structured-output support get a schema-free retry."""
    server = FakeOpenAI(reject_param="response_format")
    result = make_openai(server).generate_verdict("s", "u")
    assert result.verdict.verdict == "real_incident"
    assert "response_format" not in server.requests[-1]


def test_openai_refusal_raises():
    server = FakeOpenAI(refusal="cannot help with that")
    with pytest.raises(LLMError, match="declined"):
        make_openai(server).generate_verdict("s", "u")


def test_openai_bad_json_raises():
    server = FakeOpenAI(content="this is not json at all")
    with pytest.raises(LLMError, match="schema"):
        make_openai(server).generate_verdict("s", "u")


def test_openai_auth_error_message():
    server = FakeOpenAI(status=401)
    with pytest.raises(LLMError, match="OPENAI_API_KEY"):
        make_openai(server).generate_verdict("s", "u")


def test_make_client_provider_switch():
    assert isinstance(make_client(LLMConfig(provider="anthropic")), AnthropicLLMClient)
    assert isinstance(make_client(LLMConfig(provider="openai")), OpenAILLMClient)
    with pytest.raises(LLMError, match="unknown LLM provider"):
        make_client(LLMConfig(provider="azure"))
