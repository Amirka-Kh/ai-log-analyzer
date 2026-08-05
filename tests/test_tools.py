from __future__ import annotations

import httpx
import pytest

from ai_ops_agent.config import K8sConfig, MetricsConfig
from ai_ops_agent.core.redaction import Redactor
from ai_ops_agent.tools.base import ToolError, ToolSpec
from ai_ops_agent.tools.kubernetes import K8sClient, build_k8s_tools
from ai_ops_agent.tools.metrics import MetricsClient, build_metrics_tools

# --- ToolSpec envelope ------------------------------------------------------


def test_toolspec_truncates_and_redacts():
    spec = ToolSpec(
        name="t", description="d", schema={"type": "object", "properties": {}},
        func=lambda: "password=hunter2 " + "x" * 100,
        max_result_chars=40, redactor=Redactor(),
    )
    result = spec.run()
    assert result.ok
    assert result.truncated
    assert "hunter2" not in result.data
    assert len(result.data) <= 40


def test_toolspec_error_envelope():
    def boom():
        raise ToolError("bad input")

    spec = ToolSpec(name="t", description="d", schema={}, func=boom)
    result = spec.run()
    assert not result.ok
    assert "bad input" in result.error
    assert "[tool error]" in result.to_model_text()


def test_toolspec_unexpected_exception_caught():
    spec = ToolSpec(name="t", description="d", schema={}, func=lambda: 1 / 0)
    result = spec.run()
    assert not result.ok
    assert "ZeroDivisionError" in result.error


# --- Metrics (VictoriaMetrics HTTP API) -------------------------------------


class FakeVM:
    def __init__(self):
        self.paths: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if request.url.path.endswith("/query"):
            return httpx.Response(200, json={
                "status": "success",
                "data": {"resultType": "vector", "result": [
                    {"metric": {"__name__": "up", "job": "api"}, "value": [123, "1"]},
                ]},
            })
        if request.url.path.endswith("/query_range"):
            return httpx.Response(200, json={
                "status": "success",
                "data": {"resultType": "matrix", "result": [
                    {"metric": {"__name__": "mem"}, "values": [[1, "10"], [2, "20"], [3, "30"]]},
                ]},
            })
        if request.url.path.endswith("/series"):
            return httpx.Response(200, json={
                "status": "success", "data": [{"__name__": "up", "job": "api"}]})
        return httpx.Response(404)


def metrics_client(fake: FakeVM) -> MetricsClient:
    config = MetricsConfig(url="http://vm.test/select/0/prometheus", bearer_token="tok")
    return MetricsClient(config, transport=httpx.MockTransport(fake.handler))


def test_metrics_instant_query():
    fake = FakeVM()
    out = metrics_client(fake).instant_query("up")
    assert "up" in out and "= 1" in out


def test_metrics_range_query():
    fake = FakeVM()
    out = metrics_client(fake).range_query("mem", minutes=60, step="60s")
    assert "first=10" in out and "last=30" in out and "points=3" in out


def test_metrics_bearer_header_sent():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("Authorization")
        return FakeVM().handler(request)

    config = MetricsConfig(url="http://vm.test", bearer_token="secret-tok")
    MetricsClient(config, transport=httpx.MockTransport(handler)).instant_query("up")
    assert captured["auth"] == "Bearer secret-tok"


def test_metrics_tools_absent_when_unconfigured():
    assert build_metrics_tools(MetricsConfig()) == []


def test_metrics_query_error_surfaces():
    def handler(request):
        return httpx.Response(200, json={"status": "error", "error": "bad query"})

    config = MetricsConfig(url="http://vm.test")
    client = MetricsClient(config, transport=httpx.MockTransport(handler))
    with pytest.raises(ToolError, match="bad query"):
        client.instant_query("???")


# --- Kubernetes (REST API with SA token) ------------------------------------


class FakeK8s:
    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/pods/api-xk2"):
            return httpx.Response(200, json={
                "metadata": {"name": "api-xk2", "namespace": "prod"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{
                        "name": "api", "ready": False, "restartCount": 7,
                        "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                    }],
                },
            })
        if path.endswith("/events"):
            return httpx.Response(200, json={"items": [{
                "type": "Warning", "reason": "BackOff", "message": "Back-off restarting",
                "involvedObject": {"kind": "Pod", "name": "api-xk2"},
                "lastTimestamp": "2026-08-01T10:00:00Z",
            }]})
        if path.endswith("/log"):
            return httpx.Response(200, text="panic: runtime error\nsecret token=abc123def456\n")
        return httpx.Response(404, text="nope")


def k8s_client(namespaces=None) -> K8sClient:
    config = K8sConfig(
        api_url="https://k8s.test", token="sa-token", verify_tls=False,
        namespaces=namespaces or ["prod"],
    )
    return K8sClient(config, transport=httpx.MockTransport(FakeK8s().handler))


def test_k8s_get_pod_summary():
    out = k8s_client().get_resource("pods", "api-xk2", "prod")
    assert "CrashLoopBackOff" in out
    assert "restarts=7" in out


def test_k8s_namespace_allowlist_enforced():
    with pytest.raises(ToolError, match="allowlist"):
        k8s_client(namespaces=["prod"]).get_resource("pods", "api-xk2", "kube-system")


def test_k8s_unsupported_kind():
    with pytest.raises(ToolError, match="unsupported kind"):
        k8s_client().get_resource("secrets", "db-creds", "prod")


def test_k8s_logs_redacted_via_tool():
    tools = build_k8s_tools(
        K8sConfig(api_url="https://k8s.test", token="t", verify_tls=False, namespaces=["prod"]),
        redactor=Redactor(),
        client=k8s_client(),
    )
    logs_tool = next(t for t in tools if t.name == "k8s_logs")
    result = logs_tool.run(pod="api-xk2", namespace="prod")
    assert result.ok
    assert "panic" in result.data
    assert "abc123def456" not in result.data  # token redacted


def test_k8s_tools_absent_when_unconfigured():
    assert build_k8s_tools(K8sConfig()) == []


def test_k8s_sa_token_header():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("Authorization")
        return FakeK8s().handler(request)

    config = K8sConfig(api_url="https://k8s.test", token="sa-abc", verify_tls=False,
                       namespaces=["prod"])
    K8sClient(config, transport=httpx.MockTransport(handler)).get_resource(
        "pods", "api-xk2", "prod")
    assert captured["auth"] == "Bearer sa-abc"
