"""Kubernetes tools over the REST API with a dedicated ServiceAccount token
(spec §6). No kubectl subprocess.

Read verbs only (GET/list); a namespace allowlist is enforced client-side in
addition to whatever RBAC the ServiceAccount is granted. Log fetches are
tail-only and byte/line-capped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from ai_ops_agent.config import K8sConfig
from ai_ops_agent.tools.base import ToolError, ToolSpec

_ALLOWED_KINDS = {
    "pods": "/api/v1/namespaces/{ns}/pods/{name}",
    "deployments": "/apis/apps/v1/namespaces/{ns}/deployments/{name}",
    "statefulsets": "/apis/apps/v1/namespaces/{ns}/statefulsets/{name}",
    "daemonsets": "/apis/apps/v1/namespaces/{ns}/daemonsets/{name}",
    "replicasets": "/apis/apps/v1/namespaces/{ns}/replicasets/{name}",
    "services": "/api/v1/namespaces/{ns}/services/{name}",
    "nodes": "/api/v1/nodes/{name}",
}


class K8sClient:
    def __init__(self, config: K8sConfig, transport: httpx.BaseTransport | None = None) -> None:
        if not config.configured:
            raise ToolError("Kubernetes is not configured (AI_OPS_K8S_API_URL unset)")
        self.config = config
        token = config.token
        if not token and Path(config.token_path).exists():
            token = Path(config.token_path).read_text().strip()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        verify: Any = config.verify_tls
        if config.verify_tls and Path(config.ca_cert_path).exists():
            verify = config.ca_cert_path
        self._client = httpx.Client(
            base_url=config.api_url.rstrip("/"),  # type: ignore[union-attr]
            headers=headers,
            verify=verify,
            timeout=config.request_timeout_s,
            transport=transport,
        )

    def _check_ns(self, namespace: str | None) -> None:
        if namespace is None:
            return
        if self.config.namespaces and namespace not in self.config.namespaces:
            raise ToolError(
                f"namespace '{namespace}' is not in the allowlist "
                f"{self.config.namespaces}"
            )

    def _get(self, path: str, params: dict | None = None) -> dict:
        try:
            resp = self._client.get(path, params=params or {})
        except httpx.HTTPError as exc:
            raise ToolError(f"k8s request failed: {exc}") from exc
        if resp.status_code == 403:
            raise ToolError("k8s API forbade the request (RBAC) — read access only")
        if resp.status_code == 404:
            raise ToolError("resource not found")
        if resp.status_code >= 400:
            raise ToolError(f"k8s API {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def get_resource(self, kind: str, name: str, namespace: str | None = None) -> str:
        kind = kind.lower()
        if kind not in _ALLOWED_KINDS:
            raise ToolError(f"unsupported kind '{kind}'; allowed: {sorted(_ALLOWED_KINDS)}")
        if kind != "nodes":
            self._check_ns(namespace)
            if not namespace:
                raise ToolError(f"namespace is required for {kind}")
        path = _ALLOWED_KINDS[kind].format(ns=namespace, name=name)
        obj = self._get(path)
        return _summarize_object(kind, obj)

    def describe_events(self, namespace: str, since_minutes: int | None = None) -> str:
        self._check_ns(namespace)
        data = self._get(f"/api/v1/namespaces/{namespace}/events")
        items = data.get("items", [])
        lines = []
        for ev in items[-40:]:
            reason = ev.get("reason", "")
            etype = ev.get("type", "")
            msg = ev.get("message", "")
            obj = ev.get("involvedObject", {})
            ts = ev.get("lastTimestamp") or ev.get("eventTime", "")
            lines.append(f"{ts} [{etype}] {reason} {obj.get('kind')}/{obj.get('name')}: {msg}")
        return "\n".join(lines) if lines else "no recent events"

    def get_logs(
        self, pod: str, namespace: str, previous: bool = False,
        container: str | None = None, since_seconds: int | None = None,
    ) -> str:
        self._check_ns(namespace)
        params: dict[str, Any] = {
            "tailLines": self.config.max_log_lines,
            "limitBytes": self.config.max_log_bytes,
        }
        if previous:
            params["previous"] = "true"
        if container:
            params["container"] = container
        if since_seconds:
            params["sinceSeconds"] = since_seconds
        try:
            resp = self._client.get(
                f"/api/v1/namespaces/{namespace}/pods/{pod}/log", params=params
            )
        except httpx.HTTPError as exc:
            raise ToolError(f"k8s log request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise ToolError(f"k8s log API {resp.status_code}: {resp.text[:200]}")
        return resp.text or "(no log output)"


def _summarize_object(kind: str, obj: dict) -> str:
    """Compact the (huge) k8s object down to what matters for triage."""
    meta = obj.get("metadata", {})
    name = meta.get("name")
    lines = [f"{kind}/{name} (ns={meta.get('namespace', '-')})"]

    status = obj.get("status", {})
    if kind == "pods":
        lines.append(f"phase={status.get('phase')}")
        for cs in status.get("containerStatuses", []):
            state = cs.get("state", {})
            state_kind = next(iter(state), "unknown")
            detail = state.get(state_kind, {})
            restarts = cs.get("restartCount", 0)
            lines.append(
                f"container {cs.get('name')}: {state_kind} "
                f"reason={detail.get('reason', '')} restarts={restarts} ready={cs.get('ready')}"
            )
        for cond in status.get("conditions", []):
            if cond.get("status") != "True":
                lines.append(f"condition {cond.get('type')}={cond.get('status')} "
                             f"{cond.get('reason', '')}")
    elif kind in ("deployments", "statefulsets", "daemonsets", "replicasets"):
        spec = obj.get("spec", {})
        lines.append(
            f"replicas: desired={spec.get('replicas', status.get('desiredNumberScheduled'))} "
            f"ready={status.get('readyReplicas', status.get('numberReady', 0))} "
            f"available={status.get('availableReplicas', '-')}"
        )
        containers = spec.get("template", {}).get("spec", {}).get("containers", [])
        for c in containers:
            lines.append(f"image {c.get('name')}: {c.get('image')}")
        for cond in status.get("conditions", []):
            lines.append(f"condition {cond.get('type')}={cond.get('status')} "
                         f"{cond.get('reason', '')}")
    elif kind == "nodes":
        for cond in status.get("conditions", []):
            if cond.get("type") in ("Ready", "MemoryPressure", "DiskPressure", "PIDPressure"):
                lines.append(f"{cond.get('type')}={cond.get('status')}")
    else:
        lines.append(json.dumps(status)[:500])
    return "\n".join(lines)


def build_k8s_tools(config: K8sConfig, redactor: Any = None,
                    client: K8sClient | None = None) -> list[ToolSpec]:
    if not config.configured:
        return []
    kc = client or K8sClient(config)
    ns_hint = (
        f" Allowed namespaces: {config.namespaces}." if config.namespaces else ""
    )
    return [
        ToolSpec(
            name="k8s_get",
            description="Get and summarize a Kubernetes resource (read-only): pods, "
            "deployments, statefulsets, daemonsets, replicasets, services, nodes." + ns_hint,
            schema={
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": sorted(_ALLOWED_KINDS)},
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                },
                "required": ["kind", "name"],
                "additionalProperties": False,
            },
            func=lambda kind, name, namespace=None: kc.get_resource(kind, name, namespace),
            max_result_chars=config.max_result_chars,
            redactor=redactor,
        ),
        ToolSpec(
            name="k8s_events",
            description="List recent events for a namespace (warnings, scheduling, "
            "OOMKills, image pull failures).",
            schema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "since_minutes": {"type": "integer"},
                },
                "required": ["namespace"],
                "additionalProperties": False,
            },
            func=lambda namespace, since_minutes=None: kc.describe_events(namespace, since_minutes),
            max_result_chars=config.max_result_chars,
            redactor=redactor,
        ),
        ToolSpec(
            name="k8s_logs",
            description="Fetch tail container logs for a pod (tail-only, byte-capped). "
            "Set previous=true for the last terminated container (CrashLoopBackOff).",
            schema={
                "type": "object",
                "properties": {
                    "pod": {"type": "string"},
                    "namespace": {"type": "string"},
                    "container": {"type": "string"},
                    "previous": {"type": "boolean"},
                    "since_seconds": {"type": "integer"},
                },
                "required": ["pod", "namespace"],
                "additionalProperties": False,
            },
            func=lambda pod, namespace, container=None, previous=False, since_seconds=None: (
                kc.get_logs(pod, namespace, previous, container, since_seconds)
            ),
            max_result_chars=config.max_result_chars,
            redactor=redactor,
        ),
    ]
