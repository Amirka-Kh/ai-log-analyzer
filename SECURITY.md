# Security model (Phase 1–2 scope)

## What the agent can and cannot do

- **Read-only by design.** The engine parses and summarizes logs. It executes
  no remediation, and the LLM is never given a tool that can run commands,
  touch files, or reach the network. In CLI mode the model receives a single
  text summary and returns a structured verdict — nothing else.
- **Command execution is operator-only.** `analyze --source "cmd ..."` and
  `watch "cmd ..."` run exactly the command the human typed, parsed with
  `shlex`, executed without a shell, as the invoking user. Be aware that
  `ai-ops watch` executes what you give it. The model cannot choose or
  influence the watched command.

## Untrusted log content

Log lines and alert annotations are untrusted input. Defenses:

1. All log-derived content sent to the model is wrapped in
   `<untrusted-log-data>` delimiters with a standing instruction that content
   inside is data, never instructions.
2. The model's output is a structured verdict validated in code: every
   evidence excerpt must appear verbatim in the supplied context. Failing
   output is retried once, then discarded in favor of deterministic output.
3. The model has no tools, so a successful injection can at worst skew the
   verdict text — it cannot cause any action.

`tests/fixtures/logs/prompt_injection.log` and the accompanying tests keep
this behavior pinned.

## Secret handling

- Credentials come from the environment (`ANTHROPIC_API_KEY`); they are never
  logged, never included in prompts, never written to reports.
- A redaction pipeline runs over every excerpt, exemplar, and context blob
  before it reaches the LLM or a rendered report: JWTs, bearer tokens,
  `password=`/`token=`/`secret=` values, AWS access keys, private key blocks,
  connection-string credentials, emails, and (opt-in) IP addresses.
  Redaction is **on by default**; `--no-redact` is an explicit operator
  choice for perimeter-safe environments.
- If external LLM APIs are disallowed entirely, run with `--no-llm` (fully
  local, deterministic) until the self-hosted provider backend lands.

## Reactive alert path (Phase 4)

- **Webhook authentication.** `/webhook/alertmanager`, `/webhook/grafana`, and
  `/investigate` require a shared secret in the `X-AIOps-Token` header
  (constant-time compared). Auth is only skipped when
  `AI_OPS_SERVER_WEBHOOK_SECRET` is unset, which logs a loud dev-only warning.
- **Read-only cluster access via dedicated API accounts.** Kubernetes is
  reached over its REST API with a dedicated ServiceAccount token (no `kubectl`
  subprocess); only `get`/`list` verbs are used, and a client-side namespace
  allowlist is enforced on top of whatever the SA's RBAC grants. VictoriaMetrics
  is reached over the vmselect HTTP API with a dedicated account; write/admin
  endpoints are refused. Give both accounts least privilege — the agent can only
  do what their tokens allow.
- **The LLM has no write tools.** The agent diagnoses; every tool is read-only,
  budget-bounded (12 calls / 90s), truncated, redacted, and audit-logged. There
  is no remediation path in v1.
- **Untrusted alert + tool content.** Alert annotations, log lines, and tool
  results are wrapped in `<untrusted-data>` delimiters with a standing
  instruction that content inside is data, never instructions. The verdict is
  validated in code (every evidence excerpt must appear verbatim in the
  gathered evidence) with a retry then a `needs_human` degrade.
- **Recommended RBAC (ClusterRole for the agent's ServiceAccount):**

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: ai-ops-agent-readonly
  rules:
    - apiGroups: [""]
      resources: [pods, pods/log, services, nodes, events]
      verbs: [get, list, watch]
    - apiGroups: ["apps"]
      resources: [deployments, statefulsets, daemonsets, replicasets]
      verbs: [get, list, watch]
  ```

## Later phases

The SSH diagnostic tool (allowlisted command templates, key-only low-privilege
user, `command=` restrictions) ships with Phase 6 and will be documented here.
