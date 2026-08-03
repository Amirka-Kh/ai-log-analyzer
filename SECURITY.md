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

## Later phases

The SSH diagnostic tool (allowlisted command templates, key-only low-privilege
user, `command=` restrictions), Kubernetes RBAC snippets, and webhook
authentication ship with their respective phases and will be documented here.
