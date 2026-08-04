# `ai-ops` CLI reference

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean — no findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` severity (default `sev2`) |
| 2 | Tool or configuration error (bad source, bad flag, unreadable file) |

This makes `ai-ops analyze --no-llm --fail-on sev2` usable as a CI gate.

## `ai-ops analyze`

One-shot analysis of a finite source.

```bash
ai-ops analyze --source app.log
ai-ops analyze --source app.log --since 2h --focus errors
ai-ops analyze --source "docker logs --tail 5000 my-api"
ai-ops analyze --source - < /var/log/syslog
ai-ops analyze --source journalctl:nginx --since 1h
ai-ops analyze --source "/var/log/app/*.log" --no-llm --output json
cat app.log | ai-ops analyze            # implicit stdin when piped
```

### Sources

| Form | Behavior |
|---|---|
| `path/to/file.log` | Streamed line by line; `.gz` decompressed transparently |
| `"glob/*.log"` | All matching files, in sorted order |
| `-` (or piped stdin) | Read stdin |
| `journalctl:<unit>` | Runs `journalctl -u <unit> -o short-iso` (honors `--since`) |
| `"command with args"` | Spawned via shlex + exec (**never** `shell=True`), stdout+stderr read to completion |

`analyze`/`watch` execute the command **you** give them, as your user. The
model can never choose or influence the command — no process-spawning tool is
exposed to the LLM.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--source, -s` | stdin if piped | Source (see table above) |
| `--since` | — | Only records newer than `30m` / `2h` / `1d` (needs parseable timestamps) |
| `--focus` | — | Free-text hint passed to the model |
| `--output, -o` | `text` | `text` (rich terminal), `json`, `markdown` |
| `--no-llm` | off | Deterministic collectors only; no API key needed; deterministic output for CI |
| `--redact/--no-redact` | on | Redact secrets/PII before anything reaches the LLM or a report |
| `--fail-on` | `sev2` | Threshold for exit code 1 (`sev1`\|`sev2`\|`sev3`\|`info`) |
| `--model` | config | Override the LLM model id |
| `--provider` | `anthropic` | `anthropic` \| `openai` — the openai provider also covers self-hosted OpenAI-compatible endpoints (vLLM, Ollama, LiteLLM) via `AI_OPS_LLM_OPENAI_BASE_URL` |
| `--format` | auto | Force input format: `json`\|`logfmt`\|`access`\|`syslog`\|`plain` |
| `--config` | — | YAML config file |
| `--notify` | `none` | `none` \| `mattermost` — post the report card (+ full markdown attachment) after analysis |
| `--channel` | routed | Mattermost channel override; default follows severity/verdict routing |
| `--verbose, -v` | off | Show per-finding evidence excerpts |

Notification delivery never changes the exit code: undeliverable messages are
persisted to the retry queue and logged to stderr.

### Supported input formats (auto-detected)

JSON lines, logfmt, nginx/apache combined access logs, syslog, and plain text
with best-effort timestamp/level extraction. Java and Python stack traces are
folded into the record that started them. Detection samples the first 100
lines; force with `--format`.

## `ai-ops watch`

Continuous watch of a live stream. Learns what "normal" looks like during the
baseline period (emitting nothing), then escalates only when a deterministic
trigger fires:

- a never-seen-before **error** template appears;
- window error rate exceeds baseline by `error_rate_factor` (default 3×);
- a fatal/panic/OOM/stack-trace marker appears;
- a security-signal pattern matches (path scans, SQLi payloads, SSH failures);
- the watched process exits non-zero.

A global cooldown plus `--max-alerts-per-hour` guarantee a crash loop produces
one escalating notification, not a hundred. A session summary always prints on
exit — including Ctrl-C.

```bash
ai-ops watch "docker logs -f my-api"
ai-ops watch "kubectl logs -f deploy/api -n prod" --window 60
ai-ops watch --source /var/log/app.log --baseline 120
ai-ops watch "docker logs -f api" --restart --quiet
```

| Flag | Default | Description |
|---|---|---|
| `COMMAND` | — | Command to spawn and follow (mutually optional with `--source`) |
| `--source` | — | File to follow instead (tail -F semantics) |
| `--window` | `60` | Window size in seconds |
| `--window-lines` | `500` | Max lines per window (whichever fills first) |
| `--baseline` | `300` | Baseline learning period in seconds |
| `--cooldown` | `120` | Suppress repeat alerts with the same reasons within this period |
| `--max-alerts-per-hour` | `10` | Global rate limit |
| `--restart` | off | Respawn the command if it exits |
| `--llm/--no-llm` | `--no-llm` | Explain escalations with the LLM (triggering window + baseline + prior findings) |
| `--quiet, -q` | off | Suppress the periodic status line |
| `--format` | auto | Force input format |
| `--notify` | `none` | `none` \| `mattermost` — first finding becomes the root post, subsequent findings and the session summary thread under it |
| `--channel` | routed | Mattermost channel override |

## `ai-ops version`

Print the version.
