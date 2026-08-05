"""Application configuration.

Precedence: process environment variables > ``.env`` file in the working
directory (or any parent) > YAML file passed via ``load_config(path)`` >
defaults. Validated at startup; fail fast on bad values.

The ``.env`` file is loaded into the process environment, so it covers both
the ``AI_OPS_*`` settings and the provider keys read directly from the
environment (``ANTHROPIC_API_KEY``, ``OPENAI_API_KEY``).
"""

from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]
from dotenv import find_dotenv, load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict


class EnvFirstSettings(BaseSettings):
    """Base for all config sections: environment variables outrank the init
    kwargs we pass from the YAML overlay (pydantic's default is the reverse)."""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (env_settings, dotenv_settings, init_settings, file_secret_settings)


class LLMConfig(EnvFirstSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_LLM_", extra="ignore")

    # "anthropic" (default) or "openai". The openai provider speaks the
    # Chat Completions API, so it also covers self-hosted OpenAI-compatible
    # servers (vLLM, Ollama, LiteLLM) via ``openai_base_url``.
    provider: str = "anthropic"
    # Strong model drives the reasoning/report loop; the fast model is reserved
    # for cheap classification tasks (dedupe summaries, clustering hints).
    model: str = "claude-opus-5"
    fast_model: str = "claude-haiku-4-5"
    # OpenAI-provider settings. The key falls back to the standard
    # OPENAI_API_KEY env var; self-hosted endpoints may not need one.
    openai_base_url: str = "https://api.openai.com/v1"
    openai_api_key: str | None = None
    max_output_tokens: int = 16000
    # Budget for the compact context we hand to the model (characters, not tokens —
    # deterministic and cheap to enforce while streaming).
    max_context_chars: int = 60_000
    request_timeout_s: float = 120.0


class AnalyzeConfig(EnvFirstSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_ANALYZE_", extra="ignore")

    # Top-N templates shown to the model / in reports.
    top_templates: int = 40
    # A template whose first occurrence falls in the final fraction of the file
    # counts as "emerging".
    emerging_tail_fraction: float = 0.2
    # Silent periods longer than this (seconds) are reported as logging gaps.
    gap_threshold_s: float = 300.0
    max_timeline_buckets: int = 500


class WatchConfig(EnvFirstSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_WATCH_", extra="ignore")

    window_seconds: float = 60.0
    window_max_lines: int = 500
    baseline_seconds: float = 300.0
    # Escalate when window error rate exceeds baseline error rate by this factor.
    error_rate_factor: float = 3.0
    # Minimum absolute error rate (errors/line) before the factor trigger can fire,
    # so a baseline of ~0 doesn't make a single error a page.
    min_error_rate: float = 0.05
    cooldown_seconds: float = 120.0
    max_alerts_per_hour: int = 10


class MattermostConfig(EnvFirstSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_MATTERMOST_", extra="ignore")

    # Bot account + Personal Access Token (preferred: enables threading, message
    # updates, and file uploads). ``webhook_url`` is a reduced-feature fallback.
    url: str | None = None  # e.g. https://mattermost.example.com
    token: str | None = None
    team: str | None = None
    webhook_url: str | None = None

    default_channel: str = "ops-alerts"
    # Routing per spec §8; unset values fall back to default_channel.
    alerts_channel: str | None = None  # sev1/sev2
    noise_channel: str | None = None  # false_positive / noisy_rule
    mention_sev1: str = "@here"

    # Mattermost caps messages at 4000 chars; leave headroom for mentions.
    max_message_chars: int = 3800
    max_retries: int = 3
    backoff_base_s: float = 1.0
    request_timeout_s: float = 15.0
    # Failed posts persist here so a Mattermost outage doesn't lose an incident.
    queue_path: str = "~/.ai-ops/mattermost-queue.jsonl"

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url or (self.url and self.token))


class MetricsConfig(EnvFirstSettings):
    """VictoriaMetrics access — HTTP API with a dedicated read-only account."""

    model_config = SettingsConfigDict(env_prefix="AI_OPS_METRICS_", extra="ignore")

    url: str | None = None  # vmselect base, e.g. http://vmselect:8481/select/0/prometheus
    bearer_token: str | None = None
    username: str | None = None
    password: str | None = None
    request_timeout_s: float = 15.0
    # Hard limits per spec §6: cap step count and series returned.
    max_range_steps: int = 500
    max_series: int = 50
    max_result_chars: int = 8_000

    @property
    def configured(self) -> bool:
        return bool(self.url)


class K8sConfig(EnvFirstSettings):
    """Kubernetes access — REST API with a dedicated ServiceAccount token.

    In-cluster the defaults pick up the mounted ServiceAccount; out of
    cluster set api_url + token (or token_path) explicitly.
    """

    model_config = SettingsConfigDict(env_prefix="AI_OPS_K8S_", extra="ignore")

    api_url: str | None = None  # e.g. https://kubernetes.default.svc
    token: str | None = None
    token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_cert_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    verify_tls: bool = True
    # Namespace allowlist (empty = deny all; explicit opt-in per spec §6).
    namespaces: list[str] = Field(default_factory=list)
    request_timeout_s: float = 15.0
    max_log_lines: int = 200
    max_log_bytes: int = 64_000
    max_result_chars: int = 8_000
    events_window_minutes: int = 30

    @property
    def configured(self) -> bool:
        return bool(self.api_url)


class ServerConfig(EnvFirstSettings):
    """Webhook API server + alert gating."""

    model_config = SettingsConfigDict(env_prefix="AI_OPS_SERVER_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8080
    # Shared secret required in the X-AIOps-Token header on webhook posts.
    webhook_secret: str | None = None
    db_path: str = "~/.ai-ops/aiops.db"
    # Gate-before-spending-tokens knobs (spec §4.3).
    cooldown_minutes: int = 30
    flap_transitions: int = 4
    flap_window_minutes: int = 10
    group_window_seconds: float = 60.0


class AppConfig(EnvFirstSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_", extra="ignore")

    redact: bool = True
    redact_ips: bool = False
    llm: LLMConfig = Field(default_factory=LLMConfig)
    analyze: AnalyzeConfig = Field(default_factory=AnalyzeConfig)
    watch: WatchConfig = Field(default_factory=WatchConfig)
    mattermost: MattermostConfig = Field(default_factory=MattermostConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    k8s: K8sConfig = Field(default_factory=K8sConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)


def load_config(
    yaml_path: str | Path | None = None, env_file: str | Path | None = None
) -> AppConfig:
    """Build config from defaults, optional YAML overlay, ``.env``, then env vars.

    Env vars win because pydantic-settings applies them on top of the init
    kwargs we pass from YAML. ``.env`` values are loaded into the process
    environment but never override variables that are already set, so real
    environment variables keep the highest precedence.
    """
    if env_file is not None:
        load_dotenv(env_file, override=False)
    else:
        # Searches the working directory and its parents for a .env file.
        load_dotenv(find_dotenv(usecwd=True), override=False)
    data: dict = {}
    if yaml_path is not None:
        raw = yaml.safe_load(Path(yaml_path).read_text()) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"config file {yaml_path} must contain a mapping")
        data = raw
    top = {k: v for k, v in data.items() if k in ("redact", "redact_ips")}
    return AppConfig(
        **top,
        llm=LLMConfig(**data.get("llm", {})),
        analyze=AnalyzeConfig(**data.get("analyze", {})),
        watch=WatchConfig(**data.get("watch", {})),
        mattermost=MattermostConfig(**data.get("mattermost", {})),
        metrics=MetricsConfig(**data.get("metrics", {})),
        k8s=K8sConfig(**data.get("k8s", {})),
        server=ServerConfig(**data.get("server", {})),
    )
