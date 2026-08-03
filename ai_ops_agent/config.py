"""Application configuration.

Precedence: environment variables (``AI_OPS_`` prefix) > YAML file passed via
``load_config(path)`` > defaults. Validated at startup; fail fast on bad values.
"""

from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_LLM_", extra="ignore")

    # Strong model drives the reasoning/report loop; the fast model is reserved
    # for cheap classification tasks (dedupe summaries, clustering hints).
    model: str = "claude-opus-5"
    fast_model: str = "claude-haiku-4-5"
    max_output_tokens: int = 16000
    # Budget for the compact context we hand to the model (characters, not tokens —
    # deterministic and cheap to enforce while streaming).
    max_context_chars: int = 60_000
    request_timeout_s: float = 120.0


class AnalyzeConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_ANALYZE_", extra="ignore")

    # Top-N templates shown to the model / in reports.
    top_templates: int = 40
    # A template whose first occurrence falls in the final fraction of the file
    # counts as "emerging".
    emerging_tail_fraction: float = 0.2
    # Silent periods longer than this (seconds) are reported as logging gaps.
    gap_threshold_s: float = 300.0
    max_timeline_buckets: int = 500


class WatchConfig(BaseSettings):
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


class MattermostConfig(BaseSettings):
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


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AI_OPS_", extra="ignore")

    redact: bool = True
    redact_ips: bool = False
    llm: LLMConfig = Field(default_factory=LLMConfig)
    analyze: AnalyzeConfig = Field(default_factory=AnalyzeConfig)
    watch: WatchConfig = Field(default_factory=WatchConfig)
    mattermost: MattermostConfig = Field(default_factory=MattermostConfig)


def load_config(yaml_path: str | Path | None = None) -> AppConfig:
    """Build config from defaults, optional YAML overlay, then env vars.

    Env vars win because pydantic-settings applies them on top of the init
    kwargs we pass from YAML.
    """
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
    )
