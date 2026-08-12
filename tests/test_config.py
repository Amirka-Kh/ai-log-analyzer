from __future__ import annotations

import os

import pytest

from ai_ops_agent.config import load_config


@pytest.fixture(autouse=True)
def isolated_env():
    """Snapshot os.environ — load_dotenv writes directly to it, so restore
    everything after each test to keep the suite hermetic."""
    saved = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(saved)


def test_dotenv_file_loaded(tmp_path, monkeypatch):
    os.environ.pop("AI_OPS_LLM_MODEL", None)
    os.environ.pop("OPENAI_API_KEY", None)
    (tmp_path / ".env").write_text(
        "AI_OPS_LLM_MODEL=model-from-dotenv\nOPENAI_API_KEY=sk-from-dotenv\n"
    )
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.llm.model == "model-from-dotenv"
    # Provider keys land in the process env for the SDKs to pick up.
    assert os.environ["OPENAI_API_KEY"] == "sk-from-dotenv"


def test_real_env_wins_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("AI_OPS_LLM_MODEL=model-from-dotenv\n")
    monkeypatch.chdir(tmp_path)
    os.environ["AI_OPS_LLM_MODEL"] = "model-from-env"
    config = load_config()
    assert config.llm.model == "model-from-env"


def test_explicit_env_file(tmp_path):
    os.environ.pop("AI_OPS_LLM_MODEL", None)
    custom = tmp_path / "custom.env"
    custom.write_text("AI_OPS_LLM_MODEL=model-from-custom\n")
    config = load_config(env_file=custom)
    assert config.llm.model == "model-from-custom"


def test_yaml_overlay_below_env(tmp_path):
    os.environ.pop("AI_OPS_WATCH_BASELINE_SECONDS", None)
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("watch:\n  baseline_seconds: 42\n")
    config = load_config(yaml_file)
    assert config.watch.baseline_seconds == 42
    # Env vars outrank the YAML overlay (documented precedence).
    os.environ["AI_OPS_WATCH_BASELINE_SECONDS"] = "99"
    config = load_config(yaml_file)
    assert config.watch.baseline_seconds == 99


def test_dotenv_below_yaml_absent_env(tmp_path, monkeypatch):
    """Real env > .env; .env > defaults; YAML fills fields env didn't set."""
    os.environ.pop("AI_OPS_WATCH_BASELINE_SECONDS", None)
    os.environ.pop("AI_OPS_WATCH_COOLDOWN_SECONDS", None)
    (tmp_path / ".env").write_text("AI_OPS_WATCH_COOLDOWN_SECONDS=77\n")
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("watch:\n  baseline_seconds: 42\n")
    monkeypatch.chdir(tmp_path)
    config = load_config(yaml_file)
    assert config.watch.cooldown_seconds == 77  # from .env
    assert config.watch.baseline_seconds == 42  # from YAML
