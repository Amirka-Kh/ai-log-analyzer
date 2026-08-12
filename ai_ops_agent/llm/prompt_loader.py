"""Load versioned prompt files shipped with the package."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources

_VERSION_RE = re.compile(r"<!--\s*prompt_version:\s*(\S+)\s*-->")


@dataclass(frozen=True)
class Prompt:
    name: str
    version: str
    text: str


def load_prompt(name: str) -> Prompt:
    ref = resources.files("ai_ops_agent.llm") / "prompts" / f"{name}.md"
    raw = ref.read_text()
    m = _VERSION_RE.search(raw)
    version = m.group(1) if m else "unversioned"
    text = _VERSION_RE.sub("", raw).strip()
    return Prompt(name=name, version=version, text=text)
