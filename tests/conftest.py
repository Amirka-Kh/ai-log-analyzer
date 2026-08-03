from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "logs"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def read_fixture_lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text().splitlines(keepends=True)
