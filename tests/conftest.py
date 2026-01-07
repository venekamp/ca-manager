from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

import ca_manager.runtime as runtime
from ca_manager.settings import Settings


@pytest.fixture(autouse=True)
def reset_settings() -> Generator[None, None, None]:
    """Reset the global settings singleton before each test."""
    runtime._settings = None
    yield
    runtime._settings = None


@pytest.fixture
def ca_workspace(tmp_path: Path) -> Generator[Path, None, None]:
    """Provide a temporary workspace and configure settings to use it."""
    runtime._settings = Settings(base_path=tmp_path)
    yield tmp_path
