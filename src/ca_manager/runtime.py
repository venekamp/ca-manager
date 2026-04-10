from __future__ import annotations

from pathlib import Path

from .settings import Settings
from .settings_loader import load_settings

_settings: Settings | None = None


def get_settings(base_path: Path | None = None) -> Settings:
    global _settings

    if _settings is None:
        _settings = load_settings(config_path=None, base_path=base_path)

    return _settings
