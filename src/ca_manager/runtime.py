from __future__ import annotations

from .settings import Settings
from .settings_loader import load_settings

_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings

    if _settings is None:
        _settings = load_settings()

    return _settings
