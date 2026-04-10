from __future__ import annotations

import os
from pathlib import Path

import typer

from ca_manager.config.root_parser import parse_settings_root
from ca_manager.config.yaml_loader import load_yaml_config

from .settings import Settings

DEFAULT_CONFIG_PATH: Path = Path("/etc/ca-manager/config.yaml")


def get_config_path() -> Path:
    """Get config path from $CA_MANAGER_CONFIG or use default."""
    env_path: str | None = os.environ.get("CA_MANAGER_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_PATH


def load_settings(config_path: Path | None = None, base_path: Path | None = None) -> Settings:
    if config_path is None:
        config_path = get_config_path()
    if not config_path.exists():
        if base_path is not None:
            return Settings(base_path=base_path)

        return Settings()

    try:
        raw_yaml: dict[str, object] = load_yaml_config(path=config_path)
        return parse_settings_root(raw_yaml, base_path)
    except ValueError as e:
        typer.echo(message=str(e), err=True)
        raise typer.Exit(code=1)
