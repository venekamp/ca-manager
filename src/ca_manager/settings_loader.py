from __future__ import annotations

from pathlib import Path

import typer

from ca_manager.config.root_parser import parse_settings_root
from ca_manager.config.yaml_loader import load_yaml_root
from .settings import Settings

# Use your existing CONFIG_PATH constant.
CONFIG_PATH: Path = Path("/etc/ca-manager/config.yaml")


def load_settings(path: Path = CONFIG_PATH) -> Settings:
    if not path.exists():
        return Settings()

    try:
        raw_yaml: dict[str, object] = load_yaml_root(path)
        return parse_settings_root(raw_yaml)
    except ValueError as e:
        typer.echo(message=str(e), err=True)
        raise typer.Exit(code=1)
