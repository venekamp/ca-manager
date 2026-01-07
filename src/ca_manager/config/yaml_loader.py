from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml


def load_yaml_config(path: Path) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as f:
            raw: object = yaml.safe_load(stream=f)  # pyright: ignore[reportAny]
    except yaml.MarkedYAMLError as e:
        mark: yaml.Mark | None = e.problem_mark
        if mark is None:
            raise ValueError(f"Invalid YAML in {path}")
        raise ValueError(f"{e.problem}\nSee line: {mark.line + 1}, column: {mark.column + 1}")

    if raw is None:
        return {}

    if not isinstance(raw, dict):
        raise ValueError("Top-level YAML document is expected to be a mapping.")

    for key in raw.keys():  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(key, str):
            raise ValueError(f"Invalid configuration: top-level key {key!r} is not a string.")

    return cast(dict[str, object], raw)
