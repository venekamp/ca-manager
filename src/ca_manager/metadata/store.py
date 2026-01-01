from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import cast

from .model import IssuedCertificate


def _serialize(value: str | list[str] | bool | datetime) -> str | list[str] | bool | datetime:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def append_record(base_path: Path, record: IssuedCertificate) -> None:
    metadata_dir: Path = base_path / "metadata"
    metadata_dir.mkdir(exist_ok=True)

    index_file: Path = metadata_dir / "issued.jsonl"

    data: dict[str, str | list[str] | bool | datetime] = {
        key: _serialize(value=cast(str | list[str] | bool | datetime, value))
        for key, value in asdict(obj=record).items()  # pyright: ignore[reportAny]
    }

    with index_file.open("a", encoding="utf-8") as f:
        _ = f.write(json.dumps(obj=data, sort_keys=True))
        _ = f.write("\n")
