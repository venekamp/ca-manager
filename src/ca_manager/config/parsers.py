from pathlib import Path


def parse_positive_int(raw_data: object, name: str) -> int:
    if not isinstance(raw_data, int):
        raise ValueError(f"{name} needs to be a positive integer.")

    data: int = raw_data

    if data < 0:
        raise ValueError(f"{name} needs to be positive.")

    return data


def parse_path(raw: object, name: str) -> Path:
    if not isinstance(raw, str):
        raise ValueError(f"{name} must be a string path")
    return Path(raw)


def parse_string(raw: object, name: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"{name} must be a string")
    return raw
