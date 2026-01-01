from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Protocol, cast

type ValueParser = Callable[[object, str], object]


class RootSectionSpec(Protocol):
    """
    Non-generic interface used at the root level.
    """

    @property
    def name(self) -> str: ...

    def parse(self, raw: object) -> object: ...


@dataclass(frozen=True)
class SectionSpec[T]:
    """
    Defines how to parse a top-level section (or leaf) into a target type.

    - name: section name (for errors)
    - target: the constructor type (usually a dataclass)
    - field_parsers: mapping of allowed keys -> value parser
    - default_factory: builds default instance if section missing or null
    """

    name: str
    target: type[T]
    field_parsers: Mapping[str, ValueParser]
    default_factory: Callable[[], T]

    def parse(self, raw: object) -> T:
        # Missing section or explicit null -> defaults
        if raw is None:
            return self.default_factory()

        if not isinstance(raw, dict):
            raise ValueError(f"'{self.name}' must be a mapping")

        values: dict[str, object] = {}
        raw_map: dict[object, object] = cast(dict[object, object], raw)

        # Validate and parse each provided key
        for key, value in raw_map.items():
            if not isinstance(key, str):
                raise ValueError(f"{self.name} key {key!r} is not a string")

            parser: ValueParser | None = self.field_parsers.get(key)
            if parser is None:
                raise ValueError(f"Unknown {self.name} option: {key!r}")

            values[key] = parser(value, key)

        # Construct target. Defaults in the dataclass fill any missing keys.
        return self.target(**values)
