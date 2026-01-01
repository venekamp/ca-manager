from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias, cast

from ca_manager.settings import Settings, SettingsKwargs
from .section_spec import RootSectionSpec
from .specs import ROOT_LEAF_PARSERS, ROOT_SECTION_SPECS

LeafDefaultFactory: TypeAlias = Callable[[], object]
LeafValueParser: TypeAlias = Callable[[object, str], object]

LeafSpec: TypeAlias = tuple[LeafDefaultFactory, LeafValueParser]


def parse_settings_root(raw_yaml: dict[str, object]) -> Settings:
    values: dict[str, object] = {}

    for key, raw_value in raw_yaml.items():
        # leaf?
        leaf: LeafSpec | None = ROOT_LEAF_PARSERS.get(key)
        if leaf is not None:
            default_factory, value_parser = leaf
            # allow null -> default
            if raw_value is None:
                values[key] = default_factory()
            else:
                values[key] = value_parser(raw_value, key)
            continue

        # section?
        spec: RootSectionSpec | None = ROOT_SECTION_SPECS.get(key)
        if spec is not None:
            values[key] = spec.parse(raw_value)
            continue

        # unknown top-level key
        raise ValueError(f"Unknown configuration option: {key!r}")

    # Any missing keys will be filled by Settings defaults (frozen dataclass)
    kwargs: SettingsKwargs = cast(SettingsKwargs, cast(object, values))
    return Settings(**kwargs)
