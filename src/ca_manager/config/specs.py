from __future__ import annotations

from collections.abc import Callable, Mapping

from ca_manager.config.parsers import parse_path, parse_positive_int
from ca_manager.settings import ExpiryConfig, KeysConfig, Settings, ValidityConfig
from ca_manager.config.section_spec import RootSectionSpec, SectionSpec

# Section specs (section name + dataclass + per-field parsers + defaults)

VALIDITY_SPEC: SectionSpec[ValidityConfig] = SectionSpec(
    name="validity",
    target=ValidityConfig,
    field_parsers={
        "ca_days": parse_positive_int,
        "server_days": parse_positive_int,
        "client_days": parse_positive_int,
    },
    default_factory=ValidityConfig,
)

KEYS_SPEC: SectionSpec[KeysConfig] = SectionSpec(
    name="keys",
    target=KeysConfig,
    field_parsers={
        "ca": parse_positive_int,
        "server": parse_positive_int,
        "client": parse_positive_int,
    },
    default_factory=KeysConfig,
)

EXPIRY_SPEC: SectionSpec[ExpiryConfig] = SectionSpec(
    name="expiry",
    target=ExpiryConfig,
    field_parsers={
        "warning_days": parse_positive_int,
    },
    default_factory=ExpiryConfig,
)


# Leaf fields at the root can be expressed as a "fake section" spec too,
# but we keep them separate for clarity. Here we parse base_path as a leaf.
def _default_base_path() -> object:
    return Settings().base_path


ROOT_LEAF_PARSERS: Mapping[
    str,
    tuple[
        Callable[[], object],
        Callable[[object, str], object],
    ],
] = {
    "base_path": (_default_base_path, parse_path),
}

# Root sections: key -> SectionSpec
ROOT_SECTION_SPECS: Mapping[str, RootSectionSpec] = {
    "validity": VALIDITY_SPEC,  # type: ignore[assignment]
    "keys": KEYS_SPEC,  # type: ignore[assignment]
    "expiry": EXPIRY_SPEC,  # type: ignore[assignment]
}
