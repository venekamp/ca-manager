from __future__ import annotations

from collections.abc import Callable, Mapping

from ca_manager.config.parsers import parse_path, parse_positive_int, parse_string
from ca_manager.config.section_spec import RootSectionSpec, SectionSpec
from ca_manager.settings import (
    CertClientConfig,
    CertificatesConfig,
    CertServerConfig,
    CertSubjectConfig,
    ExpiryConfig,
    KeysConfig,
    ProfileConfig,
    Settings,
    ValidityConfig,
)


def section_parser[T](spec: SectionSpec[T]) -> Callable[[object, str], object]:
    def parse(raw: object, _: str) -> T:
        return spec.parse(raw)

    return parse


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

CERT_SUBJECT_SPEC: SectionSpec[CertSubjectConfig] = SectionSpec(
    name="subject",
    target=CertSubjectConfig,
    field_parsers={
        "country": parse_string,
        "organizational_unit": parse_string,
    },
    default_factory=CertSubjectConfig,
)

PROFILE_SPEC: SectionSpec[ProfileConfig] = SectionSpec(
    name="subject",
    target=ProfileConfig,
    field_parsers={
        "organizational_unit": parse_string,
    },
    default_factory=ProfileConfig,
)

CERT_SERVER_SPEC: SectionSpec[CertServerConfig] = SectionSpec(
    name="server",
    target=CertServerConfig,
    field_parsers={
        "subject": section_parser(spec=PROFILE_SPEC),
    },
    default_factory=CertServerConfig,
)


CERT_CLIENT_SPEC: SectionSpec[CertClientConfig] = SectionSpec(
    name="client",
    target=CertClientConfig,
    field_parsers={
        "subject": section_parser(spec=PROFILE_SPEC),
    },
    default_factory=CertClientConfig,
)
CERTIFICATES_SPEC: SectionSpec[CertificatesConfig | None] = SectionSpec(
    name="certificates",
    target=CertificatesConfig,
    field_parsers={
        "subject": section_parser(spec=CERT_SUBJECT_SPEC),
        "server": section_parser(spec=CERT_SERVER_SPEC),
        "client": section_parser(spec=CERT_CLIENT_SPEC),
    },
    default_factory=lambda: None,
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
    "validity": VALIDITY_SPEC,
    "keys": KEYS_SPEC,
    "expiry": EXPIRY_SPEC,
    "certificates": CERTIFICATES_SPEC,
}
