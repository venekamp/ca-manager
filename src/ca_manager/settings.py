from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from .config.defaults import (
    DEFAULT_BASE_PATH,
    DEFAULT_CA_KEY_SIZE,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CLIENT_CERT_VALIDITY_DAYS,
    DEFAULT_CLIENT_KEY_SIZE,
    DEFAULT_EXPIRY_WARNING_DAYS,
    DEFAULT_SERVER_CERT_VALIDITY_DAYS,
    DEFAULT_SERVER_KEY_SIZE,
)


@dataclass(frozen=True)
class ValidityConfig:
    ca_days: int = DEFAULT_CA_VALIDITY_DAYS
    server_days: int = DEFAULT_SERVER_CERT_VALIDITY_DAYS
    client_days: int = DEFAULT_CLIENT_CERT_VALIDITY_DAYS


@dataclass(frozen=True)
class KeysConfig:
    ca: int = DEFAULT_CA_KEY_SIZE
    server: int = DEFAULT_SERVER_KEY_SIZE
    client: int = DEFAULT_CLIENT_KEY_SIZE


@dataclass(frozen=True)
class ExpiryConfig:
    warning_days: int = DEFAULT_EXPIRY_WARNING_DAYS


@dataclass(frozen=True)
class CertSubjectConfig:
    country: str = ""
    organizational_unit: str = ""


@dataclass(frozen=True)
class ProfileConfig:
    organizational_unit: str = ""


@dataclass(frozen=True)
class CertServerConfig:
    subject: ProfileConfig = ProfileConfig()


@dataclass(frozen=True)
class CertClientConfig:
    subject: ProfileConfig = ProfileConfig()


@dataclass(frozen=True)
class CertificatesConfig:
    subject: CertSubjectConfig = CertSubjectConfig()
    server: CertServerConfig = CertServerConfig()
    client: CertClientConfig = CertClientConfig()


@dataclass(frozen=True)
class Settings:
    base_path: Path = DEFAULT_BASE_PATH
    validity: ValidityConfig = ValidityConfig()
    keys: KeysConfig = KeysConfig()
    expiry: ExpiryConfig = ExpiryConfig()
    certificates: CertificatesConfig = CertificatesConfig()


class SettingsKwargs(TypedDict, total=False):
    base_path: Path
    validity: ValidityConfig
    keys: KeysConfig
    expiry: ExpiryConfig
    Certificates: CertificatesConfig
