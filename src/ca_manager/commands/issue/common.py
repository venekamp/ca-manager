from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

from ca_manager.metadata.model import IssuedCertificate
from ca_manager.metadata.store import append_record
from ca_manager.runtime import get_settings
from ca_manager.settings import Settings
from ca_manager.workspace import Workspace


@dataclass(frozen=True)
class IssueContext:
    settings: Settings
    workspace: Workspace
    ca_key: rsa.RSAPrivateKey
    ca_cert: x509.Certificate


def get_issue_context() -> IssueContext:
    """Load settings, workspace, and CA materials."""
    settings: Settings = get_settings()
    ws: Workspace = Workspace(base_path=settings.base_path)

    if not ws.ca_key.exists() or not ws.ca_cert.exists():
        typer.echo(message="CA not initialised at this location", err=True)
        raise typer.Exit(code=1)

    ca_key, ca_cert = load_ca(ca_key_path=ws.ca_key, ca_cert_path=ws.ca_cert)

    return IssueContext(settings=settings, workspace=ws, ca_key=ca_key, ca_cert=ca_cert)


def load_ca(ca_key_path: Path, ca_cert_path: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Load CA private key and certificate from disk."""
    with ca_key_path.open("rb") as f:
        ca_key: PrivateKeyTypes = serialization.load_pem_private_key(data=f.read(), password=None)

    if not isinstance(ca_key, rsa.RSAPrivateKey):
        typer.echo(message="Unsupported CA key type (expected RSA)", err=True)
        raise typer.Exit(code=1)

    with ca_cert_path.open("rb") as f:
        ca_cert: x509.Certificate = x509.load_pem_x509_certificate(data=f.read())

    return ca_key, ca_cert


def check_certificate_exists(key_path: Path, cert_path: Path, cert_type: str, name: str) -> None:
    """Check if certificate already exists and exit with error if so."""
    if key_path.exists() or cert_path.exists():
        typer.echo(message=f"{cert_type.capitalize()} certificate '{name}' already exists", err=True)
        raise typer.Exit(code=1)


def generate_key(key_size: int) -> rsa.RSAPrivateKey:
    """Generate a new RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def build_subject(name: str, country: str | None, organizational_unit: str | None = None) -> x509.Name:
    """Build certificate subject with optional country code and organizational unit."""
    attrs: list[x509.NameAttribute[str]] = []
    if country:
        attrs.append(x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value=country))
    if organizational_unit:
        attrs.append(x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value=organizational_unit))
    attrs.append(x509.NameAttribute(oid=NameOID.COMMON_NAME, value=name))
    return x509.Name(attrs)


def get_country(settings: Settings) -> str | None:
    """Extract country code from settings if configured."""
    if settings.certificates and settings.certificates.subject and settings.certificates.subject.country:
        return settings.certificates.subject.country
    return None


def get_organizational_unit(settings: Settings, cert_type: Literal["client", "server"]) -> str | None:
    """Extract organizational unit from settings, with type-specific override."""
    if not settings.certificates:
        return None

    # Check for type-specific override first
    if cert_type == "server" and settings.certificates.server:
        if settings.certificates.server.subject and settings.certificates.server.subject.organizational_unit:
            return settings.certificates.server.subject.organizational_unit
    elif cert_type == "client" and settings.certificates.client:
        if settings.certificates.client.subject and settings.certificates.client.subject.organizational_unit:
            return settings.certificates.client.subject.organizational_unit

    # Fall back to global default
    if settings.certificates.subject and settings.certificates.subject.organizational_unit:
        return settings.certificates.subject.organizational_unit

    return None


def build_certificate(
    *,
    subject: x509.Name,
    key: rsa.RSAPrivateKey,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    days: int,
    extended_key_usage: x509.ObjectIdentifier,
    san_extension: x509.SubjectAlternativeName | None = None,
) -> x509.Certificate:
    """Build and sign a certificate."""
    now: datetime = datetime.now(tz=UTC)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name=subject)
        .issuer_name(name=ca_cert.subject)
        .public_key(key=key.public_key())
        .serial_number(number=x509.random_serial_number())
        .not_valid_before(time=now)
        .not_valid_after(time=now + timedelta(days=days))
        .add_extension(
            extval=x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            extval=x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            extval=x509.ExtendedKeyUsage([extended_key_usage]),
            critical=True,
        )
    )

    if san_extension is not None:
        builder = builder.add_extension(extval=san_extension, critical=False)

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    """Write private key to file with secure permissions (0o600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd: int = os.open(path=path, flags=os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode=0o600)
    try:
        _ = os.write(
            fd,
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
    finally:
        os.close(fd)


def write_certificate(path: Path, cert: x509.Certificate) -> None:
    """Write certificate to file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        _ = f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


def save_and_record(
    *,
    ctx: IssueContext,
    key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
    key_path: Path,
    cert_path: Path,
    cert_type: Literal["client", "server"],
    name: str,
    san: list[str],
) -> None:
    """Write key and certificate to disk, and record in metadata."""
    write_private_key(path=key_path, key=key)
    write_certificate(path=cert_path, cert=cert)

    record: IssuedCertificate = IssuedCertificate(
        serial=hex(cert.serial_number),
        type=cert_type,
        name=name,
        subject=cert.subject.rfc4514_string(),
        san=san,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_path=str(key_path.relative_to(other=ctx.settings.base_path)),
        cert_path=str(cert_path.relative_to(other=ctx.settings.base_path)),
    )

    append_record(base_path=ctx.settings.base_path, record=record)
