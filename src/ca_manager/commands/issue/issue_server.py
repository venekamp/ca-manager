from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.extensions import SubjectAlternativeName
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ca_manager.config.defaults import (
    DEFAULT_BASE_PATH,
    DEFAULT_SERVER_CERT_VALIDITY_DAYS,
    DEFAULT_SERVER_KEY_SIZE,
)
from ca_manager.metadata.model import IssuedCertificate
from ca_manager.metadata.store import append_record
from ca_manager.runtime import get_settings
from ca_manager.settings import Settings
from ca_manager.workspace import Workspace

app: typer.Typer = typer.Typer(help="Issue server certificates")


def validate_server_request(
    *,
    dns: list[str],
    ip: list[str],
    ca_key_path: Path,
    ca_cert_path: Path,
    key_out: Path,
    cert_out: Path,
    name: str,
) -> None:
    if not dns and not ip:
        typer.echo(
            message="At least one --dns or --ip must be specified for a server certificate",
            err=True,
        )
        raise typer.Exit(code=1)

    if not ca_key_path.exists() or not ca_cert_path.exists():
        typer.echo(message="CA not initialised at this location", err=True)
        raise typer.Exit(code=1)

    if key_out.exists() or cert_out.exists():
        typer.echo(message=f"Server certificate '{name}' already exists", err=True)
        raise typer.Exit(code=1)


def load_ca(
    ca_key_path: Path,
    ca_cert_path: Path,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    with ca_key_path.open("rb") as f:
        ca_key: PrivateKeyTypes = serialization.load_pem_private_key(data=f.read(), password=None)

    if not isinstance(ca_key, rsa.RSAPrivateKey):
        typer.echo(message="Unsupported CA key type (expected RSA)", err=True)
        raise typer.Exit(code=1)

    with ca_cert_path.open("rb") as f:
        ca_cert: x509.Certificate = x509.load_pem_x509_certificate(data=f.read())

    return ca_key, ca_cert


def build_san_extension(
    dns: list[str],
    ip: list[str],
) -> tuple[SubjectAlternativeName, list[x509.GeneralName]]:
    san_entries: list[x509.GeneralName] = []

    for d in dns:
        san_entries.append(x509.DNSName(value=d))

    for addr in ip:
        try:
            san_entries.append(x509.IPAddress(value=ip_address(address=addr)))
        except ValueError:
            typer.echo(message=f"Invalid IP address: {addr}", err=True)
            raise typer.Exit(code=1)

    return x509.SubjectAlternativeName(general_names=san_entries), san_entries


def build_server_certificate(
    *,
    name: str,
    server_key: rsa.RSAPrivateKey,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    san_extension: SubjectAlternativeName,
    days: int,
    country: str | None = None,
) -> x509.Certificate:
    subject_attrs: list[x509.NameAttribute[str]] = []
    if country:
        subject_attrs.append(x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value=country))
    subject_attrs.append(x509.NameAttribute(oid=NameOID.COMMON_NAME, value=name))
    subject: x509.Name = x509.Name(subject_attrs)

    now: datetime = datetime.now(tz=UTC)

    return (
        x509.CertificateBuilder()
        .subject_name(name=subject)
        .issuer_name(name=ca_cert.subject)
        .public_key(key=server_key.public_key())
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
            extval=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .add_extension(
            extval=san_extension,
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )


def write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        _ = f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


@app.command(name="server")
def issue_server(
    name: Annotated[
        str,
        typer.Argument(help="Server identity (Common Name)"),
    ],
    dns: Annotated[
        list[str],
        typer.Option(
            "--dns",
            help="DNS name to include as Subject Alternative Name",
            default_factory=list,
        ),
    ],
    ip: Annotated[
        list[str],
        typer.Option(
            "--ip",
            help="IP address to include as Subject Alternative Name",
            default_factory=list,
        ),
    ],
    _path: Annotated[
        Path,
        typer.Option(
            "--path",
            help="Base directory of the Certificate Authority (deprecated, use config file)",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            writable=True,
        ),
    ] = DEFAULT_BASE_PATH,
    key_size: Annotated[
        int,
        typer.Option(help="RSA key size for the server certificate"),
    ] = DEFAULT_SERVER_KEY_SIZE,
    days: Annotated[
        int,
        typer.Option(help="Validity of the server certificate in days"),
    ] = DEFAULT_SERVER_CERT_VALIDITY_DAYS,
) -> None:
    settings: Settings = get_settings()
    ws: Workspace = Workspace(base_path=settings.base_path)

    ca_key_path: Path = ws.ca_key
    ca_cert_path: Path = ws.ca_cert

    key_out: Path = ws.private_server_key(name=name)
    cert_out: Path = ws.issued_server_cert(name=name)

    validate_server_request(
        dns=dns,
        ip=ip,
        ca_key_path=ca_key_path,
        ca_cert_path=ca_cert_path,
        key_out=key_out,
        cert_out=cert_out,
        name=name,
    )
    ca_key, ca_cert = load_ca(ca_key_path, ca_cert_path)
    server_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    san_extension, san_entries = build_san_extension(dns, ip)

    country: str | None = None
    if settings.certificates and settings.certificates.subject and settings.certificates.subject.country:
        country = settings.certificates.subject.country

    certificate: x509.Certificate = build_server_certificate(
        name=name,
        server_key=server_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        san_extension=san_extension,
        days=days,
        country=country,
    )
    write_private_key(path=key_out, key=server_key)
    write_certificate(path=cert_out, cert=certificate)

    record: IssuedCertificate = IssuedCertificate(
        serial=hex(certificate.serial_number),
        type="server",
        name=name,
        subject=certificate.subject.rfc4514_string(),
        san=[str(x) for x in san_entries],
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        key_path=str(key_out.relative_to(other=settings.base_path)),
        cert_path=str(cert_out.relative_to(other=settings.base_path)),
    )

    append_record(base_path=settings.base_path, record=record)

    typer.echo(message=f"Issued server certificate '{name}'")
