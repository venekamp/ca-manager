from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ca_manager.config.defaults import (
    DEFAULT_BASE_PATH,
    DEFAULT_CLIENT_CERT_VALIDITY_DAYS,
    DEFAULT_CLIENT_KEY_SIZE,
)
from ca_manager.metadata.model import IssuedCertificate
from ca_manager.metadata.store import append_record
from ca_manager.runtime import get_settings
from ca_manager.settings import Settings
from ca_manager.workspace import Workspace

app: typer.Typer = typer.Typer(help="Issue client certificates")


@app.command(name="client")
def issue_client(
    name: Annotated[
        str,
        typer.Argument(help="Client identity (Common Name)"),
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
        typer.Option(help="RSA key size for the client certificate"),
    ] = DEFAULT_CLIENT_KEY_SIZE,
    days: Annotated[
        int,
        typer.Option(help="Validity of the client certificate in days"),
    ] = DEFAULT_CLIENT_CERT_VALIDITY_DAYS,
) -> None:
    """
    Issue a new client certificate signed by the CA.

    The Common Name (CN) becomes the client identity
    used by services such as Mosquitto.
    """
    settings: Settings = get_settings()
    ws: Workspace = Workspace(base_path=settings.base_path)

    ca_key_path: Path = ws.ca_key
    ca_cert_path: Path = ws.ca_cert

    if not ca_key_path.exists() or not ca_cert_path.exists():
        typer.echo(message="CA not initialised at this location", err=True)
        raise typer.Exit(code=1)

    key_out: Path = ws.private_client_key(name=name)
    cert_out: Path = ws.issued_client_cert(name=name)

    if key_out.exists() or cert_out.exists():
        typer.echo(message=f"Client certificate '{name}' already exists", err=True)
        raise typer.Exit(code=1)

    # Load CA materials
    with ca_key_path.open("rb") as f:
        ca_key: PrivateKeyTypes = serialization.load_pem_private_key(
            data=f.read(),
            password=None,
        )

    if not isinstance(ca_key, rsa.RSAPrivateKey):
        typer.echo(message="CA private key is not an RSA key", err=True)
        raise typer.Exit(code=1)

    with ca_cert_path.open("rb") as f:
        ca_cert: x509.Certificate = x509.load_pem_x509_certificate(data=f.read())

    # Generate client key
    client_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    subject_attrs: list[x509.NameAttribute[str]] = []
    if settings.certificates and settings.certificates.subject and settings.certificates.subject.country:
        subject_attrs.append(
            x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value=settings.certificates.subject.country)
        )
    subject_attrs.append(x509.NameAttribute(oid=NameOID.COMMON_NAME, value=name))
    subject: x509.Name = x509.Name(subject_attrs)

    now: datetime = datetime.now(tz=UTC)

    certificate: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(name=subject)
        .issuer_name(name=ca_cert.subject)
        .public_key(key=client_key.public_key())
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
            extval=x509.ExtendedKeyUsage(usages=[ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Write client key with secure permissions (0o600 set atomically)
    key_out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_out, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        _ = os.write(
            fd,
            client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
    finally:
        os.close(fd)

    # Write certificate
    cert_out.parent.mkdir(parents=True, exist_ok=True)
    with cert_out.open("wb") as f:
        _ = f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

    record: IssuedCertificate = IssuedCertificate(
        serial=hex(certificate.serial_number),
        type="client",
        name=name,
        subject=certificate.subject.rfc4514_string(),
        san=[],
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        key_path=str(key_out.relative_to(other=settings.base_path)),
        cert_path=str(cert_out.relative_to(other=settings.base_path)),
    )

    append_record(base_path=settings.base_path, record=record)

    typer.echo(message=f"Issued client certificate '{name}'")
