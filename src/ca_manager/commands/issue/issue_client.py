from __future__ import annotations

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

app: typer.Typer = typer.Typer(help="Issue client certificates")


@app.command(name="client")
def issue_client(
    name: Annotated[
        str,
        typer.Argument(help="Client identity (Common Name)"),
    ],
    path: Annotated[
        Path,
        typer.Option(
            help="Base directory of the Certificate Authority",
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

    ca_key_path: Path = path / "ca" / "ca.key"
    ca_cert_path: Path = path / "ca" / "ca.crt"

    if not ca_key_path.exists() or not ca_cert_path.exists():
        typer.echo(message="CA not initialised at this location")
        raise typer.Exit(code=1)

    key_out: Path = path / "private" / "client" / f"{name}.key"
    cert_out: Path = path / "issued" / "client" / f"{name}.crt"

    if key_out.exists() or cert_out.exists():
        typer.echo(message=f"Client certificate '{name}' already exists")
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

    subject: x509.Name = x509.Name(
        [
            x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="NL"),
            x509.NameAttribute(oid=NameOID.COMMON_NAME, value=name),
        ]
    )

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

    # Write client key (600)
    with key_out.open("wb") as f:
        _ = f.write(
            client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    key_out.chmod(mode=0o600)

    # Write certificate
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
        key_path=str(key_out.relative_to(other=path)),
        cert_path=str(cert_out.relative_to(other=path)),
    )

    append_record(base_path=path, record=record)

    typer.echo(message=f"Issued client certificate '{name}'")
