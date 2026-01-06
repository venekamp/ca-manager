from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from ca_manager.config.defaults import DEFAULT_BASE_PATH, DEFAULT_CA_KEY_SIZE, DEFAULT_CA_VALIDITY_DAYS

from .issue.common import generate_key, write_certificate, write_private_key

app: typer.Typer = typer.Typer(help="Initialise a new Certificate Authority")


def create_directory_structure(base_path: Path) -> None:
    """Create the CA directory structure."""
    for directory in (
        base_path / "ca",
        base_path / "issued" / "server",
        base_path / "issued" / "client",
        base_path / "private" / "server",
        base_path / "private" / "client",
        base_path / "csrs",
        base_path / "metadata",
    ):
        directory.mkdir(parents=True, exist_ok=True)


def build_ca_certificate(
    name: str,
    key: RSAPrivateKey,
    days: int,
) -> x509.Certificate:
    """Build a self-signed CA certificate."""
    subject: x509.Name = x509.Name([x509.NameAttribute(oid=NameOID.COMMON_NAME, value=name)])
    now: datetime = datetime.now(tz=UTC)

    return (
        x509.CertificateBuilder()
        .subject_name(name=subject)
        .issuer_name(name=subject)
        .public_key(key=key.public_key())
        .serial_number(number=x509.random_serial_number())
        .not_valid_before(time=now)
        .not_valid_after(time=now + timedelta(days=days))
        .add_extension(
            extval=x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            extval=x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, algorithm=hashes.SHA256())
    )


@app.command()
def init(
    name: Annotated[str, typer.Argument(help="Common Name (CN) for the Certificate Authority")],
    path: Annotated[
        Path,
        typer.Option(
            help="Base directory where CA data will be stored",
            exists=False,
            file_okay=False,
            dir_okay=True,
            writable=True,
        ),
    ] = DEFAULT_BASE_PATH,
    key_size: Annotated[int, typer.Option(help="RSA key size for the CA private key")] = DEFAULT_CA_KEY_SIZE,
    days: Annotated[
        int, typer.Option(help="Validity of the CA certificate in days")
    ] = DEFAULT_CA_VALIDITY_DAYS,
) -> None:
    """
    Initialise a new root Certificate Authority.

    This creates:
    - CA directory structure
    - CA private key
    - Self-signed CA certificate
    """
    key_path: Path = path / "ca" / "ca.key"
    cert_path: Path = path / "ca" / "ca.crt"

    if key_path.exists() or cert_path.exists():
        typer.echo(message="CA already exists at this location", err=True)
        raise typer.Exit(code=1)

    create_directory_structure(base_path=path)

    key: RSAPrivateKey = generate_key(key_size=key_size)
    cert: x509.Certificate = build_ca_certificate(name=name, key=key, days=days)

    write_private_key(path=key_path, key=key)
    write_certificate(path=cert_path, cert=cert)

    typer.echo(message=f"CA initialised successfully in {path}")
