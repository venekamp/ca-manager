from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ca_manager.config.defaults import DEFAULT_BASE_PATH, DEFAULT_CA_KEY_SIZE, DEFAULT_CA_VALIDITY_DAYS

app: typer.Typer = typer.Typer(help="Initialise a new Certificate Authority")


@app.command()
def init(
    name: Annotated[
        str,
        typer.Argument(help="Common Name (CN) for the Certificate Authority"),
    ],
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
    key_size: Annotated[
        int,
        typer.Option(help="RSA key size for the CA private key"),
    ] = DEFAULT_CA_KEY_SIZE,
    days: Annotated[
        int,
        typer.Option(help="Validity of the CA certificate in days"),
    ] = DEFAULT_CA_VALIDITY_DAYS,
) -> None:
    """
    Initialise a new root Certificate Authority.

    This creates:
    - CA directory structure
    - CA private key
    - Self-signed CA certificate
    """

    ca_dir: Path = path / "ca"
    key_path: Path = ca_dir / "ca.key"
    cert_path: Path = ca_dir / "ca.crt"

    if key_path.exists() or cert_path.exists():
        typer.echo(message="CA already exists at this location")
        raise typer.Exit(code=1)

    # 1. Create directory structure
    for directory in (
        ca_dir,
        path / "issued" / "server",
        path / "issued" / "client",
        path / "private" / "server",
        path / "private" / "client",
        path / "csrs",
        path / "metadata",
    ):
        directory.mkdir(parents=True, exist_ok=True)

    # 2. Generate CA private key
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # 3. Build CA certificate
    issuer: x509.Name = x509.Name(
        [
            x509.NameAttribute(oid=NameOID.COMMON_NAME, value=name),
        ]
    )
    subject: x509.Name = issuer
    now: datetime = datetime.now(tz=UTC)

    certificate: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(name=subject)
        .issuer_name(name=issuer)
        .public_key(key=private_key.public_key())
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
        .sign(private_key, algorithm=hashes.SHA256())
    )

    # 4. Write key (600)
    with key_path.open("wb") as f:
        _ = f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    key_path.chmod(mode=0o600)

    # 5. Write certificate
    with cert_path.open("wb") as f:
        _ = f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

    typer.echo(message=f"CA initialised successfully in {path}")
