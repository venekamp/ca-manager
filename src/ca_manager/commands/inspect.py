from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

import typer
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from ca_manager.runtime import get_settings
from ca_manager.workspace import Workspace


def format_datetime(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime(format="%Y-%m-%d %H:%M:%S %Z")


def get_key_size(cert: x509.Certificate) -> int | None:
    """Extract key size from certificate public key."""
    public_key: CertificatePublicKeyTypes = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size
    return None


def get_san_entries(cert: x509.Certificate) -> list[str]:
    """Extract Subject Alternative Names from certificate."""
    try:
        san_ext: x509.Extension[x509.SubjectAlternativeName] = cert.extensions.get_extension_for_class(
            extclass=x509.SubjectAlternativeName
        )
        return [
            name.value
            for name in san_ext.value  # pyright: ignore[reportAny]
            if isinstance(name.value, str)  # pyright: ignore[reportAny]
        ]
    except x509.ExtensionNotFound:
        return []


def get_key_usage(cert: x509.Certificate) -> list[str]:
    """Extract Key Usage from certificate."""
    try:
        key_usage_ext: x509.Extension[x509.KeyUsage] = cert.extensions.get_extension_for_class(x509.KeyUsage)
        usages: list[str] = []
        key_usage: x509.KeyUsage = key_usage_ext.value
        if key_usage.digital_signature:
            usages.append("digitalSignature")
        if key_usage.key_encipherment:
            usages.append("keyEncipherment")
        if key_usage.key_cert_sign:
            usages.append("keyCertSign")
        if key_usage.crl_sign:
            usages.append("cRLSign")
        if key_usage.content_commitment:
            usages.append("contentCommitment")
        if key_usage.data_encipherment:
            usages.append("dataEncipherment")
        if key_usage.key_agreement:
            usages.append("keyAgreement")
        return usages
    except x509.ExtensionNotFound:
        return []


def get_extended_key_usage(cert: x509.Certificate) -> list[str]:
    """Extract Extended Key Usage from certificate."""
    try:
        eku_ext: x509.Extension[x509.ExtendedKeyUsage] = cert.extensions.get_extension_for_class(
            extclass=x509.ExtendedKeyUsage
        )
        return [
            oid.dotted_string  # pyright: ignore[reportAny]
            for oid in eku_ext.value  # pyright: ignore[reportAny]
        ]
    except x509.ExtensionNotFound:
        return []


def is_ca(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate."""
    try:
        bc_ext: x509.Extension[x509.BasicConstraints] = cert.extensions.get_extension_for_class(
            extclass=x509.BasicConstraints
        )
        return bc_ext.value.ca
    except x509.ExtensionNotFound:
        return False


def display_certificate(cert: x509.Certificate, cert_type: str) -> None:
    """Display certificate details."""
    now: datetime = datetime.now(tz=UTC)
    not_before: datetime = cert.not_valid_before_utc
    not_after: datetime = cert.not_valid_after_utc

    expired: bool = now > not_after
    not_yet_valid: bool = now < not_before

    typer.echo(message=f"Type:         {cert_type}")
    typer.echo(message=f"Subject:      {cert.subject.rfc4514_string()}")
    typer.echo(message=f"Issuer:       {cert.issuer.rfc4514_string()}")
    typer.echo(message=f"Serial:       {hex(cert.serial_number)}")

    key_size: int | None = get_key_size(cert)
    if key_size:
        typer.echo(message=f"Key Size:     {key_size} bits")

    typer.echo(message=f"Not Before:   {format_datetime(dt=not_before)}")
    typer.echo(message=f"Not After:    {format_datetime(dt=not_after)}")

    if expired:
        typer.echo(message=typer.style(text="Status:       EXPIRED", fg=typer.colors.RED, bold=True))
    elif not_yet_valid:
        typer.echo(message=typer.style(text="Status:       NOT YET VALID", fg=typer.colors.YELLOW, bold=True))
    else:
        days_left: int = (not_after - now).days
        typer.echo(message=f"Status:       Valid ({days_left} days remaining)")

    if is_ca(cert):
        typer.echo(message="CA:           Yes")

    san_entries: list[str] = get_san_entries(cert)
    if san_entries:
        typer.echo(message=f"SAN:          {', '.join(san_entries)}")

    key_usage: list[str] = get_key_usage(cert)
    if key_usage:
        typer.echo(message=f"Key Usage:    {', '.join(key_usage)}")

    ext_key_usage: list[str] = get_extended_key_usage(cert)
    if ext_key_usage:
        typer.echo(message=f"Ext Key Use:  {', '.join(ext_key_usage)}")


def inspect_cert(
    name: Annotated[str | None, typer.Argument(help="Certificate name (not needed for CA)")] = None,
    cert_type: Annotated[
        Literal["ca", "server", "client"],
        typer.Option("--type", "-t", help="Certificate type"),
    ] = "ca",
) -> None:
    """
    Inspect a certificate and display its details.

    Examples:
        ca-manager inspect --type ca
        ca-manager inspect myserver --type server
        ca-manager inspect myclient --type client
    """
    ws: Workspace = Workspace(base_path=get_settings().base_path)

    if cert_type == "ca":
        cert_path: Path = ws.ca_cert
    elif cert_type == "server":
        if not name:
            typer.echo(message="Error: name is required for server certificates", err=True)
            raise typer.Exit(code=1)
        cert_path = ws.issued_server_cert(name=name)
    else:  # client
        if not name:
            typer.echo(message="Error: name is required for client certificates", err=True)
            raise typer.Exit(code=1)
        cert_path = ws.issued_client_cert(name=name)

    if not cert_path.exists():
        typer.echo(message=f"Error: certificate not found at {cert_path}", err=True)
        raise typer.Exit(code=1)

    with cert_path.open("rb") as f:
        cert: x509.Certificate = x509.load_pem_x509_certificate(data=f.read())

    display_certificate(cert, cert_type)
