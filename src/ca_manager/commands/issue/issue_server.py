from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
from typing import Annotated

import typer
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import Certificate
from cryptography.x509.oid import ExtendedKeyUsageOID

from ca_manager.config.defaults import (
    DEFAULT_BASE_PATH,
    DEFAULT_SERVER_CERT_VALIDITY_DAYS,
    DEFAULT_SERVER_KEY_SIZE,
)

from .common import (
    IssueContext,
    build_certificate,
    build_subject,
    check_certificate_exists,
    generate_key,
    get_country,
    get_issue_context,
    get_organizational_unit,
    save_and_record,
)

app: typer.Typer = typer.Typer(help="Issue server certificates")


def build_san_extension(dns: list[str], ip: list[str]) -> tuple[x509.SubjectAlternativeName, list[str]]:
    """Build SAN extension from DNS names and IP addresses."""
    san_entries: list[x509.GeneralName] = []
    san_strings: list[str] = []

    for d in dns:
        san_entries.append(x509.DNSName(value=d))
        san_strings.append(d)

    for addr in ip:
        try:
            san_entries.append(x509.IPAddress(value=ip_address(address=addr)))
            san_strings.append(addr)
        except ValueError:
            typer.echo(message=f"Invalid IP address: {addr}", err=True)
            raise typer.Exit(code=1)

    return x509.SubjectAlternativeName(general_names=san_entries), san_strings


@app.command(name="server")
def issue_server(
    name: Annotated[str, typer.Argument(help="Server identity (Common Name)")],
    dns: Annotated[
        list[str],
        typer.Option("--dns", help="DNS name to include as Subject Alternative Name", default_factory=list),
    ],
    ip: Annotated[
        list[str],
        typer.Option("--ip", help="IP address to include as Subject Alternative Name", default_factory=list),
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
        int, typer.Option(help="RSA key size for the server certificate")
    ] = DEFAULT_SERVER_KEY_SIZE,
    days: Annotated[
        int, typer.Option(help="Validity of the server certificate in days")
    ] = DEFAULT_SERVER_CERT_VALIDITY_DAYS,
) -> None:
    """Issue a new server certificate signed by the CA."""
    if not dns and not ip:
        typer.echo(message="At least one --dns or --ip must be specified for a server certificate", err=True)
        raise typer.Exit(code=1)

    ctx: IssueContext = get_issue_context()
    key_path: Path = ctx.workspace.private_server_key(name=name)
    cert_path: Path = ctx.workspace.issued_server_cert(name=name)

    check_certificate_exists(key_path=key_path, cert_path=cert_path, cert_type="server", name=name)

    san_extension, san_strings = build_san_extension(dns=dns, ip=ip)

    key: rsa.RSAPrivateKey = generate_key(key_size=key_size)
    subject: x509.Name = build_subject(
        name=name,
        country=get_country(ctx.settings),
        organizational_unit=get_organizational_unit(ctx.settings, "server"),
    )
    cert: Certificate = build_certificate(
        subject=subject,
        key=key,
        ca_key=ctx.ca_key,
        ca_cert=ctx.ca_cert,
        days=days,
        extended_key_usage=ExtendedKeyUsageOID.SERVER_AUTH,
        san_extension=san_extension,
    )

    save_and_record(
        ctx=ctx,
        key=key,
        cert=cert,
        key_path=key_path,
        cert_path=cert_path,
        cert_type="server",
        name=name,
        san=san_strings,
    )

    typer.echo(message=f"Issued server certificate '{name}'")
