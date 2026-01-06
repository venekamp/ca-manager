from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from cryptography.x509.name import Name
from cryptography.x509.oid import ExtendedKeyUsageOID

from ca_manager.config.defaults import (
    DEFAULT_BASE_PATH,
    DEFAULT_CLIENT_CERT_VALIDITY_DAYS,
    DEFAULT_CLIENT_KEY_SIZE,
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

app: typer.Typer = typer.Typer(help="Issue client certificates")


@app.command(name="client")
def issue_client(
    name: Annotated[str, typer.Argument(help="Client identity (Common Name)")],
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
        int, typer.Option(help="RSA key size for the client certificate")
    ] = DEFAULT_CLIENT_KEY_SIZE,
    days: Annotated[
        int, typer.Option(help="Validity of the client certificate in days")
    ] = DEFAULT_CLIENT_CERT_VALIDITY_DAYS,
) -> None:
    """
    Issue a new client certificate signed by the CA.

    The Common Name (CN) becomes the client identity
    used by services such as Mosquitto.
    """
    ctx: IssueContext = get_issue_context()
    key_path: Path = ctx.workspace.private_client_key(name=name)
    cert_path: Path = ctx.workspace.issued_client_cert(name=name)

    check_certificate_exists(key_path=key_path, cert_path=cert_path, cert_type="client", name=name)

    key: RSAPrivateKey = generate_key(key_size=key_size)
    subject: Name = build_subject(
        name=name,
        country=get_country(ctx.settings),
        organizational_unit=get_organizational_unit(ctx.settings, "client"),
    )
    cert: Certificate = build_certificate(
        subject=subject,
        key=key,
        ca_key=ctx.ca_key,
        ca_cert=ctx.ca_cert,
        days=days,
        extended_key_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )

    save_and_record(
        ctx=ctx,
        key=key,
        cert=cert,
        key_path=key_path,
        cert_path=cert_path,
        cert_type="client",
        name=name,
        san=[],
    )

    typer.echo(message=f"Issued client certificate '{name}'")
