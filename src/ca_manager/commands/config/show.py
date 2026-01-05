from __future__ import annotations

from pathlib import Path

import typer

from ca_manager.runtime import get_settings
from ca_manager.settings import (
    CertClientConfig,
    CertificatesConfig,
    CertServerConfig,
    ExpiryConfig,
    KeysConfig,
    Settings,
    ValidityConfig,
)

app: typer.Typer = typer.Typer(help="Configuration commands")


def show_base_path(base_path: Path) -> None:
    typer.echo(message="Base path:")
    typer.echo(message=f"  {base_path}")
    typer.echo(message="")


def show_validity(validity: ValidityConfig) -> None:
    typer.echo(message="Certificate validity (days):")
    typer.echo(message=f"  CA:      {validity.ca_days}")
    typer.echo(message=f"  Server:  {validity.server_days}")
    typer.echo(message=f"  Client:  {validity.client_days}")
    typer.echo(message="")


def show_key_sizes(keys: KeysConfig) -> None:
    typer.echo(message="Key sizes (bits):")
    typer.echo(message=f"  CA:      {keys.ca}")
    typer.echo(message=f"  Server:  {keys.server}")
    typer.echo(message=f"  Client:  {keys.client}")
    typer.echo(message="")


def show_expiry(expiry: ExpiryConfig) -> None:
    typer.echo(message="Expiry warnings:")
    typer.echo(message=f"  Warn if expiring within {expiry.warning_days} days")
    typer.echo(message="")


def show_certificates_server(server: CertServerConfig | None) -> None:
    typer.echo(message="Certificate server attributes:")

    if server is None or server.subject is None or server.subject.organizational_unit is None:
        typer.echo(message="  organizational_unit: ignored (not defined in configuration)")
        typer.echo(message="")
        return

    typer.echo(message=f"  organizational_unit: {server.subject.organizational_unit}")
    typer.echo(message="")


def show_certificates_client(client: CertClientConfig | None) -> None:
    typer.echo(message="Certificate client attributes:")

    if client is None or client.subject is None or client.subject.organizational_unit is None:
        typer.echo(message="  organizational_unit: ignored (not defined in configuration)")
        typer.echo(message="")
        return

    typer.echo(message=f"  organizational_unit: {client.subject.organizational_unit}")
    typer.echo(message="")


def show_certificates(certificates_settings: CertificatesConfig | None) -> None:
    if certificates_settings is None:
        return

    if certificates_settings.subject is None:
        return

    show_certificates_server(certificates_settings.server)
    show_certificates_client(certificates_settings.client)


@app.command(name="show")
def show_config() -> None:
    """
    Show the effective ca-manager configuration.
    """

    settings: Settings = get_settings()

    typer.echo(message="CA Manager configuration")
    typer.echo(message="")

    show_base_path(settings.base_path)
    show_validity(settings.validity)
    show_key_sizes(settings.keys)
    show_expiry(settings.expiry)
    show_certificates(certificates_settings=settings.certificates)
