from __future__ import annotations

import typer

from ca_manager.runtime import get_settings
from ca_manager.settings import Settings

app: typer.Typer = typer.Typer(help="Configuration commands")


@app.command(name="show")
def show_config() -> None:
    """
    Show the effective ca-manager configuration.
    """

    settings: Settings = get_settings()

    typer.echo(message="CA Manager configuration")
    typer.echo(message="")

    typer.echo(message="Base path:")
    typer.echo(message=f"  {settings.base_path}")
    typer.echo(message="")

    typer.echo(message="Certificate validity (days):")
    typer.echo(message=f"  CA:      {settings.validity.ca_days}")
    typer.echo(message=f"  Server:  {settings.validity.server_days}")
    typer.echo(message=f"  Client:  {settings.validity.client_days}")
    typer.echo(message="")

    typer.echo(message="Key sizes (bits):")
    typer.echo(message=f"  CA:      {settings.keys.ca}")
    typer.echo(message=f"  Server:  {settings.keys.server}")
    typer.echo(message=f"  Client:  {settings.keys.client}")
    typer.echo(message="")

    typer.echo(message="Expiry warnings:")
    typer.echo(message=f"  Warn if expiring within {settings.expiry.warning_days} days")

    if settings.certificates is None:
        typer.echo(message="No certificates details found.")

    if settings.certificates is not None and settings.certificates.client is not None:
        typer.echo(message=f"{settings.certificates.client.subject.organizational_unit!r}")
