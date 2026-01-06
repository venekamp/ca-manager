from importlib.metadata import version

import typer


def version_cmd() -> None:
    """Show version."""
    typer.echo(message=f"ca-manager {version(distribution_name='ca-manager')}")
