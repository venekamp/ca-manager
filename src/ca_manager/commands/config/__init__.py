import typer

from .show import app as show_app

app: typer.Typer = typer.Typer(help="Manage configuration")

app.add_typer(typer_instance=show_app)
