import typer

from .issued import app as issued_app

app = typer.Typer(help="List certificates and metadata")

app.add_typer(issued_app)
