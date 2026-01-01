import typer

from .issue_client import app as client_app
from .issue_server import app as server_app

app = typer.Typer(help="Issue certificates")

app.add_typer(client_app)
app.add_typer(server_app)
