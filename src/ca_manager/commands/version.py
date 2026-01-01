import typer

app = typer.Typer(help="Show version.")


@app.command()
def version() -> None:
    typer.echo("Version: xxx")
