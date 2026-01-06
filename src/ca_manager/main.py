"""
ca-manager

A command-line tool for managing a small, private Certificate Authority (CA).

This project is designed for home labs and small self-hosted environments,
with a focus on simplicity, explicitness, and correctness. It provides tools
to initialize a CA, issue and track certificates, and inspect configuration
and metadata, without the complexity of large PKI systems.

Key design goals:
- Explicit, spec-driven configuration with safe defaults
- Strong typing and clear trust boundaries
- Minimal magic; behavior is easy to reason about
- Practical security suitable for personal infrastructure

The CLI is implemented using Typer and organized into subcommands, each
responsible for a single, well-defined task. Configuration is loaded lazily
and validated at runtime, allowing commands like `--help` to run without
side effects.

This module defines the root CLI application and wires together all
top-level command groups.
"""

import typer

from ca_manager.commands.init import init_cmd
from ca_manager.commands.inspect import inspect_cert
from ca_manager.commands.issue import app as issue_client_cmd
from ca_manager.commands.list import app as list_cmd
from ca_manager.commands.show import app as show_cmd
from ca_manager.commands.version import version_cmd

app: typer.Typer = typer.Typer(
    help="Private Certificate Authority management tool",
    no_args_is_help=True,
)

_ = app.command(name="version", options_metavar="--help")(version_cmd)
_ = app.command(name="inspect")(inspect_cert)
_ = app.command(name="init")(init_cmd)
# app.add_typer(typer_instance=init_cmd, name="init")
app.add_typer(typer_instance=issue_client_cmd, name="issue")
app.add_typer(typer_instance=list_cmd, name="list")
app.add_typer(typer_instance=show_cmd, name="config")


if __name__ == "__main__":
    app()
