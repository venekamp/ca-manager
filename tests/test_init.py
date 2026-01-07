from __future__ import annotations

from pathlib import Path

from click.testing import Result
from typer.testing import CliRunner

from ca_manager.main import app
from ca_manager.workspace import Workspace

runner: CliRunner = CliRunner()


def test_init_creates_ca(ca_workspace: Path) -> None:
    """Test that init creates CA key and certificate."""
    result: Result = runner.invoke(app, args=["init", "Test CA"])

    assert result.exit_code == 0
    assert "CA initialised successfully" in result.stdout

    ws: Workspace = Workspace(base_path=ca_workspace)
    assert ws.ca_key.exists()
    assert ws.ca_cert.exists()


def test_init_creates_directory_structure(ca_workspace: Path) -> None:
    """Test that init creates the expected directory structure."""
    _ = runner.invoke(app, args=["init", "Test CA", "--path", str(ca_workspace)])

    expected_dirs: list[Path] = [
        ca_workspace / "ca",
        ca_workspace / "issued" / "server",
        ca_workspace / "issued" / "client",
        ca_workspace / "private" / "server",
        ca_workspace / "private" / "client",
        ca_workspace / "csrs",
        ca_workspace / "metadata",
    ]

    for directory in expected_dirs:
        assert directory.is_dir(), f"Expected directory {directory} to exist"


def test_init_fails_if_ca_exists(ca_workspace: Path) -> None:
    """Test that init fails if CA already exists."""
    # First init should succeed
    result: Result = runner.invoke(app, args=["init", "Test CA"])
    assert result.exit_code == 0

    # Second init should fail
    result = runner.invoke(app, args=["init", "Test CA"])
    assert result.exit_code == 1
    assert "CA already exists" in result.output
