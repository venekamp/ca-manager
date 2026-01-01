from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, TypeGuard

import typer

from ca_manager.config.defaults import DEFAULT_BASE_PATH
from ca_manager.metadata.types import IssueRecord

app: typer.Typer = typer.Typer(help="List issued certificates")


@app.command(name="issued")
def list_issued(
    path: Annotated[
        Path,
        typer.Option(
            help="Base directory of the Certificate Authority",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ] = DEFAULT_BASE_PATH,
    cert_type: Annotated[
        Literal["client", "server"] | None,
        typer.Option(
            "--type",
            help="Filter by certificate type",
        ),
    ] = None,
    revoked_only: Annotated[
        bool,
        typer.Option(
            "--revoked",
            help="Show only revoked certificates",
        ),
    ] = False,
    expiring: Annotated[
        int | None,
        typer.Option(
            "--expiring",
            help="Show certificates expiring within N days",
            min=1,
        ),
    ] = None,
) -> None:
    """
    List issued certificates from metadata.
    """

    index_file: Path = path / "metadata" / "issued.jsonl"

    if not index_file.exists():
        typer.echo(message="No issued certificates found")
        return

    rows: list[list[str]] = get_rows(index_file, expiring, cert_type, revoked_only=revoked_only)

    if not rows:
        typer.echo(message="No matching certificates found")
        return

    typer.echo(
        message=typer.style(
            text=f"{'TYPE':<8} {'NAME':<25} {'SERIAL':<18} {'REVOKED':<8} {'EXPIRES'}",
            bold=True,
        )
    )

    for row in rows:
        typer.echo(message=f"{row[0]:<8} {row[1]:<25} {row[2]:<18} {row[3]:<8} {row[4]}")


def matches_filters(
    record: IssueRecord,
    expiring: int | None,
    not_after: datetime,
    cert_type: str | None,
    revoked: bool,
) -> bool:
    now: datetime = datetime.now(tz=UTC)
    cutoff: datetime | None = now + timedelta(days=expiring) if expiring else None

    if cutoff and not (now <= not_after <= cutoff):
        return False

    if cert_type and not record["type"] == cert_type:
        return False

    if revoked and not record["revoked"]:
        return False

    return True


def get_rows(
    index_file: Path, expiring: int | None, cert_type: str | None, revoked_only: bool
) -> list[list[str]]:
    rows: list[list[str]] = []

    with index_file.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line: str = line.strip()
            if not line:
                continue

            try:
                record: IssueRecord = get_issuer_record(line, lineno)
                not_after: datetime = get_not_after(record, lineno)

                if matches_filters(
                    record=record,
                    not_after=not_after,
                    expiring=expiring,
                    cert_type=cert_type,
                    revoked=revoked_only,
                ):
                    rows.append(
                        [
                            record.get("type", "?"),
                            record.get("name", "?"),
                            record.get("serial", "?"),
                            "yes" if record.get("revoked") else "no",
                            not_after.isoformat(),
                        ]
                    )
            except ValueError:
                continue

    return rows


def get_issuer_record(line: str, lineno: int) -> IssueRecord:
    try:
        data = json.loads(s=line)  # pyright: ignore[reportAny]
    except json.JSONDecodeError:
        typer.echo(
            message=f"Warning: skipping malformed record at line {lineno}",
            err=True,
        )
        raise ValueError

    if not is_issuerecord(value=data):  # pyright: ignore[reportAny]
        typer.echo(
            message=f"Warning: skipping invalid record at line {lineno}",
            err=True,
        )
        raise ValueError

    return data


def get_not_after(record: IssueRecord, lineno: int) -> datetime:
    not_after_raw: str | None = record.get("not_after")

    try:
        not_after: datetime = datetime.fromisoformat(not_after_raw)
        if not_after.tzinfo is None:
            raise ValueError
    except ValueError:
        typer.echo(
            message=f"Warning: invalid not_after format at line {lineno}",
            err=True,
        )
        raise
    return not_after


def is_issuerecord(value: object) -> TypeGuard[IssueRecord]:
    if not isinstance(value, dict):
        return False

    required_fields: dict[str, type[str] | type[list[str]] | type[bool]] = {
        "serial": str,
        "type": str,
        "name": str,
        "subject": str,
        "not_before": str,
        "not_after": str,
        "key_path": str,
        "cert_path": str,
        "revoked": bool,
    }

    for key, expected_type in required_fields.items():
        if key not in value:
            return False
        if not isinstance(value[key], expected_type):
            return False

    san: Any | None = value.get("san")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportExplicitAny]
    if not isinstance(san, list):
        return False
    if not all(isinstance(x, str) for x in san):  # pyright: ignore[reportUnknownVariableType]
        return False

    if value["type"] not in ("client", "server"):
        return False

    if not all(isinstance(x, str) for x in value["san"]):  # pyright: ignore[reportUnknownVariableType]
        return False

    return True
