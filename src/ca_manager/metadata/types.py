from __future__ import annotations

from typing import Literal, TypedDict


class IssueRecord(TypedDict):
    serial: str
    type: Literal["client", "server"]
    name: str
    subject: str
    san: list[str]
    not_before: str
    not_after: str
    key_path: str
    cert_path: str
    revoked: bool
