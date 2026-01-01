from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True)
class IssuedCertificate:
    serial: str
    type: Literal["client", "server"]
    name: str
    subject: str
    san: list[str]
    not_before: datetime
    not_after: datetime
    key_path: str
    cert_path: str
    revoked: bool = False
