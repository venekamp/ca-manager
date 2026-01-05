from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Workspace:
    base_path: Path

    @property
    def ca_dir(self) -> Path:
        return self.base_path / "ca"

    @property
    def ca_key(self) -> Path:
        return self.ca_dir / "ca.key"

    @property
    def ca_cert(self) -> Path:
        return self.ca_dir / "ca.crt"

    @property
    def issued_dir(self) -> Path:
        return self.base_path / "issued"

    @property
    def private_dir(self) -> Path:
        return self.base_path / "private"

    def issued_server_cert(self, name: str) -> Path:
        return self.issued_dir / "server" / f"{name}.crt"

    def issued_client_cert(self, name: str) -> Path:
        return self.issued_dir / "client" / f"{name}.crt"

    def private_server_key(self, name: str) -> Path:
        return self.private_dir / "server" / f"{name}.key"

    def private_client_key(self, name: str) -> Path:
        return self.private_dir / "client" / f"{name}.key"

    @property
    def metadata_dir(self) -> Path:
        return self.base_path / "metadata"

    @property
    def issued_index(self) -> Path:
        return self.metadata_dir / "issued.jsonl"
