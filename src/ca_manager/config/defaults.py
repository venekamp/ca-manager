from __future__ import annotations

from pathlib import Path

# Default base directory where all CA data is stored
DEFAULT_BASE_PATH: Path = Path("/etc/ca-manager")

# ─────────────────────────────────────────────────────────────
# Certificate validity (days)
# ─────────────────────────────────────────────────────────────

# Root CA validity
DEFAULT_CA_VALIDITY_DAYS: int = 3650  # 10 years

# Issued certificates
DEFAULT_SERVER_CERT_VALIDITY_DAYS: int = 825  # ~27 months
DEFAULT_CLIENT_CERT_VALIDITY_DAYS: int = 365  # 1 year


# ─────────────────────────────────────────────────────────────
# Key sizes
# ─────────────────────────────────────────────────────────────

DEFAULT_CA_KEY_SIZE: int = 4096
DEFAULT_SERVER_KEY_SIZE: int = 2048
DEFAULT_CLIENT_KEY_SIZE: int = 2048


# ─────────────────────────────────────────────────────────────
# Expiry warnings
# ─────────────────────────────────────────────────────────────

# Default window for "expiring soon" checks
DEFAULT_EXPIRY_WARNING_DAYS: int = 30
