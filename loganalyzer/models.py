"""
Core data model — shared LogEntry dataclass used across all parsers and analyzers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LogEntry:
    """Normalised log entry produced by any parser."""

    source: str                          # parser name: nginx, apache, ssh, ...
    raw: str                             # original log line
    timestamp: datetime | None = None
    level: str = "INFO"                  # INFO | WARNING | ERROR | CRITICAL | DEBUG
    ip: str | None = None
    method: str | None = None            # HTTP method
    path: str | None = None              # HTTP path / URL
    status: int | None = None            # HTTP status code
    size: int | None = None              # response/body size in bytes
    user_agent: str | None = None
    message: str = ""
    extra: dict = field(default_factory=dict)

    # ── Computed helpers ──────────────────────────────────────────────────────

    @property
    def is_error(self) -> bool:
        if self.status and self.status >= 400:
            return True
        return self.level in ("ERROR", "CRITICAL")

    @property
    def is_client_error(self) -> bool:
        return bool(self.status and 400 <= self.status < 500)

    @property
    def is_server_error(self) -> bool:
        return bool(self.status and self.status >= 500)

    @property
    def hour(self) -> int | None:
        return self.timestamp.hour if self.timestamp else None

    @property
    def weekday(self) -> str | None:
        if not self.timestamp:
            return None
        return self.timestamp.strftime("%A")
