"""
Base parser — all parsers extend this class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from loganalyzer.models import LogEntry


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    name: str = "base"

    def parse_file(self, path: str | Path) -> Iterator[LogEntry]:
        """Parse a log file line by line."""
        path = Path(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                entry = self.parse_line(line)
                if entry:
                    yield entry

    def parse_lines(self, lines: list[str]) -> list[LogEntry]:
        """Parse a list of lines — convenience method for tests."""
        entries = []
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            entry = self.parse_line(line)
            if entry:
                entries.append(entry)
        return entries

    @abstractmethod
    def parse_line(self, line: str) -> LogEntry | None:
        """Parse a single log line. Return None if line should be skipped."""

    @staticmethod
    def _safe_int(value: str | None) -> int | None:
        if value is None or value == "-":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _clean(value: str | None) -> str | None:
        if value in (None, "-", ""):
            return None
        return value.strip('"').strip()
