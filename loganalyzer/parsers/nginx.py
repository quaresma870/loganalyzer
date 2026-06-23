"""
Nginx parser — supports combined, main, and error log formats.
"""

from __future__ import annotations

import re
from datetime import datetime

from loganalyzer.models import LogEntry
from loganalyzer.parsers.base import BaseParser

# Combined / main access log
_ACCESS_RE = re.compile(
    r'(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Error log
_ERROR_RE = re.compile(
    r'(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#\d+: \*?\d* ?(?P<message>.+)'
)

_TIME_FMT_ACCESS = "%d/%b/%Y:%H:%M:%S %z"
_TIME_FMT_ERROR = "%Y/%m/%d %H:%M:%S"

_LEVEL_MAP = {
    "debug": "DEBUG",
    "info": "INFO",
    "notice": "INFO",
    "warn": "WARNING",
    "error": "ERROR",
    "crit": "CRITICAL",
    "alert": "CRITICAL",
    "emerg": "CRITICAL",
}


class NginxParser(BaseParser):
    name = "nginx"

    def parse_line(self, line: str) -> LogEntry | None:
        # Try access log first
        m = _ACCESS_RE.match(line)
        if m:
            try:
                # %z in _TIME_FMT_ACCESS produces a timezone-AWARE datetime
                # (nginx logs the UTC offset, e.g. "+0000") — every other
                # parser in this codebase produces naive datetimes, and
                # mixing the two raises TypeError the moment two entries
                # from different sources are compared (e.g. correlation,
                # or just sorting a combined list) — strip it to match.
                ts = datetime.strptime(m.group("time"), _TIME_FMT_ACCESS).replace(tzinfo=None)
            except ValueError:
                ts = None
            status = self._safe_int(m.group("status"))
            return LogEntry(
                source=self.name,
                raw=line,
                timestamp=ts,
                level=self._status_level(status),
                ip=m.group("ip"),
                method=m.group("method"),
                path=m.group("path"),
                status=status,
                size=self._safe_int(m.group("size")),
                user_agent=self._clean(m.group("ua") if m.lastindex and m.lastindex >= 9 else None),
                message=f'{m.group("method")} {m.group("path")} {status}',
                extra={"referer": self._clean(m.group("referer") if m.lastindex and m.lastindex >= 8 else None)},
            )

        # Try error log
        m = _ERROR_RE.match(line)
        if m:
            try:
                ts = datetime.strptime(m.group("time"), _TIME_FMT_ERROR)
            except ValueError:
                ts = None
            raw_level = m.group("level").lower()
            return LogEntry(
                source=self.name,
                raw=line,
                timestamp=ts,
                level=_LEVEL_MAP.get(raw_level, "INFO"),
                message=m.group("message").strip(),
                extra={"pid": m.group("pid")},
            )

        return None

    @staticmethod
    def _status_level(status: int | None) -> str:
        if status is None:
            return "INFO"
        if status >= 500:
            return "ERROR"
        if status >= 400:
            return "WARNING"
        return "INFO"
