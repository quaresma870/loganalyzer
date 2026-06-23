"""
Apache parser — combined access log and error log formats.
"""

from __future__ import annotations

import re
from datetime import datetime

from loganalyzer.models import LogEntry
from loganalyzer.parsers.base import BaseParser

_ACCESS_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Apache 2.4 error log: [Thu Oct 11 14:05:24.903989 2018] [core:error] [pid 123] [client 1.2.3.4:56789] message
_ERROR_RE = re.compile(
    r'\[(?P<time>[^\]]+)\]\s+\[(?P<module>[^:]+):(?P<level>\w+)\]\s+'
    r'\[pid (?P<pid>\d+)\]'
    r'(?:\s+\[client (?P<client>[^\]]+)\])?'
    r'\s+(?P<message>.+)'
)

_TIME_FMT_ACCESS = "%d/%b/%Y:%H:%M:%S %z"

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


class ApacheParser(BaseParser):
    name = "apache"

    def parse_line(self, line: str) -> LogEntry | None:
        m = _ACCESS_RE.match(line)
        if m:
            try:
                # See nginx.py's parser for why .replace(tzinfo=None) is
                # needed here — %z makes this datetime timezone-aware,
                # inconsistent with every other parser's naive datetimes.
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
            )

        m = _ERROR_RE.match(line)
        if m:
            raw_level = m.group("level").lower()
            ip = None
            if m.group("client"):
                ip = m.group("client").split(":")[0]
            return LogEntry(
                source=self.name,
                raw=line,
                timestamp=None,
                level=_LEVEL_MAP.get(raw_level, "INFO"),
                ip=ip,
                message=m.group("message").strip(),
                extra={"module": m.group("module"), "pid": m.group("pid")},
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
