"""
Additional parsers: systemd/journald, syslog, SSH auth, fail2ban,
browser console (JSON), HAR, and custom regex.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

import yaml

from loganalyzer.models import LogEntry
from loganalyzer.parsers.base import BaseParser

# ── Systemd / journald ────────────────────────────────────────────────────────
# journalctl --no-pager output: "Oct 11 14:05:24 hostname service[pid]: message"
_SYSLOG_RE = re.compile(
    r'(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)'
)
_SYSTEMD_LEVEL_RE = re.compile(r'<(?P<level>\d)>')

_PRIORITY_MAP = {"0": "CRITICAL", "1": "CRITICAL", "2": "CRITICAL",
                 "3": "ERROR", "4": "WARNING", "5": "INFO",
                 "6": "INFO", "7": "DEBUG"}


class SystemdParser(BaseParser):
    name = "systemd"

    def parse_line(self, line: str) -> LogEntry | None:
        # Strip priority prefix if present (<N>)
        level = "INFO"
        lm = _SYSTEMD_LEVEL_RE.match(line)
        if lm:
            level = _PRIORITY_MAP.get(lm.group("level"), "INFO")
            line = line[lm.end():]

        m = _SYSLOG_RE.match(line)
        if not m:
            return LogEntry(source=self.name, raw=line, level=level, message=line)

        year = datetime.now().year
        try:
            ts = datetime.strptime(f"{year} {m.group('time')}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = None

        msg = m.group("message").strip()

        # Infer level from message keywords
        if level == "INFO":
            msg_lower = msg.lower()
            if any(k in msg_lower for k in ("error", "failed", "failure")):
                level = "ERROR"
            elif any(k in msg_lower for k in ("warning", "warn")):
                level = "WARNING"
            elif "critical" in msg_lower:
                level = "CRITICAL"

        return LogEntry(
            source=self.name,
            raw=line,
            timestamp=ts,
            level=level,
            message=msg,
            extra={"host": m.group("host"), "service": m.group("service").strip(),
                   "pid": m.group("pid")},
        )


# ── Syslog ────────────────────────────────────────────────────────────────────
class SyslogParser(SystemdParser):
    """Syslog uses the same format as systemd journal output."""
    name = "syslog"


# ── SSH Auth ──────────────────────────────────────────────────────────────────
_SSH_ACCEPTED_RE = re.compile(
    r'Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
_SSH_FAILED_RE = re.compile(
    r'(?:Failed (?P<method>\S+)|Invalid user (?P<inv_user>\S+)?) '
    r'(?:for (?P<user>\S+) )?from (?P<ip>\S+) port (?P<port>\d+)'
)
_SSH_DISCONNECT_RE = re.compile(
    r'Disconnected from (?:authenticating |invalid )?user (?P<user>\S+) '
    r'(?P<ip>\S+) port (?P<port>\d+)'
)


class SSHParser(BaseParser):
    name = "ssh"

    def parse_line(self, line: str) -> LogEntry | None:
        base = _SYSLOG_RE.match(line)
        year = datetime.now().year
        ts = None
        if base:
            try:
                ts = datetime.strptime(f"{year} {base.group('time')}", "%Y %b %d %H:%M:%S")
            except ValueError:
                pass
            msg = base.group("message").strip()
        else:
            msg = line

        # Only parse SSH-related lines
        if not any(k in msg for k in ("sshd", "Accepted", "Failed", "Invalid user",
                                      "Disconnected", "Connection closed")):
            if "sshd" not in line:
                return None

        m = _SSH_ACCEPTED_RE.search(msg)
        if m:
            return LogEntry(source=self.name, raw=line, timestamp=ts, level="INFO",
                            ip=m.group("ip"),
                            message=f"SSH login accepted: {m.group('user')} via {m.group('method')}",
                            extra={"user": m.group("user"), "auth_method": m.group("method"),
                                   "event": "accepted"})

        m = _SSH_FAILED_RE.search(msg)
        if m:
            ip = m.group("ip")
            user = m.group("user") or m.group("inv_user") or "unknown"
            return LogEntry(source=self.name, raw=line, timestamp=ts, level="WARNING",
                            ip=ip,
                            message=f"SSH login failed: {user} from {ip}",
                            extra={"user": user, "event": "failed"})

        m = _SSH_DISCONNECT_RE.search(msg)
        if m:
            return LogEntry(source=self.name, raw=line, timestamp=ts, level="INFO",
                            ip=m.group("ip"),
                            message=f"SSH disconnect: {m.group('user')}",
                            extra={"user": m.group("user"), "event": "disconnect"})

        return LogEntry(source=self.name, raw=line, timestamp=ts, level="INFO", message=msg)


# ── Fail2ban ──────────────────────────────────────────────────────────────────
_F2B_RE = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+'
    r'fail2ban\.(?P<component>\S+)\s+\[(?P<pid>\d+)\]:\s+(?P<level>\w+)\s+(?P<message>.+)'
)
_F2B_BAN_RE = re.compile(r'Ban (?P<ip>\S+)')
_F2B_UNBAN_RE = re.compile(r'Unban (?P<ip>\S+)')


class Fail2banParser(BaseParser):
    name = "fail2ban"

    def parse_line(self, line: str) -> LogEntry | None:
        m = _F2B_RE.match(line)
        if not m:
            return None

        try:
            ts = datetime.strptime(m.group("time").split(",")[0], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            ts = None

        msg = m.group("message").strip()
        level_map = {"DEBUG": "DEBUG", "INFO": "INFO", "WARNING": "WARNING",
                     "ERROR": "ERROR", "CRITICAL": "CRITICAL"}
        level = level_map.get(m.group("level").upper(), "INFO")

        ip = None
        event = "info"
        ban_m = _F2B_BAN_RE.search(msg)
        if ban_m:
            ip = ban_m.group("ip")
            event = "ban"
            level = "WARNING"
        unban_m = _F2B_UNBAN_RE.search(msg)
        if unban_m:
            ip = unban_m.group("ip")
            event = "unban"

        return LogEntry(source=self.name, raw=line, timestamp=ts, level=level,
                        ip=ip, message=msg,
                        extra={"component": m.group("component"), "event": event})


# ── Browser Console (JSON) ────────────────────────────────────────────────────
class BrowserConsoleParser(BaseParser):
    """
    Parses browser console logs exported as JSON.
    Expected format (array or newline-delimited JSON objects):
    {"level": "error", "message": "...", "timestamp": "...", "url": "...", "line": 42}
    """
    name = "browser"

    def parse_file(self, path: str | Path) -> Iterator[LogEntry]:
        path = Path(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        # Try array format
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    e = self._parse_obj(item, str(path))
                    if e:
                        yield e
                return
        except json.JSONDecodeError:
            pass

        # Try newline-delimited JSON
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                e = self._parse_obj(obj, line)
                if e:
                    yield e
            except json.JSONDecodeError:
                continue

    def parse_line(self, line: str) -> LogEntry | None:
        try:
            obj = json.loads(line)
            return self._parse_obj(obj, line)
        except json.JSONDecodeError:
            return None

    def _parse_obj(self, obj: dict, raw: str) -> LogEntry | None:
        if not isinstance(obj, dict):
            return None
        level_raw = str(obj.get("level", "log")).lower()
        level_map = {"error": "ERROR", "warn": "WARNING", "warning": "WARNING",
                     "info": "INFO", "log": "INFO", "debug": "DEBUG"}
        level = level_map.get(level_raw, "INFO")
        ts = None
        ts_raw = obj.get("timestamp") or obj.get("time")
        if ts_raw:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
                try:
                    ts = datetime.strptime(str(ts_raw)[:19], fmt[:len(fmt)])
                    break
                except ValueError:
                    continue
        return LogEntry(
            source=self.name, raw=str(raw), timestamp=ts, level=level,
            path=obj.get("url") or obj.get("source"),
            message=str(obj.get("message", "")),
            extra={"line": obj.get("line"), "column": obj.get("column"),
                   "stack": obj.get("stack")},
        )


# ── HAR (HTTP Archive) ────────────────────────────────────────────────────────
class HARParser(BaseParser):
    """
    Parses .har files (browser network tab export).
    Each request/response pair becomes a LogEntry.
    """
    name = "har"

    def parse_file(self, path: str | Path) -> Iterator[LogEntry]:
        path = Path(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            try:
                har = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid HAR file: {e}") from e

        entries = har.get("log", {}).get("entries", [])
        for entry in entries:
            e = self._parse_entry(entry)
            if e:
                yield e

    def parse_line(self, line: str) -> LogEntry | None:
        return None  # HAR is file-based, not line-based

    def _parse_entry(self, entry: dict) -> LogEntry | None:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        ts = None
        started = entry.get("startedDateTime")
        if started:
            try:
                ts = datetime.strptime(started[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass

        url = req.get("url", "")
        # Extract path from URL
        path = url.split("?")[0] if url else None
        if path and "://" in path:
            path = "/" + "/".join(path.split("/")[3:])

        status = resp.get("status", 0)
        size = resp.get("bodySize", -1)
        ua_list = [h["value"] for h in req.get("headers", []) if h.get("name", "").lower() == "user-agent"]

        return LogEntry(
            source=self.name, raw=str(req.get("url", "")),
            timestamp=ts,
            level="ERROR" if status >= 500 else ("WARNING" if status >= 400 else "INFO"),
            method=req.get("method"),
            path=path,
            status=status if status > 0 else None,
            size=size if size >= 0 else None,
            user_agent=ua_list[0] if ua_list else None,
            message=f'{req.get("method")} {url} {status}',
            extra={"url": url, "time_ms": entry.get("time", 0),
                   "mime_type": resp.get("content", {}).get("mimeType")},
        )


# ── Custom Regex ──────────────────────────────────────────────────────────────
class CustomParser(BaseParser):
    """
    Custom regex parser configured via a YAML file.

    YAML format:
      name: myapp
      pattern: '(?P<ip>\\S+) (?P<time>[^ ]+) (?P<level>\\w+) (?P<message>.+)'
      time_field: time
      time_format: '%Y-%m-%dT%H:%M:%S'
      level_field: level
      ip_field: ip
      message_field: message
    """
    name = "custom"

    def __init__(self, config_path: str | Path):
        config_path = Path(config_path)
        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        self.name = cfg.get("name", "custom")
        self._pattern = re.compile(cfg["pattern"])
        self._time_field = cfg.get("time_field")
        self._time_format = cfg.get("time_format")
        self._level_field = cfg.get("level_field")
        self._ip_field = cfg.get("ip_field")
        self._message_field = cfg.get("message_field", "message")
        self._status_field = cfg.get("status_field")
        self._path_field = cfg.get("path_field")
        self._method_field = cfg.get("method_field")

        self._level_map = cfg.get("level_map", {
            "debug": "DEBUG", "info": "INFO", "warn": "WARNING",
            "warning": "WARNING", "error": "ERROR", "critical": "CRITICAL",
            "fatal": "CRITICAL",
        })

    def parse_line(self, line: str) -> LogEntry | None:
        m = self._pattern.match(line)
        if not m:
            return None
        groups = m.groupdict()

        ts = None
        if self._time_field and groups.get(self._time_field) and self._time_format:
            try:
                ts = datetime.strptime(groups[self._time_field], self._time_format)
            except ValueError:
                pass

        level = "INFO"
        if self._level_field and groups.get(self._level_field):
            raw = groups[self._level_field].lower()
            level = self._level_map.get(raw, "INFO")

        return LogEntry(
            source=self.name, raw=line, timestamp=ts, level=level,
            ip=groups.get(self._ip_field) if self._ip_field else None,
            method=groups.get(self._method_field) if self._method_field else None,
            path=groups.get(self._path_field) if self._path_field else None,
            status=self._safe_int(groups.get(self._status_field)) if self._status_field else None,
            message=groups.get(self._message_field, line),
            extra={k: v for k, v in groups.items()
                   if k not in (self._time_field, self._level_field,
                                self._ip_field, self._message_field)},
        )
