"""
Additional parsers: systemd/journald, syslog, SSH auth, fail2ban,
browser console (JSON), HAR, and custom regex.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

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
            # See WindowsEventParser._parse_event for why fromisoformat()
            # replaces the previous manual strptime() loop here: the old
            # code sliced data to a fixed 19 characters while still
            # requiring formats with a literal trailing 'Z', which never
            # actually matched an ISO8601-with-Z timestamp (the most common
            # real-world shape here, e.g. JS's `new Date().toISOString()`).
            try:
                ts = datetime.fromisoformat(str(ts_raw)).replace(tzinfo=None)
            except ValueError:
                ts = None
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


# ── Windows Event Log (XML) ───────────────────────────────────────────────────
# Parses XML exported from Windows Event Viewer or converted from .evtx
# Also handles evtx2xml / python-evtx output format

_WINDOWS_CRITICAL_IDS = {
    4625: ("Failed logon attempt", "WARNING"),
    4648: ("Explicit credentials logon", "WARNING"),
    4719: ("System audit policy changed", "ERROR"),
    4720: ("User account created", "INFO"),
    4722: ("User account enabled", "INFO"),
    4724: ("Password reset attempt", "WARNING"),
    4726: ("User account deleted", "WARNING"),
    4740: ("User account locked out", "WARNING"),
    4756: ("Member added to security group", "INFO"),
    4771: ("Kerberos pre-authentication failed", "WARNING"),
    1102: ("Audit log cleared", "CRITICAL"),
    7045: ("New service installed", "WARNING"),
}

_LEVEL_MAP_WIN = {
    "0": "INFO", "1": "CRITICAL", "2": "ERROR",
    "3": "WARNING", "4": "INFO", "5": "DEBUG",
}


class WindowsEventParser(BaseParser):
    """
    Parses Windows Event Log in XML format.
    Supports:
    - Windows Event Viewer XML exports (*.xml with <Events> root)
    - Single-event XML (one <Event> per line or file)
    - python-evtx JSON output
    """
    name = "windows_event"

    def parse_file(self, path: str | Path) -> Iterator[LogEntry]:
        import xml.etree.ElementTree as ET
        path = Path(path)
        content = path.read_text(encoding="utf-8", errors="replace")

        # Try full XML document first
        try:
            root = ET.fromstring(content)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            # Handle <Events> wrapper or direct <Event>
            events = root.findall(".//e:Event", ns) or ([root] if root.tag.endswith("Event") else [])
            for event in events:
                entry = self._parse_event(event, ns)
                if entry:
                    yield entry
            return
        except ET.ParseError:
            pass

        # Try JSON (python-evtx output)
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    entry = self._parse_json_event(item)
                    if entry:
                        yield entry
            return
        except json.JSONDecodeError:
            pass

        # Fall through to line-by-line
        for line in content.splitlines():
            entry = self.parse_line(line)
            if entry:
                yield entry

    def parse_line(self, line: str) -> LogEntry | None:
        import xml.etree.ElementTree as ET
        try:
            elem = ET.fromstring(line.strip())
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            return self._parse_event(elem, ns)
        except ET.ParseError:
            return None

    @staticmethod
    def _find_ns_or_plain(parent, tag: str, ns: dict):
        """Try a namespaced find() first, falling back to a plain tag name.

        ElementTree elements are falsy in a boolean context whenever they
        have zero CHILD elements — which describes nearly every meaningful
        single-value field in Windows Event Log XML (EventID, Level,
        TimeCreated, Channel are all leaf elements). The natural-looking
        `parent.find(a) or parent.find(b)` pattern silently discards a
        correctly-found leaf element and falls through to the second
        lookup, which is wrong. Always check `is not None` explicitly.
        """
        found = parent.find(f"e:{tag}", ns)
        if found is not None:
            return found
        return parent.find(tag)

    def _parse_event(self, event, ns: dict) -> LogEntry | None:
        try:
            sys_el = self._find_ns_or_plain(event, "System", ns)
            if sys_el is None:
                return None

            def get(tag):
                el = self._find_ns_or_plain(sys_el, tag, ns)
                return el.text if el is not None else None

            # Try namespaced first, then plain
            event_id = self._safe_int(get("EventID"))
            if event_id is None:
                ei = sys_el.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
                if ei is None:
                    ei = sys_el.find("EventID")
                if ei is not None:
                    event_id = self._safe_int(ei.text)
            level_raw = get("Level") or "4"
            level = _LEVEL_MAP_WIN.get(level_raw, "INFO")
            ts_raw = get("TimeCreated")
            ts = None
            if ts_raw is None:
                tc = self._find_ns_or_plain(sys_el, "TimeCreated", ns)
                if tc is not None:
                    ts_raw = tc.get("SystemTime")
            if ts_raw:
                # datetime.fromisoformat() (3.11+) natively handles the
                # trailing 'Z' and variable-precision fractional seconds —
                # the previous manual strptime() here sliced the trailing
                # 'Z' off the data (ts_raw[:26]) while still requiring a
                # literal 'Z' in the format string, so it never actually
                # matched anything and silently produced no timestamp at
                # all. .replace(tzinfo=None) keeps this naive, matching
                # every other parser in this codebase — mixing naive and
                # aware datetimes raises TypeError the moment two entries
                # from different sources are sorted/compared together.
                try:
                    ts = datetime.fromisoformat(ts_raw).replace(tzinfo=None)
                except ValueError:
                    ts = None

            # Known critical event IDs override level
            description = "Windows event"
            if event_id and event_id in _WINDOWS_CRITICAL_IDS:
                description, override_level = _WINDOWS_CRITICAL_IDS[event_id]
                level = override_level

            # Extract data fields
            data_el = event.find("e:EventData", ns)
            if data_el is None:
                data_el = event.find("EventData")
            extra = {}
            ip = None
            if data_el is not None:
                for data in data_el:
                    name = data.get("Name", "")
                    val = data.text or ""
                    extra[name] = val
                    if name in ("IpAddress", "WorkstationName") and val and val != "-":
                        ip = val.strip().lstrip("\\")

            return LogEntry(
                source=self.name, raw="",
                timestamp=ts, level=level, ip=ip,
                message=f"EventID {event_id}: {description}",
                extra={"event_id": event_id, "channel": get("Channel"), **extra},
            )
        except Exception:
            return None

    def _parse_json_event(self, obj: dict) -> LogEntry | None:
        event_id = self._safe_int(str(obj.get("EventID", "")))
        level = "INFO"
        description = "Windows event"
        if event_id and event_id in _WINDOWS_CRITICAL_IDS:
            description, level = _WINDOWS_CRITICAL_IDS[event_id]
        ts = None
        ts_raw = obj.get("TimeCreated") or obj.get("timestamp")
        if ts_raw:
            try:
                ts = datetime.strptime(str(ts_raw)[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass
        return LogEntry(
            source=self.name, raw=json.dumps(obj),
            timestamp=ts, level=level,
            message=f"EventID {event_id}: {description}",
            extra=obj,
        )
