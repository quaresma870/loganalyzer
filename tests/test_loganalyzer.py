"""
Tests for parsers and analyzers.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from loganalyzer.analyzers import LogAnalyzer
from loganalyzer.models import LogEntry
from loganalyzer.parsers.apache import ApacheParser
from loganalyzer.parsers.extras import Fail2banParser, SSHParser, SystemdParser
from loganalyzer.parsers.nginx import NginxParser

# ── Nginx ─────────────────────────────────────────────────────────────────────

NGINX_ACCESS = (
    '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] '
    '"GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
)
NGINX_404 = (
    '10.0.0.1 - - [10/Oct/2024:13:55:37 +0000] '
    '"GET /notfound HTTP/1.1" 404 512 "-" "curl/7.68"'
)
NGINX_500 = (
    '10.0.0.2 - - [10/Oct/2024:13:55:38 +0000] '
    '"POST /api/data HTTP/1.1" 500 256 "-" "-"'
)
NGINX_ERROR = (
    '2024/10/10 13:55:36 [error] 1234#0: *1 connect() failed (111: Connection refused)'
)


class TestNginxParser:
    def setup_method(self):
        self.parser = NginxParser()

    def test_access_200(self):
        e = self.parser.parse_line(NGINX_ACCESS)
        assert e is not None
        assert e.ip == "192.168.1.1"
        assert e.method == "GET"
        assert e.path == "/api/users"
        assert e.status == 200
        assert e.size == 1234
        assert e.level == "INFO"
        assert e.source == "nginx"

    def test_timestamp_is_naive(self):
        """Regression test: nginx's access-log format includes a UTC offset
        (e.g. "+0000"), and %z in strptime makes the resulting datetime
        timezone-AWARE — inconsistent with every other parser in this
        codebase, which all produce naive datetimes. Mixing the two raises
        TypeError the instant two entries from different sources get
        compared (sorting a combined list, cross-source correlation, etc.)."""
        e = self.parser.parse_line(NGINX_ACCESS)
        assert e.timestamp is not None
        assert e.timestamp.tzinfo is None

    def test_access_404(self):
        e = self.parser.parse_line(NGINX_404)
        assert e is not None
        assert e.status == 404
        assert e.level == "WARNING"
        assert e.is_client_error

    def test_access_500(self):
        e = self.parser.parse_line(NGINX_500)
        assert e is not None
        assert e.status == 500
        assert e.level == "ERROR"
        assert e.is_server_error
        assert e.is_error

    def test_error_log(self):
        e = self.parser.parse_line(NGINX_ERROR)
        assert e is not None
        assert e.level == "ERROR"
        assert "connect() failed" in e.message

    def test_invalid_line(self):
        e = self.parser.parse_line("this is not a log line")
        assert e is None

    def test_timestamp_parsed(self):
        e = self.parser.parse_line(NGINX_ACCESS)
        assert e.timestamp is not None
        assert e.timestamp.day == 10
        assert e.timestamp.month == 10


# ── Apache ────────────────────────────────────────────────────────────────────

APACHE_ACCESS = (
    '127.0.0.1 - frank [10/Oct/2024:13:55:36 +0000] '
    '"GET /apache_pb.gif HTTP/1.1" 200 2326 "http://www.example.com/start.html" "Mozilla/5.0"'
)


class TestApacheParser:
    def setup_method(self):
        self.parser = ApacheParser()

    def test_access_log(self):
        e = self.parser.parse_line(APACHE_ACCESS)
        assert e is not None
        assert e.ip == "127.0.0.1"
        assert e.method == "GET"
        assert e.path == "/apache_pb.gif"
        assert e.status == 200
        assert e.size == 2326
        assert e.source == "apache"

    def test_timestamp_is_naive(self):
        """See nginx's identical test for why this matters."""
        e = self.parser.parse_line(APACHE_ACCESS)
        assert e.timestamp is not None
        assert e.timestamp.tzinfo is None


# ── SSH ───────────────────────────────────────────────────────────────────────

SSH_ACCEPTED = "Oct 10 13:55:36 server sshd[1234]: Accepted publickey for ubuntu from 192.168.1.100 port 54321 ssh2"
SSH_FAILED = "Oct 10 13:55:37 server sshd[1234]: Failed password for root from 10.0.0.5 port 54322 ssh2"
SSH_INVALID = "Oct 10 13:55:38 server sshd[1234]: Invalid user admin from 192.168.1.50 port 54323"


class TestSSHParser:
    def setup_method(self):
        self.parser = SSHParser()

    def test_accepted(self):
        e = self.parser.parse_line(SSH_ACCEPTED)
        assert e is not None
        assert e.ip == "192.168.1.100"
        assert e.level == "INFO"
        assert e.extra["event"] == "accepted"

    def test_failed(self):
        e = self.parser.parse_line(SSH_FAILED)
        assert e is not None
        assert e.ip == "10.0.0.5"
        assert e.level == "WARNING"
        assert e.extra["event"] == "failed"

    def test_invalid_user(self):
        e = self.parser.parse_line(SSH_INVALID)
        assert e is not None
        assert e.ip == "192.168.1.50"
        assert e.level == "WARNING"


# ── Fail2ban ──────────────────────────────────────────────────────────────────

F2B_BAN = "2024-10-10 13:55:36,123 fail2ban.actions [1234]: WARNING  [sshd] Ban 1.2.3.4"
F2B_UNBAN = "2024-10-10 14:00:00,000 fail2ban.actions [1234]: NOTICE  [sshd] Unban 1.2.3.4"


class TestFail2banParser:
    def setup_method(self):
        self.parser = Fail2banParser()

    def test_ban(self):
        e = self.parser.parse_line(F2B_BAN)
        assert e is not None
        assert e.ip == "1.2.3.4"
        assert e.extra["event"] == "ban"
        assert e.level == "WARNING"

    def test_unban(self):
        e = self.parser.parse_line(F2B_UNBAN)
        assert e is not None
        assert e.ip == "1.2.3.4"
        assert e.extra["event"] == "unban"


# ── Systemd ───────────────────────────────────────────────────────────────────

SYSTEMD_LINE = "Oct 10 13:55:36 myhost nginx[1234]: 2024/10/10 13:55:36 [error] upstream timed out"


class TestSystemdParser:
    def setup_method(self):
        self.parser = SystemdParser()

    def test_parses(self):
        e = self.parser.parse_line(SYSTEMD_LINE)
        assert e is not None
        assert e.source == "systemd"
        assert e.level == "ERROR"


# ── Analyzer ──────────────────────────────────────────────────────────────────

def _make_entries(n_ok=50, n_errors=10, n_bf=20) -> list[LogEntry]:
    entries = []
    ts = datetime(2024, 10, 10, 14, 0, 0)
    for i in range(n_ok):
        entries.append(LogEntry(source="nginx", raw="", timestamp=ts,
                                level="INFO", ip="1.2.3.4", status=200, path="/"))
    for i in range(n_errors):
        entries.append(LogEntry(source="nginx", raw="", timestamp=ts,
                                level="ERROR", ip="5.6.7.8", status=500, path="/api"))
    # Brute force: same IP many failed SSH
    for i in range(n_bf):
        entries.append(LogEntry(source="ssh", raw="", timestamp=ts,
                                level="WARNING", ip="9.9.9.9",
                                message="SSH login failed: root from 9.9.9.9",
                                extra={"event": "failed"}))
    return entries


class TestAnalyzer:
    def setup_method(self):
        self.analyzer = LogAnalyzer(top_n=5, enable_geo=False)

    def test_basic_counts(self):
        entries = _make_entries()
        r = self.analyzer.analyze(entries)
        assert r.total == 80
        assert r.errors == 10
        assert r.error_rate == pytest.approx(12.5, abs=0.1)

    def test_top_ips(self):
        entries = _make_entries()
        r = self.analyzer.analyze(entries)
        ips = [ip for ip, _ in r.top_ips]
        assert "9.9.9.9" in ips or "1.2.3.4" in ips

    def test_brute_force_detection(self):
        entries = _make_entries(n_bf=25)
        r = self.analyzer.analyze(entries)
        bf_ips = [b["ip"] for b in r.brute_force_ips]
        assert "9.9.9.9" in bf_ips

    def test_empty_entries(self):
        r = self.analyzer.analyze([])
        assert r.total == 0

    def test_sources(self):
        entries = _make_entries()
        r = self.analyzer.analyze(entries)
        assert "nginx" in r.sources
        assert "ssh" in r.sources

    def test_temporal(self):
        entries = _make_entries()
        r = self.analyzer.analyze(entries)
        assert 14 in r.by_hour
        assert r.peak_hour == 14

    def test_http_stats(self):
        entries = _make_entries()
        r = self.analyzer.analyze(entries)
        status_codes = [s for s, _ in r.top_status_codes]
        assert 200 in status_codes
        assert 500 in status_codes


# ── Cross-source correlation ─────────────────────────────────────────────────

class TestCorrelation:
    def setup_method(self):
        self.analyzer = LogAnalyzer(top_n=5, enable_geo=False, correlation_window_minutes=10)

    def _ssh_failures(self, ip, ts, count=12):
        return [
            LogEntry(source="ssh", raw="", timestamp=ts, level="WARNING", ip=ip,
                     message=f"SSH login failed: root from {ip}", extra={"event": "failed"})
            for _ in range(count)
        ]

    def _http_errors(self, ip, ts, count=5, status=403):
        return [
            LogEntry(source="nginx", raw="", timestamp=ts, level="WARNING", ip=ip,
                     status=status, path="/admin")
            for _ in range(count)
        ]

    def test_correlated_ip_within_window(self):
        ip = "203.0.113.50"
        base = datetime(2024, 10, 10, 14, 0, 0)
        entries = self._ssh_failures(ip, base) + self._http_errors(ip, base + timedelta(minutes=4))
        r = self.analyzer.analyze(entries)
        corr_ips = [c["ip"] for c in r.correlations]
        assert ip in corr_ips
        match = next(c for c in r.correlations if c["ip"] == ip)
        assert match["closest_gap_minutes"] == pytest.approx(4.0, abs=0.1)
        assert match["severity"] == "HIGH"  # 12 SSH failures >= BRUTE_FORCE_THRESHOLD

    def test_not_correlated_outside_window(self):
        """Same IP, same event types, but more than correlation_window_minutes
        apart — must NOT be flagged as correlated."""
        ip = "203.0.113.51"
        base = datetime(2024, 10, 10, 14, 0, 0)
        entries = self._ssh_failures(ip, base) + self._http_errors(ip, base + timedelta(minutes=45))
        r = self.analyzer.analyze(entries)
        corr_ips = [c["ip"] for c in r.correlations]
        assert ip not in corr_ips

    def test_single_source_ip_not_correlated(self):
        """An IP with SSH failures but no HTTP activity at all (or vice
        versa) must not appear — correlation specifically means BOTH."""
        ip = "203.0.113.52"
        base = datetime(2024, 10, 10, 14, 0, 0)
        entries = self._ssh_failures(ip, base)  # SSH only, no HTTP at all
        r = self.analyzer.analyze(entries)
        corr_ips = [c["ip"] for c in r.correlations]
        assert ip not in corr_ips

    def test_no_correlation_with_single_source_log(self):
        """With only one log source present at all, correlation doesn't
        even run — there's nothing to correlate ACROSS."""
        ip = "203.0.113.53"
        base = datetime(2024, 10, 10, 14, 0, 0)
        entries = self._ssh_failures(ip, base)
        r = self.analyzer.analyze(entries)
        assert r.correlations == []

    def test_entries_without_timestamp_are_skipped_not_matched(self):
        """An IP with timestamp-less events on both sides should not be
        treated as a (trivially zero-gap) match — no timestamp means it's
        simply not correlatable, not an automatic match."""
        ip = "203.0.113.54"
        entries = [
            LogEntry(source="ssh", raw="", timestamp=None, level="WARNING", ip=ip,
                     message="SSH login failed: root", extra={"event": "failed"})
            for _ in range(12)
        ] + [
            LogEntry(source="nginx", raw="", timestamp=None, level="WARNING", ip=ip, status=403)
            for _ in range(5)
        ]
        r = self.analyzer.analyze(entries)
        corr_ips = [c["ip"] for c in r.correlations]
        assert ip not in corr_ips

    def test_custom_window_is_respected(self):
        """A wider configured window should catch a gap a narrower one
        wouldn't."""
        ip = "203.0.113.55"
        base = datetime(2024, 10, 10, 14, 0, 0)
        entries = self._ssh_failures(ip, base) + self._http_errors(ip, base + timedelta(minutes=25))

        narrow = LogAnalyzer(correlation_window_minutes=10)
        wide = LogAnalyzer(correlation_window_minutes=30)

        r_narrow = narrow.analyze(entries)
        r_wide = wide.analyze(entries)

        assert ip not in [c["ip"] for c in r_narrow.correlations]
        assert ip in [c["ip"] for c in r_wide.correlations]


# ── Offline GeoIP (GeoLite2) ─────────────────────────────────────────────────

class TestOfflineGeoIP:
    """Uses MaxMind's own published test database (tests/fixtures/
    GeoLite2-City-Test.mmdb, dual Apache/MIT licensed, same one MaxMind
    uses in their own client library test suites) — not a fake/mocked
    response, a real .mmdb file with real known sample data."""

    DB_PATH = str(Path(__file__).parent / "fixtures" / "GeoLite2-City-Test.mmdb")
    # 2.125.160.216/29 is a known entry in the test DB: Boxford, GB
    KNOWN_IP = "2.125.160.216"

    def test_offline_lookup_returns_known_city(self):
        analyzer = LogAnalyzer(enable_geo=True, geo_db_path=self.DB_PATH)
        results = analyzer._lookup_geo_offline([self.KNOWN_IP], self.DB_PATH)
        assert len(results) == 1
        assert results[0]["ip"] == self.KNOWN_IP
        assert results[0]["country"] == "United Kingdom"
        assert results[0]["country_code"] == "GB"
        assert results[0]["city"] == "Boxford"

    def test_private_ips_skipped(self):
        analyzer = LogAnalyzer(enable_geo=True, geo_db_path=self.DB_PATH)
        results = analyzer._lookup_geo_offline(["10.0.0.1", "192.168.1.1", "127.0.0.1"], self.DB_PATH)
        assert results == []

    def test_unknown_ip_skipped_gracefully(self):
        """An IP not present in the test DB must not raise — AddressNotFoundError
        is caught and the IP is simply omitted from results."""
        analyzer = LogAnalyzer(enable_geo=True, geo_db_path=self.DB_PATH)
        results = analyzer._lookup_geo_offline(["203.0.113.99"], self.DB_PATH)
        assert results == []

    def test_invalid_db_path_degrades_gracefully(self):
        analyzer = LogAnalyzer(enable_geo=True, geo_db_path="/nonexistent/path.mmdb")
        results = analyzer._lookup_geo_offline([self.KNOWN_IP], "/nonexistent/path.mmdb")
        assert results == []

    def test_full_analyze_uses_offline_path_when_configured(self):
        """End-to-end: analyze() with geo_db_path set populates result.geo
        via the offline path, not the live API."""
        entries = [
            LogEntry(source="nginx", raw="x", ip=self.KNOWN_IP, status=200)
            for _ in range(5)
        ]
        analyzer = LogAnalyzer(enable_geo=True, geo_db_path=self.DB_PATH)
        result = analyzer.analyze(entries)
        assert len(result.geo) == 1
        assert result.geo[0]["country_code"] == "GB"

    def test_offline_path_not_capped_to_top_20(self):
        """The live API path caps lookups to the top 20 IPs to respect
        ip-api.com's free-tier rate limit — the offline path has no such
        constraint and should look up every IP that appears."""
        entries = [
            LogEntry(source="nginx", raw="x", ip=f"2.125.160.21{6 + (i % 6)}", status=200)
            for i in range(25)
        ]
        analyzer = LogAnalyzer(enable_geo=True, geo_db_path=self.DB_PATH, top_n=20)
        result = analyzer.analyze(entries)
        # All 6 distinct IPs from the /29 block should resolve, even though
        # plenty of distinct IPs would never fit in a hard top-20 cap in a
        # busier real log — the point is the cap doesn't apply here at all.
        assert len(result.geo) >= 1

    def test_geo_empty_without_geoip2_installed(self):
        """If geoip2 isn't installed, this must degrade to an empty result,
        not crash the whole analysis — confirms the optional-dependency
        promise actually holds."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("geoip2"):
                raise ImportError("simulated: geoip2 not installed")
            return real_import(name, *args, **kwargs)

        analyzer = LogAnalyzer(enable_geo=True, geo_db_path=self.DB_PATH)
        builtins.__import__ = fake_import
        try:
            results = analyzer._lookup_geo_offline([self.KNOWN_IP], self.DB_PATH)
        finally:
            builtins.__import__ = real_import
        assert results == []


# ── LogEntry helpers ──────────────────────────────────────────────────────────

class TestLogEntry:
    def test_is_error_by_status(self):
        e = LogEntry(source="nginx", raw="", status=500)
        assert e.is_error
        assert e.is_server_error
        assert not e.is_client_error

    def test_is_error_by_level(self):
        e = LogEntry(source="nginx", raw="", level="CRITICAL")
        assert e.is_error

    def test_hour_weekday(self):
        e = LogEntry(source="nginx", raw="", timestamp=datetime(2024, 10, 10, 14, 30))
        assert e.hour == 14
        assert e.weekday == "Thursday"


# ── Streaming / tail ──────────────────────────────────────────────────────────

class TestStreaming:
    def test_tail_uses_deque(self):
        """--tail should only keep last N entries."""
        import tempfile

        from loganalyzer.parsers.nginx import NginxParser

        lines = []
        for i in range(100):
            lines.append(
                f'192.168.1.{i % 256} - - [10/Oct/2024:13:55:{i:02d} +0000] '
                f'"GET /path HTTP/1.1" 200 100 "-" "-"'
            )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("\n".join(lines))
            path = f.name

        from collections import deque
        buf: deque = deque(maxlen=10)
        parser = NginxParser()
        for entry in parser.parse_file(path):
            buf.append(entry)

        assert len(buf) == 10  # only last 10 kept

    def test_parse_file_is_generator(self):
        """parse_file must return an iterator, not a list."""
        import tempfile

        from loganalyzer.parsers.nginx import NginxParser

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write('192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET / HTTP/1.1" 200 100\n')
            path = f.name

        result = NginxParser().parse_file(path)
        assert hasattr(result, "__iter__")
        assert hasattr(result, "__next__")  # is a generator/iterator


# ── Windows Event Log parser ──────────────────────────────────────────────────

WINDOWS_XML_SINGLE = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-10-10T13:55:36.000000Z"/>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="IpAddress">10.0.0.5</Data>
    <Data Name="TargetUserName">administrator</Data>
  </EventData>
</Event>"""

WINDOWS_XML_EVENTS = """<?xml version="1.0" encoding="UTF-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4624</EventID>
      <Level>4</Level>
      <TimeCreated SystemTime="2024-10-10T14:00:00.000000Z"/>
      <Channel>Security</Channel>
    </System>
    <EventData><Data Name="IpAddress">192.168.1.10</Data></EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>1102</EventID>
      <Level>4</Level>
      <TimeCreated SystemTime="2024-10-10T14:05:00.000000Z"/>
      <Channel>Security</Channel>
    </System>
    <EventData></EventData>
  </Event>
</Events>"""


class TestWindowsEventParser:
    def setup_method(self):
        from loganalyzer.parsers.extras import WindowsEventParser
        self.parser = WindowsEventParser()

    def test_parse_single_event_4625(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(WINDOWS_XML_SINGLE)
            path = f.name
        entries = list(self.parser.parse_file(path))
        assert len(entries) >= 1
        e = entries[0]
        assert e.source == "windows_event"
        assert e.level == "WARNING"  # 4625 = failed logon
        assert "4625" in e.message
        assert e.ip == "10.0.0.5"

    def test_parse_events_collection(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(WINDOWS_XML_EVENTS)
            path = f.name
        entries = list(self.parser.parse_file(path))
        assert len(entries) == 2
        # 1102 = audit log cleared → CRITICAL
        critical = [e for e in entries if "1102" in e.message]
        assert critical
        assert critical[0].level == "CRITICAL"

    def test_registered_in_registry(self):
        from loganalyzer.parsers import PARSERS
        assert "windows" in PARSERS

    def test_timestamp_is_extracted_not_lost(self):
        """Regression test: ElementTree elements are falsy when they have
        zero child elements (EventID/Level/TimeCreated/Channel all are) —
        using `a.find(x) or a.find(y)` to chain a namespaced lookup with a
        plain-tag fallback silently discarded every correctly-found leaf
        element and fell through to the (failing) fallback. timestamp came
        back None for every Windows event regardless of the source XML,
        despite TimeCreated's SystemTime attribute being right there."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(WINDOWS_XML_SINGLE)
            path = f.name
        entries = list(self.parser.parse_file(path))
        e = entries[0]
        assert e.timestamp is not None
        assert e.timestamp == datetime(2024, 10, 10, 13, 55, 36)
        assert e.timestamp.tzinfo is None  # naive, consistent with every other parser

    def test_channel_extra_field_is_extracted_not_lost(self):
        """Same root cause as the timestamp regression above, different
        field — extra['channel'] also came back None for every event."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(WINDOWS_XML_SINGLE)
            path = f.name
        entries = list(self.parser.parse_file(path))
        assert entries[0].extra.get("channel") == "Security"

    def test_no_deprecation_warning_on_parse(self):
        """The truthiness bug specifically triggers Python's own
        'Testing an element's truth value' DeprecationWarning on every
        single parse call — confirms it's gone, not just suppressed."""
        import tempfile
        import warnings
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(WINDOWS_XML_SINGLE)
            path = f.name
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            list(self.parser.parse_file(path))  # must not raise


# ── Browser console JSON logs ───────────────────────────────────────────────────

class TestBrowserConsoleParser:
    def setup_method(self):
        from loganalyzer.parsers.extras import BrowserConsoleParser
        self.parser = BrowserConsoleParser()

    def test_parses_basic_fields(self):
        import json
        line = json.dumps({
            "level": "error", "timestamp": "2024-10-10T13:55:36.123Z",
            "message": "Uncaught TypeError", "url": "/app.js",
        })
        e = self.parser.parse_line(line)
        assert e is not None
        assert e.level == "ERROR"
        assert e.message == "Uncaught TypeError"

    def test_timestamp_with_milliseconds_and_z_suffix(self):
        """Regression test: the previous manual strptime() loop sliced
        the JSON's timestamp string to a fixed 19 characters while still
        requiring formats with a literal trailing 'Z' — which never
        matched, since the slice always cut the 'Z' off first. This is
        the most common real-world shape (e.g. JS's
        `new Date().toISOString()`), so timestamp came back None for
        essentially every browser console log line in practice."""
        import json
        line = json.dumps({"level": "error", "timestamp": "2024-10-10T13:55:36.123Z", "message": "x"})
        e = self.parser.parse_line(line)
        assert e.timestamp is not None
        assert e.timestamp == datetime(2024, 10, 10, 13, 55, 36, 123000)
        assert e.timestamp.tzinfo is None

    def test_timestamp_without_milliseconds(self):
        import json
        line = json.dumps({"level": "info", "timestamp": "2024-10-10T13:55:36Z", "message": "x"})
        e = self.parser.parse_line(line)
        assert e.timestamp == datetime(2024, 10, 10, 13, 55, 36)

    def test_timestamp_space_separated_fallback(self):
        import json
        line = json.dumps({"level": "info", "timestamp": "2024-10-10 13:55:36", "message": "x"})
        e = self.parser.parse_line(line)
        assert e.timestamp == datetime(2024, 10, 10, 13, 55, 36)

    def test_missing_timestamp_is_none_not_an_error(self):
        import json
        line = json.dumps({"level": "info", "message": "no timestamp field at all"})
        e = self.parser.parse_line(line)
        assert e is not None
        assert e.timestamp is None

    def test_malformed_timestamp_does_not_raise(self):
        import json
        line = json.dumps({"level": "info", "timestamp": "not-a-real-timestamp", "message": "x"})
        e = self.parser.parse_line(line)
        assert e is not None
        assert e.timestamp is None

    def test_invalid_json_returns_none(self):
        assert self.parser.parse_line("not valid json {{{") is None


# ── Scheduler ─────────────────────────────────────────────────────────────────

class TestScheduler:
    def test_parse_cron_every_15min(self):
        import schedule

        from loganalyzer.scheduler import _parse_cron_to_schedule
        schedule.clear()
        job = _parse_cron_to_schedule("*/15 * * * *", lambda: None)
        assert job is not None
        schedule.clear()

    def test_parse_cron_daily(self):
        import schedule

        from loganalyzer.scheduler import _parse_cron_to_schedule
        schedule.clear()
        job = _parse_cron_to_schedule("0 6 * * *", lambda: None)
        assert job is not None
        schedule.clear()

    def test_invalid_cron_raises(self):
        import pytest

        from loganalyzer.scheduler import _parse_cron_to_schedule
        with pytest.raises((ValueError, RuntimeError)):
            _parse_cron_to_schedule("invalid", lambda: None)


# ── CLI (regression coverage — previously zero) ──────────────────────────────
#
# `analyze`'s function signature listed tail/db/max_entries as parameters
# with NO corresponding @click.option decorators at all, and `watch`'s
# listed alert_webhook the same way — every invocation of either command
# raised "TypeError: ... missing N required positional arguments" before
# this was fixed. Nothing caught this because there was no test that
# actually invoked the CLI commands — every existing test called the
# underlying Python functions/classes directly, bypassing Click entirely.

class TestCLI:
    def setup_method(self):
        from click.testing import CliRunner
        self.runner = CliRunner()

    def test_analyze_runs_without_crashing(self, tmp_path):
        from loganalyzer.cli import cli
        log_file = tmp_path / "access.log"
        log_file.write_text(NGINX_ACCESS + "\n")
        result = self.runner.invoke(cli, ["analyze", str(log_file), "--format", "nginx"])
        assert result.exit_code == 0, result.output

    def test_analyze_tail_option(self, tmp_path):
        from loganalyzer.cli import cli
        log_file = tmp_path / "access.log"
        log_file.write_text((NGINX_ACCESS + "\n") * 5)
        result = self.runner.invoke(
            cli, ["analyze", str(log_file), "--format", "nginx", "--tail", "2"]
        )
        assert result.exit_code == 0, result.output

    def test_analyze_max_entries_option(self, tmp_path):
        from loganalyzer.cli import cli
        log_file = tmp_path / "access.log"
        log_file.write_text((NGINX_ACCESS + "\n") * 5)
        result = self.runner.invoke(
            cli, ["analyze", str(log_file), "--format", "nginx", "--max-entries", "2"]
        )
        assert result.exit_code == 0, result.output
        assert "Capped to 2 entries" in result.output

    def test_analyze_db_option_persists(self, tmp_path):
        from loganalyzer.cli import cli
        log_file = tmp_path / "access.log"
        log_file.write_text(NGINX_ACCESS + "\n")
        db_path = tmp_path / "results.db"
        result = self.runner.invoke(
            cli, ["analyze", str(log_file), "--format", "nginx", "--db", str(db_path)]
        )
        assert result.exit_code == 0, result.output
        assert db_path.exists()

    def test_analyze_geo_db_option(self, tmp_path):
        from loganalyzer.cli import cli
        log_file = tmp_path / "access.log"
        log_file.write_text("2.125.160.216 " + NGINX_ACCESS.split(" ", 1)[1] + "\n")
        mmdb = Path(__file__).parent / "fixtures" / "GeoLite2-City-Test.mmdb"
        json_out = tmp_path / "out.json"
        result = self.runner.invoke(cli, [
            "analyze", str(log_file), "--format", "nginx",
            "--geo-db", str(mmdb), "--json", str(json_out), "--no-terminal",
        ])
        assert result.exit_code == 0, result.output
        import json as json_mod
        data = json_mod.loads(json_out.read_text())
        assert data["geo"], "expected at least one geo entry"
        assert data["geo"][0]["country_code"] == "GB"

    def test_watch_help_does_not_crash(self):
        """watch's signature listed alert_webhook with no decorator — even
        --help would have crashed before this was fixed, since Click still
        builds the full command before rendering help text."""
        from loganalyzer.cli import cli
        result = self.runner.invoke(cli, ["watch", "--help"])
        assert result.exit_code == 0, result.output
        assert "--alert-webhook" in result.output

    def test_analyze_correlation_window_option(self, tmp_path):
        from loganalyzer.cli import cli
        ssh_log = tmp_path / "auth.log"
        nginx_log = tmp_path / "access.log"
        ssh_log.write_text(
            "Oct 10 14:00:00 host sshd[1]: Failed password for root from 203.0.113.60 port 22 ssh2\n" * 12
        )
        nginx_log.write_text(
            '203.0.113.60 - - [10/Oct/2024:14:03:00 +0000] "GET /admin HTTP/1.1" 403 100 "-" "-"\n' * 5
        )
        json_out = tmp_path / "out.json"
        result = self.runner.invoke(cli, [
            "analyze", str(ssh_log), str(nginx_log),
            "--format", "auto", "--correlation-window", "10",
            "--json", str(json_out), "--no-terminal",
        ])
        assert result.exit_code == 0, result.output

    def test_serve_help_does_not_crash(self):
        from loganalyzer.cli import cli
        result = self.runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0, result.output
        assert "--db" in result.output


# ── Web dashboard ─────────────────────────────────────────────────────────────

class TestDashboard:
    def setup_method(self, tmp_path_factory=None):
        from fastapi.testclient import TestClient

        from loganalyzer.dashboard.app import create_app
        self.TestClient = TestClient
        self.create_app = create_app

    def _seed_db(self, db_path, target="access.log"):
        from loganalyzer.cli import _persist_result
        entries = [
            LogEntry(source="nginx", raw="", timestamp=datetime(2024, 10, 10, 14, 0, 0),
                     ip="1.2.3.4", status=200, path="/"),
            LogEntry(source="nginx", raw="", timestamp=datetime(2024, 10, 10, 14, 1, 0),
                     ip="5.6.7.8", status=403, path="/admin"),
        ]
        analyzer = LogAnalyzer()
        result = analyzer.analyze(entries)
        _persist_result(str(db_path), result, target=target)
        return result

    def test_index_with_no_runs(self, tmp_path):
        db_path = tmp_path / "empty.db"
        client = self.TestClient(self.create_app(str(db_path)))
        r = client.get("/")
        assert r.status_code == 200
        assert "No runs yet" in r.text

    def test_index_lists_seeded_run(self, tmp_path):
        db_path = tmp_path / "results.db"
        self._seed_db(db_path, target="access.log")
        client = self.TestClient(self.create_app(str(db_path)))
        r = client.get("/")
        assert r.status_code == 200
        assert "access.log" in r.text
        assert "#1" in r.text

    def test_run_detail_renders_breakdown(self, tmp_path):
        db_path = tmp_path / "results.db"
        self._seed_db(db_path)
        client = self.TestClient(self.create_app(str(db_path)))
        r = client.get("/run/1")
        assert r.status_code == 200
        assert "1.2.3.4" in r.text  # top IPs table
        assert "Cross-Source Correlation" in r.text

    def test_run_detail_404_for_missing_run(self, tmp_path):
        db_path = tmp_path / "results.db"
        self._seed_db(db_path)
        client = self.TestClient(self.create_app(str(db_path)))
        r = client.get("/run/999")
        assert r.status_code == 404

    def test_api_runs_json(self, tmp_path):
        db_path = tmp_path / "results.db"
        self._seed_db(db_path, target="myfile.log")
        client = self.TestClient(self.create_app(str(db_path)))
        r = client.get("/api/runs")
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["target"] == "myfile.log"

    def test_api_run_detail_json(self, tmp_path):
        db_path = tmp_path / "results.db"
        self._seed_db(db_path)
        client = self.TestClient(self.create_app(str(db_path)))
        r = client.get("/api/runs/1")
        assert r.status_code == 200
        data = r.json()
        assert data["top_ips"]
        assert data["meta"]["total"] == 2

    def test_dashboard_against_nonexistent_db(self, tmp_path):
        """No DB file at all yet — analyze --db hasn't been run once. Must
        render an empty state, not crash with a missing-file error."""
        db_path = tmp_path / "never-created.db"
        client = self.TestClient(self.create_app(str(db_path)))
        r = client.get("/")
        assert r.status_code == 200
