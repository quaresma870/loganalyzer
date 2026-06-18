"""
Tests for parsers and analyzers.
"""

from __future__ import annotations

from datetime import datetime

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
