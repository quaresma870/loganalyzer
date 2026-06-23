"""
Analyzers — process a list of LogEntry objects and return structured results.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from loganalyzer.models import LogEntry

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    total: int = 0
    errors: int = 0
    warnings: int = 0
    error_rate: float = 0.0

    # Top IPs
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_error_ips: list[tuple[str, int]] = field(default_factory=list)

    # HTTP
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    top_status_codes: list[tuple[int, int]] = field(default_factory=list)
    top_methods: list[tuple[str, int]] = field(default_factory=list)
    top_user_agents: list[tuple[str, int]] = field(default_factory=list)

    # Brute force
    brute_force_ips: list[dict] = field(default_factory=list)

    # Anomalies
    anomalies: list[dict] = field(default_factory=list)
    spike_windows: list[dict] = field(default_factory=list)

    # Temporal
    by_hour: dict[int, int] = field(default_factory=dict)
    by_weekday: dict[str, int] = field(default_factory=dict)
    peak_hour: int | None = None
    peak_weekday: str | None = None

    # Geo
    geo: list[dict] = field(default_factory=list)

    # Fail2ban
    banned_ips: list[tuple[str, int]] = field(default_factory=list)

    # Cross-source correlation
    correlations: list[dict] = field(default_factory=list)

    # Timeline (for HTML charts)
    timeline: list[dict] = field(default_factory=list)

    # Metadata
    start_time: datetime | None = None
    end_time: datetime | None = None
    sources: list[str] = field(default_factory=list)


# ── Main analyzer ─────────────────────────────────────────────────────────────

class LogAnalyzer:
    """
    Runs all analyses on a list of LogEntry objects.
    """

    # IPs with more than this many failures → brute force suspect
    BRUTE_FORCE_THRESHOLD = 10
    # Error spike: window exceeds this multiple of average → spike
    SPIKE_MULTIPLIER = 3.0
    # Minimum entries per hour-window to consider for spike
    SPIKE_MIN_ENTRIES = 5

    def __init__(self, top_n: int = 10, enable_geo: bool = False, geo_db_path: str | None = None,
                 correlation_window_minutes: int = 10):
        self.top_n = top_n
        self.enable_geo = enable_geo
        # Path to a local MaxMind GeoLite2-City.mmdb file. When set, geo
        # lookups happen offline (no network call, no rate limit, no IPs
        # sent to a third party, every IP looked up rather than just the
        # top 20) instead of the live ip-api.com call below.
        self.geo_db_path = geo_db_path
        # How close together (in minutes) events from DIFFERENT sources for
        # the same IP need to be to count as correlated — see
        # _detect_correlations below.
        self.correlation_window_minutes = correlation_window_minutes

    def analyze(self, entries: list[LogEntry]) -> AnalysisResult:
        result = AnalysisResult()
        if not entries:
            return result

        result.total = len(entries)
        result.sources = sorted({e.source for e in entries})

        # Timestamps
        timestamps = [e.timestamp for e in entries if e.timestamp]
        if timestamps:
            result.start_time = min(timestamps)
            result.end_time = max(timestamps)

        # Counts
        errors = [e for e in entries if e.level in ("ERROR", "CRITICAL")]
        warnings = [e for e in entries if e.level == "WARNING"]
        result.errors = len(errors)
        result.warnings = len(warnings)
        result.error_rate = round(len(errors) / result.total * 100, 2) if result.total else 0.0

        # Top IPs
        ip_counter: Counter = Counter(e.ip for e in entries if e.ip)
        result.top_ips = ip_counter.most_common(self.top_n)

        error_ip_counter: Counter = Counter(e.ip for e in errors if e.ip)
        result.top_error_ips = error_ip_counter.most_common(self.top_n)

        # HTTP stats
        path_counter: Counter = Counter(e.path for e in entries if e.path)
        result.top_paths = path_counter.most_common(self.top_n)

        status_counter: Counter = Counter(e.status for e in entries if e.status)
        result.top_status_codes = status_counter.most_common(self.top_n)

        method_counter: Counter = Counter(e.method for e in entries if e.method)
        result.top_methods = method_counter.most_common(self.top_n)

        ua_counter: Counter = Counter(e.user_agent for e in entries if e.user_agent)
        result.top_user_agents = ua_counter.most_common(self.top_n)

        # Brute force detection
        result.brute_force_ips = self._detect_brute_force(entries)

        # Anomaly detection
        result.anomalies = self._detect_anomalies(entries)
        result.spike_windows = self._detect_spikes(entries)

        # Temporal patterns
        hour_counter: Counter = Counter(e.hour for e in entries if e.hour is not None)
        result.by_hour = dict(sorted(hour_counter.items()))
        if hour_counter:
            result.peak_hour = hour_counter.most_common(1)[0][0]

        weekday_counter: Counter = Counter(e.weekday for e in entries if e.weekday)
        result.by_weekday = dict(weekday_counter)
        if weekday_counter:
            result.peak_weekday = weekday_counter.most_common(1)[0][0]

        # Fail2ban bans
        ban_counter: Counter = Counter(
            e.ip for e in entries
            if e.source == "fail2ban" and e.extra.get("event") == "ban" and e.ip
        )
        result.banned_ips = ban_counter.most_common(self.top_n)

        # Cross-source correlation — only meaningful with more than one source
        if len(result.sources) > 1:
            result.correlations = self._detect_correlations(entries)

        # Timeline (group by hour)
        result.timeline = self._build_timeline(entries)

        # Geo (optional, offline via a local GeoLite2 DB if configured,
        # otherwise the live ip-api.com lookup, requires network)
        if self.enable_geo:
            if self.geo_db_path:
                result.geo = self._lookup_geo_offline([ip for ip, _ in result.top_ips], self.geo_db_path)
            else:
                result.geo = self._lookup_geo([ip for ip, _ in result.top_ips[:20]])

        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _detect_brute_force(self, entries: list[LogEntry]) -> list[dict]:
        """Detect IPs with many failed auth attempts."""
        ssh_failures: Counter = Counter()
        http_failures: Counter = Counter()

        for e in entries:
            if not e.ip:
                continue
            # SSH brute force
            if e.source in ("ssh", "syslog", "systemd"):
                if e.extra.get("event") in ("failed",) or (
                    e.level in ("WARNING", "ERROR") and
                    any(k in e.message.lower() for k in ("failed", "invalid user", "authentication failure"))
                ):
                    ssh_failures[e.ip] += 1
            # HTTP brute force (many 401/403 from same IP)
            if e.status in (401, 403):
                http_failures[e.ip] += 1

        results = []
        for ip, count in ssh_failures.items():
            if count >= self.BRUTE_FORCE_THRESHOLD:
                results.append({"ip": ip, "type": "ssh_brute_force", "count": count,
                                 "severity": "HIGH" if count > 50 else "MEDIUM"})
        for ip, count in http_failures.items():
            if count >= self.BRUTE_FORCE_THRESHOLD:
                results.append({"ip": ip, "type": "http_brute_force", "count": count,
                                 "severity": "HIGH" if count > 50 else "MEDIUM"})

        return sorted(results, key=lambda x: x["count"], reverse=True)

    def _detect_correlations(self, entries: list[LogEntry]) -> list[dict]:
        """Flag IPs with suspicious activity across MORE THAN ONE log
        source within a short time window — e.g. an SSH brute-force IP
        that also shows up making 4xx/error requests against nginx shortly
        before or after. Deliberately narrow in scope for a first pass:
        only this one pairing (SSH auth failures <-> HTTP 4xx/error), not
        a general N-source correlation engine. Each source's events need a
        timestamp to be correlatable at all — entries with no timestamp
        are silently skipped here, not treated as a match.
        """
        window = timedelta(minutes=self.correlation_window_minutes)

        ssh_events: defaultdict = defaultdict(list)
        http_events: defaultdict = defaultdict(list)

        for e in entries:
            if not e.ip or not e.timestamp:
                continue
            if e.source in ("ssh", "syslog", "systemd") and (
                e.extra.get("event") == "failed" or (
                    e.level in ("WARNING", "ERROR") and
                    any(k in e.message.lower() for k in ("failed", "invalid user", "authentication failure"))
                )
            ):
                ssh_events[e.ip].append(e)
            if e.status and e.status >= 400:
                http_events[e.ip].append(e)

        correlated = []
        for ip in set(ssh_events) & set(http_events):
            ssh_times = sorted(e.timestamp for e in ssh_events[ip])
            http_times = sorted(e.timestamp for e in http_events[ip])

            # Two-pointer scan for the closest cross-source pair within window —
            # avoids an O(n*m) comparison for IPs with many events on both sides.
            best_gap = None
            i = j = 0
            while i < len(ssh_times) and j < len(http_times):
                gap = abs(ssh_times[i] - http_times[j])
                if best_gap is None or gap < best_gap:
                    best_gap = gap
                if ssh_times[i] < http_times[j]:
                    i += 1
                else:
                    j += 1

            if best_gap is not None and best_gap <= window:
                correlated.append({
                    "ip": ip,
                    "sources": ["ssh", "nginx/apache"],
                    "ssh_event_count": len(ssh_events[ip]),
                    "http_event_count": len(http_events[ip]),
                    "closest_gap_minutes": round(best_gap.total_seconds() / 60, 1),
                    "description": (
                        f"{ip}: {len(ssh_events[ip])} SSH auth failure(s) and "
                        f"{len(http_events[ip])} HTTP 4xx/error request(s), "
                        f"closest pair {round(best_gap.total_seconds() / 60, 1)} min apart"
                    ),
                    "severity": "HIGH" if len(ssh_events[ip]) >= self.BRUTE_FORCE_THRESHOLD else "MEDIUM",
                })

        return sorted(correlated, key=lambda x: x["closest_gap_minutes"])

    def _detect_anomalies(self, entries: list[LogEntry]) -> list[dict]:
        """Detect suspicious patterns."""
        anomalies = []
        ip_counter: Counter = Counter(e.ip for e in entries if e.ip)

        # Single IP with very high request count
        total = len(entries)
        for ip, count in ip_counter.most_common(5):
            pct = count / total * 100
            if pct > 20:
                anomalies.append({
                    "type": "high_volume_ip",
                    "ip": ip,
                    "count": count,
                    "pct": round(pct, 1),
                    "description": f"{ip} accounts for {pct:.1f}% of all requests",
                    "severity": "HIGH" if pct > 40 else "MEDIUM",
                })

        # High error rate
        error_count = sum(1 for e in entries if e.is_error)
        error_pct = error_count / total * 100 if total else 0
        if error_pct > 10:
            anomalies.append({
                "type": "high_error_rate",
                "count": error_count,
                "pct": round(error_pct, 1),
                "description": f"Error rate is {error_pct:.1f}% ({error_count}/{total})",
                "severity": "HIGH" if error_pct > 25 else "MEDIUM",
            })

        # Scanner/bot detection via path patterns
        scan_paths = re.compile(
            r'(\.env|\.git|wp-admin|wp-login|phpmyadmin|\.php|/etc/passwd|'
            r'eval\(|base64_decode|union\s+select|<script)', re.I
        )
        scan_hits: Counter = Counter()
        for e in entries:
            if e.path and scan_paths.search(e.path):
                if e.ip:
                    scan_hits[e.ip] += 1

        for ip, count in scan_hits.most_common(5):
            if count >= 3:
                anomalies.append({
                    "type": "scanner_detected",
                    "ip": ip,
                    "count": count,
                    "description": f"{ip} appears to be scanning for vulnerabilities ({count} hits)",
                    "severity": "HIGH",
                })

        return anomalies

    def _detect_spikes(self, entries: list[LogEntry]) -> list[dict]:
        """Detect error spikes in time windows."""
        # Group errors by hour
        hour_errors: defaultdict = defaultdict(int)
        hour_totals: defaultdict = defaultdict(int)

        for e in entries:
            if e.timestamp:
                key = e.timestamp.strftime("%Y-%m-%d %H:00")
                hour_totals[key] += 1
                if e.is_error:
                    hour_errors[key] += 1

        if not hour_totals:
            return []

        avg_errors = sum(hour_errors.values()) / len(hour_totals) if hour_totals else 0
        spikes = []

        for window, total in hour_totals.items():
            if total < self.SPIKE_MIN_ENTRIES:
                continue
            errors = hour_errors.get(window, 0)
            if avg_errors > 0 and errors > avg_errors * self.SPIKE_MULTIPLIER and errors >= 3:
                spikes.append({
                    "window": window,
                    "errors": errors,
                    "total": total,
                    "error_rate": round(errors / total * 100, 1),
                    "vs_average": round(errors / avg_errors, 1),
                })

        return sorted(spikes, key=lambda x: x["errors"], reverse=True)

    def _build_timeline(self, entries: list[LogEntry]) -> list[dict]:
        """Build hourly timeline for charts."""
        buckets: defaultdict = defaultdict(lambda: {"total": 0, "errors": 0, "warnings": 0})
        for e in entries:
            if not e.timestamp:
                continue
            key = e.timestamp.strftime("%Y-%m-%d %H:00")
            buckets[key]["total"] += 1
            if e.level in ("ERROR", "CRITICAL"):
                buckets[key]["errors"] += 1
            elif e.level == "WARNING":
                buckets[key]["warnings"] += 1

        return [{"time": k, **v} for k, v in sorted(buckets.items())]

    def _lookup_geo_offline(self, ips: list[str], db_path: str) -> list[dict]:
        """Lookup geo info for IPs using a local MaxMind GeoLite2-City.mmdb
        file — no network call, no per-request rate limit, no IPs sent to
        a third party, and not capped to the top 20 the live API path uses
        to stay within ip-api.com's free-tier limits.

        Get the free database (requires a free MaxMind account, no
        payment): https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
        """
        try:
            import geoip2.database
            import geoip2.errors
        except ImportError:
            return []

        results = []
        try:
            reader = geoip2.database.Reader(db_path)
        except Exception:
            # Bad path / corrupt file — degrade gracefully rather than
            # crashing the whole analysis over an optional enrichment step.
            return []

        try:
            for ip in ips:
                try:
                    obj = ipaddress.ip_address(ip)
                    if obj.is_private or obj.is_loopback or obj.is_reserved:
                        continue
                except ValueError:
                    continue

                try:
                    city = reader.city(ip)
                except geoip2.errors.AddressNotFoundError:
                    continue
                except Exception:
                    continue

                results.append({
                    "ip": ip,
                    "country": city.country.name,
                    "country_code": city.country.iso_code,
                    "city": city.city.name,
                    "isp": None,  # GeoLite2-City doesn't include ISP; that's a separate MaxMind product
                })
        finally:
            reader.close()

        return results

    def _lookup_geo(self, ips: list[str]) -> list[dict]:
        """Lookup geo info for IPs using ip-api.com (free, no key needed)."""
        try:
            import requests
        except ImportError:
            return []

        results = []
        # Filter out private IPs
        public_ips = []
        for ip in ips:
            try:
                obj = ipaddress.ip_address(ip)
                if not (obj.is_private or obj.is_loopback or obj.is_reserved):
                    public_ips.append(ip)
            except ValueError:
                continue

        if not public_ips:
            return []

        # Batch API (max 100 per request)
        try:
            resp = requests.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "fields": "status,country,countryCode,city,isp,query"} for ip in public_ips[:100]],
                timeout=10,
            )
            if resp.status_code == 200:
                for item in resp.json():
                    if item.get("status") == "success":
                        results.append({
                            "ip": item["query"],
                            "country": item.get("country"),
                            "country_code": item.get("countryCode"),
                            "city": item.get("city"),
                            "isp": item.get("isp"),
                        })
        except Exception:
            pass

        return results
