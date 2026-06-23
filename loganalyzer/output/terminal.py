"""
Terminal output — rich-powered coloured tables and summaries.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from loganalyzer.analyzers import AnalysisResult

console = Console()


def _level_color(level: str) -> str:
    return {"CRITICAL": "bold red", "ERROR": "red", "WARNING": "yellow",
            "INFO": "green", "DEBUG": "dim"}.get(level, "white")


def print_summary(result: AnalysisResult, title: str = "Log Analysis Report") -> None:
    """Print a full analysis report to the terminal."""

    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]")
    console.print()

    # ── Overview ──────────────────────────────────────────────────────────────
    overview = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    overview.add_column("Key", style="bold")
    overview.add_column("Value")
    overview.add_row("Total entries", str(result.total))
    overview.add_row("Errors", f"[red]{result.errors}[/red]")
    overview.add_row("Warnings", f"[yellow]{result.warnings}[/yellow]")
    overview.add_row("Error rate", f"[{'red' if result.error_rate > 10 else 'green'}]{result.error_rate}%[/]")
    if result.start_time:
        overview.add_row("Period", f"{result.start_time:%Y-%m-%d %H:%M} → {result.end_time:%Y-%m-%d %H:%M}")  # type: ignore
    if result.sources:
        overview.add_row("Sources", ", ".join(result.sources))
    console.print(Panel(overview, title="Overview", border_style="cyan"))

    # ── Top IPs ───────────────────────────────────────────────────────────────
    if result.top_ips:
        t = Table(title="Top IPs", box=box.SIMPLE_HEAD, show_lines=True)
        t.add_column("Rank", style="dim", width=6)
        t.add_column("IP Address")
        t.add_column("Requests", justify="right")
        t.add_column("Bar", width=20)
        max_count = result.top_ips[0][1] if result.top_ips else 1
        for i, (ip, count) in enumerate(result.top_ips, 1):
            bar = "█" * int(count / max_count * 18)
            t.add_row(str(i), ip, str(count), f"[cyan]{bar}[/cyan]")
        console.print(t)

    # ── HTTP Status Codes ─────────────────────────────────────────────────────
    if result.top_status_codes:
        t = Table(title="HTTP Status Codes", box=box.SIMPLE_HEAD)
        t.add_column("Status", width=8)
        t.add_column("Count", justify="right")
        t.add_column("Type")
        for status, count in result.top_status_codes:
            if status >= 500:
                color, label = "red", "Server Error"
            elif status >= 400:
                color, label = "yellow", "Client Error"
            elif status >= 300:
                color, label = "cyan", "Redirect"
            else:
                color, label = "green", "Success"
            t.add_row(f"[{color}]{status}[/]", str(count), f"[{color}]{label}[/]")
        console.print(t)

    # ── Top Paths ─────────────────────────────────────────────────────────────
    if result.top_paths:
        t = Table(title="Top Paths", box=box.SIMPLE_HEAD)
        t.add_column("Path", overflow="fold")
        t.add_column("Hits", justify="right")
        for path, count in result.top_paths[:10]:
            t.add_row(path, str(count))
        console.print(t)

    # ── Temporal patterns ─────────────────────────────────────────────────────
    if result.by_hour:
        t = Table(title="Traffic by Hour", box=box.SIMPLE_HEAD)
        t.add_column("Hour", width=6)
        t.add_column("Requests", justify="right")
        t.add_column("Bar", width=30)
        max_h = max(result.by_hour.values()) if result.by_hour else 1
        for hour in range(24):
            count = result.by_hour.get(hour, 0)
            bar = "▓" * int(count / max_h * 28)
            style = "bold cyan" if hour == result.peak_hour else "dim"
            t.add_row(f"[{style}]{hour:02d}:00[/]", str(count), f"[cyan]{bar}[/cyan]")
        console.print(t)

    if result.by_weekday:
        t = Table(title="Traffic by Weekday", box=box.SIMPLE_HEAD)
        t.add_column("Day")
        t.add_column("Requests", justify="right")
        for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]:
            count = result.by_weekday.get(day, 0)
            # An empty style ("") produces an empty Rich markup tag "[]...[/]",
            # which Rich treats as having no openable tag at all — the
            # closing "[/]" then has nothing to close and raises
            # MarkupError on every single non-peak day, i.e. on every
            # real run with weekday data. Only wrap in markup when there's
            # an actual style to apply.
            label = f"[bold cyan]{day}[/]" if day == result.peak_weekday else day
            t.add_row(label, str(count))
        console.print(t)

    # ── Brute force ───────────────────────────────────────────────────────────
    if result.brute_force_ips:
        t = Table(title="⚠  Brute Force Suspects", box=box.SIMPLE_HEAD, border_style="red")
        t.add_column("IP")
        t.add_column("Type")
        t.add_column("Attempts", justify="right")
        t.add_column("Severity")
        for bf in result.brute_force_ips:
            sev = bf["severity"]
            color = "red" if sev == "HIGH" else "yellow"
            t.add_row(bf["ip"], bf["type"], str(bf["count"]), f"[{color}]{sev}[/]")
        console.print(t)

    # ── Anomalies ─────────────────────────────────────────────────────────────
    if result.anomalies:
        t = Table(title="⚠  Anomalies", box=box.SIMPLE_HEAD, border_style="yellow")
        t.add_column("Type")
        t.add_column("Description", overflow="fold")
        t.add_column("Severity")
        for a in result.anomalies:
            sev = a.get("severity", "LOW")
            color = "red" if sev == "HIGH" else "yellow"
            t.add_row(a["type"], a["description"], f"[{color}]{sev}[/]")
        console.print(t)

    # ── Cross-source correlation ─────────────────────────────────────────────
    if result.correlations:
        t = Table(title="⚠  Cross-Source Correlation", box=box.SIMPLE_HEAD, border_style="red")
        t.add_column("IP")
        t.add_column("SSH failures", justify="right")
        t.add_column("HTTP 4xx/error", justify="right")
        t.add_column("Closest gap", justify="right")
        t.add_column("Severity")
        for c in result.correlations:
            sev = c["severity"]
            color = "red" if sev == "HIGH" else "yellow"
            t.add_row(
                c["ip"], str(c["ssh_event_count"]), str(c["http_event_count"]),
                f"{c['closest_gap_minutes']} min", f"[{color}]{sev}[/]",
            )
        console.print(t)

    # ── Error spikes ──────────────────────────────────────────────────────────
    if result.spike_windows:
        t = Table(title="Error Spikes", box=box.SIMPLE_HEAD)
        t.add_column("Window")
        t.add_column("Errors", justify="right")
        t.add_column("Total", justify="right")
        t.add_column("Error Rate", justify="right")
        t.add_column("vs Average", justify="right")
        for spike in result.spike_windows[:5]:
            t.add_row(
                spike["window"], f"[red]{spike['errors']}[/red]",
                str(spike["total"]),
                f"[red]{spike['error_rate']}%[/red]",
                f"[yellow]{spike['vs_average']}x[/yellow]",
            )
        console.print(t)

    # ── Geo ───────────────────────────────────────────────────────────────────
    if result.geo:
        t = Table(title="IP Geolocation", box=box.SIMPLE_HEAD)
        t.add_column("IP")
        t.add_column("Country")
        t.add_column("City")
        t.add_column("ISP", overflow="fold")
        for g in result.geo[:15]:
            t.add_row(g["ip"], f"{g.get('country_code', '')} {g.get('country', '')}",
                      g.get("city", ""), g.get("isp", ""))
        console.print(t)

    console.rule("[dim]End of report[/dim]")
    console.print()


def print_watch_entry(entry_str: str, level: str) -> None:
    """Print a single log entry in watch mode."""
    color = _level_color(level)
    console.print(f"[{color}]{entry_str}[/]")
