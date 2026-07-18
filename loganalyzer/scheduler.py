"""
Scheduler — runs log analysis on a cron schedule.
Uses the `schedule` library for cron-like execution.
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console

console = Console()


def _parse_cron_to_schedule(cron_expr: str, job_fn):
    """
    Map a simplified cron expression to a schedule job.
    Supports: */N (every N minutes/hours), specific values, * (any).
    Full cron: minute hour day_of_month month day_of_week

    Same reasoning and fix already applied in the sibling secureaudit and
    redteam-toolkit repos, which share this exact cron-parsing pattern —
    confirmed here for real (not assumed from the sibling repos' fixes
    alone) before fixing: both bugs reproduced through the real installed
    CLI first.
    """
    try:
        import schedule
    except ImportError:
        raise RuntimeError("schedule package required: pip install schedule") from None

    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression (need 5 fields): {cron_expr!r}")

    minute, hour, _dom, _month, _dow = parts

    try:
        # Every N minutes: */N * * * *
        if minute.startswith("*/") and hour == "*":
            n = _parse_positive_int(minute[2:], "minute interval (the N in '*/N')")
            return schedule.every(n).minutes.do(job_fn)

        # Every N hours: 0 */N * * *
        if hour.startswith("*/") and minute == "0":
            n = _parse_positive_int(hour[2:], "hour interval (the N in '*/N')")
            return schedule.every(n).hours.do(job_fn)

        # Daily at specific time: MM HH * * *
        if minute.isdigit() and hour.isdigit():
            h, m = _parse_time_of_day(hour, minute)
            return schedule.every().day.at(f"{h:02d}:{m:02d}").do(job_fn)

        # Weekly: MM HH * * DOW (0=Monday)
        dow_map = {
            "0": "monday", "1": "tuesday", "2": "wednesday",
            "3": "thursday", "4": "friday", "5": "saturday", "6": "sunday",
        }
        if _dow in dow_map and minute.isdigit() and hour.isdigit():
            h, m = _parse_time_of_day(hour, minute)
            day_fn = getattr(schedule.every(), dow_map[_dow])
            return day_fn.at(f"{h:02d}:{m:02d}").do(job_fn)
    except schedule.ScheduleError as exc:
        # Belt-and-suspenders: the explicit validation above (positive
        # intervals, in-range hour/minute) already catches the specific
        # cases confirmed real, but converting any OTHER schedule-library
        # error into the same ValueError type here means callers only
        # ever need to catch one exception type for "this cron
        # expression was bad."
        raise ValueError(str(exc)) from exc

    raise ValueError(f"Unsupported cron pattern: {cron_expr!r}. "
                     f"Supported: */N, HH:MM daily, HH:MM weekly (by weekday index).")


def _parse_positive_int(raw: str, field_desc: str) -> int:
    """Validates a '*/N' interval field. Confirmed by actually
    reproducing this for real: schedule.every(0).minutes (an N of
    exactly 0, e.g. from a typo'd '*/0 * * * *') doesn't raise — it
    hangs the process indefinitely inside the schedule library's own
    internal next-run computation, a real denial-of-service for anyone
    who fat-fingers a zero into the interval. Rejecting N<1 here, before
    the value ever reaches schedule.every(), turns that hang into an
    immediate, clear error instead."""
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"Invalid {field_desc}: {raw!r} is not an integer") from None
    if value < 1:
        raise ValueError(
            f"Invalid {field_desc}: {value} — must be a positive integer "
            f"(an interval of 0 or less would never (or always) fire)"
        )
    return value


def _parse_time_of_day(hour: str, minute: str) -> tuple[int, int]:
    """Validates an HH:MM time-of-day pair is in range. Confirmed by
    actually reproducing this for real: an out-of-range value (e.g.
    hour=25 or minute=60) is NOT caught by isdigit() (both are valid
    digit strings), and previously reached the `schedule` library's own
    at() call, which raises schedule.ScheduleValueError — NOT a subclass
    of ValueError, producing a raw, unhandled traceback through the real
    installed CLI instead of a clean error message."""
    h, m = int(hour), int(minute)
    if not (0 <= h <= 23):
        raise ValueError(f"Invalid hour: {h} — must be 0-23")
    if not (0 <= m <= 59):
        raise ValueError(f"Invalid minute: {m} — must be 0-59")
    return h, m


def run_schedule(
    files: tuple[str, ...],
    fmt: str,
    cron_expr: str,
    db: str | None,
    alert_webhook: str | None,
    top: int,
    geo: bool,
    output_dir: str | None,
    geo_db: str | None = None,
) -> None:
    """Run log analysis on a cron schedule until Ctrl+C."""
    try:
        import schedule
    except ImportError:
        console.print("[red]schedule package required: pip install schedule[/red]")
        return

    from loganalyzer.analyzers import LogAnalyzer
    from loganalyzer.output.terminal import print_summary
    from loganalyzer.parsers import detect_parser, get_parser
    run_count = [0]

    def job():
        run_count[0] += 1
        console.rule(f"[cyan]Scheduled run #{run_count[0]}[/cyan]")
        entries = []
        for f in files:
            path = Path(f)
            parser = detect_parser(path) if fmt == "auto" else get_parser(fmt)
            entries.extend(parser.parse_file(path))

        if not entries:
            console.print("[yellow]No entries parsed.[/yellow]")
            return

        analyzer = LogAnalyzer(top_n=top, enable_geo=geo or bool(geo_db), geo_db_path=geo_db)
        result = analyzer.analyze(entries)
        print_summary(result)

        if db:
            from loganalyzer.reports.history import save
            run_id = save(result, db)
            console.print(f"[green]✔[/green] Saved (run #{run_id})")

        if output_dir:
            import datetime as dt
            ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            out = Path(output_dir) / f"report_{ts}.html"
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            from loganalyzer.output.html_output import write_html
            write_html(result, out)
            console.print(f"[green]✔[/green] HTML: {out}")

        # Alert on anomalies
        if alert_webhook and (result.anomalies or result.brute_force_ips):
            import json
            import urllib.request
            payload = json.dumps({
                "run": run_count[0],
                "score": result.score if hasattr(result, "score") else None,
                "anomalies": len(result.anomalies),
                "brute_force": len(result.brute_force_ips),
                "errors": result.errors,
                "total": result.total,
            }).encode()
            try:
                req = urllib.request.Request(
                    alert_webhook, data=payload,
                    headers={"Content-Type": "application/json"}, method="POST"
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

    _parse_cron_to_schedule(cron_expr, job)
    console.print(f"[bold cyan]⏱  Scheduled:[/bold cyan] [green]{cron_expr}[/green] — press Ctrl+C to stop\n")

    # Run immediately on start
    job()

    try:
        while True:
            schedule.run_pending()
            time.sleep(30)
    except KeyboardInterrupt:
        console.print("\n[bold cyan]Scheduler stopped.[/bold cyan]")
