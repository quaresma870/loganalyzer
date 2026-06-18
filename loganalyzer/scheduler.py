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
    """
    try:
        import schedule
    except ImportError:
        raise RuntimeError("schedule package required: pip install schedule")

    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression (need 5 fields): {cron_expr!r}")

    minute, hour, _dom, _month, _dow = parts

    # Every N minutes: */N * * * *
    if minute.startswith("*/") and hour == "*":
        n = int(minute[2:])
        return schedule.every(n).minutes.do(job_fn)

    # Every N hours: 0 */N * * *
    if hour.startswith("*/") and minute == "0":
        n = int(hour[2:])
        return schedule.every(n).hours.do(job_fn)

    # Daily at specific time: MM HH * * *
    if minute.isdigit() and hour.isdigit():
        t = f"{int(hour):02d}:{int(minute):02d}"
        return schedule.every().day.at(t).do(job_fn)

    # Weekly: MM HH * * DOW (0=Monday)
    dow_map = {
        "0": "monday", "1": "tuesday", "2": "wednesday",
        "3": "thursday", "4": "friday", "5": "saturday", "6": "sunday",
    }
    if _dow in dow_map and minute.isdigit() and hour.isdigit():
        t = f"{int(hour):02d}:{int(minute):02d}"
        day_fn = getattr(schedule.every(), dow_map[_dow])
        return day_fn.at(t).do(job_fn)

    raise ValueError(f"Unsupported cron pattern: {cron_expr!r}. "
                     f"Supported: */N, HH:MM daily, HH:MM weekly (by weekday index).")


def run_schedule(
    files: tuple[str, ...],
    fmt: str,
    cron_expr: str,
    db: str | None,
    alert_webhook: str | None,
    top: int,
    geo: bool,
    output_dir: str | None,
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

        analyzer = LogAnalyzer(top_n=top, enable_geo=geo)
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
