"""
LogAnalyzer CLI — entry point.

Usage examples:
  loganalyzer analyze /var/log/nginx/access.log
  loganalyzer analyze /var/log/nginx/access.log --format nginx --output report.html
  loganalyzer analyze *.log --format auto --json results.json
  loganalyzer watch /var/log/nginx/access.log --format nginx
  loganalyzer analyze app.log --format custom --custom-config myformat.yml
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.table import Table

from loganalyzer.analyzers import LogAnalyzer
from loganalyzer.output.html_output import write_html
from loganalyzer.output.json_output import write_json
from loganalyzer.output.terminal import print_summary
from loganalyzer.parsers import PARSERS, detect_parser, get_parser
from loganalyzer.watcher import watch as watch_file

console = Console()
PARSER_CHOICES = list(PARSERS.keys()) + ["custom", "auto"]


@click.group()
@click.version_option("1.1.0", prog_name="loganalyzer")
def cli():
    """📋 LogAnalyzer — parse, analyse and report on log files."""


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--format", "fmt", default="auto", show_default=True,
              type=click.Choice(PARSER_CHOICES, case_sensitive=False),
              help="Log format. 'auto' detects from filename.")
@click.option("--custom-config", type=click.Path(exists=True),
              help="YAML config for custom parser.")
@click.option("--output", "-o", type=click.Path(),
              help="Write HTML report to this file.")
@click.option("--json", "json_out", type=click.Path(),
              help="Write JSON results to this file.")
@click.option("--top", default=10, show_default=True,
              help="Number of top items to show.")
@click.option("--geo", is_flag=True, default=False,
              help="Enable IP geolocation lookup (requires internet, unless --geo-db is set).")
@click.option("--geo-db", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Path to a local MaxMind GeoLite2-City.mmdb file — looks up every IP "
                   "offline instead of the top 20 via the live ip-api.com call. Implies --geo.")
@click.option("--no-terminal", is_flag=True, default=False,
              help="Suppress terminal output (useful with --output / --json).")
@click.option("--tail", default=0, show_default=True,
              help="Keep only the last N parsed entries per file (constant memory). 0 = disabled.")
@click.option("--db", default=None, type=click.Path(),
              help="SQLite DB to persist this run's results.")
@click.option("--max-entries", default=0, show_default=True,
              help="Cap the total number of entries analysed across all files. 0 = unlimited.")
@click.option("--correlation-window", default=10, show_default=True,
              help="Minutes within which SSH-failure and HTTP 4xx/error events from the same "
                   "IP across different sources count as correlated. Only runs with 2+ sources.")
def analyze(files, fmt, custom_config, output, json_out, top, geo, geo_db, no_terminal, tail, db,
            max_entries, correlation_window):
    """Analyse one or more log files and produce a report."""
    entries = []

    for file_path in files:
        path = Path(file_path)
        try:
            if fmt == "auto":
                parser = detect_parser(path)
                console.print(f"[dim]Auto-detected parser:[/dim] [cyan]{parser.name}[/cyan] for [green]{path.name}[/green]")
            else:
                parser = get_parser(fmt, custom_config)

            if tail > 0:
                # For --tail: buffer only the last N entries (constant memory)
                from collections import deque
                buf: deque = deque(maxlen=tail)
                for entry in parser.parse_file(path):
                    buf.append(entry)
                file_entries = list(buf)
            else:
                # Full streaming — never loads all entries at once
                file_entries = list(parser.parse_file(path))
            console.print(f"[dim]Parsed[/dim] [bold]{len(file_entries)}[/bold] entries from [green]{path.name}[/green]")
            entries.extend(file_entries)
        except Exception as e:
            console.print(f"[red]Error parsing {path}: {e}[/red]")
            sys.exit(1)

    if not entries:
        console.print("[yellow]No entries parsed. Check the file format.[/yellow]")
        sys.exit(1)

    console.print(f"\n[bold]Analysing {len(entries)} total entries...[/bold]\n")
    analyzer = LogAnalyzer(top_n=top, enable_geo=geo or bool(geo_db), geo_db_path=geo_db,
                            correlation_window_minutes=correlation_window)
    result = analyzer.analyze(entries)

    # Cap entries if --max-entries set
    if max_entries > 0 and len(entries) > max_entries:
        entries = entries[:max_entries]
        console.print(f"[dim]  Capped to {max_entries} entries (--max-entries)[/dim]")

    if db:
        _persist_result(db, result, target=", ".join(str(f) for f in files))

    if not no_terminal:
        title = f"{files[0]} ({len(files)} files)" if len(files) > 1 else str(files[0])
        print_summary(result, title=title)

    if output:
        write_html(result, output)
        console.print(f"[green]✔[/green] HTML report saved: [bold]{output}[/bold]")

    if json_out:
        write_json(result, json_out)
        console.print(f"[green]✔[/green] JSON saved: [bold]{json_out}[/bold]")


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "fmt", default="auto", show_default=True,
              type=click.Choice(PARSER_CHOICES, case_sensitive=False),
              help="Log format.")
@click.option("--custom-config", type=click.Path(exists=True),
              help="YAML config for custom parser.")
@click.option("--interval", default=0.5, show_default=True,
              help="Poll interval in seconds.")
@click.option("--alert-webhook", default=None, help="Webhook URL for anomaly alerts.")
def watch(file, fmt, custom_config, interval, alert_webhook):
    """Watch a log file in real time (tail -f equivalent with parsing)."""
    path = Path(file)
    if fmt == "auto":
        parser = detect_parser(path)
    else:
        parser = get_parser(fmt, custom_config)
    watch_file(path, parser, interval=interval, alert_webhook=alert_webhook)


@cli.command(name="list-parsers")
def list_parsers():
    """List all available log parsers."""
    console.print("\n[bold]Available parsers:[/bold]\n")
    descriptions = {
        "nginx": "Nginx access and error logs",
        "apache": "Apache httpd access and error logs",
        "systemd": "systemd/journald logs (journalctl output)",
        "syslog": "Standard syslog format (/var/log/syslog, /var/log/messages)",
        "ssh": "SSH authentication logs (/var/log/auth.log, /var/log/secure)",
        "fail2ban": "Fail2ban log files",
        "browser": "Browser console logs exported as JSON",
        "har": "HTTP Archive (.har) files from browser DevTools",
        "custom": "Custom regex format defined in a YAML config file",
        "auto": "Auto-detect parser from filename (default)",
    }
    for name, desc in descriptions.items():
        console.print(f"  [cyan]{name:<12}[/cyan] {desc}")
    console.print()



def _persist_result(db_path: str, result, target: str) -> None:
    """Persist analysis result to SQLite — including the full result as
    JSON (result_json), which is what the web dashboard (`loganalyzer
    serve`) reads to render a run's full breakdown (top IPs, brute force,
    anomalies, correlations, geo, timeline — everything print_summary
    shows, not just the summary columns already in this table)."""
    import json
    import sqlite3
    from datetime import datetime

    from loganalyzer.output.json_output import to_dict
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, timestamp TEXT, score_placeholder INTEGER,
        total INTEGER, errors INTEGER, warnings INTEGER,
        error_rate REAL, duration_ms REAL, sources TEXT,
        result_json TEXT
    )""")
    # ALTER TABLE for any pre-existing DB created before result_json existed —
    # SQLite errors on a duplicate column, so check first rather than
    # try/except-ing a generic OperationalError that could mask something else.
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
    if "result_json" not in existing_cols:
        conn.execute("ALTER TABLE runs ADD COLUMN result_json TEXT")
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER, plugin TEXT, title TEXT, severity TEXT,
        file TEXT, line INTEGER, message TEXT
    )""")
    cur = conn.execute(
        "INSERT INTO runs (target, timestamp, score_placeholder, total, errors, warnings, "
        "error_rate, duration_ms, sources, result_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (target, result.start_time.isoformat() if result.start_time else datetime.utcnow().isoformat(),
         0, result.total, result.errors, result.warnings,
         result.error_rate, 0, json.dumps(result.sources),
         json.dumps(to_dict(result), default=str))
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    console.print(f"[green]✔[/green] Results saved to [bold]{db_path}[/bold] (run #{run_id})")


@cli.command()
@click.argument("db", type=click.Path(exists=True))
@click.option("--limit", default=10, show_default=True, help="Number of recent runs to show.")
def history(db, limit):
    """Show historical analysis runs from a SQLite database."""
    import sqlite3
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT id, target, timestamp, total, errors, error_rate FROM runs ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()

    if not rows:
        console.print("[yellow]No runs recorded yet.[/yellow]")
        return

    t = Table(title=f"Last {len(rows)} runs", box=box.SIMPLE_HEAD)
    t.add_column("#", width=5)
    t.add_column("Target", overflow="fold")
    t.add_column("Timestamp")
    t.add_column("Total", justify="right")
    t.add_column("Errors", justify="right")
    t.add_column("Error rate", justify="right")
    for row in rows:
        run_id, target, ts, total, errors, rate = row
        rate_color = "red" if (rate or 0) > 10 else "green"
        t.add_row(
            str(run_id), target, ts[:19],
            str(total), f"[red]{errors}[/red]",
            f"[{rate_color}]{rate:.1f}%[/]",
        )
    console.print(t)



@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--cron", required=True,
              help='Cron expression e.g. "*/15 * * * *" (every 15min), "0 6 * * 1" (Mon 06:00).')
@click.option("--format", "fmt", default="auto", show_default=True,
              type=click.Choice(PARSER_CHOICES, case_sensitive=False))
@click.option("--db", default=None, help="SQLite DB to persist each run.")
@click.option("--alert-webhook", default=None, help="Webhook URL for anomaly alerts.")
@click.option("--output-dir", default=None, help="Directory to write HTML reports.")
@click.option("--top", default=10, show_default=True)
@click.option("--geo", is_flag=True, default=False)
@click.option("--geo-db", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Path to a local MaxMind GeoLite2-City.mmdb file. Implies --geo.")
def schedule(files, cron, fmt, db, alert_webhook, output_dir, top, geo, geo_db):
    """Run log analysis on a cron schedule (runs immediately, then repeats)."""
    try:
        import schedule as _s  # noqa: F401
    except ImportError:
        console.print("[red]Install schedule: pip install schedule[/red]")
        return

    from loganalyzer.scheduler import run_schedule
    run_schedule(
        files=files, fmt=fmt, cron_expr=cron, db=db,
        alert_webhook=alert_webhook, top=top, geo=geo or bool(geo_db), output_dir=output_dir,
        geo_db=geo_db,
    )


@cli.command()
@click.option("--db", default="results.db", show_default=True,
              help="SQLite database with analysis history (written via `analyze --db`).")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
def serve(db, host, port):
    """Start the read-only web dashboard for analysis history."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn is required: pip install loganalyzer[dashboard][/red]")
        sys.exit(1)

    from loganalyzer.dashboard.app import create_app

    console.print(f"[bold cyan]📋 LogAnalyzer Dashboard[/bold cyan] → http://{host}:{port}")
    console.print(f"[dim]API docs:[/dim] http://{host}:{port}/docs\n")

    app = create_app(db)
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main():
    cli()


if __name__ == "__main__":
    main()
