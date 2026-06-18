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
@click.version_option("1.0.0", prog_name="loganalyzer")
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
              help="Enable IP geolocation lookup (requires internet).")
@click.option("--no-terminal", is_flag=True, default=False,
              help="Suppress terminal output (useful with --output / --json).")
def analyze(files, fmt, custom_config, output, json_out, top, geo, no_terminal, tail, db):
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

            all_lines = list(parser.parse_file(path))
            file_entries = all_lines[-tail:] if tail > 0 else all_lines
            console.print(f"[dim]Parsed[/dim] [bold]{len(file_entries)}[/bold] entries from [green]{path.name}[/green]")
            entries.extend(file_entries)
        except Exception as e:
            console.print(f"[red]Error parsing {path}: {e}[/red]")
            sys.exit(1)

    if not entries:
        console.print("[yellow]No entries parsed. Check the file format.[/yellow]")
        sys.exit(1)

    console.print(f"\n[bold]Analysing {len(entries)} total entries...[/bold]\n")
    analyzer = LogAnalyzer(top_n=top, enable_geo=geo)
    result = analyzer.analyze(entries)

    if db:
        _persist_result(db, result)

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



def _persist_result(db_path: str, result) -> None:
    """Persist analysis result to SQLite."""
    import json
    import sqlite3
    from datetime import datetime
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, timestamp TEXT, score_placeholder INTEGER,
        total INTEGER, errors INTEGER, warnings INTEGER,
        error_rate REAL, duration_ms REAL, sources TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER, plugin TEXT, title TEXT, severity TEXT,
        file TEXT, line INTEGER, message TEXT
    )""")
    cur = conn.execute(
        "INSERT INTO runs (target, timestamp, score_placeholder, total, errors, warnings, error_rate, duration_ms, sources) VALUES (?,?,?,?,?,?,?,?,?)",
        (result.target, result.start_time.isoformat() if result.start_time else datetime.utcnow().isoformat(),
         0, result.total, result.errors, result.warnings,
         result.error_rate, 0, json.dumps(result.sources))
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


def main():
    cli()


if __name__ == "__main__":
    main()
