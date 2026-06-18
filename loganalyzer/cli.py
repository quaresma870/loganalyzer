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
from rich.console import Console

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
def analyze(files, fmt, custom_config, output, json_out, top, geo, no_terminal):
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
    analyzer = LogAnalyzer(top_n=top, enable_geo=geo)
    result = analyzer.analyze(entries)

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
def watch(file, fmt, custom_config, interval):
    """Watch a log file in real time (tail -f equivalent with parsing)."""
    path = Path(file)
    if fmt == "auto":
        parser = detect_parser(path)
    else:
        parser = get_parser(fmt, custom_config)
    watch_file(path, parser, interval=interval)


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


def main():
    cli()


if __name__ == "__main__":
    main()
