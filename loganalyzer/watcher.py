"""
Watch mode — tail log files in real time and print new entries.
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console

from loganalyzer.parsers import BaseParser

console = Console()

_LEVEL_STYLE = {
    "CRITICAL": "bold red on dark_red",
    "ERROR": "bold red",
    "WARNING": "bold yellow",
    "INFO": "green",
    "DEBUG": "dim",
}


def watch(path: str | Path, parser: BaseParser, interval: float = 0.5) -> None:
    """
    Tail a log file and print new entries as they appear.
    Press Ctrl+C to stop.
    """
    path = Path(path)
    console.print(f"[bold cyan]👁  Watching[/bold cyan] [green]{path}[/green] — press [bold]Ctrl+C[/bold] to stop\n")

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            # Seek to end
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(interval)
                    continue
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                entry = parser.parse_line(line)
                if entry:
                    style = _LEVEL_STYLE.get(entry.level, "")
                    ts = entry.timestamp.strftime("%H:%M:%S") if entry.timestamp else "--:--:--"
                    ip = f" [dim]{entry.ip}[/dim]" if entry.ip else ""
                    status = f" [bold]{entry.status}[/bold]" if entry.status else ""
                    msg = entry.message or line[:120]
                    console.print(
                        f"[dim]{ts}[/dim]{ip}{status} [{style}]{entry.level}[/] {msg}"
                    )
                else:
                    console.print(f"[dim]{line[:160]}[/dim]")
    except KeyboardInterrupt:
        console.print("\n[bold cyan]Watch stopped.[/bold cyan]")
    except FileNotFoundError:
        console.print(f"[red]File not found: {path}[/red]")
