"""
Watch mode — tail log files in real time with log rotation support.
Detects inode changes caused by logrotate (move + recreate).
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console

from loganalyzer.parsers import BaseParser

console = Console()

_LEVEL_STYLE = {
    "CRITICAL": "bold red on dark_red",
    "ERROR":    "bold red",
    "WARNING":  "bold yellow",
    "INFO":     "green",
    "DEBUG":    "dim",
}


def _get_inode(path: Path) -> int | None:
    try:
        return path.stat().st_ino
    except OSError:
        return None


def watch(
    path: str | Path,
    parser: BaseParser,
    interval: float = 0.5,
    alert_webhook: str | None = None,
) -> None:
    """
    Tail a log file and print new entries as they appear.
    Handles log rotation: detects inode change and reopens the new file.
    Press Ctrl+C to stop.
    """
    path = Path(path)
    console.print(
        f"[bold cyan]👁  Watching[/bold cyan] [green]{path}[/green] "
        f"— press [bold]Ctrl+C[/bold] to stop\n"
    )

    def _open_file():
        f = open(path, encoding="utf-8", errors="replace")
        f.seek(0, 2)  # seek to end
        return f, _get_inode(path)

    try:
        f, current_inode = _open_file()
        while True:
            line = f.readline()
            if not line:
                time.sleep(interval)
                # Check for inode change (log rotation)
                new_inode = _get_inode(path)
                if new_inode and new_inode != current_inode:
                    console.print("[dim]  ↻ Log rotated — reopening file[/dim]")
                    f.close()
                    time.sleep(0.1)  # brief wait for new file to be written
                    f, current_inode = _open_file()
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
                # Alert webhook on errors
                if alert_webhook and entry.is_error:
                    _send_alert(alert_webhook, entry)
            else:
                console.print(f"[dim]{line[:160]}[/dim]")

    except KeyboardInterrupt:
        console.print("\n[bold cyan]Watch stopped.[/bold cyan]")
    except FileNotFoundError:
        console.print(f"[red]File not found: {path}[/red]")
    finally:
        try:
            f.close()
        except Exception:
            pass


def _send_alert(webhook_url: str, entry) -> None:
    """POST a JSON alert to a webhook URL (fire-and-forget)."""
    import json
    import urllib.request

    payload = json.dumps({
        "level": entry.level,
        "source": entry.source,
        "message": entry.message,
        "ip": entry.ip,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
    }).encode()
    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass  # never crash the watcher on alert failure
