"""
Parser registry — auto-detect format or select by name.
"""

from __future__ import annotations

from pathlib import Path

from loganalyzer.parsers.apache import ApacheParser
from loganalyzer.parsers.base import BaseParser
from loganalyzer.parsers.extras import (
    BrowserConsoleParser,
    CustomParser,
    Fail2banParser,
    HARParser,
    SSHParser,
    SyslogParser,
    SystemdParser,
    WindowsEventParser,
)
from loganalyzer.parsers.nginx import NginxParser

PARSERS: dict[str, type[BaseParser]] = {
    "nginx": NginxParser,
    "apache": ApacheParser,
    "systemd": SystemdParser,
    "syslog": SyslogParser,
    "ssh": SSHParser,
    "fail2ban": Fail2banParser,
    "browser": BrowserConsoleParser,
    "har": HARParser,
    "windows": WindowsEventParser,
}


def get_parser(name: str, custom_config: str | None = None) -> BaseParser:
    """Return a parser instance by name."""
    if name == "custom":
        if not custom_config:
            raise ValueError("Custom parser requires --custom-config path")
        return CustomParser(custom_config)
    if name not in PARSERS:
        raise ValueError(f"Unknown parser '{name}'. Available: {', '.join(PARSERS)}, custom")
    return PARSERS[name]()


def detect_parser(path: str | Path) -> BaseParser:
    """Auto-detect parser from file name/extension."""
    name = Path(path).name.lower()
    if name.endswith(".har"):
        return HARParser()
    if name.endswith(".xml"):
        # Could be Windows Event Log — check content
        return WindowsEventParser()
    if name.endswith(".json"):
        return BrowserConsoleParser()
    if "nginx" in name:
        return NginxParser()
    if "apache" in name or "httpd" in name:
        return ApacheParser()
    if "auth" in name or "secure" in name or "ssh" in name:
        return SSHParser()
    if "fail2ban" in name:
        return Fail2banParser()
    if "syslog" in name or "messages" in name:
        return SyslogParser()
    if "journal" in name or "systemd" in name:
        return SystemdParser()
    # Default: try nginx (most common)
    return NginxParser()


__all__ = [
    "PARSERS", "get_parser", "detect_parser",
    "NginxParser", "ApacheParser", "SystemdParser", "SyslogParser",
    "SSHParser", "Fail2banParser", "BrowserConsoleParser", "HARParser", "CustomParser",
]
