# 📋 LogAnalyzer

[![CI](https://github.com/quaresma870/loganalyzer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/quaresma870/loganalyzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Parse, analyse and report on log files from the command line. Supports multiple formats, detects anomalies and brute force attempts, and generates HTML reports with charts.

---

## Features

- ✅ **9 parsers** — nginx, apache, systemd, syslog, SSH auth, fail2ban, browser console, HAR, custom regex
- ✅ **Auto-detection** — detects format from filename
- ✅ **Anomaly detection** — high-volume IPs, scanner detection, error rate spikes
- ✅ **Brute force detection** — SSH and HTTP auth failures per IP
- ✅ **Temporal patterns** — traffic by hour and weekday
- ✅ **IP geolocation** — optional lookup via ip-api.com
- ✅ **3 output formats** — rich terminal, JSON, self-contained HTML report with Chart.js
- ✅ **Watch mode** — real-time tail with `--watch`
- ✅ **Custom parser** — define any log format via a YAML regex config
- ✅ **23 tests** — full parser and analyzer coverage

---

## Installation

```bash
git clone https://github.com/quaresma870/loganalyzer.git
cd loganalyzer
pip install -r requirements.txt
```

---

## Usage

### Analyse a log file

```bash
# Auto-detect format
python -m loganalyzer.cli analyze /var/log/nginx/access.log

# Specify format explicitly
python -m loganalyzer.cli analyze /var/log/auth.log --format ssh

# Generate HTML report
python -m loganalyzer.cli analyze access.log --output report.html

# Export to JSON
python -m loganalyzer.cli analyze access.log --json results.json

# Multiple files at once
python -m loganalyzer.cli analyze nginx.log apache.log --format auto

# Include IP geolocation (requires internet)
python -m loganalyzer.cli analyze access.log --geo
```

### Watch mode (real-time)

```bash
python -m loganalyzer.cli watch /var/log/nginx/access.log
python -m loganalyzer.cli watch /var/log/auth.log --format ssh
```

### List available parsers

```bash
python -m loganalyzer.cli list-parsers
```

---

## Supported formats

| Parser | Format | Auto-detect |
|--------|--------|-------------|
| `nginx` | Access + error logs | `*nginx*` |
| `apache` | Combined access + error | `*apache*`, `*httpd*` |
| `systemd` | journalctl output | `*journal*`, `*systemd*` |
| `syslog` | Standard syslog | `*syslog*`, `*messages*` |
| `ssh` | SSH auth logs | `*auth*`, `*secure*`, `*ssh*` |
| `fail2ban` | Fail2ban log | `*fail2ban*` |
| `browser` | Browser console JSON | `*.json` |
| `har` | HTTP Archive | `*.har` |
| `custom` | User-defined YAML regex | — |

---

## Custom parser

Create a YAML config file:

```yaml
name: myapp
pattern: '(?P<ip>\S+) (?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<message>.+)'
time_field: time
time_format: '%Y-%m-%dT%H:%M:%S'
level_field: level
ip_field: ip
message_field: message
level_map:
  debug: DEBUG
  info: INFO
  warn: WARNING
  error: ERROR
  fatal: CRITICAL
```

```bash
python -m loganalyzer.cli analyze app.log --format custom --custom-config myformat.yml
```

---

## Analysis output

Each run produces:

- **Top IPs** by request volume and error count
- **HTTP stats** — status codes, methods, paths
- **Brute force suspects** — IPs exceeding failure thresholds
- **Anomalies** — high-volume IPs, scanner patterns, high error rates
- **Error spikes** — time windows where errors exceeded 3× the average
- **Temporal patterns** — requests by hour and weekday
- **IP geolocation** — country, city, ISP (optional)
- **Timeline** — hourly request/error chart (HTML report)

---

## Project structure

```
loganalyzer/
├── loganalyzer/
│   ├── cli.py              # Click CLI entry point
│   ├── models.py           # LogEntry dataclass
│   ├── watcher.py          # --watch real-time tail
│   ├── parsers/
│   │   ├── base.py         # BaseParser abstract class
│   │   ├── nginx.py        # Nginx access + error
│   │   ├── apache.py       # Apache access + error
│   │   └── extras.py       # systemd, syslog, ssh, fail2ban, browser, har, custom
│   ├── analyzers/
│   │   └── __init__.py     # LogAnalyzer + AnalysisResult
│   └── output/
│       ├── terminal.py     # Rich terminal output
│       ├── json_output.py  # JSON serialiser
│       └── html_output.py  # Self-contained HTML with Chart.js
├── tests/
│   └── test_loganalyzer.py # 23 tests
├── .github/workflows/ci.yml
├── requirements.txt
└── pyproject.toml
```

---

## Running tests

```bash
PYTHONPATH=. pytest tests/ -v
```

---

## License

MIT
