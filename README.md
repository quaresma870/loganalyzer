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
- ✅ **Cross-source correlation** — flags IPs with suspicious activity across more than one log source within a configurable time window (e.g. SSH brute-force correlated with nginx 4xx/error activity)
- ✅ **Temporal patterns** — traffic by hour and weekday
- ✅ **IP geolocation** — live lookup via ip-api.com, or fully offline via a local MaxMind GeoLite2 database (`--geo-db`, optional extra)
- ✅ **3 output formats** — rich terminal, JSON, self-contained HTML report with Chart.js
- ✅ **Watch mode** — real-time tail with `--watch`
- ✅ **Web dashboard** — read-only history viewer (`loganalyzer serve --db results.db`), optional extra
- ✅ **Custom parser** — define any log format via a YAML regex config
- ✅ **71 tests** — parsers, analyzers, and CLI command coverage

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

# Cross-source correlation — flags IPs active across BOTH files within
# the window (default 10 min); only runs when 2+ sources are present
python -m loganalyzer.cli analyze auth.log access.log --correlation-window 15

# Include IP geolocation — live API (requires internet, top 20 IPs only,
# subject to ip-api.com's free-tier rate limit)
python -m loganalyzer.cli analyze access.log --geo

# Include IP geolocation — offline, every IP, no network call, no data sent
# to a third party. Needs a free MaxMind GeoLite2-City.mmdb file:
# https://dev.maxmind.com/geoip/geolite2-free-geolocation-data (free account, no payment)
pip install loganalyzer[geoip]
python -m loganalyzer.cli analyze access.log --geo-db /path/to/GeoLite2-City.mmdb

# Keep only the last N entries per file (constant memory for huge files)
python -m loganalyzer.cli analyze huge.log --tail 10000

# Cap the total number of entries analysed
python -m loganalyzer.cli analyze access.log --max-entries 50000

# Persist this run's results to a SQLite DB, view history later
python -m loganalyzer.cli analyze access.log --db results.db
python -m loganalyzer.cli history results.db
```

### Watch mode (real-time)

```bash
python -m loganalyzer.cli watch /var/log/nginx/access.log
python -m loganalyzer.cli watch /var/log/auth.log --format ssh
```

### Web dashboard

Read-only viewer over your `--db` analysis history — no auth, since nothing
here mutates state or exposes anything sensitive enough to need it.

```bash
pip install loganalyzer[dashboard]

# Build up some history first
python -m loganalyzer.cli analyze access.log --db results.db
python -m loganalyzer.cli analyze auth.log --db results.db

# Then browse it
python -m loganalyzer.cli serve --db results.db
# → http://127.0.0.1:8080  (JSON API at /api/runs, /api/runs/{id})
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
| `windows` | Windows Event Log XML | `*.xml` |
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
- **Cross-source correlation** — IPs flagged across more than one log source within a time window
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
│   ├── dashboard/
│   │   └── app.py          # Read-only FastAPI dashboard — `loganalyzer serve`
│   └── output/
│       ├── terminal.py     # Rich terminal output
│       ├── json_output.py  # JSON serialiser
│       └── html_output.py  # Self-contained HTML with Chart.js
├── tests/
│   ├── test_loganalyzer.py # 71 tests — parsers, analyzers, CLI, dashboard
│   └── fixtures/
│       └── GeoLite2-City-Test.mmdb  # MaxMind's own test DB, Apache/MIT licensed
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

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

MIT
