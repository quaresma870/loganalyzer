# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v1.0.2
- feat: constant-memory streaming with `--tail N` using `deque(maxlen=N)` — closes #5
  (`parse_file()` is a generator; tail never loads the full file)
- feat: `--max-entries N` flag to cap memory usage on very large files — closes #5
- feat: Windows Event Log XML parser (`--format windows`) — closes #6
  (EventID 4625 → WARNING, 1102 → CRITICAL, auto-detect `.xml` files)
- feat: `loganalyzer schedule <files> --cron "*/15 * * * *"` scheduled mode — closes #7
  (runs immediately then repeats; persists to `--db`, sends `--alert-webhook` on anomalies)

### v1.0.1
- fix: watch mode detects log rotation via inode change — closes #2
- feat: `--alert-webhook URL` — POSTs JSON payload on ERROR/CRITICAL entries — closes #3
- feat: `--tail N` — analyse only last N lines — closes #1 (partial)
- feat: `--db path` — persist results to SQLite — closes #4
- feat: `loganalyzer history <db>` — historical runs with error rates — closes #4
