# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v1.0.3
- fix: **Windows Event Log entries lost their timestamp entirely** — `WindowsEventParser` used
  `element.find(a) or element.find(b)` to chain a namespaced XML lookup with a plain-tag fallback.
  ElementTree elements are falsy whenever they have zero CHILD elements, which describes nearly
  every meaningful single-value field in this XML format (`EventID`, `Level`, `TimeCreated`,
  `Channel` are all leaf elements) — so a correctly-found element was silently discarded and the
  lookup fell through to the (failing) fallback. Demonstrated with realistic, properly-namespaced
  Windows Event Log XML before fixing: `timestamp` came back `None` and `extra["channel"]` came
  back `None` for every single event, regardless of source data. This broke hourly/temporal
  analysis and day-of-week/hour-of-day pattern detection specifically for this log source (both
  silently exclude entries with no timestamp), and the live `watcher.py` tail display showed
  `--:--:--` instead of a real time for every Windows event. `level` happened to still work by
  accident, via an unrelated string-default fallback that coincidentally matched the test
  fixtures' values — masking the bug well enough that it went unnoticed through 31 previously-
  green tests, none of which asserted anything about the timestamp field specifically.
- fix: **browser console JSON log timestamps were also silently lost** — `BrowserConsoleParser`
  had an unrelated but similarly-shaped bug: `datetime.strptime(ts_raw[:19], fmt[:len(fmt)])` in a
  loop over candidate formats, where `fmt[:len(fmt)]` is a no-op slice (always equal to `fmt`
  itself) while the *data* was separately truncated to a fixed 19 characters — so formats
  expecting a literal trailing `Z` never matched data that had already had its `Z` sliced off.
  This broke the single most common real-world shape for this field (`new Date().toISOString()`
  in JavaScript, e.g. `"2024-10-10T13:55:36.123Z"`). The exact same typo existed in
  `WindowsEventParser`'s `TimeCreated`-attribute fallback path. Both replaced with
  `datetime.fromisoformat()` (handles the trailing `Z` and variable fractional-second precision
  natively in Python 3.11+), with `.replace(tzinfo=None)` to stay consistent with every other
  parser in this codebase, which produces naive datetimes — mixing naive and aware datetimes
  raises `TypeError` the moment two entries from different sources are sorted or compared together.
- test: 11 new tests — the timestamp and channel extraction regressions specifically (including a
  test that turns the underlying `DeprecationWarning` into a hard error, confirming it's gone, not
  just quietly logged), plus a full new test class for `BrowserConsoleParser`, which had zero test
  coverage at all before this.
- chore: removed leftover empty junk directories from an early shell command that didn't expand
  brace patterns as intended — never tracked in git, purely local clutter.
- chore: added a missing `.gitignore` (every other Python repo in this portfolio has one;
  this one didn't) and untracked the `__pycache__/*.pyc` files that had been committed as a
  result — compiled bytecode should never be version controlled.

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
