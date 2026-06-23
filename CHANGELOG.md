# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v1.1.0
- feat: **read-only web dashboard** (`loganalyzer serve --db results.db`, optional
  `pip install loganalyzer[dashboard]` extra) — browse analysis run history saved via
  `analyze --db`. No auth: nothing here mutates state or exposes anything sensitive enough to
  warrant it. Required extending the `runs` SQLite table with a `result_json` column (added via a
  safe `ALTER TABLE` that checks for the column first, so pre-existing databases from before this
  upgrade keep working) so the detail page can render the full breakdown — top IPs, brute force,
  correlations, anomalies, timeline — not just the summary columns that table already had.
- feat: **offline GeoIP lookup via a local MaxMind GeoLite2 database** (`--geo-db`, optional
  `pip install loganalyzer[geoip]` extra) — alongside the existing live `ip-api.com` lookup, not a
  replacement for it. No network call, no per-request rate limit, no IPs sent to a third party, and
  every IP gets looked up rather than just the top 20 (the live path's cap, there specifically to
  respect ip-api.com's free-tier limit). Verified against MaxMind's own published test database
  (`tests/fixtures/GeoLite2-City-Test.mmdb`, dual Apache/MIT licensed), not a mocked response.
- feat: **cross-source correlation** (`--correlation-window`, default 10 min) — flags IPs with
  suspicious activity across more than one log source within a short time window (e.g. an SSH
  brute-force IP that also shows up making 4xx/error requests against nginx shortly after).
  Deliberately narrow in scope: this one pairing only, not a general N-source correlation engine.
  Only runs when 2+ sources are actually present in a given run.
- **While building these, found and fixed five real, independent, pre-existing bugs** — none caused
  by this work, all surfaced by it because nothing had ever actually exercised these code paths
  for real before:
  - **`analyze`'s CLI command was completely non-functional** — its function signature listed
    `tail`/`db`/`max_entries` as parameters with zero corresponding `@click.option` decorators.
    Every single invocation raised `TypeError: missing 3 required positional arguments`. Nothing
    caught this because there was no test that actually invoked the CLI — every existing test
    called the underlying Python functions/classes directly, bypassing Click entirely.
  - **`watch`'s CLI command had the identical bug** for `alert_webhook` — even `--help` crashed.
  - **A `Rich.errors.MarkupError` crashed terminal output** on every run with weekday data, for
    every non-peak day: `style = "bold cyan" if day == peak_weekday else ""` produces an EMPTY
    markup tag (`"[]Monday[/]"`) for nearly every row, which Rich treats as having nothing to
    open — the closing `[/]` then has nothing to close. Fixed by only wrapping in markup when
    there's an actual style to apply, rather than ever emitting an empty tag pair.
  - **`--db` crashed with `AttributeError: 'AnalysisResult' object has no attribute 'target'`** —
    `_persist_result` referenced a field that doesn't exist on this dataclass (the `runs` table
    schema itself, including an unused `score_placeholder` column, looks like it was adapted from
    a different project's schema without being fully adapted). Fixed by passing the actually-
    analysed file path(s) through as `target` from the call site.
  - **nginx and apache parsers produced timezone-AWARE timestamps**, inconsistent with every other
    parser in this codebase (all naive) — their access-log format includes a UTC offset (`+0000`),
    and `%z` in `strptime` captures that into `tzinfo`. Mixing aware and naive datetimes raises
    `TypeError` the instant two entries from different sources are compared — exactly what
    correlation needs to do, which is how this surfaced. Fixed with `.replace(tzinfo=None)` in
    both parsers, matching the established naive-datetime convention everywhere else.
- test: 30 new tests (41 → 71) — 7 for offline GeoIP (real `.mmdb` lookups, private/unknown IP
  handling, missing-dependency degradation), 6 for correlation (window boundaries, single-source
  no-ops, missing-timestamp handling), 8 for the CLI bugs (`analyze`/`watch`/`serve` actually being
  invoked via `CliRunner` for the first time), 7 for the dashboard (empty state, seeded runs, 404,
  both JSON API endpoints), plus 2 timezone-naivety regression tests for nginx/apache.
- chore: synced `pyproject.toml`'s `version` field (was hardcoded `"1.0.0"` since the project's
  first release, never updated through v1.0.1–v1.0.3) and the CLI's `--version` output to match.

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
