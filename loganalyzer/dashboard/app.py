"""
LogAnalyzer web dashboard — FastAPI, read-only.
Start with: loganalyzer serve --db results.db

Reads the same SQLite history `loganalyzer analyze --db results.db` already
writes (see cli.py's _persist_result) — nothing new to persist, this just
renders what's already there. No write endpoints, no auth needed: there's
nothing here that mutates state or exposes anything sensitive enough to
warrant the token-gating secureaudit's dashboard needs for its scan-trigger
endpoints.
"""

from __future__ import annotations

import json
import sqlite3

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

_CSS = """
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--accent:#4f8ef7;
--text:#e2e8f0;--muted:#64748b;--critical:#ef4444;--high:#f97316;
--medium:#f59e0b;--low:#3b82f6;--ok:#22c55e;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;padding:2rem}
h1{font-size:1.6rem;font-weight:700;color:var(--accent);margin-bottom:.25rem}
h2{font-size:1rem;font-weight:600;margin-bottom:.75rem}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{text-align:left;padding:.5rem .75rem;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)}
td{padding:.5rem .75rem;border-bottom:1px solid #1f2230}
tr:last-child td{border:none}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin-bottom:1rem}
.stat{font-size:1.8rem;font-weight:800}
.badge{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.72rem;font-weight:700}
.HIGH,.CRITICAL{background:#3f1010;color:var(--critical)}
.MEDIUM{background:#3f2a00;color:var(--medium)}
.LOW{background:#0c1f3f;color:var(--low)}
footer{color:var(--muted);font-size:.75rem;margin-top:2rem;text-align:center}
</style>
"""


def _get_runs(db_path: str, limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, target, timestamp, total, errors, warnings, error_rate, sources "
            "FROM runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # table doesn't exist yet — no runs persisted at all
    finally:
        conn.close()
    return [dict(r) for r in rows]


def _get_run_result(db_path: str, run_id: int) -> dict | None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, target, timestamp, result_json FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()
    if not row or not row["result_json"]:
        return None
    data = json.loads(row["result_json"])
    data["_id"] = row["id"]
    data["_target"] = row["target"]
    data["_timestamp"] = row["timestamp"]
    return data


def create_app(db_path: str) -> FastAPI:
    app = FastAPI(title="LogAnalyzer Dashboard")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        runs = _get_runs(db_path)
        rows = ""
        for r in runs:
            rate_color = "critical" if r["error_rate"] > 10 else "ok"
            sources = ", ".join(json.loads(r["sources"])) if r["sources"] else "—"
            rows += (
                f'<tr><td><a href="/run/{r["id"]}">#{r["id"]}</a></td>'
                f'<td style="max-width:240px;overflow:hidden;text-overflow:ellipsis">{r["target"]}</td>'
                f'<td>{(r["timestamp"] or "")[:16]}</td>'
                f'<td>{sources}</td>'
                f'<td>{r["total"]}</td>'
                f'<td style="color:var(--{rate_color})">{r["error_rate"]}%</td></tr>\n'
            )
        if not rows:
            rows = (
                '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem">'
                "No runs yet. Run: <code>loganalyzer analyze access.log --db results.db</code>"
                "</td></tr>"
            )

        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>LogAnalyzer Dashboard</title>{_CSS}</head><body>
<h1>📋 LogAnalyzer</h1>
<p class="sub">Analysis run history — <a href="/api/runs">JSON API</a></p>
<div class="card">
<h2>Runs</h2>
<table><tr><th>#</th><th>Target</th><th>Timestamp</th><th>Sources</th><th>Total</th><th>Error rate</th></tr>
{rows}</table></div>
<footer>LogAnalyzer Dashboard — read-only, no auth (nothing here mutates state)</footer>
</body></html>""")

    @app.get("/run/{run_id}", response_class=HTMLResponse)
    async def run_detail(run_id: int):
        data = _get_run_result(db_path, run_id)
        if not data:
            raise HTTPException(status_code=404, detail="Run not found")

        meta = data["meta"]

        ip_rows = "".join(
            f'<tr><td>{i["ip"]}</td><td>{i["count"]}</td></tr>\n' for i in data["top_ips"][:15]
        ) or '<tr><td colspan="2" style="color:var(--muted)">No data</td></tr>'

        bf_rows = "".join(
            f'<tr><td>{b["ip"]}</td><td>{b["type"]}</td><td>{b["count"]}</td>'
            f'<td><span class="badge {b["severity"]}">{b["severity"]}</span></td></tr>\n'
            for b in data["brute_force"]
        ) or '<tr><td colspan="4" style="color:var(--ok)">None detected</td></tr>'

        corr_rows = "".join(
            f'<tr><td>{c["ip"]}</td><td>{c["ssh_event_count"]}</td><td>{c["http_event_count"]}</td>'
            f'<td>{c["closest_gap_minutes"]} min</td>'
            f'<td><span class="badge {c["severity"]}">{c["severity"]}</span></td></tr>\n'
            for c in data.get("correlations", [])
        ) or '<tr><td colspan="5" style="color:var(--ok)">None detected</td></tr>'

        anomaly_rows = "".join(
            f'<tr><td>{a["type"]}</td><td>{a["description"]}</td>'
            f'<td><span class="badge {a.get("severity", "LOW")}">{a.get("severity", "LOW")}</span></td></tr>\n'
            for a in data["anomalies"]
        ) or '<tr><td colspan="3" style="color:var(--ok)">None detected</td></tr>'

        timeline = data.get("timeline", [])
        labels = [t["time"] for t in timeline]
        totals = [t["total"] for t in timeline]
        errors = [t["errors"] for t in timeline]

        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Run #{run_id} — LogAnalyzer</title>{_CSS}
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head><body>
<p><a href="/">← Back</a></p>
<h1>Run #{run_id}</h1>
<p class="sub">{data["_target"]} — {(data["_timestamp"] or "")[:16]}</p>
<div class="card" style="display:flex;gap:2.5rem;align-items:center">
  <div><div class="stat">{meta["total"]}</div><div style="color:var(--muted)">Total entries</div></div>
  <div><div class="stat" style="color:var(--critical)">{meta["errors"]}</div><div style="color:var(--muted)">Errors</div></div>
  <div><div class="stat" style="color:var(--medium)">{meta["warnings"]}</div><div style="color:var(--muted)">Warnings</div></div>
  <div><div class="stat">{meta["error_rate"]}%</div><div style="color:var(--muted)">Error rate</div></div>
  <div><div class="stat" style="font-size:1.1rem;color:var(--muted)">{", ".join(meta["sources"])}</div><div style="color:var(--muted)">Sources</div></div>
</div>
<div class="card">
<h2>Timeline</h2>
<div style="height:220px;position:relative"><canvas id="timelineChart"></canvas></div>
</div>
<div class="card"><h2>Top IPs</h2>
<table><tr><th>IP</th><th>Requests</th></tr>{ip_rows}</table></div>
<div class="card"><h2>🔐 Brute Force Suspects</h2>
<table><tr><th>IP</th><th>Type</th><th>Attempts</th><th>Severity</th></tr>{bf_rows}</table></div>
<div class="card"><h2>🔗 Cross-Source Correlation</h2>
<table><tr><th>IP</th><th>SSH failures</th><th>HTTP 4xx/error</th><th>Closest gap</th><th>Severity</th></tr>{corr_rows}</table></div>
<div class="card"><h2>⚠ Anomalies</h2>
<table><tr><th>Type</th><th>Description</th><th>Severity</th></tr>{anomaly_rows}</table></div>
<footer>LogAnalyzer Dashboard</footer>
<script>
new Chart(document.getElementById('timelineChart'), {{
  type: 'line',
  data: {{
    labels: {labels!r},
    datasets: [
      {{ label: 'Total', data: {totals!r}, borderColor: '#4f8ef7', backgroundColor: '#4f8ef722', fill: true, tension: 0.3 }},
      {{ label: 'Errors', data: {errors!r}, borderColor: '#ef4444', backgroundColor: '#ef444422', fill: true, tension: 0.3 }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    scales: {{ y: {{ ticks: {{ color: '#64748b' }} }}, x: {{ ticks: {{ color: '#64748b' }} }} }},
    plugins: {{ legend: {{ labels: {{ color: '#e2e8f0' }} }} }}
  }}
}});
</script>
</body></html>""")

    @app.get("/api/runs")
    async def api_runs(limit: int = 20):
        return JSONResponse(_get_runs(db_path, limit=limit))

    @app.get("/api/runs/{run_id}")
    async def api_run_detail(run_id: int):
        data = _get_run_result(db_path, run_id)
        if not data:
            raise HTTPException(status_code=404, detail="Run not found")
        return JSONResponse(data)

    return app
