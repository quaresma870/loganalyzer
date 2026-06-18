"""
HTML report — self-contained report with Chart.js charts (no server needed).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from loganalyzer.analyzers import AnalysisResult
from loganalyzer.output.json_output import to_dict

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LogAnalyzer Report — {title}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
    --accent: #4f8ef7; --error: #ef4444; --warn: #f59e0b;
    --ok: #22c55e; --text: #e2e8f0; --muted: #64748b;
    --font: 'Segoe UI', system-ui, sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  h1 {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); margin-bottom: .25rem; }}
  h2 {{ font-size: 1.1rem; font-weight: 600; color: var(--text); margin-bottom: 1rem; }}
  .subtitle {{ color: var(--muted); font-size: .9rem; margin-bottom: 2rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; }}
  .stat {{ font-size: 2.2rem; font-weight: 700; }}
  .stat.error {{ color: var(--error); }}
  .stat.warn {{ color: var(--warn); }}
  .stat.ok {{ color: var(--ok); }}
  .stat-label {{ color: var(--muted); font-size: .85rem; margin-top: .25rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
  th {{ text-align: left; padding: .6rem .75rem; color: var(--muted); font-weight: 500;
        border-bottom: 1px solid var(--border); }}
  td {{ padding: .55rem .75rem; border-bottom: 1px solid #1f2230; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
  .badge.high {{ background: #3f1010; color: var(--error); }}
  .badge.medium {{ background: #3f2a00; color: var(--warn); }}
  .badge.low {{ background: #0f2a1a; color: var(--ok); }}
  .badge.ok {{ background: #0f2a1a; color: var(--ok); }}
  .badge.err {{ background: #3f1010; color: var(--error); }}
  .badge.warn {{ background: #3f2a00; color: var(--warn); }}
  .chart-wrap {{ position: relative; height: 260px; }}
  .section {{ margin-bottom: 2rem; }}
  .anomaly {{ background: #1e1020; border-left: 3px solid var(--error); padding: .75rem 1rem;
              border-radius: 0 6px 6px 0; margin-bottom: .5rem; }}
  .anomaly .desc {{ font-size: .9rem; }}
  .anomaly .sev {{ font-size: .75rem; color: var(--error); font-weight: 600; }}
  footer {{ color: var(--muted); font-size: .8rem; margin-top: 3rem; text-align: center; }}
</style>
</head>
<body>
<h1>📊 LogAnalyzer Report</h1>
<p class="subtitle">Generated {generated} &nbsp;|&nbsp; Period: {period} &nbsp;|&nbsp; Sources: {sources}</p>

<!-- Overview stats -->
<div class="grid">
  <div class="card">
    <div class="stat">{total}</div>
    <div class="stat-label">Total log entries</div>
  </div>
  <div class="card">
    <div class="stat error">{errors}</div>
    <div class="stat-label">Errors &amp; Critical</div>
  </div>
  <div class="card">
    <div class="stat warn">{warnings}</div>
    <div class="stat-label">Warnings</div>
  </div>
  <div class="card">
    <div class="stat {error_rate_class}">{error_rate}%</div>
    <div class="stat-label">Error rate</div>
  </div>
</div>

<!-- Timeline chart -->
{timeline_section}

<!-- Two-column charts -->
<div class="grid section">
  <div class="card">
    <h2>Traffic by Hour</h2>
    <div class="chart-wrap"><canvas id="hourChart"></canvas></div>
  </div>
  <div class="card">
    <h2>Traffic by Weekday</h2>
    <div class="chart-wrap"><canvas id="weekdayChart"></canvas></div>
  </div>
</div>

<div class="grid section">
  <div class="card">
    <h2>HTTP Status Codes</h2>
    <div class="chart-wrap"><canvas id="statusChart"></canvas></div>
  </div>
  <div class="card">
    <h2>HTTP Methods</h2>
    <div class="chart-wrap"><canvas id="methodChart"></canvas></div>
  </div>
</div>

<!-- Tables -->
<div class="grid section">
  <div class="card">
    <h2>Top IPs</h2>
    <table>
      <tr><th>#</th><th>IP</th><th>Requests</th></tr>
      {top_ips_rows}
    </table>
  </div>
  <div class="card">
    <h2>Top Error IPs</h2>
    <table>
      <tr><th>#</th><th>IP</th><th>Errors</th></tr>
      {top_error_ip_rows}
    </table>
  </div>
</div>

<div class="card section">
  <h2>Top Paths</h2>
  <table>
    <tr><th>Path</th><th>Hits</th></tr>
    {top_path_rows}
  </table>
</div>

<!-- Anomalies & Brute Force -->
{anomaly_section}
{brute_force_section}
{spike_section}
{geo_section}

<footer>LogAnalyzer &nbsp;|&nbsp; {generated}</footer>

<script>
const DATA = {json_data};

// Timeline
{timeline_js}

// Hour chart
new Chart(document.getElementById('hourChart'), {{
  type: 'bar',
  data: {{
    labels: Array.from({{length: 24}}, (_, i) => `${{String(i).padStart(2,'0')}}:00`),
    datasets: [{{
      label: 'Requests',
      data: Array.from({{length: 24}}, (_, i) => DATA.temporal.by_hour[i] || 0),
      backgroundColor: '#4f8ef7aa',
      borderColor: '#4f8ef7',
      borderWidth: 1,
    }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ x: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }} }} }},
               y: {{ ticks: {{ color: '#64748b' }} }} }} }}
}});

// Weekday chart
const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
new Chart(document.getElementById('weekdayChart'), {{
  type: 'bar',
  data: {{
    labels: days,
    datasets: [{{
      label: 'Requests',
      data: days.map(d => DATA.temporal.by_weekday[d] || 0),
      backgroundColor: '#22c55e88',
      borderColor: '#22c55e',
      borderWidth: 1,
    }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ x: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }} }} }},
               y: {{ ticks: {{ color: '#64748b' }} }} }} }}
}});

// Status codes
const statusData = DATA.top_status_codes.slice(0, 8);
new Chart(document.getElementById('statusChart'), {{
  type: 'doughnut',
  data: {{
    labels: statusData.map(s => String(s.status)),
    datasets: [{{
      data: statusData.map(s => s.count),
      backgroundColor: statusData.map(s => s.status >= 500 ? '#ef444488' : s.status >= 400 ? '#f59e0b88' : '#22c55e88'),
      borderColor: statusData.map(s => s.status >= 500 ? '#ef4444' : s.status >= 400 ? '#f59e0b' : '#22c55e'),
      borderWidth: 1,
    }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ labels: {{ color: '#e2e8f0', font: {{ size: 11 }} }} }} }} }}
}});

// Methods
const methodData = DATA.top_methods.slice(0, 6);
new Chart(document.getElementById('methodChart'), {{
  type: 'pie',
  data: {{
    labels: methodData.map(m => m.method),
    datasets: [{{
      data: methodData.map(m => m.count),
      backgroundColor: ['#4f8ef788','#22c55e88','#f59e0b88','#a855f788','#ef444488','#06b6d488'],
      borderWidth: 1,
    }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ labels: {{ color: '#e2e8f0' }} }} }} }}
}});
</script>
</body>
</html>"""

_TIMELINE_SECTION = """
<div class="card section">
  <h2>Request Timeline</h2>
  <div class="chart-wrap" style="height:200px"><canvas id="timelineChart"></canvas></div>
</div>"""

_TIMELINE_JS = """
const tlData = DATA.timeline;
new Chart(document.getElementById('timelineChart'), {
  type: 'line',
  data: {
    labels: tlData.map(d => d.time),
    datasets: [
      { label: 'Total', data: tlData.map(d => d.total), borderColor: '#4f8ef7', backgroundColor: '#4f8ef722', fill: true, tension: 0.3, pointRadius: 2 },
      { label: 'Errors', data: tlData.map(d => d.errors), borderColor: '#ef4444', backgroundColor: '#ef444422', fill: true, tension: 0.3, pointRadius: 2 },
    ]
  },
  options: { responsive: true, maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#e2e8f0' } } },
    scales: { x: { ticks: { color: '#64748b', maxTicksLimit: 12 } }, y: { ticks: { color: '#64748b' } } } }
});"""


def write_html(result: AnalysisResult, path: str | Path, title: str = "Analysis") -> None:
    data = to_dict(result)
    json_data = json.dumps(data, default=str)

    period = "—"
    if result.start_time and result.end_time:
        period = f"{result.start_time:%Y-%m-%d %H:%M} → {result.end_time:%Y-%m-%d %H:%M}"

    error_rate_class = "error" if result.error_rate > 10 else ("warn" if result.error_rate > 5 else "ok")

    # Top IPs rows
    top_ips_rows = "\n".join(
        f"<tr><td>{i}</td><td>{ip}</td><td>{c}</td></tr>"
        for i, (ip, c) in enumerate(result.top_ips[:10], 1)
    )
    top_error_ip_rows = "\n".join(
        f"<tr><td>{i}</td><td>{ip}</td><td>{c}</td></tr>"
        for i, (ip, c) in enumerate(result.top_error_ips[:10], 1)
    )
    top_path_rows = "\n".join(
        f"<tr><td style='font-family:monospace;font-size:.85rem'>{p}</td><td>{c}</td></tr>"
        for p, c in result.top_paths[:15]
    )

    # Anomalies
    anomaly_section = ""
    if result.anomalies or result.brute_force_ips:
        rows = ""
        for a in result.anomalies:
            sev = a.get("severity", "LOW").lower()
            rows += f'<div class="anomaly"><div class="sev">{sev.upper()}</div><div class="desc">{a["description"]}</div></div>\n'
        if rows:
            anomaly_section = f'<div class="card section"><h2>⚠ Anomalies</h2>{rows}</div>'

    brute_force_section = ""
    if result.brute_force_ips:
        rows = '<table><tr><th>IP</th><th>Type</th><th>Attempts</th><th>Severity</th></tr>'
        for bf in result.brute_force_ips:
            sev = bf["severity"].lower()
            rows += f'<tr><td>{bf["ip"]}</td><td>{bf["type"]}</td><td>{bf["count"]}</td><td><span class="badge {sev}">{bf["severity"]}</span></td></tr>'
        rows += "</table>"
        brute_force_section = f'<div class="card section"><h2>🔐 Brute Force Suspects</h2>{rows}</div>'

    spike_section = ""
    if result.spike_windows:
        rows = '<table><tr><th>Window</th><th>Errors</th><th>Total</th><th>Error Rate</th><th>vs Avg</th></tr>'
        for s in result.spike_windows[:5]:
            rows += f'<tr><td>{s["window"]}</td><td style="color:var(--error)">{s["errors"]}</td><td>{s["total"]}</td><td>{s["error_rate"]}%</td><td>{s["vs_average"]}x</td></tr>'
        rows += "</table>"
        spike_section = f'<div class="card section"><h2>📈 Error Spikes</h2>{rows}</div>'

    geo_section = ""
    if result.geo:
        rows = '<table><tr><th>IP</th><th>Country</th><th>City</th><th>ISP</th></tr>'
        for g in result.geo[:20]:
            rows += f'<tr><td>{g["ip"]}</td><td>{g.get("country_code","")} {g.get("country","")}</td><td>{g.get("city","")}</td><td>{g.get("isp","")}</td></tr>'
        rows += "</table>"
        geo_section = f'<div class="card section"><h2>🌍 IP Geolocation</h2>{rows}</div>'

    timeline_section = _TIMELINE_SECTION if result.timeline else ""
    timeline_js = _TIMELINE_JS if result.timeline else ""

    html = _TEMPLATE.format(
        title=title,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        period=period,
        sources=", ".join(result.sources) or "—",
        total=result.total,
        errors=result.errors,
        warnings=result.warnings,
        error_rate=result.error_rate,
        error_rate_class=error_rate_class,
        top_ips_rows=top_ips_rows,
        top_error_ip_rows=top_error_ip_rows,
        top_path_rows=top_path_rows,
        anomaly_section=anomaly_section,
        brute_force_section=brute_force_section,
        spike_section=spike_section,
        geo_section=geo_section,
        timeline_section=timeline_section,
        timeline_js=timeline_js,
        json_data=json_data,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
