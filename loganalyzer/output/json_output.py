"""
JSON output — serialise AnalysisResult to JSON.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from loganalyzer.analyzers import AnalysisResult


def _serialise(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Not serialisable: {type(obj)}")


def to_dict(result: AnalysisResult) -> dict:
    return {
        "meta": {
            "total": result.total,
            "errors": result.errors,
            "warnings": result.warnings,
            "error_rate": result.error_rate,
            "start_time": result.start_time.isoformat() if result.start_time else None,
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "sources": result.sources,
        },
        "top_ips": [{"ip": ip, "count": c} for ip, c in result.top_ips],
        "top_error_ips": [{"ip": ip, "count": c} for ip, c in result.top_error_ips],
        "top_paths": [{"path": p, "count": c} for p, c in result.top_paths],
        "top_status_codes": [{"status": s, "count": c} for s, c in result.top_status_codes],
        "top_methods": [{"method": m, "count": c} for m, c in result.top_methods],
        "top_user_agents": [{"ua": ua, "count": c} for ua, c in result.top_user_agents],
        "brute_force": result.brute_force_ips,
        "anomalies": result.anomalies,
        "spike_windows": result.spike_windows,
        "temporal": {
            "by_hour": result.by_hour,
            "by_weekday": result.by_weekday,
            "peak_hour": result.peak_hour,
            "peak_weekday": result.peak_weekday,
        },
        "geo": result.geo,
        "banned_ips": [{"ip": ip, "count": c} for ip, c in result.banned_ips],
        "timeline": result.timeline,
    }


def write_json(result: AnalysisResult, path: str | Path) -> None:
    data = to_dict(result)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=_serialise)
