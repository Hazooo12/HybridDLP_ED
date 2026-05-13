"""
Environmental Score — Noteupdate §3.3.
EnvironmentalScore = 0.30*User + 0.20*Time + 0.25*Asset + 0.25*Destination
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from loguru import logger

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def _parse_ts(ctx: Dict[str, Any]) -> datetime | None:
    t = ctx.get("time")
    if t is None:
        return None
    if isinstance(t, (int, float)):
        return datetime.fromtimestamp(float(t), tz=timezone.utc)
    s = str(t).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def score_user_context(ctx: Dict[str, Any]) -> float:
    """0–10 — role/privilege ước lượng từ process / user string."""
    user = str(ctx.get("user") or "unknown").lower()
    proc = str(ctx.get("process_name") or "").lower()
    s = 1.8
    if any(x in proc for x in ("admin", "system", "root")):
        s += 3.5
    if user in {"system", "network service"}:
        s += 2.0
    return min(10.0, s)


def score_time_context(ctx: Dict[str, Any]) -> float:
    """0–10 — ngoài giờ làm việc tăng điểm."""
    dt = _parse_ts(ctx)
    if dt is None:
        return 1.8
    h = dt.hour
    wd = dt.weekday()
    if wd >= 5:
        return 7.5
    if h < 7 or h >= 20:
        return 6.5
    if h < 8 or h >= 19:
        return 4.5
    return 1.5


def score_asset_context(ctx: Dict[str, Any]) -> float:
    """0–10 — crown-jewel path / sensitive folder."""
    loc = str(ctx.get("location", "")).lower()
    s = 1.2
    for folder in WorkerConfig.SENSITIVE_EXFIL_FOLDERS:
        if folder and folder in loc:
            s += 4.5
            break
    if ctx.get("force_max_risk"):
        s = max(s, 9.0)
    return min(10.0, s)


def score_destination_environmental(ctx: Dict[str, Any]) -> float:
    """0–10 — đích môi trường (khác channel temparol)."""
    dest = str(ctx.get("destination") or "").lower()
    if not dest:
        return 1.2
    if any(k in dest for k in ("usb", "removable", "e:\\", "f:\\")):
        return 7.0
    if any(k in dest for k in ("http", "drive.google", "dropbox", "onedrive")):
        return 8.5
    if "\\\\" in dest:
        return 5.5
    return 2.8


def compute_environmental_score(event_context: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
    w = getattr(WorkerConfig, "CVSS_DLP_ENV_WEIGHTS", None) or {
        "user": 0.30,
        "time": 0.20,
        "asset": 0.25,
        "destination": 0.25,
    }
    u = score_user_context(event_context)
    t = score_time_context(event_context)
    a = score_asset_context(event_context)
    d = score_destination_environmental(event_context)

    env = w["user"] * u + w["time"] * t + w["asset"] * a + w["destination"] * d
    env = max(0.0, min(10.0, env))
    parts = {
        "user_context": round(u, 2),
        "time_context": round(t, 2),
        "asset_context": round(a, 2),
        "destination_context": round(d, 2),
        "environmental_score": round(env, 2),
    }
    logger.debug(f"CVSS-DLP Environmental: {parts}")
    return env, parts
