"""
Exfiltration Temparol (U/P/A/X) — Noteupdate §3.2, §5.
TemparolScore = Channel + Concealment + Volume + Destination + Anomaly (signal groups)
Map: 0–24→U, 25–54→P, 55+→A; thiếu telemetry → X
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple

from loguru import logger

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def _event_data(ctx: Dict[str, Any]) -> Dict[str, Any]:
    ed = ctx.get("_event_data")
    return ed if isinstance(ed, dict) else {}


def _action_and_dest(ctx: Dict[str, Any]) -> Tuple[str, str]:
    at = str(ctx.get("action_type") or "").lower()
    dest = str(ctx.get("destination") or "").lower()
    src = str(ctx.get("source") or "").lower()
    return at, dest + " " + src


def _whole_token(hay: str, token: str) -> bool:
    """Khớp token tách biệt — tránh 'sync' trong 'async', 'mail' trong 'gmail'."""
    if not hay or not token:
        return False
    return re.search(
        r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])",
        hay,
        flags=re.IGNORECASE,
    ) is not None


def score_channel(ctx: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Nhóm 1 — kênh exfil (Noteupdate §5.1)."""
    reasons: List[str] = []
    at, combined = _action_and_dest(ctx)
    s = 0.0

    if "usb" in at or "removable" in combined or "usb" in combined:
        s += 2.0
        reasons.append("channel_usb")
    if "clipboard" in at or "clipboard" in combined:
        s += 1.0
        reasons.append("channel_clipboard")
    if "print" in at:
        s += 1.5
        reasons.append("channel_print")
    if any(x in at for x in ("upload", "browser", "http")) or "upload" in combined:
        s += 3.0
        reasons.append("channel_browser_upload")
    if "email" in at or "smtp" in combined or _whole_token(combined, "mail"):
        s += 3.0
        reasons.append("channel_email")
    if (
        _whole_token(combined, "network")
        or _whole_token(combined, "cloud")
        or _whole_token(combined, "sync")
    ):
        s += 2.8
        reasons.append("channel_network_cloud")

    ev = _event_data(ctx)
    et = str(ev.get("type") or "").lower()
    if et.startswith("corr_") and "upload" in et:
        s += 2.5
        reasons.append("channel_correlated_upload")

    return min(3.5, s), reasons


def score_concealment(fast_scan_result: Dict[str, Any], ctx: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Nhóm 2 — che giấu / evasion."""
    reasons: List[str] = []
    s = 0.0
    if fast_scan_result.get("is_encrypted_zip"):
        s += 2.0
        reasons.append("concealment_password_archive")
    ft = str(fast_scan_result.get("file_type") or "").lower()
    if "archive" in ft or "zip" in ft or "rar" in ft:
        s += 1.0
        reasons.append("concealment_archive")
    obj = _event_data(ctx).get("object")
    if isinstance(obj, dict):
        ext = str(obj.get("ext") or "").lower()
        name = str(obj.get("name") or "").lower()
        if ext in (".tmp", ".dat", ".bin") and any(c in name for c in (".doc", ".xls", ".pdf")):
            s += 1.0
            reasons.append("concealment_masquerade_ext")
    return min(4.0, s), reasons


def score_volume(ctx: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Nhóm 3 — volume (single + bulk window)."""
    reasons: List[str] = []
    s = 0.0
    mb = float(ctx.get("file_size_mb") or 0)
    if mb > 100:
        s += 1.5
        reasons.append("volume_large_file")
    elif mb > 50:
        s += 0.8
        reasons.append("volume_medium_file")

    # Bulk transfer window (from worker aggregation)
    try:
        bulk_files = int(ctx.get("bulk_file_count_window") or 0)
    except Exception:
        bulk_files = 0
    try:
        bulk_mb = float(ctx.get("bulk_total_mb_window") or 0.0)
    except Exception:
        bulk_mb = 0.0
    try:
        cfg_min_files = int(getattr(WorkerConfig, "BULK_EXFIL_MIN_FILES", 10))
    except Exception:
        cfg_min_files = 10
    try:
        cfg_min_mb = float(getattr(WorkerConfig, "BULK_EXFIL_MIN_TOTAL_MB", 100.0))
    except Exception:
        cfg_min_mb = 100.0

    # Primary thresholds align with demo trigger (default: 10 files / 100MB)
    if bulk_files >= max(2 * cfg_min_files, cfg_min_files + 5):
        s += 1.2
        reasons.append("volume_bulk_many_files")
    elif bulk_files >= cfg_min_files:
        s += 0.6
        reasons.append("volume_bulk_some_files")
    if bulk_mb >= max(5.0 * cfg_min_mb, cfg_min_mb + 200.0):
        s += 1.3
        reasons.append("volume_bulk_very_large_total")
    elif bulk_mb >= cfg_min_mb:
        s += 0.8
        reasons.append("volume_bulk_large_total")

    return min(2.5, s), reasons


def score_destination_ctx(ctx: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Nhóm 4 — hướng / đích."""
    reasons: List[str] = []
    s = 0.0
    dest = str(ctx.get("destination") or "").lower()
    if not dest.strip():
        return 0.0, reasons
    external_kw = ("http", "https", "drive.google", "dropbox", "onedrive", "wetransfer", "mega", "telegram")
    if any(k in dest for k in external_kw):
        s += 2.5
        reasons.append("destination_confirmed_external")
    elif "\\\\" in dest or "//" in dest:
        s += 1.2
        reasons.append("destination_network_path")
    return min(3.0, s), reasons


def score_anomaly_signal(ctx: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Nhóm 5 — anomaly (Noteupdate §5.1)."""
    reasons: List[str] = []
    s = 0.0
    ml = float(ctx.get("ml_anomaly_score") or 0.0)
    if ml >= 7.0:
        s += 2.0
        reasons.append("anomaly_high")
    elif ml >= 4.0:
        s += 1.0
        reasons.append("anomaly_medium")
    if ctx.get("ml_is_anomaly"):
        s = max(s, 1.5)
        reasons.append("anomaly_flag")
    return min(2.5, s), reasons


def telemetry_insufficient(ctx: Dict[str, Any]) -> bool:
    """EM:X — telemetry thiếu (Noteupdate §3.2.2)."""
    if ctx.get("telemetry_insufficient") or ctx.get("cvss_dlp_em_unknown"):
        return True
    if os.getenv("NETWORK_SENSOR_ENABLED", "1").strip().lower() in {"0", "false", "off", "no"}:
        at, _ = _action_and_dest(ctx)
        if "upload" in at or "network" in str(ctx.get("source", "")).lower():
            return True
    return False


def compute_exfiltration_temparol(
    fast_scan_result: Dict[str, Any],
    event_context: Dict[str, Any],
) -> Dict[str, Any]:
    ch, r_ch = score_channel(event_context)
    co, r_co = score_concealment(fast_scan_result, event_context)
    vo, r_vo = score_volume(event_context)
    de, r_de = score_destination_ctx(event_context)
    an, r_an = score_anomaly_signal(event_context)

    raw_sum = ch + co + vo + de + an
    reasons = list(dict.fromkeys(r_ch + r_co + r_vo + r_de + r_an))

    unknown = telemetry_insufficient(event_context)
    if unknown:
        em_code = "X"
        temparol_band = "unknown_telemetry"
    elif raw_sum <= 2.4:
        em_code = "U"
        temparol_band = "preliminary"
    elif raw_sum <= 5.4:
        em_code = "P"
        temparol_band = "suspicious_attempt"
    else:
        em_code = "A"
        temparol_band = "active_exfiltration"

    level_scores = getattr(WorkerConfig, "CVSS_DLP_TEMPAROL_LEVEL_SCORES", None) or {
        "U": 2.0,
        "P": 5.0,
        "A": 8.5,
        "X": 3.5,
    }
    temparol_numeric = float(level_scores.get(em_code, 3.5))

    em_factors = getattr(WorkerConfig, "CVSS_DLP_EM_FACTORS", None) or {
        "U": 0.85,
        "P": 1.0,
        "A": 1.25,
        "X": 0.95,
    }
    em_factor = float(em_factors.get(em_code, 1.0))

    out = {
        "exfiltration_temparol": em_code,
        "temparol_band": temparol_band,
        "temparol_score": round(raw_sum, 2),
        "temparol_numeric": temparol_numeric,
        "em_factor": em_factor,
        "channel_score": round(ch, 2),
        "concealment_score": round(co, 2),
        "volume_score": round(vo, 2),
        "destination_score": round(de, 2),
        "anomaly_score_component": round(an, 2),
        "reason_codes": reasons,
        "telemetry_unknown": unknown,
    }
    logger.debug(f"CVSS-DLP EM: {em_code} raw={raw_sum}")
    return out
