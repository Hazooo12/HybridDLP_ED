"""
Base Score — CVSS-inspired DLP (Noteupdate §3.1).
BaseScore = 0.35*ContentSensitivity + 0.25*DataCriticality + 0.25*BehaviorAnomaly + 0.15*Confidence
"""
from __future__ import annotations

import re
from typing import Any, Dict, Tuple

from loguru import logger

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def _clamp(v: float, lo: float = 0.0, hi: float = 10.0) -> float:
    return max(lo, min(hi, float(v)))


def _event_data(ctx: Dict[str, Any]) -> Dict[str, Any]:
    ed = ctx.get("_event_data")
    return ed if isinstance(ed, dict) else {}


# Tránh false positive: "src" trong "...\source\...", "mat" trong "...information...".
_STRICT_PATH_KEYWORDS = frozenset({"src", "hr", "mat"})


def _path_keyword_hit(path: str, kw: str) -> bool:
    """Khớp theo tên segment đường dẫn, không dùng substring trên cả chuỗi path."""
    if not path or not kw:
        return False
    lowered = path.lower()
    kw = kw.lower()
    segments = [p for p in re.split(r"[\\/]+", lowered) if p]
    for seg in segments:
        base = seg.split(".", 1)[0]
        if kw in _STRICT_PATH_KEYWORDS:
            if base == kw or base.startswith(f"{kw}_") or base.endswith(f"_{kw}"):
                return True
            continue
        if kw in base or base.startswith(f"{kw}_") or base.endswith(f"_{kw}"):
            return True
    return False


def compute_content_sensitivity(
    fast_scan_result: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
    event_context: Dict[str, Any],
) -> float:
    """0–10 từ YARA, IOC, deep is_sensitive."""
    score = 0.0
    event_data = _event_data(event_context)
    action_type = str(event_context.get("action_type") or "").lower()
    source = str(event_context.get("source") or "").lower()
    location = str(event_context.get("location") or "").lower()
    is_clipboard_event = bool(event_context.get("is_clipboard_paste")) or any(
        x in action_type for x in ("clipboard", "paste")
    ) or "clipboard" in source or "clipboard" in location
    yara_weight_multiplier = (
        float(getattr(WorkerConfig, "CLIPBOARD_YARA_WEIGHT_MULTIPLIER", 1.0))
        if is_clipboard_event
        else 1.0
    )

    for match in fast_scan_result.get("yara_matches") or []:
        rule = str(match.get("rule", "")).lower()
        if any(k in rule for k in ("id", "cmnd", "cccd")):
            score += 5.0 * yara_weight_multiplier
        elif "credit" in rule or "card" in rule:
            score += 4.0 * yara_weight_multiplier
        elif "api" in rule or "key" in rule:
            score += 3.5 * yara_weight_multiplier
        elif "email" in rule:
            score += 2.0 * yara_weight_multiplier
        elif "phone" in rule:
            score += 1.5 * yara_weight_multiplier
        else:
            score += 2.8 * yara_weight_multiplier

    for ioc in event_data.get("ioc_hits") or []:
        if not isinstance(ioc, dict):
            continue
        tag = str(ioc.get("tag", "")).lower()
        if "id" in tag or "cmnd" in tag:
            score += 4.5
        elif "credit" in tag or "card" in tag:
            score += 3.8
        elif "email" in tag:
            score += 2.2
        elif "phone" in tag:
            score += 1.2
        else:
            score += 2.0

    if deep_analysis_result.get("is_sensitive"):
        score += 2.5
    if fast_scan_result.get("is_encrypted_zip"):
        score += 1.5
    if fast_scan_result.get("is_suspicious"):
        score += 1.0

    return _clamp(score)


def compute_data_criticality(event_context: Dict[str, Any]) -> float:
    """0–10 — giá trị kinh doanh ước lượng từ path / tags."""
    loc = str(event_context.get("location", "")).lower()
    obj = _event_data(event_context).get("object")
    path = loc
    if isinstance(obj, dict):
        path = str(obj.get("path") or path).lower()

    critical_kw = (
        "payroll", "salary", "luong", "hr", "nhansu", "contract", "hopdong",
        "customer", "khachhang", "src", "financial", "taichinh",
        "medical", "benhan", "secret", "confidential", "mat",
    )
    s = 0.5
    for kw in critical_kw:
        if _path_keyword_hit(path, kw):
            s += 1.8
    tags = _event_data(event_context).get("tags") or []
    if isinstance(tags, (list, tuple)):
        for t in tags:
            if str(t).lower().startswith("corr_"):
                s += 0.8
    return _clamp(s)


def compute_behavior_anomaly(
    event_context: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
) -> float:
    """0–10 — behavioral + UEBA."""
    base = 0.6
    boost = float(event_context.get("behavioral_risk_boost") or 0)
    base = _clamp(base + boost * 0.5)

    ml = float(event_context.get("ml_anomaly_score") or 0.0)
    if ml <= 0 and deep_analysis_result.get("ml_anomaly_score") is not None:
        ml = float(deep_analysis_result.get("ml_anomaly_score") or 0.0)

    if event_context.get("ml_is_anomaly") or deep_analysis_result.get("ml_is_anomaly"):
        ml = max(ml, 4.8)

    return _clamp(max(base, ml * 0.85))


def compute_confidence(
    fast_scan_result: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
) -> float:
    """0–10 — độ tin cậy detection (YARA mạnh → cao)."""
    yara_n = len(fast_scan_result.get("yara_matches") or [])
    if yara_n == 0 and not fast_scan_result.get("is_suspicious"):
        return 2.2
    if yara_n >= 3:
        return 9.2
    if yara_n >= 1:
        return 7.2
    if deep_analysis_result.get("is_sensitive"):
        return 6.5
    return 5.5


def compute_base_score(
    fast_scan_result: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
    event_context: Dict[str, Any],
) -> Tuple[float, Dict[str, float]]:
    w = getattr(WorkerConfig, "CVSS_DLP_BASE_WEIGHTS", None) or {
        "content_sensitivity": 0.35,
        "data_criticality": 0.25,
        "behavior_anomaly": 0.25,
        "confidence": 0.15,
    }

    cs = compute_content_sensitivity(fast_scan_result, deep_analysis_result, event_context)
    dc = compute_data_criticality(event_context)
    ba = compute_behavior_anomaly(event_context, deep_analysis_result)
    cf = compute_confidence(fast_scan_result, deep_analysis_result)

    base = (
        w["content_sensitivity"] * cs
        + w["data_criticality"] * dc
        + w["behavior_anomaly"] * ba
        + w["confidence"] * cf
    )
    base = _clamp(base)

    components = {
        "content_sensitivity": round(cs, 2),
        "data_criticality": round(dc, 2),
        "behavior_anomaly": round(ba, 2),
        "confidence": round(cf, 2),
        "base_score": round(base, 2),
    }
    logger.debug(f"CVSS-DLP Base: {components}")
    return base, components
