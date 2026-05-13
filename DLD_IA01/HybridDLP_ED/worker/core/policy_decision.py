"""
Policy / Action mapping — Noteupdate §7 (adapted: hệ alert-only giữ block không khả dụng).
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def decide_recommended_action(
    final_risk: float,
    em_code: str,
    content_sensitivity: float,
) -> Tuple[str, str]:
    """
    Trả về (action_key, recommended_label).
    action_key: 'log' | 'alert' — block được map thành alert vì RISK_THRESHOLDS['block'] không dùng.
    """
    block_unreachable = float(WorkerConfig.RISK_THRESHOLDS.get("block", 10**9)) >= 500.0
    alert_th = float(WorkerConfig.RISK_THRESHOLDS.get("alert", 4.0))

    # Biên thang 0–10 (CVSS Severity): Low <4, Medium 4–6.9, High 7–8.9, Critical ≥9
    cvss_medium = float(getattr(WorkerConfig, "RISK_LEVEL_LOW_MAX", 40.0))
    cvss_high = float(getattr(WorkerConfig, "RISK_LEVEL_MEDIUM_MAX", 70.0))
    cvss_critical = float(getattr(WorkerConfig, "RISK_LEVEL_HIGH_MAX", 90.0))

    label = "log_only"
    action = "log"

    if final_risk < cvss_medium:
        label = "log_only"
        action = "log"
    elif final_risk < cvss_high:
        label = "medium_band"
        action = "alert" if final_risk >= alert_th else "log"
    elif final_risk < cvss_critical:
        label = "high_band"
        action = "alert" if final_risk >= alert_th else "log"
    else:
        label = "critical_block_or_escalate"
        action = "alert"
        if not block_unreachable and final_risk >= 9.5:
            action = "block"

    # Chỉ leo thang khi đã gần ngưỡng alert (tránh A do heuristic kênh quá nhạy).
    if em_code == "A" and final_risk >= max(alert_th - 0.3, cvss_medium + 0.8):
        action = "alert"
        if label == "log_only":
            label = "temparol_active_escalated"
    elif em_code == "U" and final_risk < alert_th and content_sensitivity < 5.5:
        action = "log"
        label = "temparol_preliminary_watch"

    return action, label


def build_reason_codes(
    base_components: Dict[str, Any],
    em_payload: Dict[str, Any],
    env_parts: Dict[str, Any],
    chain_reasons: list,
    extra: list | None = None,
) -> list:
    codes: list = []
    if base_components.get("content_sensitivity", 0) >= 5.0:
        codes.append("sensitive_data_detected")
    for c in em_payload.get("reason_codes") or []:
        codes.append(c)
    if env_parts.get("time_context", 0) >= 6.0:
        codes.append("outside_business_hours")
    if env_parts.get("asset_context", 0) >= 6.0:
        codes.append("sensitive_asset_path")
    for c in chain_reasons:
        codes.append(c)
    if em_payload.get("telemetry_unknown"):
        codes.append("telemetry_insufficient")
    if extra:
        codes.extend(x for x in extra if x)
    return list(dict.fromkeys(codes))
