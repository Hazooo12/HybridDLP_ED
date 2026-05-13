"""
Attack Chain Bonus — Noteupdate §3.4 (0–2 trên thang risk 0–10).
Phase 1: heuristic từ event type, correlation tags, fast_scan + kênh.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from loguru import logger


def _event_data(ctx: Dict[str, Any]) -> Dict[str, Any]:
    ed = ctx.get("_event_data")
    return ed if isinstance(ed, dict) else {}


def compute_attack_chain_bonus(
    event_context: Dict[str, Any],
    fast_scan_result: Dict[str, Any],
) -> Tuple[float, List[str]]:
    bonus = 0.0
    reasons: List[str] = []
    ev = _event_data(event_context)
    et = str(ev.get("type") or "").lower()
    tags = ev.get("tags") or []
    if not isinstance(tags, list):
        tags = []

    if et.startswith("corr_"):
        bonus += 0.8
        reasons.append("attack_chain_correlation_event")

    for t in tags:
        ts = str(t).lower()
        if ts.startswith("corr_"):
            bonus += 0.5
            reasons.append("attack_chain_tag_corr")
            break

    susp = bool(fast_scan_result.get("is_suspicious"))
    enc = bool(fast_scan_result.get("is_encrypted_zip"))
    at = str(event_context.get("action_type") or "").lower()
    dest = str(event_context.get("destination") or "").lower()

    if susp and enc:
        bonus += 0.5
        reasons.append("attack_chain_sensitive_plus_archive")

    if enc and ("usb" in at or "usb" in dest or "removable" in dest):
        bonus += 0.5
        reasons.append("attack_chain_archive_usb")

    if enc and any(x in at for x in ("upload", "browser")):
        bonus += 1.0
        reasons.append("attack_chain_archive_external_upload")

    if susp and event_context.get("behavioral_details"):
        bonus += 0.4
        reasons.append("attack_chain_behavioral_context")

    bonus = min(2.0, bonus)
    if reasons:
        logger.debug(f"CVSS-DLP AttackChain: +{bonus} {reasons}")
    return bonus, list(dict.fromkeys(reasons))
