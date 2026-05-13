"""
event_enricher.py — Thêm chi tiết match information vào events trước khi gửi

Sử dụng: 
    from event_enricher import enrich_event
    
    # Sau khi detection engine xử lý event
    detailed_event = enrich_event(
        event=event_dict,
        yara_matches_count=5,
        yara_rules_matched=[
            {"rule": "Credit_Card", "strings": ["visa1", "mastercard1"]},
            {"rule": "API_Key", "strings": ["aws_key"]}
        ],
        behavioral_matches_count=2,
        behavioral_rules_matched=[
            {"rule": "clipboard_copy_large_data", "score": 0.6},
            {"rule": "rapid_clipboard_access", "score": 0.4}
        ],
        risk_score_breakdown={
            "keyword_score": 1.5,
            "yara_score": 3.0,
            "behavioral_score": 1.5,
            "final_score": 6.0
        },
        action_reason="Multiple credit card patterns detected (2) + API key (1)",
        event_type="clipboard_access",
        content_size=15240,
        check_duration_ms=245
    )
    
    # Gửi detailed_event lên server
    sender.send(detailed_event)
"""

import json
from typing import Optional


def enrich_event(
    event: dict,
    yara_matches_count: int = 0,
    yara_rules_matched: list = None,
    behavioral_matches_count: int = 0,
    behavioral_rules_matched: list = None,
    risk_score_breakdown: dict = None,
    action_reason: str = "",
    event_type: str = "unknown",
    content_size: int = 0,
    check_duration_ms: int = 0,
) -> dict:
    """
    Thêm chi tiết match information vào event.
    Trả về event dict mở rộng có thể gửi lên server.
    
    Args:
        event: Original event dict từ detection engine
        yara_matches_count: Số lượng YARA rules matched
        yara_rules_matched: List các rules matched: [{"rule": name, "strings": [...]}, ...]
        behavioral_matches_count: Số lượng behavioral rules matched
        behavioral_rules_matched: List behavioral rules: [{"rule": name, "score": float}, ...]
        risk_score_breakdown: Dict breakdown của risk score calculation
        action_reason: Giải thích tại sao choose action này
        event_type: Loại event (clipboard, file, process, etc)
        content_size: Kích thước content đã check
        check_duration_ms: Thời gian xử lý (milliseconds)
    
    Returns:
        dict: Enriched event - compatible với database.py schema
    """
    
    enriched = event.copy()
    
    # Thêm chi tiết match
    enriched["yara_matches_count"] = yara_matches_count
    enriched["behavioral_matches_count"] = behavioral_matches_count
    enriched["yara_rules_matched"] = yara_rules_matched or []
    enriched["behavioral_rules_matched"] = behavioral_rules_matched or []
    
    # Thêm chi tiết scoring
    enriched["risk_score_breakdown"] = risk_score_breakdown or {}
    enriched["action_reason"] = action_reason
    
    # Metadata
    enriched["event_type"] = event_type
    enriched["content_size"] = content_size
    enriched["check_duration_ms"] = check_duration_ms
    
    return enriched


def format_yara_match(rule_name: str, matched_strings: list) -> dict:
    """Định dạng một YARA match."""
    return {
        "rule": rule_name,
        "strings": matched_strings,
        "timestamp": _now_iso()
    }


def format_behavioral_match(rule_name: str, score: float, reason: str = "") -> dict:
    """Định dạng một behavioral match."""
    return {
        "rule": rule_name,
        "score": score,
        "reason": reason
    }


def format_risk_breakdown(
    keyword_score: float = 0.0,
    yara_score: float = 0.0,
    behavioral_score: float = 0.0,
    application_score: float = 0.0,
    final_score: float = 0.0,
) -> dict:
    """Định dạng risk score breakdown."""
    return {
        "keyword_score": keyword_score,
        "yara_score": yara_score,
        "behavioral_score": behavioral_score,
        "application_score": application_score,
        "final_score": final_score,
    }


def _now_iso() -> str:
    """Trả về ISO timestamp hiện tại."""
    from datetime import datetime, timezone, timedelta
    tz = timezone(timedelta(hours=7))  # UTC+7
    return datetime.now(tz=tz).isoformat()


# ============================================================
# EXAMPLE: Cách sử dụng
# ============================================================
if __name__ == "__main__":
    # Giả sử detection engine đã xử lý event
    original_event = {
        "timestamp": "2026-04-16T15:30:45+07:00",
        "risk_score": 6.5,
        "action": "ALERT",
        "file_path": "/clipboard",
        "keywords": ["credit card", "visa"],
        "window_title": "Browser",
        "process_name": "chrome.exe",
        "user": "admin",
        "source": "clipboard",
        "is_clipboard": True,
    }
    
    # Gian sử YARA detected các rule
    yara_matches = [
        format_yara_match("Credit_Card", ["visa1", "mastercard1"]),
        format_yara_match("API_Key", ["aws_key"])
    ]
    
    # Behavioral rules
    behavioral_matches = [
        format_behavioral_match("clipboard_copy_large_data", 0.6, "Copied >10KB data"),
        format_behavioral_match("rapid_clipboard_access", 0.4, "Accessed clipboard 5 times in 10s")
    ]
    
    # Risk breakdown
    breakdown = format_risk_breakdown(
        keyword_score=1.5,
        yara_score=3.0,
        behavioral_score=1.5,
        application_score=0.5,
        final_score=6.5
    )
    
    # Enriched event ready to send
    enriched = enrich_event(
        event=original_event,
        yara_matches_count=len(yara_matches),
        yara_rules_matched=yara_matches,
        behavioral_matches_count=len(behavioral_matches),
        behavioral_rules_matched=behavioral_matches,
        risk_score_breakdown=breakdown,
        action_reason="Credit card (2) + API key detected | Rapid clipboard access | Large data copy",
        event_type="clipboard_access",
        content_size=15240,
        check_duration_ms=245
    )
    
    print("Enriched Event:")
    print(json.dumps(enriched, indent=2, ensure_ascii=False))
