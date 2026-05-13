"""
event_enricher.py — Helper module để format match details trước gửi server

CÁCH DÙNG:
──────────
from event_enricher import enrich_event, format_yara_match, format_behavioral_match

# 1. Format YARA matches
yara_formatted = [
    format_yara_match("CreditCard", ["4532-****-****-5678"]),
    format_yara_match("APIKey", ["sk-proj-aB3cD..."]),
]

# 2. Format Behavioral matches
behavioral_formatted = [
    format_behavioral_match("BulkClipboardAccess", 0.92, "copied 50+ items"),
]

# 3. Enrich event
enriched = enrich_event(
    event=base_event,
    yara_matches_count=len(yara_formatted),
    yara_rules_matched=yara_formatted,
    behavioral_matches_count=len(behavioral_formatted),
    behavioral_rules_matched=behavioral_formatted,
    risk_score_breakdown={
        "keyword_score": 3.0,
        "yara_score": 2.5,
        "behavioral_score": 1.8,
        "application_score": 0.2,
        "final_score": 7.5,
    },
    action_reason="Matched payment card + API key",
    event_type="clipboard",
    content_size=1024,
    check_duration_ms=145,
)

# 4. Send to server
from agent_sender import sender
sender.send(enriched)
"""

import json
from typing import Dict, List, Any, Optional


def format_yara_match(rule_name: str, matched_strings: List[str]) -> Dict[str, Any]:
    """
    Format a YARA rule match.
    
    Args:
        rule_name: Name of the YARA rule (e.g., "CreditCard")
        matched_strings: List of matched patterns/strings from the scan
        
    Returns:
        Dict with rule name and matched patterns
        
    Example:
        format_yara_match("CreditCard", ["4532-****-****-5678"])
        # → {"rule": "CreditCard", "matched": ["4532-****-****-5678"]}
    """
    return {
        "rule": rule_name,
        "matched": matched_strings or [],
    }


def format_behavioral_match(
    rule_name: str,
    score: float,
    reason: str,
) -> Dict[str, Any]:
    """
    Format a behavioral rule match.
    
    Args:
        rule_name: Name of the behavioral rule (e.g., "BulkClipboardAccess")
        score: Match score/confidence (0.0 - 1.0)
        reason: Human-readable reason for the match
        
    Returns:
        Dict with rule, score, and reason
        
    Example:
        format_behavioral_match("BulkClipboardAccess", 0.92, "copied 50+ items")
        # → {"rule": "BulkClipboardAccess", "score": 0.92, "reason": "copied 50+ items"}
    """
    return {
        "rule": rule_name,
        "score": round(float(score), 2),  # Max 2 decimal places
        "reason": str(reason or ""),
    }


def format_risk_breakdown(
    keyword_score: float = 0.0,
    yara_score: float = 0.0,
    behavioral_score: float = 0.0,
    application_score: float = 0.0,
    final_score: float = 0.0,
) -> Dict[str, float]:
    """
    Format risk score breakdown into components.
    
    Args:
        keyword_score: Score from keyword/pattern matching (0-10)
        yara_score: Score from YARA rules (0-10)
        behavioral_score: Score from behavioral analysis (0-10)
        application_score: Score from application/context (0-10)
        final_score: Combined final score (0-10)
        
    Returns:
        Dict with all risk components
        
    Example:
        format_risk_breakdown(keyword=3.0, yara=2.5, behavioral=1.8, final=7.5)
    """
    return {
        "keyword_score": round(float(keyword_score), 1),
        "yara_score": round(float(yara_score), 1),
        "behavioral_score": round(float(behavioral_score), 1),
        "application_score": round(float(application_score), 1),
        "final_score": round(float(final_score), 1),
    }


def enrich_event(
    event: Dict[str, Any],
    yara_matches_count: int = 0,
    yara_rules_matched: Optional[List[Dict[str, Any]]] = None,
    behavioral_matches_count: int = 0,
    behavioral_rules_matched: Optional[List[Dict[str, Any]]] = None,
    risk_score_breakdown: Optional[Dict[str, float]] = None,
    action_reason: str = "",
    event_type: str = "",
    content_size: int = 0,
    check_duration_ms: int = 0,
) -> Dict[str, Any]:
    """
    Enrich an event with detailed match information.
    
    Adds 9 enrichment fields to a base event:
    - yara_matches_count: Number of YARA rules matched
    - yara_rules_matched: List of YARA match details
    - behavioral_matches_count: Number of behavioral rules matched
    - behavioral_rules_matched: List of behavioral match details
    - risk_score_breakdown: Risk score components
    - action_reason: Why this action/decision was made
    - event_type: Type of event (clipboard, file, process, etc.)
    - content_size: Size of analyzed content (bytes)
    - check_duration_ms: How long analysis took (milliseconds)
    
    Args:
        event: Base event dict (must have timestamp, risk_score, action, etc.)
        yara_matches_count: Number of YARA rule matches
        yara_rules_matched: List of formatted YARA matches
        behavioral_matches_count: Number of behavioral rule matches
        behavioral_rules_matched: List of formatted behavioral matches
        risk_score_breakdown: Risk component breakdown
        action_reason: Explanation of action decision
        event_type: Type of event being processed
        content_size: Size of analyzed content in bytes
        check_duration_ms: Analysis duration in milliseconds
        
    Returns:
        Enhanced event dict with all enrichment fields
        
    Example:
        enriched = enrich_event(
            event={"timestamp": "...", "risk_score": 7.5, "action": "block"},
            yara_matches_count=2,
            yara_rules_matched=[
                {"rule": "CreditCard", "matched": ["4532-****"]},
            ],
            behavioral_matches_count=1,
            behavioral_rules_matched=[
                {"rule": "BulkClipboardAccess", "score": 0.92, "reason": "50+ items"},
            ],
            risk_score_breakdown={
                "keyword_score": 3.0, "yara_score": 2.5, "behavioral_score": 1.8, "final_score": 7.5
            },
            action_reason="Matched payment card rules",
            event_type="clipboard",
            content_size=1024,
            check_duration_ms=145,
        )
    """
    
    # Start with a copy of the base event
    enriched = dict(event) if isinstance(event, dict) else {}
    
    # Add enrichment fields (all are optional/nullable)
    enriched["yara_matches_count"] = int(yara_matches_count)
    enriched["yara_rules_matched"] = yara_rules_matched or []
    
    enriched["behavioral_matches_count"] = int(behavioral_matches_count)
    enriched["behavioral_rules_matched"] = behavioral_rules_matched or []
    
    enriched["risk_score_breakdown"] = risk_score_breakdown or {}
    
    enriched["action_reason"] = str(action_reason or "")
    enriched["event_type"] = str(event_type or "")
    enriched["content_size"] = int(content_size)
    enriched["check_duration_ms"] = int(check_duration_ms)
    
    return enriched


# ============================================================
# Utility: Safely serialize enriched event to JSON
# ============================================================

def serialize_for_json(event: Dict[str, Any]) -> str:
    """
    Serialize an enriched event to JSON string.
    Handles datetime objects and other non-serializable types.
    """
    def default_handler(obj):
        # Handle datetime objects
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        # Handle sets
        if isinstance(obj, set):
            return list(obj)
        # Default fallback
        return str(obj)
    
    return json.dumps(event, ensure_ascii=False, default=default_handler)
