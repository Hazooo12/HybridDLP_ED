"""
EXAMPLE_INTEGRATION_MAIN.PY

Ví dụ cách integrate event_enricher vào main.py của worker
Chỉ là reference - adapt theo cấu trúc thực tế của project bạn
"""

# ============================================================
# ở phần import, thêm vào:
# ============================================================
from event_enricher import enrich_event, format_yara_match, format_behavioral_match, format_risk_breakdown
from agent_sender import sender


# ============================================================
# Ví dụ 1: Clipboard Event (clipboard_sensor_started)
# ============================================================

def _process_clipboard_event(self, event):
    """Enhanced version with detailed matching info"""
    
    # ... code xử lý event, scan clipboard, etc ...
    
    clipboard_text = event.get("clipboard_content", "")
    
    # Step 1: Scan YARA
    yara_matches_dict = self.fast_scan.scan(clipboard_text)  # Returns {rule_name: [matched_strings]}
    yara_matches_count = len(yara_matches_dict)
    
    # Step 2: Behavioral analysis
    behavioral_scores = {}  # {rule_name: score}
    if self.correlator:
        behavioral_scores = self.correlator.analyze_clipboard(event)
    behavioral_matches_count = len(behavioral_scores)
    
    # Step 3: Calculate risk score
    risk_score = self.risk_scoring.calculate_score(
        yara_matches=yara_matches_dict,
        behavioral_scores=behavioral_scores,
        keywords=keywords,
        window_title=window_title,
    )
    
    action = self.action_executor.decide_action(risk_score)
    
    # ════════════════════════════════════════════════════════
    # NEW: Format match data for enrichment
    # ════════════════════════════════════════════════════════
    
    # Format YARA matches
    yara_formatted = []
    for rule_name, matched_strings in yara_matches_dict.items():
        yara_formatted.append(format_yara_match(
            rule_name=rule_name,
            matched_strings=matched_strings
        ))
    
    # Format Behavioral matches
    behavioral_formatted = []
    for rule_name, score in behavioral_scores.items():
        behavioral_formatted.append(format_behavioral_match(
            rule_name=rule_name,
            score=score,
            reason=f"Behavioral pattern detected"
        ))
    
    # Get risk breakdown from risk_scoring module
    breakdown = self.risk_scoring.get_breakdown()  # Should return dict with score components
    if not breakdown:
        breakdown = {
            "keyword_score": 0.0,
            "yara_score": 0.0,
            "behavioral_score": 0.0,
            "application_score": 0.0,
            "final_score": risk_score,
        }
    
    # Create action reason
    action_reason_parts = []
    if yara_formatted:
        action_reason_parts.append(f"YARA: {', '.join([r['rule'] for r in yara_formatted])}")
    if behavioral_formatted:
        action_reason_parts.append(f"Behavioral: {len(behavioral_formatted)} patterns")
    if keywords:
        action_reason_parts.append(f"Keywords: {', '.join(keywords[:3])}")
    action_reason = " | ".join(action_reason_parts) or "Routine clipboard access"
    
    # Capture processing time
    import time
    start_time = time.time()  # Should be at beginning of function
    check_duration_ms = int((time.time() - start_time) * 1000)
    
    # ════════════════════════════════════════════════════════
    # Create base event dict
    # ════════════════════════════════════════════════════════
    
    base_event = {
        "timestamp": datetime.now(tz=TZ_VN).isoformat(),
        "risk_score": risk_score,
        "action": action,
        "file_path": "/clipboard",
        "file_name": "clipboard_data",
        "keywords": keywords,
        "window_title": window_title,
        "process_name": process_name,
        "user": get_current_user(),
        "source": "clipboard",
        "is_clipboard": True,
    }
    
    # ════════════════════════════════════════════════════════
    # ENRICH event with match details
    # ════════════════════════════════════════════════════════
    
    enriched_event = enrich_event(
        event=base_event,
        yara_matches_count=yara_matches_count,
        yara_rules_matched=yara_formatted,
        behavioral_matches_count=behavioral_matches_count,
        behavioral_rules_matched=behavioral_formatted,
        risk_score_breakdown=breakdown,
        action_reason=action_reason,
        event_type="clipboard_access",
        content_size=len(clipboard_text),
        check_duration_ms=check_duration_ms,
    )
    
    # ════════════════════════════════════════════════════════
    # Execute action & log
    # ════════════════════════════════════════════════════════
    
    self.action_executor.execute(enriched_event)
    
    # Log local
    self.logger.info(
        f"Clipboard: {len(clipboard_text)} chars | "
        f"YARA: {yara_matches_count} | "
        f"Behavioral: {behavioral_matches_count} | "
        f"Score: {risk_score} | Action: {action}"
    )
    
    # ════════════════════════════════════════════════════════
    # SEND to central server (không block)
    # ════════════════════════════════════════════════════════
    
    sender.send(enriched_event)
    
    return enriched_event


# ============================================================
# Ví dụ 2: File Event (file_copy_event)
# ============================================================

def _process_file_copy_event(self, event):
    """File copy with enrichment"""
    
    file_path = event.get("file_path", "")
    file_content = self.read_file_content(file_path, max_size=1024*1024)  # 1MB limit
    
    # YARA scan
    yara_matches = self.fast_scan.scan(file_content)
    
    # Behavioral
    behavioral_scores = self.correlator.analyze_file_copy(event)
    
    # Risk calculation
    risk_score = self.risk_scoring.calculate_score(
        yara_matches=yara_matches,
        behavioral_scores=behavioral_scores,
        file_path=file_path,
    )
    
    action = self.action_executor.decide_action(risk_score)
    
    # ════ Format matches ════
    yara_formatted = [
        format_yara_match(name, strings) 
        for name, strings in yara_matches.items()
    ]
    behavioral_formatted = [
        format_behavioral_match(name, score, "File copy detected") 
        for name, score in behavioral_scores.items()
    ]
    
    # ════ Create event ════
    base_event = {
        "timestamp": datetime.now(tz=TZ_VN).isoformat(),
        "risk_score": risk_score,
        "action": action,
        "file_path": file_path,
        "file_name": Path(file_path).name,
        "user": get_current_user(),
        "source": "file_copy",
    }
    
    # ════ Enrich ════
    enriched = enrich_event(
        event=base_event,
        yara_matches_count=len(yara_formatted),
        yara_rules_matched=yara_formatted,
        behavioral_matches_count=len(behavioral_formatted),
        behavioral_rules_matched=behavioral_formatted,
        risk_score_breakdown=self.risk_scoring.get_breakdown() or {},
        action_reason=f"File copy detected: {len(yara_formatted)} YARA + {len(behavioral_formatted)} behavioral",
        event_type="file_copy",
        content_size=len(file_content),
        check_duration_ms=100,  # capture actual duration
    )
    
    self.action_executor.execute(enriched)
    sender.send(enriched)
    

# ============================================================
# Ví dụ 3: Process Event (suspicious process)
# ============================================================

def _process_process_event(self, event):
    """Process running with enrichment"""
    
    process_name = event.get("process_name", "")
    
    # Check against behavioral rules
    behavioral_scores = self.correlator.analyze_process(event)
    
    # Risk score
    risk_score = self.risk_scoring.calculate_score(
        behavioral_scores=behavioral_scores,
        process_name=process_name,
    )
    
    action = self.action_executor.decide_action(risk_score)
    
    behavioral_formatted = [
        format_behavioral_match(
            rule_name=name,
            score=score,
            reason=f"Process behavior pattern: {name}"
        )
        for name, score in behavioral_scores.items()
    ]
    
    base_event = {
        "timestamp": datetime.now(tz=TZ_VN).isoformat(),
        "risk_score": risk_score,
        "action": action,
        "process_name": process_name,
        "user": get_current_user(),
        "source": "process",
    }
    
    enriched = enrich_event(
        event=base_event,
        behavioral_matches_count=len(behavioral_formatted),
        behavioral_rules_matched=behavioral_formatted,
        action_reason=f"Behavioral: {len(behavioral_formatted)} patterns detected",
        event_type="process_start",
        check_duration_ms=50,
    )
    
    self.action_executor.execute(enriched)
    sender.send(enriched)


# ============================================================
# TIPS:
# ============================================================

# 1. Luôn capture start_time ở đầu function để tính check_duration_ms
# 2. Reuse format_* helpers (có sẵn ở event_enricher.py)
# 3. Nếu module cũ không có get_breakdown(), tạo dict thủ công
# 4. action_reason nên có ý nghĩa cho admin, không quá dài
# 5. event_type giúp filter ở dashboard sau (clipboard_access, file_copy, etc)
# 6. content_size = 0 là OK nếu không có content (process events)
# 7. sender.send() không block, không cần async
# 8. Nếu server down, event vẫn ghi local (alerts.json) - sender tự handle

