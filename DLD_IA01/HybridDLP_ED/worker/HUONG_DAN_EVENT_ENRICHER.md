"""
HUONG_DAN_SU_DUNG_EVENT_ENRICHER.md

Hướng dẫn sử dụng event_enricher để gửi chi tiết match thông tin lên admin server
"""

# INTEGRATION GUIDE: Event Enricher

## Tóm tắt
- **event_enricher.py** là module giúp thêm chi tiết YARA/behavioral match vào events
- Dùng `enrich_event()` trước khi gửi event lên server
- Server sẽ lưu vào database và hiển thị ở admin panel

## Bước 1: Import module

```python
from event_enricher import enrich_event, format_yara_match, format_behavioral_match, format_risk_breakdown
from agent_sender import sender  # để gửi lên server
```

## Bước 2: Khi detection engine xử lý event, capture chi tiết

Giả sử ở main.py, trong hàm `_process_clipboard_event()` hoặc `_process_file_event()`:

```python
def _process_clipboard_event(self, event):
    # ... xử lý event ... 
    
    # Chạy YARA scan
    yara_matches = self.fast_scan.scan(clipboard_text)
    
    # Chạy behavioral analysis
    behavioral_scores = self.correlator.analyze(event)
    
    # Tính toán risk score
    risk_score = self.risk_scoring.calculate(
        keyword_matches=keyword_matches,
        yara_matches=yara_matches,
        behavioral_scores=behavioral_scores,
    )
    
    # ... tạo event dict ...
    event = {
        "timestamp": "2026-04-16T15:30:45+07:00",
        "risk_score": risk_score,
        "action": "ALERT",
        # ... các field khác ...
    }
    
    # ═══ THÊM CHI TIẾT MATCH ═══
    # Định dạng YARA matches
    yara_formatted = []
    if yara_matches:
        for rule_name, matched_strings in yara_matches.items():
            yara_formatted.append(format_yara_match(rule_name, matched_strings))
    
    # Định dạng behavioral matches
    behavioral_formatted = []
    if behavioral_scores:
        for rule_name, score in behavioral_scores.items():
            behavioral_formatted.append(format_behavioral_match(rule_name, score))
    
    # Định dạng risk breakdown (từ risk_scoring module)
    breakdown = {
        "keyword_score": keyword_score,
        "yara_score": yara_score,
        "behavioral_score": behavioral_score,
        "application_score": app_score,
        "final_score": risk_score,
    }
    
    # Tạo action reason tường minh
    action_reason = ""
    if yara_formatted:
        action_reason += f"YARA: {len(yara_formatted)} rules matched. "
    if behavioral_formatted:
        action_reason += f"Behavioral: {len(behavioral_formatted)} patterns. "
    action_reason += f"Risk: {risk_score}/10"
    
    # Thêm tất cả vào event
    enriched_event = enrich_event(
        event=event,
        yara_matches_count=len(yara_formatted),
        yara_rules_matched=yara_formatted,
        behavioral_matches_count=len(behavioral_formatted),
        behavioral_rules_matched=behavioral_formatted,
        risk_score_breakdown=breakdown,
        action_reason=action_reason,
        event_type="clipboard_access",  # hoặc "file_access", "process_start", etc
        content_size=len(clipboard_text),
        check_duration_ms=elapsed_ms,
    )
    
    # Ghi log (tuỳ chọn)
    logger.info(f"Event enriched: yara={len(yara_formatted)}, behavioral={len(behavioral_formatted)}, score={risk_score}")
    
    # Gửi lên server (không block)
    sender.send(enriched_event)
    
    # Tiếp tục xử lý bình thường (save to alerts.json, etc)
    # ...
```

## Bước 3: Server sẽ tự động process

Không cần thay đổi gì ở main.py của dlp-server:
- Database sẽ tự động lưu tất cả fields mới (yara_rules_matched, risk_score_breakdown, etc)
- Admin panel sẽ tự động hiển thị trong chi tiết modal

## Cấu trúc Data Formats

### YARA Match Format
```json
{
  "rule": "Credit_Card",
  "strings": ["visa1", "mastercard1"],
  "timestamp": "2026-04-16T15:30:45+07:00"
}
```

### Behavioral Match Format
```json
{
  "rule": "clipboard_copy_large_data",
  "score": 0.6,
  "reason": "Copied >10KB data in <5 seconds"
}
```

### Risk Score Breakdown Format
```json
{
  "keyword_score": 1.5,
  "yara_score": 3.0,
  "behavioral_score": 1.5,
  "application_score": 0.5,
  "final_score": 6.5
}
```

## Event Type Categories

Sử dụng các loại này cho `event_type` parameter:
- `clipboard_access` - Clipboard operations
- `file_access` - File read/write
- `file_copy` - File copy to USB/network
- `process_start` - Process execution
- `network_send` - Network transmission
- `print_job` - Printing
- `screenshot` - Screenshot capture
- `clipboard_paste` - Paste operation

## Testing

Chạy event_enricher.py để xem example:
```bash
cd HybridDLP_ED/worker
python event_enricher.py
```

Sẽ print ra enriched event JSON hoàn chỉnh.

## Migration (nếu có events cũ)

Nếu database đã có events cũ, chúng sẽ có giá trị NULL cho các field mới.
Admin panel sẽ tự động xử lý (hiển thị "N/A" hoặc "-").

Để backfill (tuỳ chọn):
```python
# Trong database.py, thêm function này:
def backfill_missing_fields():
    """Set default values cho events cũ"""
    conn = get_conn()
    conn.execute("""
        UPDATE events 
        SET yara_rules_matched = '[]',
            behavioral_rules_matched = '[]',
            risk_score_breakdown = '{}',
            action_reason = ''
        WHERE yara_rules_matched IS NULL
    """)
    conn.commit()
    conn.close()
    print("Backfill complete")
```

---

**Questions?** Check example output in event_enricher.py main section.
