"""
API ENDPOINT GUIDE for Admin Dashboard

Chi tiết các endpoint đã update và cách sử dụng
"""

# ============================================================
# GET /api/events/{id}
# ============================================================
# Lấy chi tiết 1 event (dùng ở detail modal)

Response:
{
  "id": 123,
  "machine_name": "PC-01",
  "received_at": "2026-04-16T15:30:45+07:00",
  "timestamp": "2026-04-16T15:30:42+07:00",
  "risk_score": 6.5,
  "action": "alert",
  "file_path": "/clipboard",
  "file_name": "clipboard_data",
  "keywords": ["credit card", "visa"],
  "window_title": "Google Chrome",
  "process_name": "chrome.exe",
  "user": "admin",
  "source": "clipboard",
  "is_clipboard": true,
  
  // ==== CHI TIẾT MATCH (MỚI) ====
  "yara_matches_count": 2,           // Số lượng YARA rules matched
  "yara_rules_matched": [             // Chi tiết từng rule
    {
      "rule": "Credit_Card",
      "strings": ["visa1", "mastercard1"],
      "timestamp": "2026-04-16T15:30:45+07:00"
    },
    {
      "rule": "API_Key",
      "strings": ["aws_key"],
      "timestamp": "2026-04-16T15:30:45+07:00"
    }
  ],
  
  "behavioral_matches_count": 2,      // Số lượng behavioral rules matched
  "behavioral_rules_matched": [        // Chi tiết behavioral
    {
      "rule": "clipboard_copy_large_data",
      "score": 0.6,
      "reason": "Copied >10KB data in <5 seconds"
    },
    {
      "rule": "rapid_clipboard_access",
      "score": 0.4,
      "reason": "Accessed clipboard 5 times in 10s"
    }
  ],
  
  // ==== RISK SCORING BREAKDOWN (MỚI) ====
  "risk_score_breakdown": {
    "keyword_score": 1.5,             // Từ keywords phát hiện
    "yara_score": 3.0,                // Từ YARA rules
    "behavioral_score": 1.5,          // Từ behavioral analysis
    "application_score": 0.5,         // Từ app risk level
    "final_score": 6.5                // Total
  },
  
  // ==== ACTION REASONING (MỚI) ====
  "action_reason": "Credit card (2) + API key detected | Rapid clipboard access | Large data copy",
  
  // ==== METADATA (MỚI) ====
  "event_type": "clipboard_access",
  "content_size": 15240,              // bytes
  "check_duration_ms": 245            // milliseconds
}


# ============================================================
# GET /api/events (list with filters)
# ============================================================

Same fields as above, but trong array.
Server sẽ apply filters dựa trên query params có sẵn:
  - ?limit=500
  - ?action=blocked|alert|allowed
  - ?min_risk=7&max_risk=10
  - ?machine=PC-01


# ============================================================
# Python Implementation (main.py của dlp-server)
# ============================================================

from flask import Flask, jsonify, request
from database import query_events, get_agents, insert_batch

app = Flask(__name__)

@app.route('/api/events/<int:event_id>')
def get_event_detail(event_id):
    """GET single event detail with all enriched data"""
    try:
        conn = get_conn()
        row = conn.execute(
            'SELECT * FROM events WHERE id = ?', 
            (event_id,)
        ).fetchone()
        conn.close()
        
        if not row:
            return jsonify({"error": "Not found"}), 404
        
        event = dict(row)
        # Deserialize JSON fields
        event["keywords"] = json.loads(event.get("keywords") or "[]")
        event["yara_rules_matched"] = json.loads(event.get("yara_rules_matched") or "[]")
        event["behavioral_rules_matched"] = json.loads(event.get("behavioral_rules_matched") or "[]")
        event["risk_score_breakdown"] = json.loads(event.get("risk_score_breakdown") or "{}")
        event["is_clipboard"] = bool(event.get("is_clipboard"))
        
        return jsonify(event)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/events/batch', methods=['POST'])
def create_events_batch():
    """POST batch events from agents (with enriched data)"""
    try:
        data = request.get_json()
        api_key = request.headers.get('X-API-Key')
        
        # Validate API key
        agent = get_agent(api_key)
        if not agent:
            return jsonify({"error": "Invalid API key"}), 401
        
        # Insert batch
        machine_name = agent['machine_name']
        count = insert_batch(machine_name, data if isinstance(data, list) else [data])
        
        # Update last connection
        update_agent_last_connection(api_key)
        
        return jsonify({"inserted": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# Frontend Display (index.html - JS)
# ============================================================

Ở openModal() function:
- YARA section: Hiển thị số lượng matches + từng rule name
- Behavioral section: Hiển thị score + reason
- Risk Breakdown: Hiển thị table breakdown
- Action Reason: Giải thích tại sao chọn action này
- Metadata: Processing time + content size


# ============================================================
# Example: Admin xem chi tiết event
# ============================================================

1. Click row ở table → openModal(id)
2. Frontend fetch /api/events/{id}
3. Server query từ database, return JSON với tất cả fields
4. Frontend format and display:
   - YARA matches (nếu có)
   - Behavioral matches (nếu có)
   - Risk breakdown (table)
   - Action reason (giải thích)
   - Metadata (duration, size)


# ============================================================
# Backward Compatibility
# ============================================================

- Old events (không có enriched data) sẽ có NULL values
- Frontend sẽ check và hiển thị "Not analyzed" hoặc skip sections
- Database migration không cần (SQLite có default NULL cho columns mới)
- Agents cũ vẫn work (gửi events cũ, server sẽ lưu với NULL cho new fields)
