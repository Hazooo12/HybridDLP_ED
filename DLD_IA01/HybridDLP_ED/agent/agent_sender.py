"""
agent_sender.py — Thêm file này vào project DLP hiện tại


CÁCH DÙNG — chỉ cần 2 bước:


1. Copy file này vào cùng thư mục với DLP của bạn


2. Ở chỗ nào DLP append event vào alerts.json, thêm 1 dòng:
       sender.send(event_dict)


   Ví dụ trước đây:
       alerts.append(event)
       save_to_json(alerts)


   Sau khi thêm:
       alerts.append(event)
       save_to_json(alerts)
       sender.send(event)   # ← chỉ thêm dòng này


Nếu server không chạy hoặc mất mạng → DLP vẫn hoạt động bình thường,
event chỉ đơn giản là không được gửi lên (silent fail).


KIẾN TRÚC BỈ THẺ (Enriched Events) — Gửi chi tiết phát hiện:
════════════════════════════════════════════════════════════════╗

Để admin dashboard hiển thị chi tiết match:
  - YARA rules matched
  - Behavioral rules matched  
  - Risk score breakdown
  - Action reason + processing metadata

Thêm các trường này vào event trước gọi sender.send():

  Trường Enrichment:
  ├─ yara_matches_count      : int (số rules YARA matches)
  ├─ yara_rules_matched      : list[dict] (chi tiết mỗi rule)
  │   └─ [{"rule": "CreditCard", "matched": ["4532-****"]}, ...]
  ├─ behavioral_matches_count : int (số rules behavior matches)
  ├─ behavioral_rules_matched: list[dict]
  │   └─ [{"rule": "FileExfil", "score": 0.85, "reason": "..."}, ...]
  ├─ risk_score_breakdown    : dict (từng component score)
  │   └─ {"keyword_score": 3.0, "yara_score": 2.5, ...}
  ├─ action_reason           : str (tại sao chọn action này)
  ├─ event_type             : str ("clipboard"|"file"|"process"|...)
  ├─ content_size           : int (kích thước data bytes)
  └─ check_duration_ms      : int (thời gian phân tích ms)

EXAMPLE 1 — Simple approach (manual append):
───────────────────────────────────────────
  event = {
      "timestamp": "2026-04-16T10:30:45.123456+07:00",
      "file_path": "C:\\\\Users\\\\User\\\\Desktop\\\\data.xlsx",
      "risk_score": 7.5,
      "action": "block",
      ...existing fields...
      
      # Enrichment fields
      "yara_matches_count": 2,
      "yara_rules_matched": [
          {"rule": "CreditCard", "matched": ["4532-****-****-5678"]},
          {"rule": "APIKey", "matched": ["sk-proj-aB3cD..."]},
      ],
      "behavioral_matches_count": 1,
      "behavioral_rules_matched": [
          {"rule": "BulkClipboardAccess", "score": 0.92, "reason": "copied 50+ items"},
      ],
      "risk_score_breakdown": {
          "keyword_score": 3.0,
          "yara_score": 2.5,
          "behavioral_score": 1.8,
          "application_score": 0.2,
          "final_score": 7.5
      },
      "action_reason": "Matched payment card + API key in clipboard",
      "event_type": "clipboard",
      "content_size": 1024,
      "check_duration_ms": 145
  }
  sender.send(event)

EXAMPLE 2 — Using EnrichedEventBuilder (recommended):
──────────────────────────────────────────────────────
  builder = EnrichedEventBuilder(event)
  builder.add_yara_matches([
      {"rule": "CreditCard", "matched": ["4532-****-****-5678"]},
  ])
  builder.add_behavioral_matches([
      {"rule": "BulkClipboardAccess", "score": 0.92, "reason": "copied 50+ items"},
  ])
  builder.set_risk_breakdown(keyword=3.0, yara=2.5, behavioral=1.8)
  builder.set_action_reason("Matched payment card en API key")
  builder.set_metadata("clipboard", content_size=1024, check_duration_ms=145)
  
  enriched = builder.build()
  sender.send(enriched)

ADMIN DASHBOARD EFFECT:
────────────────────
  ✓ Khi click event detail trên admin:
    • Hiển thị "YARA Matches" section (orange box)
      └─ Rule names + matched patterns
    • Hiển thị "Behavioral Matches" section (green box)
      └─ Rule + score + reason (mô tả hành động)
    • Hiển thị "Risk Breakdown" table (blue box)
      └─ 5 thành phần: keyword, yara, behavioral, application, final
    • Hiển thị "Action Reason" (red box)
      └─ Giải thích tại sao chọn action này
    • Metadata (gray section)
      └─ Processing time + content size

════════════════════════════════════════════════════════════════╝
"""


import httpx
import threading
import queue
import time
import json
import os
from pathlib import Path
import sys

# Thêm parent dir để import agent.*
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.config import get_server_url, get_api_key

# ============================================================
# CONFIG — đọc từ config.json (quản lý bởi setup wizard)
# ============================================================
SERVER_URL = get_server_url()   # IP Tailscale của máy admin
API_KEY    = get_api_key()      # Key của máy này
# ============================================================


BATCH_SIZE     = 5      
FLUSH_INTERVAL = 5       # Hoặc mỗi 5 giây, tùy cái nào đến trước
TIMEOUT        = 5       # Timeout HTTP (giây)




# ============================================================
# HELPER: EnrichedEventBuilder — Xây dựng events với chi tiết
# ============================================================
class EnrichedEventBuilder:
    """
    Trợ tích xây dựng enriched events với tất cả chi tiết phát hiện.
    
    Usage:
        builder = EnrichedEventBuilder(base_event)
        builder.add_yara_matches([...])
        builder.add_behavioral_matches([...])
        builder.set_risk_breakdown(...)
        builder.set_action_reason("...")
        builder.set_metadata("clipboard", content_size=1024)
        enriched = builder.build()
        sender.send(enriched)
    """
    
    def __init__(self, base_event: dict):
        """Khởi tạo từ base event (sự kiện cơ bản)."""
        self._event = base_event.copy()
    
    
    def add_yara_matches(self, matches: list | None) -> "EnrichedEventBuilder":
        """
        Thêm YARA matches.
        
        Args:
            matches: List of dicts:
                [
                    {"rule": "CreditCard", "matched": ["pattern1", "pattern2"]},
                    {"rule": "APIKey", "matched": ["sk-proj-..."]},
                ]
        """
        if not matches:
            matches = []
        
        self._event["yara_matches_count"] = len(matches)
        self._event["yara_rules_matched"] = matches
        return self
    
    
    def add_behavioral_matches(self, matches: list | None) -> "EnrichedEventBuilder":
        """
        Thêm Behavioral matches.
        
        Args:
            matches: List of dicts:
                [
                    {"rule": "BulkClipboardAccess", "score": 0.92, "reason": "copied 50+ items"},
                    {"rule": "FileExfil", "score": 0.78, "reason": "large file copy to USB"},
                ]
        """
        if not matches:
            matches = []
        
        self._event["behavioral_matches_count"] = len(matches)
        self._event["behavioral_rules_matched"] = matches
        return self
    
    
    def set_risk_breakdown(
        self,
        keyword: float = 0.0,
        yara: float = 0.0,
        behavioral: float = 0.0,
        application: float = 0.0,
        final: float = 0.0,
    ) -> "EnrichedEventBuilder":
        """
        Thiết lập risk score breakdown (từng thành phần của score).
        
        Args:
            keyword: Score từ keyword matching (0-10)
            yara: Score từ YARA rules (0-10)
            behavioral: Score từ behavioral analysis (0-10)
            application: Score từ application/context (0-10)
            final: Final combined score (0-10)
        """
        self._event["risk_score_breakdown"] = {
            "keyword_score": keyword,
            "yara_score": yara,
            "behavioral_score": behavioral,
            "application_score": application,
            "final_score": final,
        }
        return self
    
    
    def set_action_reason(self, reason: str) -> "EnrichedEventBuilder":
        """
        Thiết lập lý do tại sao chọn action này.
        
        Args:
            reason: Mô tả ngắn gọn (vd: "Matched credit card in clipboard")
        """
        self._event["action_reason"] = reason or ""
        return self
    
    
    def set_metadata(
        self,
        event_type: str,
        content_size: int = 0,
        check_duration_ms: int = 0,
    ) -> "EnrichedEventBuilder":
        """
        Thiết lập metadata xử lý.
        
        Args:
            event_type: "clipboard"|"file"|"process"|"network"|...
            content_size: Kích thước data (bytes)
            check_duration_ms: Thời gian phân tích (milliseconds)
        """
        self._event["event_type"] = event_type
        self._event["content_size"] = content_size
        self._event["check_duration_ms"] = check_duration_ms
        return self
    
    
    def build(self) -> dict:
        """Trả về event đã hoàn chỉnh."""
        return self._event



class DLPSender:
    """
    Gửi events lên central server bất đồng bộ.
    Không block luồng chính của DLP.
    
    Hỗ trợ:
      • Basic events: Chỉ có base fields (timestamp, risk_score, action, ...)
      • Enriched events: Có thêm chi tiết (yara_matches, behavioral_matches, risk_breakdown, ...)
      • Mixed: Server gracefully handles cả hai loại trong cùng database
    
    Ví dụ:
        sender = DLPSender()
        
        # Cách 1: Event cơ bản
        sender.send(event)
        
        # Cách 2: Enriched event (sử dụng builder)
        builder = EnrichedEventBuilder(event)
        builder.add_yara_matches([...])
        builder.add_behavioral_matches([...])
        builder.set_risk_breakdown(...)
        enriched = builder.build()
        sender.send(enriched)
    """


    def __init__(self):
        self._queue: queue.Queue = queue.Queue()
        self._running = False
        self._thread: threading.Thread | None = None
        self._client = httpx.Client(
            base_url=SERVER_URL,
            headers={"X-API-Key": API_KEY},
            timeout=TIMEOUT,
        )
        self.start()


    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        print(f"[DLPSender] Started -> {SERVER_URL}")


    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)


    def send(self, event: dict):
        """Đưa event vào queue — không block."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            pass  # bỏ qua nếu queue đầy


    def _worker(self):
        """Thread nền: gom batch rồi POST lên server."""
        buffer: list = []
        last_flush = time.time()


        while self._running:
            # Lấy event từ queue (chờ tối đa 1 giây)
            try:
                event = self._queue.get(timeout=1)
                buffer.append(event)
            except queue.Empty:
                pass


            # Flush khi đủ batch size hoặc hết interval
            should_flush = (
                len(buffer) >= BATCH_SIZE
                or (buffer and time.time() - last_flush >= FLUSH_INTERVAL)
            )


            if should_flush:
                self._flush(buffer.copy())
                buffer.clear()
                last_flush = time.time()


        # Flush phần còn lại khi shutdown
        if buffer:
            self._flush(buffer)


    def _flush(self, events: list):
        """Gửi batch events lên server."""
        if not events:
            return
        try:
            endpoint = "/api/events/batch" if len(events) > 1 else "/api/events"
            payload  = events if len(events) > 1 else events[0]
            resp = self._client.post(endpoint, json=payload)
            resp.raise_for_status()
        except Exception as e:
            # Không crash DLP — chỉ log lỗi
            print(f"[DLPSender] Gửi thất bại ({len(events)} events): {e}")




# ── Singleton dùng chung toàn app ──
sender = DLPSender()




# ============================================================
# TÙY CHỌN: Gửi toàn bộ alerts.json hoặc test enriched events
# Chạy: 
#   - python agent_sender.py                    # gửi alerts.json
#   - python agent_sender.py --test-enriched    # test enriched events
# ============================================================
if __name__ == "__main__":
    import sys


    if "--test-enriched" in sys.argv:
        # Demo: Gửi enriched events để test admin dashboard
        print("=" * 70)
        print("DEMO: Gửi enriched events lên server")
        print("=" * 70)
        
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Test Event 1: CreditCard + APIKey in clipboard
        event1 = {
            "timestamp": now,
            "event_type": "clipboard",
            "file_path": None,
            "file_name": None,
            "user": "admin",
            "window_title": "Chrome - Gmail",
            "process_name": "chrome.exe",
            "keywords": ["credit card", "api key"],
            "source": "clipboard",
            "is_clipboard": True,
            "risk_score": 6.5,
            "action": "log",
        }
        
        builder1 = EnrichedEventBuilder(event1)
        builder1.add_yara_matches([
            {"rule": "CreditCard", "matched": ["4532-****-****-5678"]},
            {"rule": "APIKey", "matched": ["sk-proj-aB3cD..."]},
        ])
        builder1.add_behavioral_matches([
            {"rule": "BulkClipboardAccess", "score": 0.92, "reason": "copied 50+ items"},
        ])
        builder1.set_risk_breakdown(keyword=3.0, yara=2.5, behavioral=1.0)
        builder1.set_action_reason("Matched payment card + API key in clipboard")
        builder1.set_metadata("clipboard", content_size=1024, check_duration_ms=145)
        
        event1_enriched = builder1.build()
        
        # Test Event 2: Financial data in file copy
        event2 = {
            "timestamp": now,
            "event_type": "file",
            "file_path": "C:\\\\Users\\\\User\\\\Documents\\\\Q1_Financial.xlsx",
            "file_name": "Q1_Financial.xlsx",
            "user": "admin",
            "window_title": "Explorer",
            "process_name": "explorer.exe",
            "keywords": ["bank account", "revenue"],
            "source": "file_copy",
            "is_clipboard": False,
            "risk_score": 7.2,
            "action": "block",
        }
        
        builder2 = EnrichedEventBuilder(event2)
        builder2.add_yara_matches([
            {"rule": "BankAccount", "matched": ["Account: ****-****-2024"]},
        ])
        builder2.add_behavioral_matches([
            {"rule": "LargeSensitiveFileCopy", "score": 0.88, "reason": "2.5MB financial file"},
            {"rule": "USBDeviceAccess", "score": 0.75, "reason": "copying to removable media"},
        ])
        builder2.set_risk_breakdown(keyword=3.0, yara=2.2, behavioral=2.0)
        builder2.set_action_reason("Attempted copy of financial document to USB")
        builder2.set_metadata("file", content_size=2500000, check_duration_ms=234)
        
        event2_enriched = builder2.build()
        
        # Gửi test events
        events_to_send = [event1_enriched, event2_enriched]
        
        try:
            resp = httpx.post(
                f"{SERVER_URL}/api/events/batch",
                json=events_to_send,
                headers={"X-API-Key": API_KEY},
                timeout=30,
            )
            resp.raise_for_status()
            print(f"\n✓ Đã gửi {len(events_to_send)} enriched events lên {SERVER_URL}")
            print(f"✓ Response: {resp.status_code} - {resp.json()}")
            print("\n→ Mở admin dashboard để xem chi tiết:")
            print(f"  http://<admin-ip>/events")
            print("\n→ Click 'Detail' trên mỗi event để xem:")
            print("  • YARA Matches (orange)")
            print("  • Behavioral Matches (green)")
            print("  • Risk Breakdown (blue)")
            print("  • Action Reason (red)")
        except Exception as e:
            print(f"\n✗ Lỗi gửi: {e}")
            sys.exit(1)
    
    else:
        # Mode bình thường: Gửi alerts.json
        json_path = sys.argv[1] if len(sys.argv) > 1 else "dashboard/logs/alerts.json"


        if not os.path.exists(json_path):
            print(f"Không tìm thấy: {json_path}")
            sys.exit(1)


        with open(json_path, encoding="utf-8") as f:
            events = json.load(f)


        print(f"Đang gửi {len(events)} events từ {json_path} lên {SERVER_URL} ...")


        # Gửi theo batch 100
        chunk = 100
        ok = 0
        for i in range(0, len(events), chunk):
            batch = events[i:i+chunk]
            try:
                resp = httpx.post(
                    f"{SERVER_URL}/api/events/batch",
                    json=batch,
                    headers={"X-API-Key": API_KEY},
                    timeout=30,
                )
                resp.raise_for_status()
                ok += len(batch)
                print(f"  [{ok}/{len(events)}] [v]")
            except Exception as e:
                print(f"  Lỗi batch {i}: {e}")


        print(f"Hoàn tất: {ok}/{len(events)} events đã gửi.")