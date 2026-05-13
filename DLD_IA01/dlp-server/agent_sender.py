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
"""

import httpx
import threading
import queue
import time
import json
import os

# ============================================================
# CONFIG — sửa 2 dòng này cho phù hợp
# ============================================================
SERVER_URL = os.getenv("DLP_SERVER_URL", "http://100.91.22.25:8000")   # IP Tailscale của máy admin
API_KEY    = os.getenv("DLP_API_KEY",    "dlp-key-may-ketoan-01")    # Key của máy này
# ============================================================

BATCH_SIZE     = 20      # Gửi khi đủ 20 events
FLUSH_INTERVAL = 5       # Hoặc mỗi 5 giây, tùy cái nào đến trước
TIMEOUT        = 5       # Timeout HTTP (giây)


class DLPSender:
    """
    Gửi events lên central server bất đồng bộ.
    Không block luồng chính của DLP.
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
# TÙY CHỌN: Gửi toàn bộ alerts.json hiện có lên server 1 lần
# Chạy: python agent_sender.py
# ============================================================
if __name__ == "__main__":
    import sys

    json_path = sys.argv[1] if len(sys.argv) > 1 else "logs/alerts.json"

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
            print(f"  [{ok}/{len(events)}] ✓")
        except Exception as e:
            print(f"  Lỗi batch {i}: {e}")

    print(f"Hoàn tất: {ok}/{len(events)} events đã gửi.")
