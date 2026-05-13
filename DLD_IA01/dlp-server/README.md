# DLP Central Server — Hướng dẫn triển khai

## Cấu trúc
```
dlp-server/
├── main.py           ← FastAPI server (chạy trên máy admin)
├── database.py       ← SQLite storage
├── agent_sender.py   ← Copy vào project DLP của bạn
├── static/
│   └── index.html    ← Dashboard web
└── dlp_events.db     ← Tự tạo khi chạy lần đầu
```

---

## BƯỚC 1 — Cài dependencies (máy admin)
```bash
pip install fastapi uvicorn httpx
```

---

## BƯỚC 2 — Thêm API key cho từng máy endpoint
Mở `main.py`, tìm dict `AGENT_KEYS` và thêm vào:
```python
AGENT_KEYS = {
    "dlp-key-may-ketoan-01": "PC-KeToan-01",
    "dlp-key-may-nhansu-02": "PC-NhanSu-02",
    # thêm máy mới tại đây
}
```
Tạo key mới bằng lệnh:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## BƯỚC 3 — Chạy server (máy admin)
```bash
cd dlp-server
python main.py
```
Dashboard mở tại: http://localhost:8000

---

## BƯỚC 4 — Cài Tailscale (để xem từ xa)
1. Vào https://tailscale.com → tạo account miễn phí
2. Cài Tailscale trên máy admin + tất cả máy endpoint
3. Ghi lại IP Tailscale của máy admin (dạng 100.x.x.x)
4. Dashboard sẽ truy cập được tại: http://100.x.x.x:8000

---

## BƯỚC 5 — Thêm agent_sender vào DLP hiện tại

### Copy file
```
agent_sender.py  →  cùng thư mục với code DLP của bạn
```

### Sửa config trong agent_sender.py
```python
SERVER_URL = "http://100.64.0.1:8000"   # IP Tailscale máy admin
API_KEY    = "dlp-key-may-ketoan-01"    # Key của máy này
```

### Thêm vào code DLP (chỉ 1 dòng)
```python
from agent_sender import sender   # import 1 lần ở đầu file

# Chỗ nào bạn tạo ra event dict, thêm vào:
sender.send(event)   # ← thêm dòng này sau khi tạo event
```

---

## BƯỚC 6 — (Tùy chọn) Gửi dữ liệu cũ từ alerts.json
```bash
# Trên máy endpoint, chạy 1 lần để upload lịch sử
python agent_sender.py logs/alerts.json
```

---

## API Endpoints

| Method | URL                  | Dùng để                          |
|--------|----------------------|----------------------------------|
| POST   | /api/events          | Agent gửi 1 event                |
| POST   | /api/events/batch    | Agent gửi nhiều events cùng lúc  |
| GET    | /api/events          | Dashboard đọc danh sách          |
| GET    | /api/stats           | KPI tổng hợp                     |
| GET    | /api/machines        | Danh sách máy đã kết nối         |
| GET    | /                    | Dashboard HTML                   |

---

## Mở rộng sau này
- Đổi SQLite → PostgreSQL: thay `DB_PATH` và dùng `asyncpg`
- Thêm auth dashboard: thêm middleware check cookie/JWT
- Alert email: dùng `smtplib` gửi mail khi risk_score >= 9
- WebSocket realtime: thay polling 3s bằng `ws://server/ws`
