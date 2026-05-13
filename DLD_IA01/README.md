# DLD_IA01 — Hybrid DLP (Endpoint)

Dự án **phòng chống mất mát dữ liệu (Data Loss Prevention)** hướng tới máy trạm Windows (SME), kết hợp **rule-based (YARA)**, **phân tích hành vi**, **ML/UEBA (Isolation Forest)** và **OCR có điều kiện**. Kiến trúc tách **thu thập sự kiện nhẹ (Agent L1/L2)** và **xử lý phát hiện nặng (Worker L3)** để tránh treo máy khi có nhiều sự kiện.

Mã nguồn chính nằm trong thư mục **`HybridDLP_ED/`**.

---

## Mục tiêu và phạm vi

- **Giám sát endpoint**: file system, USB, clipboard, process, endpoint (mở/đọc file), mạng (tùy cấu hình), in, tùy chọn upload trình duyệt (native messaging).
- **Phát hiện**: dữ liệu nhạy cảm (PII Việt Nam, thẻ, email, …) qua YARA; điểm rủi ro đa yếu tố; hành vi bất thường (ML) khi có model.
- **Thiết kế thực tế**: queue bền vững (SQLite), hash cache SHA-256, **panic mode** khi queue quá tải, OCR/ML **lazy load**, debounce file trước khi hash.

---

## Kiến trúc tổng thể

```text
┌─────────────────────────────────────────────────────────────────┐
│  Windows Endpoint                                                │
│                                                                  │
│  ┌──────────────────────────┐     ┌──────────────────────────┐  │
│  │  Agent (L1 + L2)         │     │  Worker (L3)             │  │
│  │  python -m agent.sensor  │     │  python worker/worker.py │  │
│  │  hoặc python -m agent    │     │                          │  │
│  └────────────┬─────────────┘     └────────────┬─────────────┘  │
│               │                                │                 │
│               │  JSONL + events.db            │  Đọc queue      │
│               │  + agent_store.db (queue L3)   │  YARA / OCR / ML│
│               └────────────────┬───────────────┘                 │
│                                ▼                                 │
│              agent/runtime/  (events, state, DB)                 │
└─────────────────────────────────────────────────────────────────┘
```

### L1 — Thu thập sự kiện (sensors)

- Các luồng sensor đưa sự kiện vào **hàng đợi trong bộ nhớ**, consumer chuẩn hóa và ghi **JSONL** + **SQLite `events.db`**.
- Tùy cấu hình, sau khi chuẩn hóa sự kiện được **enqueue** vào **`agent/runtime/agent_store.db`** (bảng `event_queue`) để Worker xử lý bất đồng bộ; crash Agent/Worker ít làm mất sự kiện đã commit.

### L2 — Chuẩn hóa và tương quan (trong tiến trình Agent)

- **`event_pipeline`**: chuẩn hóa schema, metadata thiết bị/người dùng.
- **`ContextCorrelator`**: mặc định **có thể tắt trên Sensor** (`SENSOR_ENABLE_CORRELATOR=0`); logic tương quan nặng (ví dụ upload nghi ngờ) có thể chạy trên **Worker** để Sensor nhẹ hơn.

### L3 — Detection Engine (Worker)

- Đọc hàng đợi: **`WORKER_QUEUE_BACKEND=sqlite`** (mặc định) từ `agent_store.db`, hoặc **`jsonl`** (legacy).
- Pipeline điển hình: **ổn định file → SHA-256 (chunk) → scan cache → fast scan (YARA, header)** → nếu cần **deep scan (OCR/ML)** → **risk scoring** → hành động (alert/log).
- **Hash cache** lưu `scan_result`, `risk_score`, phiên bản policy/engine để invalidate khi đổi rule/model.

Chi tiết kiến trúc có thể xem thêm: [`HybridDLP_ED/docs/architecture.md`](HybridDLP_ED/docs/architecture.md).

---

## Cấu trúc thư mục (rút gọn)

```text
DLD_IA01/
├── Noteupdate.txt              # Ghi chú thiết kế / checklist (tham khảo)
├── README.md                   # File này
└── HybridDLP_ED/
    ├── agent/                  # L1 + L2
    │   ├── __main__.py         # python -m agent → chạy sensor
    │   ├── sensor.py           # Điểm vào chính: queue, consumer, sensors
    │   ├── persistent_queue.py # Queue SQLite cho Worker (event_queue, …)
    │   ├── event_pipeline.py   # Chuẩn hóa sự kiện
    │   ├── sensors/            # file, usb, clipboard, process, network, …
    │   ├── native_host/        # Native messaging (browser upload) — tùy chọn
    │   └── runtime/            # events_*.jsonl, events.db, agent_store.db, state/
    ├── worker/                 # L3
    │   ├── worker.py           # Detection Engine — vòng lặp chính
    │   ├── config.py           # Ngưỡng panic, OCR, ML, hash chunk, …
    │   ├── core/               # hash_cache, fast_scan, deep_analysis, risk_scoring, …
    │   ├── yara_rules/         # Quy tắc YARA
    │   └── ml_models/          # Model UEBA (.pkl) — tùy huấn luyện
    ├── ML/                     # Script huấn luyện / phân tích ML (UEBA)
    ├── docs/                   # Hướng dẫn tiếng Việt
    ├── dashboard/              # Giao diện (Streamlit) — nếu dùng
    ├── docker-compose.yml      # Triển khai Docker (Worker + tuỳ chọn)
    └── README.md               # Quick start chi tiết trong monorepo
```

---

## Thành phần chính (Agent)

| Thành phần | Mô tả ngắn |
|------------|------------|
| `file_sensor` | Theo dõi thay đổi file (watchdog / polling). |
| `endpoint_sensor` | Sự kiện mở/đọc file theo path được giám sát. |
| `usb_sensor` | Gắn/tháo USB, có thể mở rộng watch path. |
| `clipboard_sensor` | Nội dung clipboard (text / metadata ảnh-file list). |
| `process_sensor` | Tiến trình tạo/kết thúc, IOC, công cụ chuyển file. |
| `network_sensor` | Gói tin / upload — thường cần quyền admin (WinDivert). |
| `print_sensor` | In ấn (tùy môi trường). |
| `browser_upload_sensor` | TCP nhận JSON từ extension/native host. |

Watchdog / Windows Service (nếu dùng): xem `agent/watchdog_core.py`, `agent/service.py`, hoặc `service/` trong `HybridDLP_ED`.

---

## Thành phần chính (Worker)

| Thành phần | Mô tả ngắn |
|------------|------------|
| `sqlite_queue_consumer` / JSONL | Lấy sự kiện từ queue. |
| `hash_cache` | SHA-256 theo chunk, cache + phiên bản policy/engine. |
| `file_stability` | Chờ file ổn định trước khi hash. |
| `fast_scan` | YARA, kiểu file, panic mode giảm chi phí. |
| `deep_analysis` | OCR / ML lazy. |
| `risk_scoring` | Điểm rủi ro (NIST/truyền thống — theo `config`). |
| `behavioral_rules` | Rule hành vi bổ sung. |
| `BehavioralMLAnalyzer` | UEBA — load model khi cần. |

---

## Yêu cầu môi trường

- **Windows 10/11** (hoặc Server) cho Agent đầy đủ tính năng.
- **Python 3.10+** (khuyến nghị 3.12).
- Một số tính năng: **quyền Administrator** (network sensor, driver).
- Worker: xem **`HybridDLP_ED/worker/requirements.txt`** (loguru, yara-python, psutil, …).

---

## Cài đặt nhanh

```powershell
cd DLD_IA01\HybridDLP_ED
python -m venv .venv
.\.venv\Scripts\activate
pip install -r worker\requirements.txt
pip install -r agent\requirements.txt
# Bổ sung nếu dùng network/file sensor: psutil, watchdog, pydivert, pywin32
pip install psutil watchdog pywin32
```

Huấn luyện ML (tùy chọn): thư mục **`HybridDLP_ED/ML/`** (`README.md`, `HUONG_DAN_TRAIN.md`).

---

## Chạy thử (development)

**Bước 1 — Agent (L1/L2)** — từ thư mục `HybridDLP_ED`:

```powershell
cd DLD_IA01\HybridDLP_ED
python -m agent.sensor
# hoặc tương đương:
python -m agent
```

**Bước 2 — Worker (L3)** — terminal khác:

```powershell
cd DLD_IA01\HybridDLP_ED\worker
python worker.py
```

Biến môi trường quan trọng (tóm tắt):

| Biến | Ý nghĩa |
|------|---------|
| `SENSOR_WATCH_PATHS` | Danh sách thư mục giám sát (Windows, cách nhau `;`). |
| `NETWORK_SENSOR_ENABLED` | `0` để tắt network sensor nếu không có quyền admin. |
| `SENSOR_SQLITE_QUEUE` | `1` (mặc định): ghi queue persistent cho Worker. |
| `SENSOR_ENABLE_CORRELATOR` | `0` (mặc định): correlator nặng chuyển Worker. |
| `WORKER_QUEUE_BACKEND` | `sqlite` (mặc định) hoặc `jsonl`. |
| `SCAN_ENGINE_VERSION` / `POLICY_VERSION` | Đổi để invalidate hash cache. |

Tài liệu đầy đủ: **[`HybridDLP_ED/docs/HUONG_DAN_CHAY_AGENT.md`](HybridDLP_ED/docs/HUONG_DAN_CHAY_AGENT.md)**.

---

## Kiểm thử tự động (một phần)

```powershell
cd DLD_IA01\HybridDLP_ED
python scripts\test_sha_cache_checklist.py
```

Script trên kiểm tra hash theo chunk, invalidation cache theo policy version, và debounce file (không cần YARA).

---

## Tài liệu trong repo

| Tài liệu | Nội dung |
|----------|----------|
| [`HybridDLP_ED/docs/HUONG_DAN_CHAY_AGENT.md`](HybridDLP_ED/docs/HUONG_DAN_CHAY_AGENT.md) | Chạy Agent, đường dẫn runtime, biến môi trường. |
| [`HybridDLP_ED/docs/GIAI_THICH_AGENT_VA_SU_KIEN.md`](HybridDLP_ED/docs/GIAI_THICH_AGENT_VA_SU_KIEN.md) | Giải thích module agent và luồng sự kiện. |
| [`HybridDLP_ED/docs/PHUONG_PHAP_RISK_SCORE_VA_NGUONG.md`](HybridDLP_ED/docs/PHUONG_PHAP_RISK_SCORE_VA_NGUONG.md) | Risk score và ngưỡng. |
| [`HybridDLP_ED/worker/README.md`](HybridDLP_ED/worker/README.md) | Worker / Docker / cấu hình. |
| [`HybridDLP_ED/HUONG_DAN_CHAY.md`](HybridDLP_ED/HUONG_DAN_CHAY.md) | Hướng dẫn chạy tổng hợp trong monorepo. |

---

## Docker

Trong `HybridDLP_ED` có **`docker-compose.yml`** để chạy Worker (và dịch vụ liên quan). Agent Windows thường chạy **native** trên máy trạm; Worker có thể chạy container nếu bạn mount `agent/runtime` và rule YARA đúng đường dẫn. Chi tiết: `HybridDLP_ED/README.md` và `docker-compose.yml`.

---

## Giấy phép và đóng góp

Thông tin license (nếu có) nên bổ sung vào file `LICENSE` ở root. Đóng góp: fork, branch, pull request; giữ commit message rõ ràng.

---

## Tóm tắt

**DLD_IA01** là workspace chứa **HybridDLP_ED**: hệ DLP lai **rule + ML**, **hai tiến trình** (Agent nhẹ + Worker nặng), **queue và cache SQLite**, phù hợp báo cáo đồ án và triển khai SME trên Windows.
