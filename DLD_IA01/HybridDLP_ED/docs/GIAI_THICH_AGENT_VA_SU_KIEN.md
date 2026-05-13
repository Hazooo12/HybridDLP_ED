# Giải thích cấu trúc agent và các loại sự kiện (L1)

Tài liệu mô tả phần **agent** trong `HybridDLP_ED/agent/`: kiến trúc, luồng hoạt động, và các **loại event** (`type`) mà hệ thống có thể ghi nhận hoặc phát sinh.

---

## 1. Cấu trúc thư mục (tóm tắt)

| Thành phần | Vai trò |
|------------|---------|
| `sensor.py` | Điểm vào chính (`main`): khởi tạo hàng đợi, sink (JSONL + SQLite), các thread sensor, consumer, heartbeat, giám sát queue, shutdown. |
| `sensors/` | Các sensor thu thập sự kiện tầng L1 (metadata, chưa phân tích sâu / chặn). |
| `event_pipeline.py` | Hàm `canonicalize_event()` — chuẩn hóa mọi event về schema thống nhất. |
| `event_schema.py` | `normalize_event()`, `empty_event()` — cấu trúc event chuẩn (actor, object, context, device, …). |
| `event_emit.py` | Helper `emit_event()` để dựng dữ liệu event. |
| `sensors/context_correlator.py` | Tương quan hóa chuỗi hành vi (file ↔ mạng ↔ USB ↔ clipboard) và phát sinh event `corr_*`. |
| `queue_monitor.py` | Theo dõi mức đầy queue; bật **panic mode** (ưu tiên giữ một số loại event, bỏ qua phần còn lại khi quá tải). |
| `queue_monitor.py` + `sensor.py` | `QueueManager` đồng bộ `panic_mode` để `enqueue_event()` có thể drop có kiểm soát. |
| `watchdog_*.py`, `service.py`, `exfil_server.py` | Dịch vụ / tiện ích hỗ trợ (ngoài phạm vi chi tiết tài liệu này). |

Thư mục runtime mặc định: `agent/runtime/` — ghi `events*.jsonl` (xoay vòng theo ngày/dung lượng) và `events.db`.

---

## 2. Luồng hoạt động

1. **Khởi động:** `main()` trong `sensor.py` tạo `QueueManager`, các sink (`JsonlFileSink`, `SQLiteEventStore`), `ContextCorrelator`, tùy chọn `ContextProvider` (foreground user, cửa sổ, …).

2. **Thread sensor:** Mỗi sensor chạy trong `sensor_thread_runner` — trước khi vào vòng lặp chính sẽ enqueue một event `{tên_sensor}_started`. Nếu vòng lặp sensor lỗi nặng, sẽ có `{tên_sensor}_error` và có thể dừng `stop_event`.

3. **Sinh event:** Sensor gọi `queue_manager.enqueue_event(evt)`. Timestamp được chuẩn hóa qua `adapt_for_queue`.

4. **Consumer:** `consumer_loop` lấy event từ queue:
   - Gọi `ContextCorrelator.on_event(event)` — correlator có thể trả về thêm event và **enqueue** lại (event `corr_*`).
   - Áp dụng `canonicalize_event(event)` rồi ghi qua từng sink.

5. **Heartbeat:** Thread riêng định kỳ enqueue `heartbeat` và ghi file `sensor_heartbeat.json` (trạng thái queue, PID, …).

6. **Dừng:** `SIGINT`/`SIGTERM`, file `stop.flag`, hoặc lỗi sensor — enqueue `shutdown` (nếu có), drain queue ngắn, đóng sink.

7. **Panic mode:** Khi queue gần đầy (`queue_monitor`), `panic_mode` bật; `enqueue_event` chỉ cho phép một tập nhỏ `type` (heartbeat, shutdown, overload, các `*_sensor_error`, `*_started`, …) — các event khác bị bỏ để tránh crash.

---

## 3. Schema event (ý niệm)

Sau khi qua `canonicalize_event` + `normalize_event`, event có các nhóm trường chính:

- **type**, **source**, **severity**, **ts** (ISO UTC), **tags**, **ioc_hits**
- **device** (host, device_id)
- **actor** / **process** (user, pid, exe, cmdline, …)
- **object** (path, hash, kích thước, volume, …)
- **context** (foreground app, tiêu đề cửa sổ, domain gợi ý, …)
- **operation**, **metrics**, **flags**, **content**
- Các bucket chuyên biệt: **clipboard**, **usb**, **print**, **network**, **decision**, **debug**
- Dữ liệu pháp y: **raw_original**, **raw_envelope**

L1 là layer “chỉ thu thập/metadata”; logic phát hiện nặng thường nằm ở worker/engine khác (nếu có trong repo).

---

## 4. Các loại event (`type`) theo nguồn

### 4.1. Sensor tệp (`file_sensor.py`)

- `file_created` — tạo file  
- `file_modified` — sửa file  
- `file_deleted` — xóa file  
- `file_moved` — đổi tên / di chuyển  

(Nội dung: `file_{evt_kind}` với `evt_kind` ∈ {created, modified, deleted, moved}.)

**Lưu ý:** Trong `main()`, mặc định chỉ watch thư mục `runtime/watch_test` (và USB có thể thêm path khi cắm). Muốn nhiều file event hơn cần cấu hình `watch_paths`.

### 4.2. Sensor USB (`usb_sensor.py`)

- `usb_connected`  
- `usb_disconnected`  

### 4.3. Sensor tiến trình (`process_sensor.py`)

- `proc_start` — tiến trình trong danh sách theo dõi (ví dụ powershell, curl, browser, …) vừa chạy  
- `proc_end` — tiến trình kết thúc (nếu bật `emit_end`)  
- `proc_sensor_error` — lỗi cấu hình (ví dụ không có `psutil`)

### 4.4. Sensor mạng (`network_sensor.py`)

- `network_upload_summary` — tóm tắt tải lên (theo ngưỡng byte, process, …)

Trong `event_pipeline.py` còn có mapping cho các tên kiểu legacy (ví dụ `network_flow_summary`, `http_upload`, …) khi suy luận `operation` — có thể xuất hiện nếu code/phiên bản khác còn emit.

### 4.5. Sensor clipboard (`clipboard_sensor.py`)

- `clipboard_copy`  
- `clipboard_paste`  
- `clipboard_sensor_error` — lỗi sensor  

### 4.6. Sensor in (`print_sensor.py`, tùy môi trường)

- `print_job`  
- `print_sensor_error`  

### 4.7. Điều khiển & vận hành (`sensor.py`)

- `heartbeat` — sống của agent  
- `shutdown` — tắt có kiểm soát  
- `{sensor_name}_started` — ví dụ: `file_sensor_started`, `usb_sensor_started`, `clipboard_sensor_started`, `process_sensor_started`, `network_sensor_started`, `print_sensor_started`  
- `{sensor_name}_error` — lỗi trong `sensor_thread_runner` (wrapper của sensor)

### 4.8. Correlator (`context_correlator.py`)

Các event kết nối hành vi nghi ngờ (staging, upload, exfil USB/clipboard, …):

- `corr_staging_detected`  
- `corr_archive_staging`  
- `corr_suspected_upload`  
- `corr_network_exfil_suspected`  
- `corr_exfil_usb_suspected`  
- `corr_clipboard_exfil_suspected`  

### 4.9. Đặc biệt

- `unknown` — event không phải dict hợp lệ khi vào pipeline.  
- `overload_drop_summary` — (liên quan cơ chế quá tải; có thể xuất hiện nếu module tương ứng enqueue.)

---

## 5. Ví dụ thực tế từ log `events_20260318_1.jsonl`

Trong file log mẫu đó, các `type` xuất hiện gồm:

`clipboard_paste`, `clipboard_sensor_started`, `corr_suspected_upload`, `file_sensor_started`, `heartbeat`, `network_sensor_started`, `network_upload_summary`, `print_sensor_started`, `proc_sensor_error`, `process_sensor_started`, `shutdown`, `usb_sensor_started`

Điều này cho thấy phiên chạy đó có: clipboard, tóm tắt upload mạng, một cảnh báo correlator upload, lỗi process sensor, và các event điều khiển — **không** thấy `file_*` hay `usb_connected` trong file đó (có thể do không có thay đổi file trong thư mục được watch, hoặc không cắm USB / không có sự kiện tương ứng trong khoảng thời gian đó).

---

## 6. Tài liệu liên quan trong repo

- `docs/L1_EVENT_CONVENTIONS.md` — quy ước event L1 (nếu có cập nhật).  
- `docs/architecture.md` — kiến trúc tổng thể (nếu có).
- **`docs/PHUONG_PHAP_RISK_SCORE_VA_NGUONG.md`** — công thức Risk Score (traditional / NIST / research), tích hợp điểm Isolation Forest, ngưỡng Low–Critical và cấu hình worker (phục vụ chương phương pháp / luận văn).

---

*Tài liệu được tạo để mô tả mã nguồn trong `HybridDLP_ED/agent/`; nếu có thay đổi tên event hoặc cấu hình `main()`, nên đối chiếu lại trực tiếp trong code.*
