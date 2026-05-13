# Hướng dẫn chạy Agent (L1)

Tài liệu này mô tả cách khởi động **sensor agent** (`agent.sensor`), thư mục dữ liệu, biến môi trường và các lưu ý thường gặp trên Windows. Nội dung bám theo mã nguồn `HybridDLP_ED/agent/sensor.py` và các sensor trong `HybridDLP_ED/agent/sensors/`.

## 1. Yêu cầu môi trường

| Mục | Ghi chú |
|-----|---------|
| Hệ điều hành | Code hiện tại được thiết kế chủ yếu cho **Windows** (WFP/WinDivert, ctypes, v.v.). |
| Python | Khuyến nghị **Python 3.10+** (ví dụ 3.12). |
| Thư mục làm việc | Phải chạy lệnh từ thư mục **`HybridDLP_ED`** để import `agent` đúng (xem mục 3). |

### Gói Python nên cài (thực tế dùng trong code)

`agent/requirements.txt` có thể không liệt kê đủ; các module sau được dùng trực tiếp hoặc tùy chọn:

- **`psutil`**: bắt buộc cho `endpoint_sensor` và hữu ích cho `network_sensor` (PID, open files).
- **`watchdog`**: khuyến nghị cho `file_sensor` (theo dõi file tốt hơn khi có).
- **`pydivert`**: cần khi **bật** `network_sensor` và dùng sniff WinDivert (thường cần **quyền Administrator**).
- **`pywin32`**: có trong `agent/requirements.txt`, dùng cho một số tích hợp Windows.

Ví dụ cài nhanh:

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
python -m pip install -U psutil watchdog pydivert pywin32
```

## 2. Cách chạy cơ bản

Từ thư mục **`HybridDLP_ED`**:

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
python -m agent.sensor
```

Khi chạy thành công, console sẽ in các dòng tương tự:

- `[main] started pid= ...`
- `[main] watch_paths: ...`
- `[main] network_sensor: enabled|disabled ...`
- `[main] endpoint_sensor: enabled ...`
- `[main] browser_upload_sensor: ...`
- `[main] entering run loop`

Agent chạy **tiến trình foreground** cho đến khi bị dừng (xem mục 6).

## 3. Vì sao phải `cd` vào `HybridDLP_ED`

Module được gọi là `python -m agent.sensor`, nghĩa là Python cần tìm package **`agent`** trên `sys.path`. Thư mục gốc chứa package `agent` là **`HybridDLP_ED`** (có `agent\__init__.py` hoặc cấu trúc package tương đương). Nếu chạy từ thư mục khác, có thể gặp `ModuleNotFoundError: No module named 'agent'`.

Nếu bắt buộc chạy từ nơi khác, có thể đặt:

```powershell
$env:PYTHONPATH="C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED"
python -m agent.sensor
```

## 4. Đường dẫn runtime và log sự kiện

Theo `sensor.py`, các đường dẫn mặc định (dưới `agent/`):

| Đường dẫn | Mục đích |
|-----------|----------|
| `agent/runtime/state/sensor_heartbeat.json` | Nhịp tim (heartbeat) ghi định kỳ. |
| `agent/runtime/state/sensor.pid` | PID tiến trình agent. |
| `agent/runtime/state/stop.flag` | Cờ dừng từ bên ngoài (xem mục 6). |
| `agent/runtime/state/sensor_stats.json` | Thống kê hàng đợi (queue), panic mode. |
| `agent/runtime/events.jsonl` (base) | Sink JSONL; file thực tế là dạng xoay vòng: `events_YYYYMMDD_N.jsonl`. |
| `agent/runtime/events.db` | SQLite lưu sự kiện đã xử lý. |

**Ghi chú:** JSONL được đặt tên theo ngày UTC và kích thước (xoay khi vượt ngưỡng, mặc định ~50 MB/file trong code).

## 5. Biến môi trường quan trọng

### 5.1. Phạm vi giám sát file

| Biến | Mặc định | Ý nghĩa |
|------|----------|---------|
| `SENSOR_WATCH_PATHS` | *(trống → dùng `C:\`)* | Danh sách thư mục cách nhau bởi **`;`** (Windows). Ghi đè `watch_paths` cho `file_sensor` và `endpoint_sensor`. |

Ví dụ chỉ theo dõi thư mục dự án:

```powershell
$env:SENSOR_WATCH_PATHS="D:\Data;C:\Users\Public\Documents"
python -m agent.sensor
```

### 5.2. Network sensor (WinDivert / pydivert)

| Biến | Mặc định | Ý nghĩa |
|------|----------|---------|
| `NETWORK_SENSOR_ENABLED` | `1` | `0` / `false` / `off` → **không** khởi động luồng `network_sensor`. Hữu ích khi không có quyền admin hoặc không cần bắt gói tin. |
| `NET_PREFER_SNIFF` | `1` | Ưu tiên sniff (phụ thuộc pydivert). |
| `NET_ENFORCE_UPLOAD_GATE` | `0` | Bật “gate” giữ upload (cần hiểu rõ hành vi và quyền). |
| `NET_GATE_HOLD_SEC` | `1.2` | Thời gian giữ (giây) khi gate bật. |

**Lưu ý bảo mật / quyền:** Trên Windows, mở handle WinDivert thường gặp `PermissionError (WinError 5) Access is denied` nếu **không chạy PowerShell/CMD với quyền Administrator**. Khi `network_sensor` lỗi trong luồng, code có thể **kết thúc toàn bộ agent** (đặt `stop_event`).

- Muốn dùng network sensor: chạy terminal **Run as administrator** và cài `pydivert` + driver WinDivert đúng cách.
- Chỉ cần endpoint/file/clipboard/process: đặt `NETWORK_SENSOR_ENABLED=0`.

```powershell
$env:NETWORK_SENSOR_ENABLED="0"
python -m agent.sensor
```

### 5.3. Browser upload sensor (TCP local)

| Biến | Mặc định | Ý nghĩa |
|------|----------|---------|
| `BROWSER_UPLOAD_SENSOR` | `0` | `1` / `true` / `on` → bật server TCP nhận JSON từ extension/native host. |
| `BROWSER_UPLOAD_HOST` | `127.0.0.1` | Địa chỉ bind. |
| `BROWSER_UPLOAD_PORT` | `47266` | Cổng TCP. |

Cần cấu hình extension/native messaging gửi đúng host/port và định dạng message mà `browser_upload_sensor` mong đợi.

#### Setup đầy đủ cho `browser_upload_sensor` (CMD)

1) **Cài extension (Chrome/Edge) ở chế độ Developer**

- Mở `chrome://extensions` (hoặc `edge://extensions`)
- Bật **Developer mode**
- Chọn **Load unpacked**
- Trỏ tới thư mục:
  - `C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\agent\browser_extension`
- Copy **Extension ID** vừa tạo (ví dụ: `pafbpfhlcnllebdecgfbpoofcccfbhdf`)

2) **Cập nhật `allowed_origins` trong native host manifest**

Mở file `agent\native_host\native_host.json`, sửa:

```json
"allowed_origins": [
  "chrome-extension://<EXTENSION_ID>/"
]
```

> Với Edge Chromium, vẫn dùng định dạng `chrome-extension://<EXTENSION_ID>/`.

3) **Đăng ký Native Messaging Host vào Registry (HKCU)**

```bat
cd /d C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
python .\agent\native_host\install_host.py
```

Lệnh này sẽ:
- tự cập nhật trường `path` trong `native_host.json` trỏ đúng `native_host.bat`
- ghi key registry cho Chrome/Edge:
  - `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.dlp.browser_upload`
  - `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.dlp.browser_upload`

4) **Khởi động lại browser** (đóng/mở lại Chrome/Edge) để nhận registry mới.

5) **Chạy sensor browser upload**

```bat
cd /d C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
set SENSOR_ONLY=browser_upload_sensor
set BROWSER_UPLOAD_SENSOR=1
set BROWSER_UPLOAD_HOST=127.0.0.1
set BROWSER_UPLOAD_PORT=47266
python -m agent.sensor
```

6) **Test kết nối native host (tuỳ chọn)**

Mở terminal khác:

```bat
cd /d C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
python .\agent\native_host\native_host.py --test
```

Nếu thành công sẽ có log kiểu `Event sent successfully`.

7) **Verify event đã vào JSONL**

```bat
cd /d C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
python -c "import json,glob; p=sorted(glob.glob(r'agent/runtime/events_*.jsonl'))[-1]; c=0; \
f=open(p,encoding='utf-8',errors='ignore'); \
[print(x.strip()) for x in f if x.strip() and json.loads(x).get('source') in ('browser_upload','browser_upload_sensor')];"
```

Nếu không thấy event:
- kiểm tra `allowed_origins` có đúng Extension ID hiện tại không
- remove/reload extension sau khi sửa `manifest.json` hoặc `native_host.json`
- chạy lại `install_host.py`
- kiểm tra log `agent\native_host\native_host.log`

### 5.4. Chạy riêng từng sensor (mới)

| Biến | Ví dụ | Ý nghĩa |
|------|-------|---------|
| `SENSOR_ONLY` | `file_sensor` hoặc `file_sensor,endpoint_sensor` | Chỉ chạy sensor trong danh sách này. |
| `SENSOR_ENABLE_<SENSOR_NAME>` | `SENSOR_ENABLE_USB_SENSOR=0` | Bật/tắt từng sensor cụ thể (ưu tiên cao hơn mặc định). |

Tên sensor hợp lệ:

- `file_sensor`
- `usb_sensor`
- `clipboard_sensor`
- `process_sensor`
- `endpoint_sensor`
- `network_sensor`
- `browser_upload_sensor`
- `print_sensor`

## 6. Cách dừng agent

1. **Ctrl+C** trong cửa sổ đang chạy — xử lý `SIGINT`, enqueue `shutdown`, sau đó thoát.
2. Tạo file **`agent/runtime/state/stop.flag`** (file rỗng cũng được). Vòng lặp main phát hiện file này và gọi shutdown tương tự SIGTERM.

Sau khi dừng, log có thể hiển thị: `[main] stop_event set -> draining queue` rồi `[main] exit`.

## 7. Kiến trúc luồng (tóm tắt)

- **Consumer** đọc hàng đợi, gọi **ContextCorrelator** (tạo thêm sự kiện tương quan nếu có), **canonicalize** và ghi ra **JSONL + SQLite**.
- Các luồng sensor: `file_sensor`, `usb_sensor`, `clipboard_sensor`, `process_sensor`, `endpoint_sensor`, tùy chọn `network_sensor`, `browser_upload_sensor`, `print_sensor`.
- **Heartbeat** và **queue_monitor** cập nhật trạng thái định kỳ.

## 8. Xử lý sự cố thường gặp

| Hiện tượng | Nguyên nhân có thể | Gợi ý |
|------------|-------------------|--------|
| Agent thoát ngay sau `entering run loop` | `network_sensor` lỗi (WinDivert không có quyền) | Chạy **admin** hoặc `NETWORK_SENSOR_ENABLED=0`. |
| Không thấy `file_*` / `endpoint_*` | Phạm vi `watch_paths` không chứa đường dẫn bạn thao tác | Kiểm tra `SENSOR_WATCH_PATHS` hoặc dùng mặc định `C:\`. |
| `endpoint_sensor_error` / thiếu psutil | Chưa cài `psutil` | `pip install psutil`. |
| `ModuleNotFoundError: agent` | Sai thư mục làm việc | `cd HybridDLP_ED` hoặc `PYTHONPATH`. |

## 9. Kiểm tra nhanh sau khi chạy

1. Xem `agent/runtime/state/sensor_heartbeat.json` — `seq` tăng theo thời gian.
2. Mở file JSONL ngày hiện tại trong `agent/runtime/events_*_*.jsonl` — có dòng `heartbeat`, `*_sensor_started`.
3. Truy vấn `agent/runtime/events.db` bảng `events` nếu cần phân tích SQL.

---

## 10. Test từng sensor (prático)

Hiện tại bạn có thể chạy riêng sensor bằng `SENSOR_ONLY`.

### 10.1. Chuẩn bị session test sạch

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
Remove-Item -Force .\agent\runtime\events_*.jsonl -ErrorAction SilentlyContinue
Remove-Item -Force .\agent\runtime\events.db -ErrorAction SilentlyContinue
```

### 10.2. Chạy agent với phạm vi nhỏ để giảm nhiễu

```powershell
$env:SENSOR_WATCH_PATHS="C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\agent\runtime\watch_test"
$env:NETWORK_SENSOR_ENABLED="0"
$env:BROWSER_UPLOAD_SENSOR="0"
python -m agent.sensor
```

> Gợi ý: nếu cần test network riêng thì bật lại `NETWORK_SENSOR_ENABLED=1` (mở terminal Admin).

### 10.3. Lệnh chạy từng sensor riêng (không chạy chung)

Chuẩn bị chung:

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
$env:SENSOR_WATCH_PATHS="C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\agent\runtime\watch_test"
$env:BROWSER_UPLOAD_SENSOR="0"
```

Chạy từng sensor (CMD):

```bat
REM file_sensor
set SENSOR_ONLY=file_sensor
python -m agent.sensor

REM endpoint_sensor
set SENSOR_ONLY=endpoint_sensor
python -m agent.sensor

REM clipboard_sensor
set SENSOR_ONLY=clipboard_sensor
python -m agent.sensor

REM process_sensor
set SENSOR_ONLY=process_sensor
python -m agent.sensor

REM usb_sensor
set SENSOR_ONLY=usb_sensor
python -m agent.sensor

REM network_sensor (cần Run as Administrator + pydivert)
set SENSOR_ONLY=network_sensor
set NETWORK_SENSOR_ENABLED=1
python -m agent.sensor

REM browser_upload_sensor
set SENSOR_ONLY=browser_upload_sensor
set BROWSER_UPLOAD_SENSOR=1
python -m agent.sensor

REM all sensors
set SENSOR_ONLY=
set NETWORK_SENSOR_ENABLED=1
set BROWSER_UPLOAD_SENSOR=1
python -m agent.sensor
```

> Sau mỗi lần test, có thể xóa biến:
> `Remove-Item Env:SENSOR_ONLY -ErrorAction SilentlyContinue`

### 10.4. Kịch bản test theo từng sensor

- **`file_sensor`**: tạo/sửa/xóa/đổi tên file trong `watch_test`.
- **`endpoint_sensor`**: mở file bằng Notepad/VSCode rồi đọc/sửa.
- **`clipboard_sensor`**: copy/paste đoạn text dài hơn ngưỡng tối thiểu.
- **`process_sensor`**: chạy tool nằm trong watch list (vd `powershell`, `curl`, `7z`).
- **`usb_sensor`**: cắm/rút USB.
- **`network_sensor`** (khi bật): upload thử file nhỏ/lớn qua web/cloud để tạo `network_upload_summary`.
- **`browser_upload_sensor`** (khi bật): gửi message từ extension/native host.

### 10.5. Lọc event theo sensor sau khi test

Mở terminal khác:

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED
python -c "import json,glob; p=sorted(glob.glob(r'agent/runtime/events_*.jsonl'))[-1]; \
from collections import Counter; c=Counter(); \
[c.update([(json.loads(x).get('source'), json.loads(x).get('type'))]) for x in open(p,encoding='utf-8',errors='ignore') if x.strip()]; \
print('file_sensor ->', sum(v for (s,t),v in c.items() if s=='file')); \
print('endpoint_sensor ->', sum(v for (s,t),v in c.items() if s=='endpoint')); \
print('clipboard_sensor ->', sum(v for (s,t),v in c.items() if s=='clipboard')); \
print('process_sensor ->', sum(v for (s,t),v in c.items() if s=='process')); \
print('usb_sensor ->', sum(v for (s,t),v in c.items() if s=='usb')); \
print('network_sensor ->', sum(v for (s,t),v in c.items() if s=='network')); \
print('browser_upload_sensor ->', sum(v for (s,t),v in c.items() if s=='browser_upload_sensor'))"
```

Nếu muốn xem chi tiết một sensor:

```powershell
python -c "import json,glob; p=sorted(glob.glob(r'agent/runtime/events_*.jsonl'))[-1]; \
[print(x.strip()) for x in open(p,encoding='utf-8',errors='ignore') if x.strip() and json.loads(x).get('source')=='endpoint']"
```

### 10.6. Dừng test

- Nhấn `Ctrl + C` ở cửa sổ đang chạy agent, hoặc tạo `agent/runtime/state/stop.flag`.

---

*Tài liệu được sinh từ mã nguồn; nếu thay đổi `sensor.py`, nên đối chiếu lại giá trị mặc định và tên biến môi trường.*
