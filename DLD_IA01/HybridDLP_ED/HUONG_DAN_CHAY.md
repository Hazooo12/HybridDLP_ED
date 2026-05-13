# HUONG DAN CHAY HE THONG (KHONG DOCKER)

Tai lieu nay huong dan chay HybridDLP theo kieu native tren Windows.
Muc tieu: chay duoc Agent + Worker + Dashboard va hien popup canh bao Windows native.

## 1) Yeu cau moi truong

- Windows 10/11
- Python 3.10+ (khuyen nghi 3.11/3.12)
- Quyen Administrator de bat packet capture/sensor
- Co internet de cai package

## 2) Cau truc thanh phan

- `agent/`: thu thap event tu endpoint (process, clipboard, network, browser upload)
- `worker/`: fast scan + deep analysis + risk scoring + action
- `dashboard/`: giao dien Streamlit de theo doi log canh bao

## 3) Cai dependencies

Mo 3 terminal PowerShell, tat ca deu o root:
`C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED`

### 3.1 Agent

```powershell
cd agent
pip install -r requirements.txt
```

### 3.2 Worker

```powershell
cd ..\worker
pip install -r requirements.txt
```

Neu can popup Windows native, cai them:

```powershell
pip install win10toast plyer pywin32
```

### 3.3 Dashboard

```powershell
cd ..\dashboard
pip install -r requirements.txt
```

## 4) Cau hinh nhanh quan trong

File: `worker/config.py`

- `RISK_ALERT_THRESHOLD = 4.0` (thang 0-10)
- `WINDOWS_ALERT_MIN_SCORE = 7.0` (chi popup native khi diem cao)

Neu muon popup nhieu hon khi test, ha tam:
- `WINDOWS_ALERT_MIN_SCORE = 4.0`

## 5) Thu tu chay dung

## B1. Chay Worker (Terminal 1)

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\worker
python worker.py
```

Ky vong:
- Log co dong khoi tao Detection Engine
- Khong bao loi import/module

## B2. Chay Dashboard (Terminal 2)

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\dashboard
streamlit run dashB.py
```

Mo browser:
- http://localhost:8501

Cho phep Notification cho tab dashboard (neu ban muon browser notification).

## B3. Chay Agent (Terminal 3 - Administrator)

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\agent
python -m agent.sensor
```

Hoac neu du an dang dung watchdog:

```powershell
python watchdog_core.py
```

## 6) Kiem tra he thong dang hoat dong

### 6.1 Kiem tra event queue

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\agent\runtime
dir
```

Kiem tra co:
- `events.db`
- `events_*.jsonl` (neu co backend jsonl)

### 6.2 Kiem tra Worker da xu ly

Xem log:

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\worker
Get-Content .\logs\detection_engine.log -Tail 50
```

### 6.3 Kiem tra Dashboard log

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\dashboard\logs
dir
```

Can co `alerts.json`.

## 7) Test popup Windows native dung cach

Popup native Windows chi co khi Worker chay tren host Windows (khong Docker Linux).

Chay test truc tiep:

```powershell
cd C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\worker
python -c "from core.windows_notification import WindowsNotification as W; W().show_violation_alert('TEST POPUP', {'risk_score': 9.2, 'window_title': 'Manual Test', 'yara_matches': [{'rule':'demo_rule'}]})"
```

Neu popup khong hien:
- Cai them: `pip install win10toast plyer pywin32`
- Chay lai terminal bang quyen user desktop (khong phai session service khong co UI)

## 8) Khac phuc loi thuong gap

### A. Co event nhung khong co popup native

- Worker dang chay trong Docker Linux -> khong the toast native
- `WINDOWS_ALERT_MIN_SCORE` qua cao
- Thieu package notification (`win10toast/plyer/pywin32`)

### B. Dashboard co log nhung khong thay dong moi

- Kiem tra file `dashboard/logs/alerts.json` co duoc cap nhat khong
- Kiem tra `action_executor.py` co log "Saved alert to dashboard"

### C. Network sensor spam log

Da co co che throttle flow debug trong `agent/sensors/network_sensor.py`.
Neu van nhieu, tang nguong:
- `flow_debug_min_interval_sec`
- `flow_debug_min_bytes_delta`
- `flow_debug_min_packets_delta`

## 9) Lenh tat nhanh

Dung `Ctrl + C` o tung terminal:
1. Agent
2. Worker
3. Dashboard

## 10) Checklist run thanh cong

- [ ] Agent chay khong crash
- [ ] Worker chay va consume event
- [ ] Dashboard mo duoc localhost:8501
- [ ] Co ban ghi moi trong `dashboard/logs/alerts.json`
- [ ] Popup Windows native hien khi event risk cao

---

Neu ban muon, buoc tiep theo minh co the tach tai lieu rieng:
- `HUONG_DAN_CHAY_NATIVE.md` (khong docker)
- `HUONG_DAN_CHAY_DOCKER.md` (docker)
de khong bi lon thong tin.
#  HƯỚNG DẪN CHẠY TOÀN BỘ HỆ THỐNG HybridDLP

##  Mục lục

1. [Tổng quan hệ thống](#tổng-quan-hệ-thống)
2. [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
3. [Cài đặt](#cài-đặt)
4. [Chạy hệ thống](#chạy-hệ-thống)
5. [Kiểm tra và xác minh](#kiểm-tra-và-xác-minh)
6. [Troubleshooting](#troubleshooting)
7. [Cấu hình nâng cao](#cấu-hình-nâng-cao)

---

## [TARGET] Tổng quan hệ thống

HybridDLP gồm 3 thành phần chính:

```
┌─────────────────────────────────────────────────────────┐
│              HybridDLP System Architecture              │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐         ┌──────────────┐            │
│  │ Agent (L1)   │────────▶│   SQLite     │            │
│  │ Windows      │ Events  │  (events.db) │            │
│  │ Service      │         │              │            │
│  └──────────────┘         └──────┬───────┘            │
│                                   │                    │
│                          ┌────────┴────────┐          │
│                          │                 │          │
│                   ┌──────▼──────┐  ┌──────▼──────┐   │
│                   │  Worker     │  │  Dashboard  │   │
│                   │  (L3)       │  │  (Streamlit)│   │
│                   │ Detection   │  │  Web UI     │   │
│                   │ Engine      │  │             │   │
│                   └──────────────┘  └──────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Components

1. **Agent (L1)** - Windows Service
   - Thu thập events từ file system, USB, clipboard, processes
   - Ghi events vào SQLite database (`agent/runtime/events.db`)
   - Chạy như Windows Service với SYSTEM privileges

2. **Worker (L3)** - Detection Engine
   - Đọc events từ SQLite database
   - Fast Scan: YARA rules (16 rules)
   - Deep Analysis: ML classification, OCR
   - Risk Scoring & Action Execution
   - Có thể chạy trong Docker hoặc native Python

3. **Dashboard** - Web UI (Streamlit)
   - Hiển thị alerts, statistics
   - Real-time monitoring
   - Truy cập qua http://localhost:8501

---

##  Yêu cầu hệ thống

### Bắt buộc

- **Windows 10/11** hoặc **Windows Server** (cho Agent)
- **Python 3.10+** (cho Agent và scripts)
- **Docker Desktop** (cho Worker và Dashboard - khuyến nghị)
- **Administrator privileges** (để cài đặt Windows Service)

### Tùy chọn (cho Deep Analysis)

- **Tesseract OCR** (cho OCR features)
- **ML Models** (cho ML classification - có thể train sau)

---

##  Cài đặt

### Bước 1: Clone/Download source code

```bash
# Nếu dùng Git
git clone <repository-url>
cd DLD_IA01/HybridDLP_ED

# Hoặc giải nén file ZIP vào thư mục DLD_IA01/HybridDLP_ED
```

### Bước 2: Cài đặt Python dependencies

#### Agent (Windows)

```bash
cd agent
pip install -r requirements.txt
```

**Lưu ý:** Nếu gặp lỗi với `pywin32`, chạy:
```bash
pip install pywin32
python Scripts/pywin32_postinstall.py -install
```

#### Worker (nếu chạy native, không dùng Docker)

```bash
cd worker
pip install -r requirements.txt
```

#### Dashboard (nếu chạy native, không dùng Docker)

```bash
cd dashboard
pip install -r requirements.txt
```

### Bước 3: Cài đặt Docker Desktop (khuyến nghị)

1. Download Docker Desktop từ: https://www.docker.com/products/docker-desktop
2. Cài đặt và khởi động Docker Desktop
3. Verify: `docker --version` và `docker-compose --version`

### Bước 4: Setup ML Models (Tùy chọn)

```bash
cd worker
python scripts/collect_dataset.py
python scripts/train_model.py
```

**Lưu ý:** Nếu chưa có ML models, hệ thống vẫn hoạt động với YARA rules và OCR.

---

## [START] Chạy hệ thống

### Phương án 1: Docker (Khuyến nghị - Dễ nhất)

#### Bước 1: Start Docker Desktop

- Mở **Docker Desktop**
- Đợi Docker khởi động hoàn toàn (icon Docker ở system tray không còn loading)

#### Bước 2: Build và start services

```bash
cd DLD_IA01/HybridDLP_ED

# Build Docker images
docker-compose build

# Start services (background)
docker-compose up -d

# Hoặc start và xem logs
docker-compose up
```

#### Bước 3: Kiểm tra status

```bash
# Xem status các services
docker-compose ps

# Expected output:
# NAME                      STATUS
# hybrid-dlp-worker         Up
# hybrid-dlp-dashboard      Up
```

#### Bước 4: Xem logs

```bash
# Xem logs Worker
docker-compose logs -f worker

# Xem logs Dashboard
docker-compose logs -f dashboard

# Xem tất cả logs
docker-compose logs -f
```

#### Bước 5: Truy cập Dashboard

- Mở trình duyệt: **http://localhost:8501**
- Dashboard sẽ tự động refresh mỗi 2 giây

#### Bước 6: Chạy Agent (Windows Service)

```bash
cd agent

# Test run (không cần service)
python sensor.py

# Hoặc cài đặt như Windows Service
python service.py install
python service.py start
```

**Lưu ý:** Cần chạy Command Prompt/PowerShell với quyền Administrator.

---

### Phương án 2: Chạy Native (Không dùng Docker)

#### Bước 1: Chạy Worker

```bash
cd worker
python worker.py
```

**Expected output:**
```
============================================================
Detection Engine Starting...
============================================================
Initializing Detection Engine components...
Loaded 16 YARA rule files: [...]
Detection Engine initialized successfully
============================================================
Detection Engine running...
============================================================
```

#### Bước 2: Chạy Dashboard (Terminal mới)

```bash
cd dashboard
streamlit run dashB.py
```

**Expected output:**
```
You can now view your Streamlit app in your browser.
Local URL: http://localhost:8501
```

#### Bước 3: Chạy Agent (Terminal mới)

```bash
cd agent

# Test run
python sensor.py

# Hoặc Windows Service
python service.py install
python service.py start
```

---

## [OK] Kiểm tra và xác minh

### 1. Kiểm tra Agent

```bash
# Kiểm tra SQLite database có events không
cd agent/runtime
sqlite3 events.db "SELECT COUNT(*) FROM events;"

# Xem một số events mới nhất
sqlite3 events.db "SELECT id, type, ts FROM events ORDER BY id DESC LIMIT 10;"

# Kiểm tra logs
cat logs/agent.log | tail -20
```

**Expected:** Database có events (số lượng > 0)

### 2. Kiểm tra Worker

```bash
# Nếu dùng Docker
docker-compose logs worker | grep -i "processed\|error\|yara"

# Nếu chạy native
# Xem output trong terminal hoặc
cat worker/logs/detection_engine.log | tail -20
```

**Expected:** Worker đang đọc và xử lý events, không có lỗi

### 3. Kiểm tra Dashboard

- Mở http://localhost:8501
- Kiểm tra:
  - [OK] Dashboard load được
  - [OK] Có hiển thị statistics
  - [OK] Có hiển thị alerts (nếu có)
  - [OK] Auto-refresh hoạt động

### 4. Test với file nhạy cảm

```bash
# Tạo file test với CMND
echo "CMND: 123456789" > test_cmnd.txt

# Copy file vào thư mục được monitor
# Agent sẽ phát hiện và ghi event
# Worker sẽ scan và phát hiện CMND
# Dashboard sẽ hiển thị alert
```

---

## [SEARCH] Troubleshooting

### Vấn đề 1: Docker không start được

**Lỗi:** `Cannot connect to Docker daemon`

**Giải pháp:**
1. Kiểm tra Docker Desktop đã chạy chưa
2. Restart Docker Desktop
3. Kiểm tra: `docker ps` (phải chạy được)

### Vấn đề 2: Worker không đọc được events

**Lỗi:** `Events database not found` hoặc `No events to process`

**Giải pháp:**
```bash
# Kiểm tra SQLite database tồn tại
ls -la agent/runtime/events.db

# Kiểm tra volume mount (nếu dùng Docker)
docker exec -it hybrid-dlp-worker ls -la /app/agent/runtime/

# Kiểm tra Agent có đang chạy không
# Windows: Services.msc → Tìm "HybridDLP Watchdog Service"
```

### Vấn đề 3: YARA rules không load

**Lỗi:** `No YARA rule files found` hoặc `Error loading YARA rules`

**Giải pháp:**
```bash
# Kiểm tra YARA rules tồn tại
ls -la worker/yara_rules/*.yar

# Kiểm tra trong Docker
docker exec -it hybrid-dlp-worker ls -la /app/yara_rules/

# Kiểm tra YARA đã cài đặt
yara --version
```

### Vấn đề 4: Dashboard không hiển thị data

**Lỗi:** Dashboard trống hoặc không load

**Giải pháp:**
```bash
# Kiểm tra logs
docker-compose logs dashboard

# Kiểm tra port 8501 có bị chiếm không
netstat -ano | findstr :8501

# Restart dashboard
docker-compose restart dashboard
```

### Vấn đề 5: Agent không cài được Windows Service

**Lỗi:** `Access denied` hoặc `Permission denied`

**Giải pháp:**
1. Chạy Command Prompt/PowerShell với quyền **Administrator**
2. Kiểm tra Python path đúng
3. Thử: `python service.py install` lại

### Vấn đề 6: OCR không hoạt động

**Lỗi:** `Tesseract OCR not found` hoặc `OCR error`

**Giải pháp:**
1. Cài đặt Tesseract OCR: https://github.com/UB-Mannheim/tesseract/wiki
2. Thêm Tesseract vào PATH
3. Verify: `tesseract --version`

**Lưu ý:** OCR là tùy chọn, hệ thống vẫn hoạt động nếu không có OCR.

---

## [SETTING] Cấu hình nâng cao

### Cấu hình Worker

File: `worker/config.py`

```python
# Panic Mode thresholds
PANIC_MODE_THRESHOLD = 1000  # Enable khi queue > 1000
PANIC_MODE_DISABLE_THRESHOLD = 500  # Disable khi queue < 500

# OCR Configuration
OCR_ENABLED = True
OCR_MAX_FILE_SIZE_MB = 5
OCR_MAX_CPU_PERCENT = 70

# Risk Scoring
RISK_THRESHOLDS = {
    'block': 70,
    'alert': 50,
    'log': 0
}
```

### Cấu hình Agent

File: `agent/config.py`

```python
# Watch paths
WATCH_PATHS = [
    "C:\\Users",
    "D:\\Documents"
]

# File size limit
MAX_FILE_SIZE_MB = 100
```

### Environment Variables

**Worker (Docker):**
```bash
# Trong docker-compose.yml hoặc .env file
LOG_LEVEL=INFO
SERVER_URL=https://dlp-server.example.com
SERVER_API_KEY=your-api-key
DEVICE_ID=worker-1
```

**Agent:**
```bash
# Trong Windows Environment Variables hoặc .env
AGENT_LOG_LEVEL=INFO
RUNTIME_DIR=C:\PRJ\ProjectIA\DLD_IA01\HybridDLP_ED\agent\runtime
```

---

## [CHART] Monitoring và Logs

### Logs Location

**Agent:**
- `agent/runtime/logs/agent.log` - Main log
- `agent/runtime/logs/watchdog.log` - Watchdog log
- `agent/runtime/logs/sensor.stdout.log` - Sensor stdout
- `agent/runtime/logs/sensor.stderr.log` - Sensor stderr

**Worker:**
- `worker/logs/detection_engine.log` - Main log
- Docker: `docker-compose logs worker`

**Dashboard:**
- Docker: `docker-compose logs dashboard`

### Monitoring Commands

```bash
# Xem real-time logs
docker-compose logs -f worker

# Xem số events trong database
sqlite3 agent/runtime/events.db "SELECT COUNT(*) FROM events;"

# Xem cache stats
sqlite3 worker/database/cache.db "SELECT COUNT(*) FROM hash_cache;"

# Xem YARA matches
docker-compose logs worker | grep -i "yara\|match"
```

---

##  Dừng hệ thống

### Docker

```bash
# Stop services
docker-compose stop

# Stop và remove containers
docker-compose down

# Stop và remove containers + volumes
docker-compose down -v
```

### Native

- **Worker:** `Ctrl+C` trong terminal
- **Dashboard:** `Ctrl+C` trong terminal
- **Agent (Service):**
  ```bash
  python service.py stop
  python service.py remove  # Nếu muốn gỡ service
  ```

---

## [DOC] Checklist chạy hệ thống

### Trước khi chạy

- [ ] Docker Desktop đã cài đặt và chạy
- [ ] Python 3.10+ đã cài đặt
- [ ] Dependencies đã cài đặt (`pip install -r requirements.txt`)
- [ ] YARA rules có trong `worker/yara_rules/` (16 files)
- [ ] SQLite database tồn tại (`agent/runtime/events.db`)

### Khi chạy

- [ ] Docker services start thành công (`docker-compose ps`)
- [ ] Worker logs không có lỗi (`docker-compose logs worker`)
- [ ] Dashboard accessible (http://localhost:8501)
- [ ] Agent đang chạy (Windows Service hoặc `python sensor.py`)
- [ ] Events được ghi vào SQLite (`sqlite3 events.db "SELECT COUNT(*) FROM events;"`)

### Sau khi chạy

- [ ] Worker đang xử lý events (logs có "Processed:")
- [ ] Dashboard hiển thị data
- [ ] YARA rules match được (test với file nhạy cảm)
- [ ] Alerts hiển thị trong Dashboard (nếu có)

---

## [TARGET] Quick Reference

### Start tất cả (Docker)

```bash
cd DLD_IA01/HybridDLP_ED
docker-compose up -d
```

### Stop tất cả (Docker)

```bash
docker-compose down
```

### Xem logs

```bash
docker-compose logs -f
```

### Restart service

```bash
docker-compose restart worker
docker-compose restart dashboard
```

### Kiểm tra database

```bash
sqlite3 agent/runtime/events.db "SELECT COUNT(*) FROM events;"
```

### Test YARA rules

```bash
# Tạo file test
echo "CMND: 123456789" > test.txt

# Worker sẽ tự động scan khi Agent phát hiện file
```

---

##  Tài liệu tham khảo

- **Architecture:** `docs/architecture.md`
- **Setup Guide:** `SETUP_GUIDE.md`
- **Quick Start:** `QUICK_START.md`
- **YARA Rules:** `worker/yara_rules/YARA_RULES_ANALYSIS.md`

---

##  Hỗ trợ

Nếu gặp vấn đề:

1. Kiểm tra logs: `docker-compose logs -f`
2. Kiểm tra database: `sqlite3 agent/runtime/events.db "SELECT COUNT(*) FROM events;"`
3. Kiểm tra YARA rules: `ls -la worker/yara_rules/*.yar`
4. Xem Troubleshooting section ở trên
5. Kiểm tra Docker: `docker ps` và `docker-compose ps`

---

** Chúc bạn chạy hệ thống thành công!**
