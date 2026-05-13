# [SEC] HybridDLP - Hybrid Data Loss Prevention System

##  Tổng quan

HybridDLP là hệ thống phòng chống mất mát dữ liệu (Data Loss Prevention) sử dụng kiến trúc Event-Driven, kết hợp rule-based (YARA) và Machine Learning để phát hiện và ngăn chặn rò rỉ dữ liệu nhạy cảm.

---

## ️ Kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                    HybridDLP System                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐         ┌──────────────┐                │
│  │ Agent (L1)   │────────▶│   SQLite     │                │
│  │ Windows      │ Events  │  (events.db) │                │
│  │ Service      │         │              │                │
│  └──────────────┘         └──────┬───────┘                │
│                                   │                         │
│                          ┌────────┴────────┐               │
│                          │                 │               │
│                   ┌──────▼──────┐  ┌──────▼──────┐        │
│                   │  Worker     │  │  Dashboard  │        │
│                   │  (L3)       │  │  (Streamlit)│        │
│                   │ Detection   │  │  Web UI      │        │
│                   │ Engine       │  │             │        │
│                   └──────────────┘  └──────────────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Components

1. **Agent (L1)** - Lightweight Sensor
   - Windows Service chạy với SYSTEM privileges
   - Monitor file system, USB, clipboard, processes
   - Gửi events vào SQLite database (`agent/runtime/events.db`)

2. **Worker (L3)** - Detection Engine
   - Đọc events từ SQLite database
   - Fast Scan (YARA rules) - 12 rules
   - Deep Analysis (ML, OCR) - Lazy loading
   - Risk Scoring & Action Execution

3. **Dashboard** - Web UI
   - Streamlit-based dashboard
   - Hiển thị alerts, statistics
   - Real-time monitoring (auto-refresh 2s)

4. **SQLite** - IPC Database
   - Events database: `agent/runtime/events.db`
   - IPC giữa Agent và Worker
   - File-based, không cần external service

---

## [START] Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.9+ (cho Agent trên Windows)
- Windows (cho Agent service)

### Docker Deployment (Recommended)

```bash
# Clone repository
cd DLD_IA01/HybridDLP_ED

# Build và start
docker-compose build
docker-compose up -d

# Xem logs
docker-compose logs -f

# Truy cập Dashboard
# Open http://localhost:8501
```

### Manual Setup

#### 1. Agent (Windows Service)

```bash
cd agent
pip install -r requirements.txt
python service.py install
python service.py start
```

#### 2. Worker (Detection Engine)

```bash
cd worker
pip install -r requirements.txt
python worker.py
```

#### 3. Dashboard

```bash
cd dashboard
pip install -r requirements.txt
streamlit run dashB.py
```

---

##  Cấu trúc Project

```
HybridDLP_ED/
├── agent/              # L1 Sensor (Windows Service)
│   ├── sensors/        # File, USB, Clipboard, Process sensors
│   ├── sensor.py       # Main sensor orchestrator
│   ├── service.py      # Windows Service wrapper
│   └── watchdog_*.py   # Watchdog & auto-recovery
│
├── worker/             # L3 Detection Engine
│   ├── core/           # Core components
│   │   ├── queue_consumer.py    # SQLite queue reader
│   │   ├── hash_cache.py        # Hash cache manager
│   │   ├── fast_scan.py         # YARA scanning
│   │   ├── deep_analysis.py     # ML & OCR
│   │   ├── risk_scoring.py      # Risk calculation
│   │   └── action_executor.py   # Action execution
│   ├── models/         # ML models
│   ├── yara_rules/     # YARA detection rules (12 rules)
│   └── worker.py       # Main worker process
│
├── dashboard/          # Streamlit Dashboard
│   └── dashB.py        # Main dashboard app
│
├── docs/              # Documentation
├── scripts/            # Utility scripts
├── docker-compose.yml  # Docker orchestration
└── README.md          # This file
```

---

##  Configuration

### Environment Variables

**Worker:**
```bash
LOG_LEVEL=INFO                # Logging level
SERVER_URL=...                # Central server URL
SERVER_API_KEY=...            # API key
DEVICE_ID=...                 # Device identifier
```

**Agent:**
- Configure trong `agent/config.py`
- Hoặc qua environment variables

---

## [CHART] Detection Engine (L3) - Architecture

### Processing Pipeline

```
Event từ Agent (SQLite)
    ↓
1. Queue Consumer
   - Đọc từ SQLite: agent/runtime/events.db
   - Panic Mode detection (queue > 1000)
    ↓
2. Hash Cache Check
   - SHA256 hash calculation
   - Skip nếu file đã scan (cached safe)
    ↓
3. Fast Scan
   - YARA rules matching (12 rules)
   - File type detection (magic bytes)
   - Encrypted ZIP detection
    ↓
4. Decision Point
   - Safe? → Allow, Update Cache
   - Suspicious? → Deep Analysis
    ↓
5. Deep Analysis (Lazy Load)
   - OCR: Conditional (size < 5MB, CPU < 70%, là ảnh)
   - ML Classification: Lazy load model
   - Skip trong panic mode
    ↓
6. Risk Scoring
   - Content Score (50%): YARA, ML, OCR, Encrypted ZIP
   - Behavior Score (30%): USB copy, network, clipboard
   - Context Score (20%): Sensitive folder, file size
   - Thresholds: Block (70), Alert (50), Log (0)
    ↓
7. Action Executor
   - Block/Alert/Log
   - Gửi về Management Server
    ↓
8. Update Cache
```

### Key Features

- [OK] **Lazy Loading**: OCR/ML chỉ load khi cần
- [OK] **Overload Protection**: Panic Mode khi queue > 1000
- [OK] **Hash Cache**: Skip file đã scan (SQLite cache)
- [OK] **Conditional OCR**: Chỉ OCR khi đủ điều kiện
- [OK] **Risk Scoring**: Weighted formula (Content 50% + Behavior 30% + Context 20%)

---

## [CHART] Detection Capabilities

### YARA Rules (12 rules)

- [OK] **PII Detection**: CMND/CCCD, Phone numbers, Email, Bank accounts
- [OK] **Financial Data**: Credit cards, Financial reports
- [OK] **Sensitive Documents**: Contracts, HR data, Legal documents
- [OK] **Code & Secrets**: API keys, Source code
- [OK] **Export Detection**: CSV/Excel with sensitive data
- [OK] **Archive Detection**: Password-protected archives

### Detection Methods

1. **Fast Scan (YARA)**
   - 12 YARA rules
   - Pattern-based detection
   - < 10ms per file

2. **Deep Analysis**
   - Machine Learning classification
   - OCR for images (Tesseract)
   - Lazy loading for performance

3. **Risk Scoring**
   - Content sensitivity (50%)
   - User behavior (30%)
   - Context analysis (20%)

---

##  Docker Deployment

### Services

#### **1. Worker (L3 Detection Engine)**

- **Build:** `worker/Dockerfile`
- **Volumes:**
  - `worker-logs` - Logs
  - `worker-models` - ML models
  - `worker-database` - Hash cache database
  - `./worker/yara_rules` - YARA rules (read-only)
  - `./agent/runtime` - **SQLite events database** (read-only)

**IPC Mechanism:**
- Worker đọc events từ SQLite: `agent/runtime/events.db`
- Agent (Windows) ghi events vào SQLite
- SQLite database được mount vào Docker container

#### **2. Dashboard (Streamlit)**

- **Build:** `dashboard/Dockerfile`
- **Port:** `8501`
- **URL:** http://localhost:8501

### Docker Commands

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# View logs
docker-compose logs -f worker
docker-compose logs -f dashboard

# Stop services
docker-compose down

# Restart services
docker-compose restart

# Check status
docker-compose ps
```

### Troubleshooting

**Worker không đọc được events:**
```bash
# Kiểm tra SQLite database
ls -la agent/runtime/events.db
sqlite3 agent/runtime/events.db "SELECT COUNT(*) FROM events;"

# Kiểm tra volume mount
docker exec -it hybrid-dlp-worker ls -la /app/agent/runtime/
```

**Dashboard không hiển thị data:**
```bash
# Kiểm tra logs
docker-compose logs dashboard

# Health check
curl http://localhost:8501/_stcore/health
```

**YARA rules không load:**
```bash
# Kiểm tra YARA rules
docker exec -it hybrid-dlp-worker ls -la /app/yara_rules/
docker-compose logs worker | grep -i yara
```

---

## [DOC] IPC Communication (SQLite)

### Data Flow

```
Agent (L1) → SQLite DB (events.db) → Worker (L3)
```

### SQLite Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    severity TEXT,
    source TEXT,
    payload_json TEXT
);
```

### Worker Processing

1. Track `last_processed_id`
2. Query `SELECT * FROM events WHERE id > last_processed_id ORDER BY id ASC LIMIT 1`
3. Process event
4. Update `last_processed_id`

**Advantages:**
- [OK] Simple: File-based, không cần external service
- [OK] Reliable: SQLite WAL mode, durable writes
- [OK] Portable: Single file, dễ backup/move
- [OK] No Dependencies: Không cần Redis server

---

##  Configuration Details

### Panic Mode

```python
PANIC_MODE_THRESHOLD = 1000  # Enable khi queue > 1000
PANIC_MODE_DISABLE_THRESHOLD = 500  # Disable khi queue < 500
```

### OCR Configuration

```python
OCR_ENABLED = True
OCR_MAX_FILE_SIZE_MB = 5
OCR_MAX_CPU_PERCENT = 70
OCR_SUPPORTED_FORMATS = ['.jpg', '.jpeg', '.png', '.pdf', '.tiff']
```

### Risk Scoring

```python
RISK_THRESHOLDS = {
    'block': 70,
    'alert': 50,
    'log': 0
}

RISK_WEIGHTS = {
    'content': 0.5,
    'behavior': 0.3,
    'context': 0.2
}
```

---

##  Testing

```bash
# Test Docker setup
make test

# Test Worker
docker-compose logs worker | tail -20

# Test Dashboard
curl http://localhost:8501/_stcore/health

# Test SQLite database
sqlite3 agent/runtime/events.db "SELECT COUNT(*) FROM events;"
```

---

##  Documentation

- **Source Code**: Xem `worker/` directory
- **YARA Rules**: Xem `worker/yara_rules/`
- **Architecture**: Xem `docs/architecture.md`

---

## [OK] Checklist Deployment

- [ ] Docker và Docker Compose đã cài đặt
- [ ] YARA rules đã có trong `worker/yara_rules/`
- [ ] Agent runtime directory tồn tại (`agent/runtime/`)
- [ ] SQLite database tồn tại (`agent/runtime/events.db`)
- [ ] Build images thành công: `docker-compose build`
- [ ] Start services thành công: `docker-compose up -d`
- [ ] Worker logs không có lỗi: `docker-compose logs worker`
- [ ] Dashboard accessible: http://localhost:8501
- [ ] Agent (Windows) đang ghi events vào SQLite

---

## [TARGET] Key Implementation Details

### Queue Consumer (`core/queue_consumer.py`)
- Đọc events từ SQLite
- Panic Mode detection
- Track `last_processed_id`

### Hash Cache (`core/hash_cache.py`)
- SHA256 hash calculation
- SQLite cache database
- Auto cleanup entries cũ

### Fast Scan (`core/fast_scan.py`)
- YARA rules matching
- File type detection (magic bytes)
- Encrypted ZIP detection

### Deep Analysis (`core/deep_analysis.py`)
- OCR với conditional execution
- ML Classification (lazy load)
- Skip trong panic mode

### Risk Scoring (`core/risk_scoring.py`)
- Weighted formula: Content (50%) + Behavior (30%) + Context (20%)
- Thresholds: Block (70), Alert (50), Log (0)

### Action Executor (`core/action_executor.py`)
- Block/Alert/Log actions
- Server communication (HTTP POST)

---

## [DOC] License

[Your License Here]

##  Contributors

[Your Team Here]

---

## [START] Quick Setup

### **1. Setup ML Models (Optional)**
```bash
# Windows
scripts\setup_ml_models.bat

# Linux/Mac
bash scripts/setup_ml_models.sh
```

### **2. Test Docker Setup**
```bash
# Windows
scripts\quick_test.bat

# Linux/Mac
bash scripts/quick_test.sh
```

### **3. Setup Agent (Windows)**
```bash
cd agent
pip install -r requirements.txt
python sensor.py  # Test run
```

### **4. Test Integration**
```bash
python scripts/test_worker.py
# Check Dashboard: http://localhost:8501
```

Xem chi tiết: [SETUP_GUIDE.md](SETUP_GUIDE.md) | [NEXT_STEPS.md](NEXT_STEPS.md)

---

**[SEC] Protect Your Data with HybridDLP**
