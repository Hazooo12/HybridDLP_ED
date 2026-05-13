# [START] SETUP GUIDE - HybridDLP System

## ⚡ Quick Setup (5 phút)

### **Bước 1: Setup ML Models (Optional)**

```bash
# Windows
cd worker
python scripts\collect_dataset.py
python scripts\train_model.py

# Linux/Mac
cd worker
python scripts/collect_dataset.py
python scripts/train_model.py
```

**Hoặc dùng script:**
```bash
# Windows
scripts\setup_ml_models.bat

# Linux/Mac
bash scripts/setup_ml_models.sh
```

**Lưu ý:** Nếu chưa có ML models, Worker vẫn hoạt động với YARA rules và OCR.

---

### **Bước 2: Test Docker Setup**

```bash
# Windows
scripts\quick_test.bat

# Linux/Mac
bash scripts/quick_test.sh
```

**Hoặc manual:**
```bash
# Build và start
docker-compose build
docker-compose up -d

# Check logs
docker-compose logs -f worker
docker-compose logs -f dashboard

# Access Dashboard
# Open http://localhost:8501
```

---

### **Bước 3: Setup Agent (Windows)**

```bash
cd agent
pip install -r requirements.txt

# Test run
python sensor.py

# Install as Windows Service
python service.py install
python service.py start
```

---

### **Bước 4: Test Integration**

```bash
# Tạo test event
python scripts/test_worker.py

# Check Worker logs
docker-compose logs worker | tail -20

# Check Dashboard
# Open http://localhost:8501
```

---

##  Detailed Setup

### **1. Prerequisites**

- [OK] Docker & Docker Compose
- [OK] Python 3.9+ (cho Agent và scripts)
- [OK] Windows (cho Agent service)

### **2. Install Dependencies**

**Worker:**
```bash
cd worker
pip install -r requirements.txt
```

**Worker Scripts (cho training):**
```bash
cd worker
pip install -r scripts/requirements.txt
```

**Agent:**
```bash
cd agent
pip install -r requirements.txt
```

**Dashboard:**
```bash
cd dashboard
pip install -r requirements.txt
```

---

### **3. Setup ML Models**

**Option 1: Auto-generate dataset và train**
```bash
cd worker
python scripts/collect_dataset.py  # Tạo 50 sensitive + 50 normal docs
python scripts/train_model.py      # Train model
```

**Option 2: Manual dataset**
- Thu thập sensitive documents → `worker/dataset/sensitive/`
- Thu thập normal documents → `worker/dataset/normal/`
- Run: `python scripts/train_model.py`

**Kết quả:**
- `worker/ml_models/classifier.pkl`
- `worker/ml_models/vectorizer.pkl`

---

### **4. Docker Setup**

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

**Services:**
- Worker: `hybrid-dlp-worker`
- Dashboard: `hybrid-dlp-dashboard` (port 8501)

---

### **5. Agent Setup (Windows)**

**Test run:**
```bash
cd agent
python sensor.py
```

**Install as Service:**
```bash
python service.py install
python service.py start
```

**Check service:**
```bash
sc query HybridDLPWatchdog
```

**Agent sẽ:**
- Monitor file system, USB, clipboard, processes
- Ghi events vào `agent/runtime/events.db`

---

### **6. Verification**

**Check SQLite database:**
```bash
sqlite3 agent/runtime/events.db "SELECT COUNT(*) FROM events;"
```

**Check Worker:**
```bash
docker-compose logs worker | grep -i "processed\|error"
```

**Check Dashboard:**
- Open http://localhost:8501
- Should see dashboard interface

---

##  Testing

### **Test 1: Create Test Event**

```bash
python scripts/test_worker.py
```

Sẽ tạo test event trong SQLite database.

### **Test 2: Trigger Real Event**

1. Copy file có sensitive data (CMND, credit card, etc.)
2. Agent sẽ detect và ghi vào SQLite
3. Worker sẽ đọc và process
4. Check Dashboard để xem alerts

### **Test 3: YARA Rules**

Tạo file test với content:
```
CMND: 123456789
Email: test@example.com
Credit Card: 4111 1111 1111 1111
```

Worker sẽ detect và alert.

---

##  Troubleshooting

### **Worker không đọc được events**

```bash
# Check SQLite database
ls -la agent/runtime/events.db
sqlite3 agent/runtime/events.db "SELECT COUNT(*) FROM events;"

# Check volume mount
docker exec -it hybrid-dlp-worker ls -la /app/agent/runtime/
```

### **ML model không load**

```bash
# Check model files
ls -la worker/ml_models/

# Nếu chưa có, train model:
cd worker
python scripts/collect_dataset.py
python scripts/train_model.py
```

### **YARA rules không load**

```bash
# Check YARA rules
docker exec -it hybrid-dlp-worker ls -la /app/yara_rules/

# Check logs
docker-compose logs worker | grep -i yara
```

---

## [OK] Checklist

- [ ] ML models đã train (optional)
- [ ] Docker images đã build
- [ ] Services đã start
- [ ] Agent đã setup (Windows)
- [ ] SQLite database có events
- [ ] Worker đọc được events
- [ ] Dashboard accessible
- [ ] Test events hoạt động

---

** Setup completed! System is ready to use!**
