# Bảng So Sánh Các Script Training

## [CHART] Tổng Quan

| Script | Max Events/File | Sample Ratio | Tổng Events (ước tính) | RAM Usage | Thời gian |
|--------|----------------|--------------|------------------------|-----------|-----------|
| `train.bat` | **KHÔNG GIỚI HẠN** | Không | **TOÀN BỘ** (có thể 120M+) | 50-100GB+ | 10+ giờ |
| `train_simple.bat` | **KHÔNG GIỚI HẠN** | Không | **TOÀN BỘ CERT** (có thể 120M+) | 50-100GB+ | 10+ giờ |
| `train_large_dataset.bat` | **1,000,000** | **1%** | ~1.2M (1% của 117M) | 2-4GB | 10-20 phút |

## [SEARCH] Chi Tiết Từng Script

### 1. `train.bat` (Script Mặc Định)

**Tham số:**
```bash
--cert-dir Dataset
--synthetic synthetic_events.jsonl
--output worker/ml_models/ueba_iso_forest.pkl
--contamination 0.01
--n-estimators 100
```

**Max rows:**
- [FAIL] **KHÔNG GIỚI HẠN** - Load TOÀN BỘ dataset
- Email.csv: **117,000,000 rows** (toàn bộ)
- File.csv: **TOÀN BỘ**
- HTTP.csv: **TOÀN BỘ**
- Synthetic: **10,050 events**

**[WARN] Cảnh báo:**
- Với 117M rows email.csv → Cần ~50-100GB RAM
- Có thể crash hệ thống nếu không đủ RAM
- Training time: 10+ giờ

**Khi nào dùng:**
- Chỉ dùng nếu có server với RAM rất lớn (64GB+)
- Không khuyến nghị cho máy thường

---

### 2. `train_simple.bat` (Chỉ CERT Dataset)

**Tham số:**
```bash
--cert-dir Dataset
--output worker/ml_models/ueba_iso_forest.pkl
```

**Max rows:**
- [FAIL] **KHÔNG GIỚI HẠN** - Load TOÀN BỘ CERT dataset
- Email.csv: **117,000,000 rows** (toàn bộ)
- File.csv: **TOÀN BỘ**
- HTTP.csv: **TOÀN BỘ**
- Synthetic: **KHÔNG DÙNG**

**[WARN] Cảnh báo:**
- Tương tự `train.bat` - cần RAM rất lớn

---

### 3. `train_large_dataset.bat` (Khuyến Nghị) ⭐

**Tham số:**
```bash
--cert-dir Dataset
--synthetic synthetic_events.jsonl
--output worker/ml_models/ueba_iso_forest.pkl
--contamination 0.01
--n-estimators 100
--sample-ratio 0.01          # ← Sample 1%
--max-events-per-file 1000000  # ← Limit 1M/file
```

**Max rows:**
- [OK] **1,000,000 events/file** (giới hạn)
- [OK] **Sample 1%** (random sampling)
- Email.csv: 117M rows → **~1,170,000 events** (1% của 117M)
- File.csv: **1,000,000 events** (hoặc toàn bộ nếu < 1M)
- HTTP.csv: **1,000,000 events** (hoặc toàn bộ nếu < 1M)
- Synthetic: **10,050 events** (toàn bộ)

**Tổng ước tính:**
- **~2-3 triệu events** (đủ để train model tốt)

**[OK] Ưu điểm:**
- RAM: Chỉ cần 2-4GB
- Time: 10-20 phút
- Chất lượng: Đủ tốt (Isolation Forest không cần toàn bộ data)

**Khi nào dùng:**
- ⭐ **KHUYẾN NGHỊ** cho dataset lớn (117M rows)
- Máy tính thường (8-16GB RAM)
- Cần train nhanh

---

## [TARGET] Khuyến Nghị

### Cho Dataset 117M Rows:

**[OK] Dùng `train_large_dataset.bat`** vì:
1. Sample 1% = ~1.17M events từ email.csv (đủ để train)
2. Limit 1M/file → Tránh hết RAM
3. Nhanh (10-20 phút)
4. Chất lượng model vẫn tốt

### Nếu Muốn Tăng Chất Lượng:

Có thể tăng sample ratio:
```bash
--sample-ratio 0.05    # 5% → ~5.85M events
--sample-ratio 0.1     # 10% → ~11.7M events
```

---

## [DOC] Cách Tùy Chỉnh

### Option 1: Tăng Sample Ratio (Chất lượng tốt hơn)
```bash
python -m ML.train_ueba \
    --cert-dir Dataset \
    --sample-ratio 0.05 \      # 5% thay vì 1%
    --max-events-per-file 2000000
```

### Option 2: Giảm Limit (Tiết kiệm RAM hơn)
```bash
python -m ML.train_ueba \
    --cert-dir Dataset \
    --sample-ratio 0.01 \
    --max-events-per-file 500000  # 500K thay vì 1M
```

### Option 3: Không Sampling, Chỉ Limit
```bash
python -m ML.train_ueba \
    --cert-dir Dataset \
    --max-events-per-file 2000000  # 2M/file, không sampling
```

---

## ⚡ Tóm Tắt

| Script | Max Rows | Khuyến Nghị |
|--------|----------|-------------|
| `train.bat` | **TOÀN BỘ** (117M+) | [FAIL] Không (quá lớn) |
| `train_simple.bat` | **TOÀN BỘ** (117M+) | [FAIL] Không (quá lớn) |
| `train_large_dataset.bat` | **1M/file + 1% sample** | [OK] **CÓ** (tối ưu) |

**Kết luận:** Với dataset 117M rows, dùng `train_large_dataset.bat` để có **~1-2M events** (đủ để train model tốt mà không hết RAM).
