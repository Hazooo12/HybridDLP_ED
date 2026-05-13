# Hướng Dẫn Train với Dataset Lớn (117 triệu rows)

## [WARN] Vấn đề

Với file email.csv có **117 triệu rows**, nếu load toàn bộ vào memory sẽ:
- Hết RAM (cần ~50-100GB RAM)
- Training rất chậm
- Có thể crash hệ thống

## [OK] Giải pháp: Streaming + Sampling

Code đã được tối ưu với:
1. **Streaming mode**: Đọc và xử lý từng chunk, không load toàn bộ vào memory
2. **Feature extraction on-the-fly**: Extract features ngay khi đọc, không lưu events
3. **Sampling option**: Sample một phần data để train nhanh hơn

## [START] Cách sử dụng

### Option 1: Sample 1% data (Khuyến nghị cho 117M rows)

```bash
cd HybridDLP_ED/ML
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --output ../worker/ml_models/ueba_iso_forest.pkl \
    --sample-ratio 0.01 \
    --max-events-per-file 1000000
```

**Kết quả:**
- Email.csv: 117M rows → ~1.17M events (1%)
- File.csv: Toàn bộ hoặc limit 1M
- HTTP.csv: Toàn bộ hoặc limit 1M
- Total: ~2-3M events (đủ để train model tốt)

### Option 2: Sample 10% data (Chất lượng tốt hơn)

```bash
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --output ../worker/ml_models/ueba_iso_forest.pkl \
    --sample-ratio 0.1 \
    --max-events-per-file 5000000
```

**Kết quả:**
- Email.csv: 117M rows → ~11.7M events (10%)
- Total: ~12-15M events

### Option 3: Limit events per file (Không sampling)

```bash
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --output ../worker/ml_models/ueba_iso_forest.pkl \
    --max-events-per-file 2000000
```

**Kết quả:**
- Mỗi file: Tối đa 2M events
- Total: ~6M events (2M file + 2M email + 2M http)

### Option 4: Script tự động (Windows)

```bash
cd HybridDLP_ED/ML
train_large_dataset.bat
```

## [CHART] So sánh Options

| Option | Sample Ratio | Events | RAM Usage | Training Time | Quality |
|--------|-------------|--------|-----------|---------------|---------|
| 1% Sample | 0.01 | ~2-3M | ~2-4GB | 10-20 phút | Good |
| 10% Sample | 0.1 | ~12-15M | ~8-12GB | 1-2 giờ | Very Good |
| Limit 2M/file | None | ~6M | ~4-6GB | 30-60 phút | Good |
| Full Dataset | None | ~120M+ | 50-100GB+ | 10+ giờ | Best (nhưng không practical) |

## [TARGET] Khuyến nghị

**Cho dataset 117M rows:**
- **Option 1 (1% sample)** là tốt nhất: Đủ data để train model tốt, nhanh, tiết kiệm memory
- Isolation Forest không cần toàn bộ data, 1-2M samples đã đủ để học patterns

##  Tham số

| Tham số | Mô tả | Ví dụ |
|---------|-------|-------|
| `--sample-ratio` | Tỷ lệ sample (0.01 = 1%, 0.1 = 10%) | `0.01` |
| `--max-events-per-file` | Giới hạn events mỗi file | `1000000` |
| `--cert-dir` | Folder CERT dataset | `../Dataset` |
| `--synthetic` | File synthetic data | `../synthetic_events.jsonl` |

## ⚡ Tối ưu Memory

Code đã tự động:
- [OK] Streaming CSV files (chunk size: 10k rows)
- [OK] Extract features on-the-fly (không lưu events)
- [OK] Sliding window cho frequency features (chỉ giữ 1000 events gần nhất)
- [OK] Giải phóng memory sau mỗi chunk

## [DOC] Log Output

Bạn sẽ thấy:
```
Streaming email events from: Dataset/email.csv/email.csv
Using sampling ratio: 1.0%
  Streamed 50,000 email events...
  Streamed 100,000 email events...
[OK] Streamed 1,170,000 email events

Processing CERT dataset in chunks...
[OK] Processed 1,170,000 CERT events
[OK] Total features extracted: 2,500,000 from 2,500,000 events
```

## [HINT] Tips

1. **Bắt đầu với 1% sample** để test
2. Nếu model tốt → giữ nguyên
3. Nếu cần tốt hơn → tăng lên 5-10%
4. **Không cần train với 100% data** - Isolation Forest hoạt động tốt với sample
