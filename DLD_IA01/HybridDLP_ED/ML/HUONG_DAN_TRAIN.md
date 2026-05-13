# Hướng Dẫn Train UEBA Model với CERT Dataset

##  Yêu cầu

1. **CERT Dataset** đã được download và đặt trong folder `HybridDLP_ED/Dataset/`
   - Cấu trúc: `Dataset/file.csv/file.csv`, `Dataset/email.csv/email.csv`, `Dataset/http.csv/http.csv`
   
2. **Python packages** đã cài đặt:
   ```bash
   pip install pandas numpy scikit-learn joblib loguru
   ```

## [START] Cách 1: Sử dụng Script Tự Động (Khuyến nghị)

### Windows:
```bash
cd HybridDLP_ED/ML
train.bat
```

### Linux/Mac:
```bash
cd HybridDLP_ED/ML
chmod +x train.sh
./train.sh
```

Script này sẽ:
1. Tự động generate synthetic data (10,000 normal + 50 anomalous events)
2. Load CERT dataset từ `Dataset/` folder
3. Train model và lưu vào `worker/ml_models/ueba_iso_forest.pkl`

## [START] Cách 2: Chạy Manual từng bước

### Bước 1: Generate Synthetic Data (Tùy chọn)

```bash
cd HybridDLP_ED/ML
python generate_synthetic_data.py --output ../synthetic_events.jsonl --normal 10000 --anomalous 50
```

**Lưu ý:** Nếu bạn chỉ muốn train với CERT dataset, có thể bỏ qua bước này.

### Bước 2: Train Model với CERT Dataset

#### Chỉ dùng CERT Dataset:
```bash
cd HybridDLP_ED/ML
python train_ueba.py --cert-dir ../Dataset --output ../worker/ml_models/ueba_iso_forest.pkl
```

#### Kết hợp CERT + Synthetic Data:
```bash
cd HybridDLP_ED/ML
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --output ../worker/ml_models/ueba_iso_forest.pkl \
    --contamination 0.01 \
    --n-estimators 100
```

#### Kết hợp CERT + Synthetic + Agent Events (nếu có):
```bash
cd HybridDLP_ED/ML
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --agent-events ../agent/runtime/events_20260313_1.jsonl \
    --output ../worker/ml_models/ueba_iso_forest.pkl
```

## [CHART] Các tham số Training

| Tham số | Mô tả | Mặc định |
|---------|-------|----------|
| `--cert-dir` | Đường dẫn đến folder CERT dataset | Bắt buộc |
| `--synthetic` | Đường dẫn đến file synthetic events JSONL | Tùy chọn |
| `--agent-events` | Đường dẫn đến file agent events JSONL | Tùy chọn |
| `--output` | Đường dẫn lưu model | `worker/ml_models/ueba_iso_forest.pkl` |
| `--contamination` | Tỷ lệ anomalies mong đợi (0.01 = 1%) | `0.01` |
| `--n-estimators` | Số lượng trees trong Isolation Forest | `100` |

## [OK] Kiểm tra kết quả

Sau khi train xong, kiểm tra:

1. **Model file đã được tạo:**
   ```bash
   ls worker/ml_models/ueba_iso_forest.pkl
   ```

2. **Log output sẽ hiển thị:**
   - Số lượng events đã load từ mỗi nguồn
   - Feature matrix shape
   - Số lượng anomalies được phát hiện trong training data
   - Đường dẫn model đã lưu

3. **Model sẽ tự động được load** khi L3 engine khởi động (nếu model path đúng)

##  Troubleshooting

### Lỗi: "CERT dataset files not found"
- Kiểm tra đường dẫn: `Dataset/file.csv/file.csv` có tồn tại không
- Đảm bảo cấu trúc folder đúng: `Dataset/file.csv/file.csv`, `Dataset/email.csv/email.csv`, `Dataset/http.csv/http.csv`

### Lỗi: "No events loaded!"
- Kiểm tra CERT dataset có dữ liệu không
- Thử load với `--cert-dir` path tuyệt đối

### Lỗi: "ModuleNotFoundError"
- Cài đặt dependencies: `pip install pandas numpy scikit-learn joblib loguru`

### Model không được load trong L3 engine
- Kiểm tra model path: `worker/ml_models/ueba_iso_forest.pkl`
- Kiểm tra log của worker để xem có thông báo "UEBA model loaded" không

## [DOC] Ví dụ Output

```
Loading 50000 file events from CERT dataset
Loading 25000 email events from CERT dataset
Loading 30000 HTTP events from CERT dataset
Total CERT events loaded: 105000
Loaded 10050 events from synthetic data
Total events for training: 115050
Extracting features...
Processing event 0/115050
Processing event 1000/115050
...
Feature matrix shape: (115050, 13)
Feature names: ['is_off_hours', 'is_weekend', ...]
Training Isolation Forest (contamination=0.01, n_estimators=100)...
Detected 1150 anomalies (1.00%) in training data
Model saved to worker/ml_models/ueba_iso_forest.pkl
Training completed!
```

## [TARGET] Kết quả mong đợi

- Model file: `worker/ml_models/ueba_iso_forest.pkl`
- Model sẽ tự động được sử dụng trong L3 Detection Engine
- Anomaly detection sẽ hoạt động real-time trên các events mới
