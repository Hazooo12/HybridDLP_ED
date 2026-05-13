# UEBA ML Pipeline - User and Entity Behavior Analytics

Hệ thống Machine Learning phát hiện hành vi bất thường (Anomaly Detection) sử dụng Isolation Forest.

## Cấu trúc

- `feature_extractor.py`: Trích xuất 13 features từ events (temparol, frequency, quantitative, contextual)
- `behavioral_ml_analyzer.py`: Load model và predict anomaly score real-time
- `train_ueba.py`: Training script với CERT dataset + Synthetic data

## Cách sử dụng

### 1. Tạo Synthetic Data (Test nhanh)

```bash
cd HybridDLP_ED/worker
python scripts/generate_synthetic_data.py \
    --output synthetic_events.jsonl \
    --normal 10000 \
    --anomalous 50
```

### 2. Train Model với CERT Dataset

**Bước 1:** Download CERT Insider Threat Dataset v4.2 từ:
- https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099
- Giải nén vào thư mục `data/cert/`

**Bước 2:** Train model:

```bash
cd HybridDLP_ED/worker
python -m ml_pipeline.train_ueba \
    --cert-dir data/cert \
    --synthetic synthetic_events.jsonl \
    --output ml_models/ueba_iso_forest.pkl \
    --contamination 0.01 \
    --n-estimators 100
```

**Tham số:**
- `--cert-dir`: Thư mục chứa CERT dataset files (logon.csv, file.csv, email.csv, http.csv)
- `--synthetic`: Path đến synthetic events JSONL file
- `--agent-events`: (Optional) Path đến real agent events JSONL
- `--output`: Path để lưu trained model
- `--contamination`: Tỷ lệ anomalies mong đợi (default: 0.01 = 1%)
- `--n-estimators`: Số cây trong Isolation Forest (default: 100)

### 3. Model sẽ tự động load khi Worker khởi động

Model được load tự động từ `worker/ml_models/ueba_iso_forest.pkl` khi `BehavioralMLAnalyzer` được khởi tạo.

Nếu model không tồn tại, hệ thống vẫn chạy bình thường nhưng không có ML anomaly detection.

## Features được trích xuất

### Temparol Features (4)
- `is_off_hours`: 1 nếu 18:00-08:00, 0 nếu trong giờ hành chính
- `is_weekend`: 1 nếu T7/CN, 0 nếu ngày thường
- `hour_of_day`: Giờ trong ngày [0, 1] (normalized)
- `day_of_week`: Ngày trong tuần [0, 1] (normalized)

### Frequency Features (3)
- `clipboard_pastes_last_10m`: Số lần paste trong 10 phút qua
- `bytes_transferred_usb_last_1h`: Tổng bytes copy ra USB trong 1 giờ
- `file_operations_last_1h`: Số file operations trong 1 giờ

### Quantitative Features (3)
- `entropy_value`: Shannon entropy của content [0, 1]
- `content_size_log`: Log scale của content size [0, 1]
- `file_count`: Số files trong bulk operation [0, 1]

### Contextual Features (3)
- `dest_app_category`: 0=Local, 1=Browser, 2=Chat, 3=Cloud, 4=USB [0, 1]
- `source_type`: 0=File, 1=Clipboard Text, 2=Clipboard Image, 3=Network [0, 1]
- `operation_type`: 0=Copy, 1=Move, 2=Delete, 3=Print, 4=Upload [0, 1]

**Tổng: 13 features**

## Anomaly Score

- **Range**: 0-100 (higher = more anomalous)
- **Threshold**: Score > 75 được coi là anomaly
- **Integration**: Anomaly score được thêm vào Likelihood trong NIST risk scoring

## Workflow

1. **Training Phase:**
   - Load CERT dataset + Synthetic data
   - Extract features từ tất cả events
   - Train Isolation Forest
   - Save model + scaler

2. **Inference Phase (Real-time):**
   - Worker nhận event từ agent
   - Extract features (sử dụng event history cho frequency)
   - Predict anomaly score
   - Thêm vào risk scoring context
   - NIST engine sử dụng ML score để boost likelihood

## Lưu ý

- **Cold Start**: Hệ thống cần ít nhất 100 events trong history để tính frequency features chính xác
- **Event History**: Worker lưu tối đa 1000 events gần nhất trong memory
- **Performance**: Isolation Forest rất nhanh, không ảnh hưởng đáng kể đến throughput
