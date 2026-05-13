# ML Module - UEBA (User and Entity Behavior Analytics)

Module Machine Learning cho phát hiện hành vi bất thường (Anomaly Detection) trong hệ thống DLP.

##  Tổng quan

Module này implement **UEBA (User and Entity Behavior Analytics)** sử dụng **Isolation Forest** để phát hiện các hành vi bất thường trong hệ thống DLP, theo mô tả trong `ML_DEVELOPMENT_PLAN.md`.

## ️ Cấu trúc

```
ML/
├── __init__.py                    # Module initialization
├── cert_dataset_loader.py         # Load CERT Insider Threat Dataset
├── feature_extractor.py           # Extract features từ events
├── behavioral_ml_analyzer.py     # Real-time anomaly detection
├── train_ueba.py                 # Training script
├── generate_synthetic_data.py      # Generate synthetic events
└── README.md                      # This file
```

## [START] Sử dụng

### 1. Generate Synthetic Data

```bash
cd HybridDLP_ED/ML
python generate_synthetic_data.py --output ../synthetic_events.jsonl --normal 10000 --anomalous 50
```

### 2. Train UEBA Model

```bash
cd HybridDLP_ED/ML
python train_ueba.py \
    --cert-dir ../Dataset \
    --synthetic ../synthetic_events.jsonl \
    --output ../worker/ml_models/ueba_iso_forest.pkl \
    --contamination 0.01 \
    --n-estimators 100
```

### 3. Tích hợp với L3 Engine

Model đã được tích hợp tự động trong `worker.py`. Khi model được train và lưu tại `worker/ml_models/ueba_iso_forest.pkl`, L3 engine sẽ tự động load và sử dụng.

## [CHART] Features

Theo `ML_DEVELOPMENT_PLAN.md`, module extract 13 features:

### Temparol Features (4)
- `is_off_hours`: 1 nếu từ 18:00 - 08:00, 0 nếu trong giờ hành chính
- `is_weekend`: 1 nếu là T7/CN, 0 nếu là ngày thường
- `hour_of_day`: Giờ trong ngày (normalized [0, 1])
- `day_of_week`: Ngày trong tuần (normalized [0, 1])

### Frequency/Velocity Features (3)
- `clipboard_pastes_last_10m`: Số lần paste trong 10 phút qua
- `bytes_transferred_usb_last_1h`: Tổng dung lượng copy ra USB trong 1 giờ
- `file_operations_last_1h`: Số lần file operations trong 1 giờ

### Quantitative Features (3)
- `entropy_value`: Mức độ mã hóa/ngẫu nhiên của text (normalized [0, 1])
- `content_size_log`: Dung lượng text/file (log scale, normalized)
- `file_count`: Số lượng files trong bulk operation (normalized [0, 1])

### Contextual/Categorical Features (3)
- `dest_app_category`: 0: Local App, 1: Browser, 2: Chat App, 3: Cloud Sync, 4: USB/External
- `source_type`: 0: File, 1: Clipboard Text, 2: Clipboard Image, 3: Network
- `operation_type`: 0: Copy, 1: Move, 2: Delete, 3: Print, 4: Upload

##  Thuật toán

**Isolation Forest** (scikit-learn):
- Unsupervised Anomaly Detection
- Contamination: 0.01 (1% expected anomalies)
- Output: Anomaly Score [0, 100] (higher = more anomalous)

## [DOC] Dataset

### CERT Insider Threat Dataset
- Format: CSV files trong `Dataset/` folder
- Files: `file.csv`, `email.csv`, `http.csv`
- Mapping: Tự động convert sang Agent event format

### Synthetic Data
- Format: JSONL
- Normal events: 10,000
- Anomalous events: 50
- Patterns: bulk_copy_usb, paste_chatgpt, off_hours_bulk, encrypted_zip_copy

##  Tích hợp với L3 Engine

Module được tích hợp trong `worker/worker.py`:

```python
from ML.behavioral_ml_analyzer import BehavioralMLAnalyzer

# Trong DetectionEngine.__init__()
self.ml_analyzer = BehavioralMLAnalyzer()

# Trong process_event()
ml_anomaly_result = self.ml_analyzer.predict(event, event_history=recent_history)
```

Anomaly score được truyền vào `risk_scoring.py` để tính điểm rủi ro tổng thể.

##  Tài liệu tham khảo

- `ML_DEVELOPMENT_PLAN.md`: Kế hoạch phát triển ML
- `CERT_DATASET_PREPARATION.md`: Hướng dẫn chuẩn bị dataset
- `worker/core/risk_scoring.py`: Risk scoring với ML anomaly score
