# Thêm Trọng Số Cho Các Case Cao Risk (ChatGPT, USB)

## [TARGET] Vấn Đề

Các case như:
- **Copy vào ChatGPT** (external chat app)
- **Copy ra USB** (removable media)
- **Off-hours activity** với sensitive data

Nên có **trọng số cao hơn** để model phát hiện dễ hơn.

## [OK] Giải Pháp Đã Triển Khai

### 1. Feature Weights trong Feature Extractor

**File:** `ML/feature_extractor.py`

**Thêm weights cho các features quan trọng:**
```python
self.feature_weights = {
    'is_off_hours': 1.5,  # Off-hours activity
    'entropy_value': 2.0,  # High entropy = encrypted/sensitive
    'dest_app_category': 2.5,  # External destinations (ChatGPT, USB)
    'bytes_transferred_usb_last_1h': 2.0,  # USB transfers
    'clipboard_pastes_last_10m': 1.5,  # Bulk paste activity
}
```

**Áp dụng weights:**
- `is_off_hours`: x1.5 nếu > 0
- `entropy_value`: x2.0 nếu > 0.7
- `dest_app_category`: x2.5 nếu > 0.25 (external destinations)
- `bytes_transferred_usb_last_1h`: x2.0 nếu > 0
- `clipboard_pastes_last_10m`: x1.5 nếu > 0.1

### 2. Risk Boost trong ML Analyzer

**File:** `ML/behavioral_ml_analyzer.py`

**Thêm risk boost cho high-risk cases:**
```python
def _calculate_risk_boost(self, features):
    boost = 0.0
    
    # USB: +15 points
    if dest_category >= 0.95:  # USB
        boost += 15.0
    
    # ChatGPT: +12 points
    elif dest_category >= 0.45 and dest_category < 0.55:  # Chat
        boost += 12.0
    
    # Cloud: +8 points
    elif dest_category >= 0.7 and dest_category < 0.8:  # Cloud
        boost += 8.0
    
    # Browser: +5 points
    elif dest_category >= 0.2 and dest_category < 0.3:  # Browser
        boost += 5.0
    
    # Off-hours: +5 points
    if is_off_hours > 0.5:
        boost += 5.0
    
    # High entropy: +8 points
    if entropy > 0.8:
        boost += 8.0
    
    # USB transfers: +10 points
    if usb_bytes > 0.01:
        boost += 10.0
    
    # Bulk paste: +5 points
    if clipboard_pastes > 0.15:
        boost += 5.0
    
    return min(30.0, boost)  # Cap at 30 points
```

**Công thức tính anomaly score:**
```python
base_anomaly_score = (1 - raw_score) / 2 * 100
risk_boost = _calculate_risk_boost(features)
anomaly_score = min(100.0, base_anomaly_score + risk_boost)
```

## [CHART] Trọng Số Chi Tiết

| Case | Feature Weight | Risk Boost | Tổng Impact |
|------|----------------|------------|-------------|
| **USB Copy** | dest_app_category x2.5 | +15 points | **Rất cao** |
| **ChatGPT Paste** | dest_app_category x2.5 | +12 points | **Rất cao** |
| **Off-hours + High Entropy** | is_off_hours x1.5, entropy x2.0 | +13 points | **Cao** |
| **USB Transfer** | usb_bytes x2.0 | +10 points | **Cao** |
| **Bulk Paste** | clipboard_pastes x1.5 | +5 points | **Trung bình** |

## [TARGET] Kết Quả Mong Đợi

### Trước khi thêm trọng số:
- Normal Event: 41.09
- Anomalous Off-hours: 49.11
- Anomalous USB: 50.32

### Sau khi thêm trọng số:
- Normal Event: **~41** (không đổi)
- Anomalous Off-hours: **~65-75** (+15-25 points)
- Anomalous USB: **~75-85** (+25-35 points)

## [START] Test Lại

### Bước 1: Train lại model

```bash
cd HybridDLP_ED/ML
train_improved.bat
```

### Bước 2: Test với trọng số mới

```bash
test_model.bat
```

**Kỳ vọng:**
- Normal Event: Score < 50 [OK]
- Anomalous Off-hours: Score **65-80** [WARN] (tăng từ 49)
- Anomalous USB: Score **75-90** [WARN] (tăng từ 50)

## [OK] Kết Luận

**Đã thêm trọng số cho các case cao risk:**
1. [OK] Feature weights trong feature extractor
2. [OK] Risk boost trong ML analyzer
3. [OK] Ưu tiên USB và ChatGPT

**Model sẽ phát hiện các case này dễ hơn!**
