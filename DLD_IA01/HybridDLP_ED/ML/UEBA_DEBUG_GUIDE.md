# UEBA ML Debug Guide

## Tổng quan

UEBA (User and Entity Behavior Analytics) trong HybridDLP sử dụng 3 thành phần chính:

1. **IsolationForest Model** - Phát hiện anomaly dựa trên features
2. **Profile Deviation** - So sánh với hành vi gần đây của user
3. **Baseline Drift** - So sánh với baseline dài hạn của user
4. **Slow Burn Accumulator** - Tích lũy "low-and-slow" attack patterns

## Cách kích hoạt Debug Logging

### Bật debug cho Worker (chạy real-time)

```powershell
$env:DEBUG_ML = "1"
python -m worker.worker
```

### Bật debug cho Test Model

```bash
# Mặc định đã bật DEBUG
python -m ML.test_model
```

### Xem log chi tiết

```powershell
# Xem log UEBA trong worker
Get-Content worker\logs\detection_engine.log -Tail 100 -Wait

# Hoặc xem log ueba (baseline profiles)
Get-Content worker\logs\ueba\ueba_user_baselines.json
```

## Score Breakdown (0-10)

```
Anomaly Score = Model Score × 0.65 + Profile Score × 0.25 + Baseline Score × 0.10 + Slow Burn × Boost Factor
```

### Ngưỡng (Threshold)
- **ML_ANOMALY_THRESHOLD = 7.0** (có thể điều chỉnh trong `worker/config.py`)
- Score >= 7.0 → Alert

## Khi nào UEBA kích hoạt?

### Case 4: Nhỏ giọt AI bắt (UEBA)

UEBA được gọi ở **4 vị trí** trong `worker.py`:

1. **File Events** (line ~782) - khi file được copy/move ra USB/External
2. **Browser Upload** (line ~1273) - khi upload lên cloud
3. **Clipboard** (line ~1672) - khi paste vào app bên ngoài
4. **Special Events** (line ~2102) - các event đặc biệt khác

### Case 5: Pipeline người dùng (User Behavior)

User pipeline hoạt động qua 3 layers:

#### Layer 1: Profile Deviation (Short-term)
- **Off-hours deviation**: Nếu user hiếm khi làm việc ngoài giờ (off_ratio < 0.08)
- **Clipboard spike**: >= 15 paste trong 10 phút → +1.2 điểm
- **External channel spike**: >= 6 transfer trong 1 giờ → +2.2 điểm
- **Fragmented exfiltration**: >= 4 small fragments + external/risk app → +2.5 điểm

#### Layer 2: Baseline Drift (Long-term)
- So sánh với EMA (Exponential Moving Average) của user
- **Off-hours baseline**: p < 0.10 → +2.4 điểm
- **External channel first time**: p < 0.05 → +3.2 điểm
- **Sequence detection**: off-hours + external + risky app → +1.4 điểm

#### Layer 3: Slow Burn Accumulator
- Tích lũy dần theo thời gian
- Decay: ~6 giờ half-life
- Cap: 6.0 điểm
- Fragmented exfil: +1.2 điểm/event

## Debug Output Mẫu

```
[ML DEBUG] === New Event ===
[ML DEBUG] User: john, Type: clipboard_paste, Time: 2026-05-04 20:30:00
[ML DEBUG] History size: 150 events
[ML DEBUG] Raw score: -0.0353 -> Model score: 4.71, Threshold: 7.00
[ML DEBUG] Score Breakdown:
  - Model Score:     4.706 x 0.65 = 3.059
  - Profile Score:   1.600 x 0.25 = 0.400
  - Baseline Score:  0.000 x 0.10 = 0.000
  - Slow Burn:       0.000 x 1.00 = 0.000
  - TOTAL: 3.459, Is Anomaly: False
[ML DEBUG] Profile reasons: ['clipboard_elevated_10m', 'risky_app_clipboard_sequence']
[ML DEBUG] Baseline reasons: ['baseline_warmup']

[ProfileDeviation] User=john, is_off=1, off_ratio=0.000, clip_10m=20, ext_1h=3, ...
[BaselineDrift] n=35, is_off=1, is_ext=1, is_clip=1, is_risky=1, ...
[Accumulator] User=john, elapsed_h=2.5, decay=0.659, old_value=0.5, incremental=1.65, new_value=2.15
```

## Profile Files

Baseline profiles được lưu tại:
```
worker/logs/ueba/ueba_user_baselines.json
```

Format:
```json
{
  "version": 1,
  "saved_ts": 1714814400.0,
  "profiles": {
    "john": {
      "n": 150,
      "last_ts": 1714814400.0,
      "ema_off_hours": 0.05,
      "ema_external": 0.02,
      "ema_clipboard": 0.15,
      "ema_risky_app": 0.08,
      "hour_hist": [0, 0, 0, 0, 0, 0, 2, 5, 12, ...]
    }
  }
}
```

## Tuning Parameters

### Trong `worker/config.py`:

```python
# ML Anomaly Thresholds
ML_ANOMALY_THRESHOLD = 7.0  # Ngưỡng alert (0-10)

# Baseline settings (trong ML module)
UEBA_PROFILE_MIN_EVENTS = 35    # Số event tối thiểu để có baseline
UEBA_PROFILE_DECAY_HOURS = 168  # 7 ngày decay
UEBA_PROFILE_SAVE_EVERY = 25    # Save sau mỗi N events
```

### Environment Variables:

```powershell
$env:DEBUG_ML = "1"                              # Bật debug logging
$env:UEBA_PROFILE_DECAY_HOURS = "168"           # 7 ngày
$env:UEBA_PROFILE_MIN_EVENTS = "35"             # Tối thiểu 35 events
$env:ML_ANOMALY_THRESHOLD = "7.0"               # Ngưỡng alert
```

## Troubleshooting

### 1. Model không load được
```
[FAIL] Model not found at: worker\ml_models\ueba_iso_forest.pkl
```
**Giải pháp**: Train model trước:
```bash
python -m ML.train_large_dataset
```

### 2. Baseline luôn "warmup"
```
Baseline Reasons: ['baseline_warmup']
Baseline N events: 1
```
**Giải pháp**: Cần ít nhất 35 events để có baseline. Đợi worker chạy một thời gian hoặc giảm `UEBA_PROFILE_MIN_EVENTS`.

### 3. Anomalous event không được phát hiện
- Kiểm tra threshold: `ML_ANOMALY_THRESHOLD`
- Xem score breakdown: model_score, profile_score, baseline_score
- Kiểm tra signal flags: `is_external`, `is_clipboard`, `app_risky`

### 4. Xem feature values
```python
from ML.feature_extractor import EventFeatureExtractor

extractor = EventFeatureExtractor()
features = extractor.extract(event)
print(extractor.get_feature_names())
print(features)
```

## Test với Simulated Data

Chạy test model:
```bash
python -m ML.test_model
```

Output mẫu:
```
Testing: Normal Event
  Anomaly Score: 4.01/10
  Is Anomaly: False
  Model Score: 6.175, Profile: 0.00, Baseline: 0.00, SlowBurn: 0.00

Testing: Anomalous: Off-hours + ChatGPT
  Anomaly Score: 3.46/10
  Is Anomaly: False
  Model Score: 4.706, Profile: 1.60, Baseline: 0.00, SlowBurn: 0.00
  Profile Reasons: ['clipboard_elevated_10m', 'risky_app_clipboard_sequence']

Testing: Anomalous: USB Bulk Copy
  Anomaly Score: 3.13/10
  Is Anomaly: False
  Model Score: 4.464, Profile: 0.90, Baseline: 0.00, SlowBurn: 0.35
  Profile Reasons: ['transformation_signal']
```

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                     Event Input                             │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Feature Extraction (13 features)                            │
│  - Temporal: is_off_hours, hour, day_of_week               │
│  - Frequency: clip_paste_10m, usb_bytes_1h, file_ops_1h    │
│  - Quantitative: entropy, size_log, file_count               │
│  - Contextual: dest_app, source_type, op_type               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────┐ │
│  │ IsolationForest │  │   Profile    │  │    Baseline    │ │
│  │    (65%)        │  │ Deviation    │  │     Drift      │ │
│  │                 │  │   (25%)      │  │    (10%)       │ │
│  └────────┬────────┘  └──────┬───────┘  └───────┬───────┘ │
│           │                  │                   │         │
│           └──────────────────┴───────────────────┘         │
│                          │                                 │
│                          ▼                                 │
│                 ┌─────────────────┐                         │
│                 │  Slow Burn      │                         │
│                 │  Accumulator    │                         │
│                 └────────┬────────┘                         │
│                          │                                 │
└──────────────────────────┼──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Final Anomaly Score = Σ(weighted_components)               │
│  if Score >= Threshold → ALERT                              │
└─────────────────────────────────────────────────────────────┘
```
