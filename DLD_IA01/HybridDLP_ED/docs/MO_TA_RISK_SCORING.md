# Mô tả Risk Scoring trong HybridDLP (Worker L3)

Tài liệu này mô tả **cách tính điểm rủi ro** đang được triển khai trong **Detection Engine** (`worker/`), cụ thể qua `RiskScoringEngine` trong `worker/core/risk_scoring.py` và các module con. Điểm đầu ra được chuẩn hoá **0–100**, kèm **mức rủi ro** (`low` / `medium` / `high` / `critical`) và **hành động gợi ý** (`alert` hoặc `log`).

---

## 1. Luồng tổng quan

1. Worker nhận sự kiện (từ agent / queue), chạy **fast scan** (YARA, IOC, …) và có thể chạy **deep analysis** (ML, OCR, …).
2. Xây **`event_context`** (user, thời gian, destination, `action_type`, các counter tần suất, `_event_data` chứa bản raw event, …).
3. Gọi `RiskScoringEngine.calculate_score(fast_scan_result, deep_analysis_result, event_context)`.
4. Phương pháp tính được chọn bởi biến môi trường **`RISK_SCORING_METHOD`** (mặc định trong code: **`cvss_dlp`** — xem `worker/config.py`).

---

## 2. Phân loại mức rủi ro (0–100 → nhãn)

Hàm `classify_risk_level(total_score)` trong `risk_scoring.py` ánh xạ điểm tổng sang:

| Mức | Điều kiện (mặc định) |
|-----|----------------------|
| `low` | `< RISK_LEVEL_LOW_MAX` (mặc định 25) |
| `medium` | `[LOW_MAX, MEDIUM_MAX)` (mặc định 25–50) |
| `high` | `[MEDIUM_MAX, HIGH_MAX)` (mặc định 50–75) |
| `critical` | `≥ HIGH_MAX` (mặc định ≥ 75) |

Ngưỡng có thể chỉnh qua biến môi trường: `RISK_LEVEL_LOW_MAX`, `RISK_LEVEL_MEDIUM_MAX`, `RISK_LEVEL_HIGH_MAX` (có clamp trong `WorkerConfig`).

---

## 3. Ngưỡng hành động (alert / log)

`WorkerConfig.RISK_THRESHOLDS`:

- **`alert`**: nếu `total_score >= RISK_ALERT_THRESHOLD` (mặc định ~40, có thể chỉnh trong khoảng cho phép) → `action = "alert"`.
- **`block`**: trong cấu hình hiện tại được đặt **rất cao** (không dùng — chế độ **alert-only**).
- Ngược lại → `action = "log"`.

---

## 4. Các phương pháp tính điểm (`RISK_SCORING_METHOD`)

### 4.1. `nist_based`

Theo lớp **`NISTBasedRiskScoringEngine`**: mô hình gần **NIST SP 800-30**.

- **Impact (I)** thang **1–4** (Public → Secret): lấy **max** theo tất cả tín hiệu:
  - YARA (ID/CCCD, thẻ, API key, email, phone, …),
  - IOC từ agent,
  - ML `is_sensitive` + độ tin cậy,
  - ZIP mật khẩu, pattern OCR (CMND/CCCD, thẻ),
  - Nếu không có tín hiệu: dựa `location` (thư mục nhạy cảm → 3, không thì 1).

- **Likelihood (L)** thang ~**1–5**: trung bình có trọng số của:
  - **destination** (trọng số 0.4): USB/removable, app/domain ngoài, cloud, email, mạng, local, …
  - **user_behavior** (0.3): ngoài giờ, cuối tuần, bulk (số file / paste clipboard),
  - **file_protection** (0.2): archive mã hoá, đuôi nghi ngờ, …
  - **frequency** (0.1): paste clipboard 1h, copy USB 24h, URL ngoài 24h,
  - Cộng thêm **boost từ ML anomaly** (`ml_is_anomaly`, `ml_anomaly_score` so với `ML_ANOMALY_BOOST_THRESHOLD`).

Công thức chuẩn hoá về **0–100**:

\[
\text{total\_score} = \frac{L \times I}{L_{\max} \times I_{\max}} \times 100
\]

với `L_max = 5`, `I_max = 4` (cấu hình `NIST_MAX_VALUES`).

**Ghi đè:** nếu `event_context.force_max_risk == True` → `total_score = 100`, `action = "alert"`.

---

### 4.2. `traditional`

Ba thành phần **0–100**:

1. **Content score (Sc)** — `_calculate_content_score`: YARA, IOC, ZIP mã hoá, ML, OCR (giống tinh thần bảng điểm cộng dồn, cap 100).
2. **Behavior score (Sb)** — `_calculate_behavior_score`: paste clipboard vào app/domain/tiêu đề nhạy cảm, USB, cloud, screenshot/print, …; cộng thêm **anomaly** đã chuẩn hoá:  
   `Sb = min(100, behavior_base + ml_anomaly * ML_ANOMALY_BEHAVIOR_BLEND)`.
3. **Context score (Sx)** — `_calculate_context_score`: tiêu đề cửa sổ, domain, app nhắn tin, thư mục nhạy cảm, kích thước file, …

**Gộp tổng** — do `RISK_COMPOSITE_MODEL`:

- **`weighted_sum`**:  
  `R = wc*Sc + wb*Sb + wx*Sx`  
  (trọng số mặc định `RISK_WEIGHTS`: content 0.5, behavior 0.3, context 0.2).

- **`nist_multiplicative`** (mặc định nếu env không đổi):  
  - `impact = Sc`  
  - `likelihood = alpha * Sb + (1-alpha) * Sx` với `alpha = RISK_LIKELIHOOD_ALPHA` (mặc định 0.6)  
  - `R = (impact * likelihood) / 100`

**Chuẩn hoá anomaly thô:** `normalize_anomaly_score()` — policy `ML_ANOMALY_NORM_METHOD` (`percentile` / `minmax`) và các ngưỡng P5/P95 hoặc min/max.

---

### 4.3. `research_based`

**`ResearchBasedRiskScoringEngine`**: tổng hợp **5 nhân tố** (mỗi thành phần 0–100), trọng số `RESEARCH_RISK_WEIGHTS`:

\[
R = w_A A + w_B B + w_C C + w_T T + w_F F
\]

- **A (Anomaly)**: ML anomaly (chuẩn hoá hoặc 0–100) + boost theo số YARA/IOC, ZIP, ML sensitive.
- **B (Behavioral deviation)**: nếu **chưa có baseline** user → **50** (trung tính); nếu có baseline → Z-score các metric (`file_accesses_last_1h`, USB, paste, URL, …).
- **C (Content sensitivity)**: YARA/IOC với trọng số nhóm (id/credit/api/email/…), ML, OCR.
- **T (Temparol)**: ngoài giờ / cuối tuần (0–45 điểm theo tổ hợp).
- **F (Frequency)**: paste 1h, copy USB 24h, URL 24h — nhân **frequency multiplier** (1.0–2.5) theo mức đếm.

---

### 4.4. `cvss_dlp` (CVSS-inspired DLP, Noteupdate) — **mặc định trong `config`**

**`CVSSDLPScoringEngine`** (`worker/core/cvss_dlp_orchestrator.py`) — pipeline:

1. **Base score (0–100)** — `base_scoring.compute_base_score`:
   - Trọng số `CVSS_DLP_BASE_WEIGHTS` (mặc định):  
     `0.35*content_sensitivity + 0.25*data_criticality + 0.25*behavior_anomaly + 0.15*confidence`
   - **Content sensitivity**: YARA, IOC, ML sensitive, ZIP, suspicious flag.
   - **Data criticality**: từ đường dẫn / tag (payroll, HR, contract, …) và tag `corr_*`.
   - **Behavior anomaly**: `behavioral_risk_boost`, `ml_anomaly_score`, cờ `ml_is_anomaly`.
   - **Confidence**: số match YARA / suspicious / ML.

2. **Exfiltration temparol (U / P / A / X)** — `exfiltration_temparol.compute_exfiltration_temparol`:
   - Cộng điểm các nhóm: **channel**, **concealment**, **volume**, **destination**, **anomaly** (mỗi nhóm có trần riêng).
   - Map tổng điểm thô → mức **U** (≤24), **P** (25–54), **A** (≥55), hoặc **X** nếu telemetry thiếu / cờ unknown.
   - Gán **`temparol_numeric`** và **`em_factor`** theo bảng `CVSS_DLP_TEMPAROL_LEVEL_SCORES` và `CVSS_DLP_EM_FACTORS`.

3. **Environmental score (0–100)** — `environmental_scoring.compute_environmental_score`:
   - Trọng số `CVSS_DLP_ENV_WEIGHTS`: user, time, asset, destination (mỗi mục một hàm con 0–100).

4. **Attack chain bonus** — `attack_chain.compute_attack_chain_bonus` (tối đa 20, cộng vào tổng sau fusion).

5. **Fusion** — `final_risk_fusion.fuse_final_risk` (**công thức 2 mặc định**):  
   `FinalRisk = min(100, F_base*Base + F_mat*TemparolNumeric + F_env*Environmental + ChainBonus)`  
   với `CVSS_DLP_FUSION_WEIGHTS` (mặc định 0.60 / 0.25 / 0.15).  
   Nếu `CVSS_DLP_USE_FORMULA1=1`: biến thể nhân `em_factor` lên base (xem comment trong code).

6. **`apply_force_max_risk`**: nếu `force_max_risk` → ép tối thiểu ~88 (floor).

7. **Policy** — `policy_decision.decide_recommended_action` + `build_reason_codes` (nhãn gợi ý và mã lý do).

Kết quả trả về có `details.cvss_dlp` chứa đầy đủ thành phần để audit.

---

## 5. Bảng tham chiếu biến môi trường chính

| Biến | Ý nghĩa |
|------|---------|
| `RISK_SCORING_METHOD` | `cvss_dlp` (mặc định) \| `nist_based` \| `traditional` \| `research_based` |
| `RISK_ALERT_THRESHOLD` | Ngưỡng `alert` (0–100, có clamp) |
| `RISK_LEVEL_*_MAX` | Ngăn `low` / `medium` / `high` / `critical` |
| `RISK_COMPOSITE_MODEL` | `weighted_sum` \| `nist_multiplicative` (chỉ `traditional`) |
| `RISK_LIKELIHOOD_ALPHA` | Trọng số Sb trong likelihood (multiplicative) |
| `ML_ANOMALY_BEHAVIOR_BLEND` | β gộp anomaly vào behavior (`traditional`) |
| `ML_ANOMALY_NORM_METHOD`, `ML_ANOMALY_P5`, `ML_ANOMALY_P95`, … | Chuẩn hoá tín hiệu anomaly |
| `CVSS_DLP_*` | Trọng số base, fusion, temparol, environmental, EM factor, công thức 1 |

Chi tiết đầy đủ nằm trong **`worker/config.py`**.

---

## 6. Lưu ý vận hành

- **Agent L1** không tính risk score tổng hợp này; phần lớn logic nằm ở **Worker**.
- **`research_based`**: điểm **behavioral deviation** phụ thuộc baseline user — nếu chưa nạp baseline, nhánh B luôn ~50.
- **`cvss_dlp`** phụ thuộc **`event_context`** đầy đủ (thời gian, destination, `force_max_risk`, …) để environmental và temparol phản ánh đúng.
- Mọi phương pháp đều dùng chung **`classify_risk_level`** và ngưỡng **`RISK_THRESHOLDS`** cho `action` (trừ khi `force_max_risk` trong NIST/CVSS-DLP xử lý riêng).

---

*Tài liệu căn cự mã nguồn tại `HybridDLP_ED/worker/core/risk_scoring.py`, `worker/config.py` và các module `base_scoring.py`, `exfiltration_temparol.py`, `environmental_scoring.py`, `final_risk_fusion.py`, `cvss_dlp_orchestrator.py`. Khi đổi config hoặc công thức, nên cập nhật lại mục tương ứng trong file này.*
