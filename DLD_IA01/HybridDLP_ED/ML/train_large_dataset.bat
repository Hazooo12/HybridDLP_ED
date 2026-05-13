@echo off
REM Script tối ưu để train với dataset lớn (117 triệu rows)
REM Sử dụng sampling và streaming để tiết kiệm memory

cd /d "%~dp0\.."

echo ========================================
echo TRAINING VỚI DATASET LỚN (OPTIMIZED)
echo ========================================
echo.
echo Options:
echo 1. Sample 1%% of data (recommended for 117M rows)
echo 2. Limit 1M events per file
echo 3. Streaming mode (memory efficient)
echo.

echo === Training với Sampling 1%% ===
python -m ML.train_ueba ^
    --cert-dir Dataset ^
    --synthetic synthetic_events.jsonl ^
    --output worker/ml_models/ueba_iso_forest.pkl ^
    --contamination 0.01 ^
    --n-estimators 100 ^
    --sample-ratio 0.01 ^
    --max-events-per-file 1000000

echo.
if exist worker\ml_models\ueba_iso_forest.pkl (
    echo === Training Complete ===
    echo Model saved to: worker/ml_models/ueba_iso_forest.pkl
    echo.
    echo NOTE: Model trained on 1%% sample of data
    echo For full dataset, remove --sample-ratio parameter
) else (
    echo === Training Failed ===
    echo Please check the error messages above
)
pause
