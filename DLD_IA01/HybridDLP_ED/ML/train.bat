@echo off
REM Script để train UEBA model trên Windows
REM Sử dụng: train.bat

cd /d "%~dp0\.."

echo === Checking Dependencies ===
python -c "import pandas, numpy, sklearn, joblib" 2>nul
if errorlevel 1 (
    echo Installing required packages...
    pip install -r ML/requirements.txt
)

echo.
echo === Generating Synthetic Data ===
python -m ML.generate_synthetic_data --output synthetic_events.jsonl --normal 10000 --anomalous 50

echo.
echo === Training UEBA Model voi CERT Dataset ===
echo.
echo [INFO] Limit: 1,000,000 rows per file (de tranh OOM voi dataset lon)
echo.
python -m ML.train_ueba --cert-dir Dataset --synthetic synthetic_events.jsonl --output worker/ml_models/ueba_iso_forest.pkl --contamination 0.01 --n-estimators 100 --max-events-per-file 1000000

echo.
if exist worker\ml_models\ueba_iso_forest.pkl (
    echo === Training Complete ===
    echo Model saved to: worker/ml_models/ueba_iso_forest.pkl
) else (
    echo === Training Failed ===
    echo Please check the error messages above
)
pause
