@echo off
REM Script đơn giản để train chỉ với CERT dataset
REM Sử dụng: train_simple.bat

cd /d "%~dp0\.."

echo === Checking Dependencies ===
python -c "import pandas, numpy, sklearn, joblib" 2>nul
if errorlevel 1 (
    echo Installing required packages...
    pip install -r ML/requirements.txt
)

echo.
echo === Training UEBA Model với CERT Dataset ONLY ===
echo.
echo [WARN]  WARNING: This will load TOÀN BỘ CERT dataset (no limit)
echo    For large datasets (117M rows), use train_large_dataset.bat instead
echo.
python -m ML.train_ueba --cert-dir Dataset --output worker/ml_models/ueba_iso_forest.pkl

echo.
if exist worker\ml_models\ueba_iso_forest.pkl (
    echo === Training Complete ===
    echo Model saved to: worker/ml_models/ueba_iso_forest.pkl
) else (
    echo === Training Failed ===
    echo Please check the error messages above
)
pause
