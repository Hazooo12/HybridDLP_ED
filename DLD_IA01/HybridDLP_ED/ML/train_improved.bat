@echo off
REM Script để train UEBA model với parameters tốt hơn
REM Sử dụng: train_improved.bat

cd /d "%~dp0\.."

echo ========================================
echo TRAINING UEBA MODEL (IMPROVED)
echo ========================================
echo.
echo Parameters:
echo - Sample Ratio: 5%% (thay vì 1%%)
echo - Contamination: 2%% (thay vì 1%%)
echo - Max Events/File: 2M
echo.
echo This will train with ~150K events instead of 30K
echo Training time: ~30-60 minutes
echo.

pause

echo === Checking Dependencies ===
python -c "import pandas, numpy, sklearn, joblib" 2>nul
if errorlevel 1 (
    echo Installing required packages...
    pip install -r ML/requirements.txt
)

echo.
echo === Training UEBA Model với Improved Parameters ===
python -m ML.train_ueba ^
    --cert-dir Dataset ^
    --synthetic synthetic_events.jsonl ^
    --output worker/ml_models/ueba_iso_forest.pkl ^
    --contamination 0.02 ^
    --n-estimators 200 ^
    --sample-ratio 0.05 ^
    --max-events-per-file 2000000

echo.
if exist worker\ml_models\ueba_iso_forest.pkl (
    echo === Training Complete ===
    echo Model saved to: worker/ml_models/ueba_iso_forest.pkl
    echo.
    echo Next steps:
    echo 1. Run: test_model.bat
    echo 2. Check if anomaly scores improved
) else (
    echo === Training Failed ===
    echo Please check the error messages above
)
pause
