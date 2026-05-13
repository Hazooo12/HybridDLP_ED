@echo off
REM Setup ML models script for Windows

echo  Setting up ML models...

cd worker

REM Create directories
if not exist "ml_models" mkdir ml_models
if not exist "dataset\sensitive" mkdir dataset\sensitive
if not exist "dataset\normal" mkdir dataset\normal

REM Collect dataset
echo [CHART] Collecting dataset...
python scripts\collect_dataset.py

REM Train model
echo  Training ML model...
python scripts\train_model.py

echo [OK] ML models setup completed!
echo    Models location: worker\ml_models\

pause
