@echo off
REM Script để test UEBA model đã train
REM Sử dụng: test_model.bat

cd /d "%~dp0\.."

echo ========================================
echo TESTING UEBA MODEL
echo ========================================
echo.

python -m ML.test_model

echo.
pause
