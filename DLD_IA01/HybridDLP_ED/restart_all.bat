@echo off
REM ========================================
REM Restart All HybridDLP Services
REM ========================================

echo.
echo ========================================
echo Restarting HybridDLP System...
echo ========================================
echo.

cd /d "%~dp0"

echo Step 1: Stopping all services...
call stop_all.bat

echo.
echo Waiting 5 seconds...
timeout /t 5 >nul

echo.
echo Step 2: Starting all services...
call start_all.bat

echo.
echo ========================================
echo Restart Complete!
echo ========================================
echo.

pause
