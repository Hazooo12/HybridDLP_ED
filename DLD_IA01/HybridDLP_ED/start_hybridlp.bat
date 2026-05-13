@echo off
REM ========================================
REM HybridDLP System Tray Launcher
REM ========================================
REM Khởi động hệ thống HybridDLP với:
REM - Setup wizard lần đầu (password + config)
REM - System tray app để manage services
REM ========================================

echo.
echo ========================================
echo  HybridDLP - System Launcher
echo ========================================
echo.

cd /d "%~dp0"

REM Kiểm tra Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python not found in PATH
    echo Please install Python 3.8+ and add to PATH
    pause
    exit /b 1
)

echo [OK] Python detected
echo.

REM Check lần đầu
echo [Boot] Checking setup status...
python -c "from agent.password_manager import is_password_set; exit(0 if is_password_set() else 1)" >nul 2>&1

if %errorLevel% equ 0 (
    echo [OK] Already configured - starting system tray...
    echo.
) else (
    echo [Setup] First-time setup required
    echo.
)

REM Chạy boot.py
python agent/boot.py

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Failed to start
    pause
    exit /b 1
)
