@echo off
REM ========================================
REM Stop All HybridDLP Services
REM ========================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo Stopping HybridDLP System...
echo ========================================
echo.

cd /d "%~dp0"

REM Check if running as Administrator for Windows Service
net session >nul 2>&1
if %errorLevel% == 0 (
    set IS_ADMIN=1
    echo [OK] Running with Administrator privileges
) else (
    set IS_ADMIN=0
    echo [WARNING] Not running as Administrator - Windows Service may not stop
)

echo.
echo Step 1: Stopping Docker Services (Worker + Dashboard)...
echo ----------------------------------------
docker --version >nul 2>&1
if %errorLevel% == 0 (
    docker-compose ps >nul 2>&1
    if %errorLevel% == 0 (
        echo Stopping Docker containers...
        docker-compose stop
        if %errorLevel% == 0 (
            echo [OK] Docker services stopped
        ) else (
            echo [WARNING] Some Docker services may not have stopped
        )
    ) else (
        echo [INFO] Docker Compose not available
    )
) else (
    echo [INFO] Docker not installed
)

echo.
echo Step 2: Stopping Windows Service (Agent)...
echo ----------------------------------------
if %IS_ADMIN% == 1 (
    cd agent
    python service.py stop
    if %errorLevel% == 0 (
        echo [OK] Windows Service stopped
    ) else (
        echo [INFO] Service may already be stopped
    )
    cd ..
) else (
    echo [SKIP] Cannot stop Windows Service without Administrator privileges
    echo Please run this script as Administrator to stop Windows Service
    echo.
    echo To stop Agent manually:
    echo   cd agent\runtime\state
    echo   echo. ^> stop.flag
)

echo.
echo Step 3: Checking for running processes...
echo ----------------------------------------
echo.

REM Check for Python sensor processes
tasklist | findstr "python" | findstr /i "sensor" >nul
if %errorLevel% == 0 (
    echo [WARNING] Found Python sensor processes still running
    echo You may need to stop them manually:
    tasklist | findstr "python"
    echo.
    echo To kill all Python processes (use with caution):
    echo   taskkill /F /IM python.exe
) else (
    echo [OK] No Python sensor processes found
)

REM Check for pythonservice.exe
tasklist | findstr "pythonservice" >nul
if %errorLevel% == 0 (
    echo [INFO] pythonservice.exe is still running (Windows Service)
    echo This is normal if service is installed but stopped
) else (
    echo [OK] No pythonservice.exe found
)

echo.
echo Step 4: Final Status Check...
echo ----------------------------------------
echo.

REM Check Worker
docker-compose ps worker 2>nul | findstr "Up" >nul
if %errorLevel% == 0 (
    echo [WARNING] Worker: Still Running
) else (
    echo [OK] Worker: Stopped
)

REM Check Dashboard
docker-compose ps dashboard 2>nul | findstr "Up" >nul
if %errorLevel% == 0 (
    echo [WARNING] Dashboard: Still Running
) else (
    echo [OK] Dashboard: Stopped
)

REM Check Agent Service
sc query HybridDLPWatchdog 2>nul | findstr "RUNNING" >nul
if %errorLevel% == 0 (
    echo [WARNING] Agent Service: Still Running
) else (
    echo [OK] Agent Service: Stopped
)

echo.
echo ========================================
echo Shutdown Complete!
echo ========================================
echo.
echo All services have been stopped.
echo.
goto :end

:end
pause
