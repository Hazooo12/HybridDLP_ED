@echo off
REM ========================================
REM Check Status of All HybridDLP Services
REM ========================================

echo.
echo ========================================
echo HybridDLP System Status
echo ========================================
echo.

cd /d "%~dp0"

echo [1] Docker Services Status
echo ----------------------------------------
docker-compose ps 2>nul
if %errorLevel% neq 0 (
    echo [X] Docker not available or not running
    echo Please start Docker Desktop
)
echo.

echo [2] Windows Service Status
echo ----------------------------------------
sc query HybridDLPWatchdog 2>nul
if %errorLevel% neq 0 (
    echo [X] Windows Service not installed
) else (
    sc query HybridDLPWatchdog | findstr "STATE"
)
echo.

echo [3] Process Status
echo ----------------------------------------
echo Python processes:
tasklist | findstr "python"
if %errorLevel% neq 0 (
    echo [INFO] No Python processes found
)
echo.

echo pythonservice.exe (Windows Service):
tasklist | findstr "pythonservice"
if %errorLevel% neq 0 (
    echo [INFO] No pythonservice.exe found
)
echo.

echo [4] Database Status
echo ----------------------------------------
if exist "agent\runtime\events.db" (
    python -c "import sqlite3; conn = sqlite3.connect('agent/runtime/events.db'); cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM events'); count = cursor.fetchone()[0]; print(f'Total events: {count}'); conn.close()" 2>nul
    if %errorLevel% == 0 (
        echo [OK] Database accessible
    ) else (
        echo [WARNING] Cannot read database
    )
) else (
    echo [X] Database not found
)
echo.

echo [5] Heartbeat Files
echo ----------------------------------------
if exist "agent\runtime\state\sensor_heartbeat.json" (
    echo [OK] Sensor heartbeat file exists
    type "agent\runtime\state\sensor_heartbeat.json" 2>nul
) else (
    echo [X] Sensor heartbeat file not found
)
echo.

if exist "agent\runtime\state\watchdog_heartbeat.json" (
    echo [OK] Watchdog heartbeat file exists
    type "agent\runtime\state\watchdog_heartbeat.json" 2>nul
) else (
    echo [X] Watchdog heartbeat file not found
)
echo.

echo [6] Summary
echo ----------------------------------------
echo.

REM Check Worker
docker-compose ps worker 2>nul | findstr "Up" >nul
if %errorLevel% == 0 (
    echo [OK] Worker: Running
    set WORKER_STATUS=OK
) else (
    echo [X] Worker: Not Running
    set WORKER_STATUS=FAIL
)

REM Check Dashboard
docker-compose ps dashboard 2>nul | findstr "Up" >nul
if %errorLevel% == 0 (
    echo [OK] Dashboard: Running (http://localhost:8501)
    set DASHBOARD_STATUS=OK
) else (
    echo [X] Dashboard: Not Running
    set DASHBOARD_STATUS=FAIL
)

REM Check Agent Service
sc query HybridDLPWatchdog 2>nul | findstr "RUNNING" >nul
if %errorLevel% == 0 (
    echo [OK] Agent Service: Running
    set AGENT_STATUS=OK
) else (
    REM Check if sensor process is running
    tasklist | findstr "python" | findstr /i "sensor" >nul
    if %errorLevel% == 0 (
        echo [OK] Agent Sensor: Running (direct mode)
        set AGENT_STATUS=OK
    ) else (
        echo [X] Agent: Not Running
        set AGENT_STATUS=FAIL
    )
)

echo.
echo ========================================
if "%WORKER_STATUS%"=="OK" if "%DASHBOARD_STATUS%"=="OK" if "%AGENT_STATUS%"=="OK" (
    echo All services are running!
) else (
    echo Some services are not running
)
echo ========================================
echo.

pause
