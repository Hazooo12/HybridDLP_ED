@echo off
REM ========================================
REM Start All HybridDLP Services
REM ========================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo Starting HybridDLP System...
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
    echo [WARNING] Not running as Administrator - Windows Service may fail
)

echo.
echo Step 1: Starting Docker Services (Worker + Dashboard)...
echo ----------------------------------------
docker --version >nul 2>&1
if %errorLevel% == 0 (
    docker-compose ps >nul 2>&1
    if %errorLevel% == 0 (
        echo Starting Docker containers...
        docker-compose up -d
        if %errorLevel% == 0 (
            echo [OK] Docker services started
            timeout /t 3 >nul
            docker-compose ps
        ) else (
            echo [WARNING] Failed to start, trying to build first...
            docker-compose build
            docker-compose up -d
            if %errorLevel% == 0 (
                echo [OK] Docker services started after build
                timeout /t 3 >nul
                docker-compose ps
            ) else (
                echo [ERROR] Failed to start Docker services
                echo Please check Docker Desktop is running
                goto :error
            )
        )
    ) else (
        echo [WARNING] Docker Compose not available
        echo Please install Docker Desktop
    )
) else (
    echo [WARNING] Docker not installed or not running
    echo Please start Docker Desktop manually
)

echo.
echo Step 2: Starting Windows Service (Agent)...
echo ----------------------------------------
if %IS_ADMIN% == 1 (
    cd agent
    python service.py start
    if %errorLevel% == 0 (
        echo [OK] Windows Service started
    ) else (
        echo [WARNING] Failed to start Windows Service
        echo Service may already be running
    )
    cd ..
) else (
    echo [SKIP] Cannot start Windows Service without Administrator privileges
    echo Please run this script as Administrator to start Windows Service
    echo.
    echo To start Agent manually:
    echo   cd agent
    echo   python -m agent.sensor
)

echo.
echo Step 3: Checking Service Status...
echo ----------------------------------------
echo.

echo Docker Services:
docker-compose ps 2>nul
if %errorLevel% neq 0 (
    echo [WARNING] Docker not available
)

echo.
echo Windows Service:
sc query HybridDLPWatchdog 2>nul | findstr "STATE"
if %errorLevel% neq 0 (
    echo [INFO] Windows Service not installed or not running
)

echo.
echo ========================================
echo System Status Summary
echo ========================================
echo.

REM Check Worker
docker-compose ps worker 2>nul | findstr "Up" >nul
if %errorLevel% == 0 (
    echo [OK] Worker: Running
) else (
    echo [X] Worker: Not Running
)

REM Check Dashboard
docker-compose ps dashboard 2>nul | findstr "Up" >nul
if %errorLevel% == 0 (
    echo [OK] Dashboard: Running (http://localhost:8501)
) else (
    echo [X] Dashboard: Not Running
)

REM Check Agent Service
sc query HybridDLPWatchdog 2>nul | findstr "RUNNING" >nul
if %errorLevel% == 0 (
    echo [OK] Agent Service: Running
) else (
    REM Check if sensor process is running
    tasklist | findstr "python" | findstr "sensor" >nul
    if %errorLevel% == 0 (
        echo [OK] Agent Sensor: Running (direct mode)
    ) else (
        echo [X] Agent: Not Running
    )
)

echo.
echo ========================================
echo Startup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Check Worker logs: docker-compose logs -f worker
echo 2. Open Dashboard: http://localhost:8501
echo 3. Check Agent: sc query HybridDLPWatchdog
echo.
goto :end

:error
echo.
echo [ERROR] Failed to start some services
echo Please check the errors above
exit /b 1

:end
pause
