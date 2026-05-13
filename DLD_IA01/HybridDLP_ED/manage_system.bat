@echo off
REM ========================================
REM HybridDLP System Manager
REM Usage: manage_system.bat [start|stop|restart|status]
REM ========================================

setlocal enabledelayedexpansion

if "%1"=="" (
    echo.
    echo ========================================
    echo HybridDLP System Manager
    echo ========================================
    echo.
    echo Usage: manage_system.bat [command]
    echo.
    echo Commands:
    echo   start    - Start all services
    echo   stop     - Stop all services
    echo   restart  - Restart all services
    echo   status   - Check status of all services
    echo.
    echo Examples:
    echo   manage_system.bat start
    echo   manage_system.bat stop
    echo   manage_system.bat status
    echo.
    goto :end
)

cd /d "%~dp0"

set COMMAND=%1
if /i "%COMMAND%"=="start" (
    call start_all.bat
) else if /i "%COMMAND%"=="stop" (
    call stop_all.bat
) else if /i "%COMMAND%"=="restart" (
    call restart_all.bat
) else if /i "%COMMAND%"=="status" (
    call status_all.bat
) else (
    echo [ERROR] Unknown command: %COMMAND%
    echo.
    echo Available commands: start, stop, restart, status
    exit /b 1
)

:end
