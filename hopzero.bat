@echo off
REM ==============================================================================
REM HopZero One-Click Native Launcher (Windows)
REM ==============================================================================
setlocal enabledelayedexpansion

cd /d "%~dp0"
python scripts\launch.py %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] HopZero exited with error code %ERRORLEVEL%
    pause
)
