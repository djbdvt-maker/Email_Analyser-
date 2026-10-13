@echo off
REM ==============================================================================
REM HopZero Remote Multi-Network Launcher (Windows)
REM Enables secure public HTTPS tunnel for remote laptops on different networks.
REM ==============================================================================
setlocal enabledelayedexpansion

cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

%PYTHON_EXE% scripts\launch.py --remote %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] HopZero exited with error code %ERRORLEVEL%
    pause
)
