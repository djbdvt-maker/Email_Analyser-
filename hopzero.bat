@echo off
REM ==============================================================================
REM HopZero One-Click Native Launcher (Windows)
REM ==============================================================================
setlocal enabledelayedexpansion

cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

%PYTHON_EXE% scripts\launch.py %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] HopZero exited with error code %ERRORLEVEL%
    pause
)
