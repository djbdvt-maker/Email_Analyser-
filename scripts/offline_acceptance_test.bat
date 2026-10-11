@echo off
REM Two-Phase Offline Acceptance Test runner for HopZero (Windows CMD)
python "%~dp0offline_acceptance_test.py"
if %errorlevel% neq 0 (
    echo [ERROR] Offline acceptance test failed!
    exit /b %errorlevel%
)
exit /b 0
