# ==============================================================================
# HopZero One-Click Native Launcher (PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
$PythonExe = "python"
if (Test-Path "$ScriptDir\.venv\Scripts\python.exe") {
    $PythonExe = "$ScriptDir\.venv\Scripts\python.exe"
}

& $PythonExe "$ScriptDir\scripts\launch.py" @args
