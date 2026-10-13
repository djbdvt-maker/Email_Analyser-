# ==============================================================================
# HopZero Remote Multi-Network Launcher (PowerShell)
# Enables secure public HTTPS tunnel for remote laptops on different networks.
# ==============================================================================
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
$PythonExe = "python"
if (Test-Path "$ScriptDir\.venv\Scripts\python.exe") {
    $PythonExe = "$ScriptDir\.venv\Scripts\python.exe"
}

& $PythonExe "$ScriptDir\scripts\launch.py" --remote @args
