# ==============================================================================
# HopZero One-Click Native Launcher (PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

python "$ScriptDir\scripts\launch.py" @args
