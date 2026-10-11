# Two-Phase Offline Acceptance Test runner for HopZero (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python "$ScriptDir\offline_acceptance_test.py"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Offline acceptance test failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
exit 0
