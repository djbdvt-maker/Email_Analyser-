$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$env:PYTHONPATH = "$repoRoot\01_REGISTRY;$repoRoot\02_FORENSICS;$repoRoot\03_BACKEND;$scriptDir;$env:PYTHONPATH"
python "$scriptDir\check_golden.py" $args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
