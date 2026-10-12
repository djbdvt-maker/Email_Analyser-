# scripts/package.ps1
# Cross-platform PowerShell launcher for HopZero release packager
param(
    [string]$Version,
    [string]$KeyFile,
    [switch]$SkipFrontendBuild,
    [switch]$Unsigned
)

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$PythonBin = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonBin)) {
    $PythonBin = "python"
}

$Arguments = @((Join-Path $PSScriptRoot "package_release.py"))
if ($Version) { $Arguments += @("--version", $Version) }
if ($KeyFile) { $Arguments += @("--key-file", $KeyFile) }
if ($SkipFrontendBuild) { $Arguments += "--skip-frontend-build" }
if ($Unsigned) { $Arguments += "--unsigned" }

& $PythonBin @Arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
