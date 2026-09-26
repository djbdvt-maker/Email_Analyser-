$source = "C:\Users\HELLO\Desktop\sih"
$destination = "C:\Users\HELLO\Desktop\HopZero_Final_Submission.zip"
if (Test-Path $destination) { Remove-Item $destination }
Add-Type -AssemblyName System.IO.Compression.FileSystem

$tempDir = Join-Path $env:TEMP "HopZero_Temp_Package"
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Path $tempDir | Out-Null

Copy-Item -Path "$source\*" -Destination $tempDir -Recurse -Exclude ".venv", "node_modules", "__pycache__", ".pytest_cache", "dist", "*.egg-info", "storage", ".git"
Remove-Item -Path "$tempDir\03_BACKEND\.venv" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$tempDir\04_FRONTEND\node_modules" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$tempDir\03_BACKEND\storage" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $tempDir -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -Path $tempDir -Recurse -Filter ".pytest_cache" | Remove-Item -Recurse -Force

[System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $destination)
Remove-Item -Recurse -Force $tempDir
Write-Host "Zipped to $destination"
