#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$exePath = Join-Path $PSScriptRoot "..\killswitch.exe"

if (-not (Test-Path $exePath)) {
    Write-Error "killswitch.exe not found. Run 'go build' first."
    exit 1
}

Write-Host "Installing Advanced Kill Switch service..." -ForegroundColor Cyan
& $exePath install

if ($LASTEXITCODE -eq 0) {
    Write-Host "Starting service..." -ForegroundColor Cyan
    & $exePath start
    Write-Host "Done. Kill switch is active." -ForegroundColor Green
} else {
    Write-Error "Installation failed."
    exit 1
}
