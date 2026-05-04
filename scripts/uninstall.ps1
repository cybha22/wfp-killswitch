#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$exePath = Join-Path $PSScriptRoot "..\killswitch.exe"

if (-not (Test-Path $exePath)) {
    Write-Warning "killswitch.exe not found. Attempting manual cleanup..."

    $svcName = "AdvancedKillSwitch"
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        sc.exe delete $svcName
    }

    Write-Host "Manual cleanup complete. WFP filters may still be active until reboot." -ForegroundColor Yellow
    exit 0
}

Write-Host "Uninstalling Advanced Kill Switch..." -ForegroundColor Cyan
& $exePath uninstall

if ($LASTEXITCODE -eq 0) {
    Write-Host "Done. All WFP filters removed. Internet restored." -ForegroundColor Green
} else {
    Write-Error "Uninstall failed. Try rebooting to clear dynamic WFP filters."
    exit 1
}
