#Requires -RunAsAdministrator

$scriptPath = Join-Path $PSScriptRoot "boot-restart.ps1"
$taskName = "AdvancedKillSwitch-BootRestart"

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Restart Advanced Kill Switch service after boot (start -> stop -> sleep 2 minutes -> start)" `
    -Force | Out-Null

Write-Host "Scheduled task '$taskName' installed." -ForegroundColor Green
Write-Host "On next boot: service starts, stops, waits 2 minutes, starts again." -ForegroundColor Cyan
