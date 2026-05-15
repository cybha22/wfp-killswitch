#Requires -RunAsAdministrator

$taskName = "AdvancedKillSwitch-BootRestart"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Scheduled task '$taskName' removed." -ForegroundColor Green
} else {
    Write-Host "No scheduled task '$taskName' found." -ForegroundColor Yellow
}
