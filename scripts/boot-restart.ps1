Start-Sleep -Seconds 5
Stop-Service -Name "AdvancedKillSwitch" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Service -Name "AdvancedKillSwitch"
