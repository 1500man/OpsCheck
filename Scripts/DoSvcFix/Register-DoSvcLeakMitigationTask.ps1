param(
    [int]$ThresholdMB = 1024,
    [int]$StartDelayMinutes = 2,
    [int]$IntervalMinutes = 5
)

Set-StrictMode -Version Latest

$taskName = "DoSvcLeakMitigation_RestartIfHigh"
$script   = "C:\Scripts\DoSvcFix\DoSvcLeakMitigation.ps1"

# Build arguments for scheduled task action
$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Action RestartIfHigh -MemoryThresholdMB $ThresholdMB"

# Remove existing task if present
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Action
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg

# Trigger: start after delay, repeat every N minutes (duration omitted = repeat indefinitely)
$start = (Get-Date).AddMinutes($StartDelayMinutes)
$triggerRepeat  = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

# Trigger: run once at startup
$triggerStartup = New-ScheduledTaskTrigger -AtStartup

# Run as SYSTEM
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Settings
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
                                         -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# Register
$task = New-ScheduledTask -Action $action -Trigger @($triggerRepeat, $triggerStartup) -Principal $principal -Settings $settings
Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null

# Show summary + arguments
Get-ScheduledTask -TaskName $taskName | Format-List TaskName,State,Triggers,Actions,Principal,Settings
(Get-ScheduledTask -TaskName $taskName).Actions | Format-List Execute,Arguments
