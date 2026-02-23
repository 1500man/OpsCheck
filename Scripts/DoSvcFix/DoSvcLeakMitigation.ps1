<#
DoSvcLeakMitigation.ps1
Mitigation for DoSvc (Delivery Optimization) memory growth.
#>

#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [ValidateSet("Status","DisablePeering","DisableDO","RestartIfHigh","RestoreDefault")]
    [string]$Action = "Status",

    [ValidateSet(0, 99)]
    [int]$DownloadMode = 0,

    [int]$MemoryThresholdMB = 1024,

    [switch]$ClearCache,
    [switch]$UsePolicyKey,

    [string]$StatePath = "$env:ProgramData\DoSvcFix\state.json",
    [string]$LogPath   = "$env:ProgramData\DoSvcFix\DoSvcFix.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ConfigKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
$PolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
$ValueName = "DODownloadMode"

function Ensure-Folder([string]$filePath) {
    $dir = Split-Path -Parent $filePath
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

function Write-Log([string]$message) {
    Ensure-Folder $LogPath
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $LogPath -Value "[$ts] $message"
}

function Get-RegDword([string]$path, [string]$name) {
    try {
        if (-not (Test-Path $path)) { return $null }
        $v = Get-ItemPropertyValue -Path $path -Name $name -ErrorAction Stop
        return [int]$v
    } catch { return $null }
}

function Set-RegDword([string]$path, [string]$name, [int]$value) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name $name -Type DWord -Value $value -Force
}

function Remove-RegValueSafe([string]$path, [string]$name) {
    try {
        if (Test-Path $path) { Remove-ItemProperty -Path $path -Name $name -ErrorAction Stop }
    } catch { }
}

function Get-DoSvcInfo {
    $svc = Get-CimInstance Win32_Service -Filter "Name='DoSvc'"
    $procId = [int]$svc.ProcessId
    $memMB = $null

    if ($procId -gt 0) {
        try {
            $p = Get-Process -Id $procId -ErrorAction Stop
            $memMB = [math]::Round(($p.WorkingSet64 / 1MB), 0)
        } catch { $memMB = $null }
    }

    [pscustomobject]@{
        ServiceName  = $svc.Name
        DisplayName  = $svc.DisplayName
        State        = $svc.State
        StartMode    = $svc.StartMode
        ProcessId    = $procId
        WorkingSetMB = $memMB
        ConfigMode   = Get-RegDword $ConfigKey $ValueName
        PolicyMode   = Get-RegDword $PolicyKey $ValueName
    }
}

function Save-StateOnce {
    if (Test-Path $StatePath) { return }
    Ensure-Folder $StatePath
    $info = Get-DoSvcInfo
    $state = [pscustomobject]@{
        SavedAt     = (Get-Date).ToString("o")
        ConfigMode  = $info.ConfigMode
        PolicyMode  = $info.PolicyMode
        StartMode   = $info.StartMode
    }
    $state | ConvertTo-Json -Depth 3 | Set-Content -Path $StatePath -Encoding UTF8
    Write-Log "State saved to $StatePath"
}

function Clear-DeliveryOptimizationArtifacts {
    try {
        $cmd = Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue
        if ($null -ne $cmd) {
            Write-Log "Deleting DO cache via cmdlet."
            Delete-DeliveryOptimizationCache -Force -IncludePinnedFiles | Out-Null
        } else {
            Write-Log "Delete-DeliveryOptimizationCache not found; skip."
        }
    } catch { Write-Log "Cache deletion failed: $($_.Exception.Message)" }

    try {
        $logGlob = Join-Path $env:WINDIR "ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs\*.etl"
        Remove-Item -Path $logGlob -Force -ErrorAction SilentlyContinue
        Write-Log "Deleted DO logs (*.etl) if present."
    } catch { Write-Log "Log cleanup failed: $($_.Exception.Message)" }
}

function Apply-DownloadMode([int]$mode) {
    if ($PSCmdlet.ShouldProcess($ConfigKey, "Set $ValueName=$mode")) {
        Set-RegDword $ConfigKey $ValueName $mode
        Write-Log "Set Config $ValueName=$mode"
    }
    if ($UsePolicyKey) {
        if ($PSCmdlet.ShouldProcess($PolicyKey, "Set $ValueName=$mode")) {
            Set-RegDword $PolicyKey $ValueName $mode
            Write-Log "Set Policy $ValueName=$mode"
        }
    }
}

function Restart-DoSvcSafe {
    try {
        $svc = Get-Service -Name DoSvc -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            Restart-Service -Name DoSvc -Force -ErrorAction Stop
            Write-Log "Restarted DoSvc."
        } else {
            Start-Service -Name DoSvc -ErrorAction SilentlyContinue
            Write-Log "Started DoSvc (was not running)."
        }
    } catch { Write-Log "Restart/Start DoSvc failed: $($_.Exception.Message)" }
}

function Stop-DoSvcSafe {
    try {
        Stop-Service -Name DoSvc -Force -ErrorAction Stop
        Write-Log "Stopped DoSvc."
    } catch { Write-Log "Stop DoSvc failed: $($_.Exception.Message)" }
}

function Set-StartupMode([ValidateSet("Automatic","Manual","Disabled")]$mode) {
    if ($PSCmdlet.ShouldProcess("DoSvc", "Set startup to $mode")) {
        Set-Service -Name DoSvc -StartupType $mode
        Write-Log "Set DoSvc StartupType=$mode"
    }
}

function Restore-DefaultFromState {
    if (-not (Test-Path $StatePath)) {
        Write-Log "No state file. Removing our registry values and setting startup to Manual."
        Remove-RegValueSafe $ConfigKey $ValueName
        if ($UsePolicyKey) { Remove-RegValueSafe $PolicyKey $ValueName }
        Set-StartupMode Manual
        Start-Service -Name DoSvc -ErrorAction SilentlyContinue
        return
    }

    $state = Get-Content -Path $StatePath -Encoding UTF8 | ConvertFrom-Json
    Write-Log "Restoring from state saved at $($state.SavedAt)"

    if ($null -eq $state.ConfigMode) { Remove-RegValueSafe $ConfigKey $ValueName }
    else { Set-RegDword $ConfigKey $ValueName ([int]$state.ConfigMode) }

    if ($null -eq $state.PolicyMode) { Remove-RegValueSafe $PolicyKey $ValueName }
    else { Set-RegDword $PolicyKey $ValueName ([int]$state.PolicyMode) }

    $sm = [string]$state.StartMode
    switch ($sm) {
        "Auto"     { Set-StartupMode Automatic }
        "Manual"   { Set-StartupMode Manual }
        "Disabled" { Set-StartupMode Disabled }
        default    { Set-StartupMode Manual }
    }

    Start-Service -Name DoSvc -ErrorAction SilentlyContinue
    Write-Log "Restore complete."
}

# ---- Main ----
$before = Get-DoSvcInfo
Write-Log "Action=$Action, Before: State=$($before.State), StartMode=$($before.StartMode), WS(MB)=$($before.WorkingSetMB), ConfigMode=$($before.ConfigMode), PolicyMode=$($before.PolicyMode)"

switch ($Action) {
    "Status" {
        (Get-DoSvcInfo) | Format-List
        break
    }

    "DisablePeering" {
        Save-StateOnce
        Apply-DownloadMode $DownloadMode
        if ($ClearCache) {
            Stop-DoSvcSafe
            Clear-DeliveryOptimizationArtifacts
        }
        Restart-DoSvcSafe
        (Get-DoSvcInfo) | Format-List
        break
    }

    "DisableDO" {
        Save-StateOnce
        Apply-DownloadMode $DownloadMode
        if ($ClearCache) {
            Stop-DoSvcSafe
            Clear-DeliveryOptimizationArtifacts
        } else {
            Stop-DoSvcSafe
        }
        Set-StartupMode Disabled
        (Get-DoSvcInfo) | Format-List
        break
    }

    "RestartIfHigh" {
        $info = Get-DoSvcInfo
        if ($null -ne $info.WorkingSetMB -and $info.WorkingSetMB -ge $MemoryThresholdMB) {
            Write-Log "WorkingSetMB($($info.WorkingSetMB)) >= threshold($MemoryThresholdMB). Restarting DoSvc."
            Restart-DoSvcSafe
        } else {
            Write-Log "WorkingSetMB is below threshold or unknown. No action."
        }
        (Get-DoSvcInfo) | Format-List
        break
    }

    "RestoreDefault" {
        Restore-DefaultFromState
        (Get-DoSvcInfo) | Format-List
        break
    }
}

$after = Get-DoSvcInfo
Write-Log "After: State=$($after.State), StartMode=$($after.StartMode), WS(MB)=$($after.WorkingSetMB), ConfigMode=$($after.ConfigMode), PolicyMode=$($after.PolicyMode)"
