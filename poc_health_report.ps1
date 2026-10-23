#requires -Version 5.1
<#
Virgo Standard / Lite - poc_health_report.ps1
ASCII-safe edition for Windows PowerShell 5.1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$BaseDir    = 'C:\OpsCheck'
$ConfigPath = Join-Path $BaseDir 'config.dpapi'
$LogPath    = Join-Path $BaseDir 'poc_health_report.log'
$ScriptVersion = 'virgo-health-v5-deviceid-smart-1.5.0'
$ReleaseRevision = 20261023

function Get-NowText {
    return (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
}

function Mask-DeployUrlInText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $Text
    }

    return ($Text -replace 'https://script\.google\.com/macros/s/[^/\s"]+/exec', 'https://script.google.com/macros/s/***masked***/exec')
}

function Mask-SensitiveText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $Text
    }

    $masked = $Text
    $masked = $masked -replace '"secret"\s*:\s*"[^"]+"', '"secret":"***masked***"'
    $masked = $masked -replace '"signature"\s*:\s*"[^"]+"', '"signature":"***masked***"'
    $masked = $masked -replace '"payloadBase64"\s*:\s*"[^"]+"', '"payloadBase64":"***masked***"'
    $masked = Mask-DeployUrlInText -Text $masked
    return $masked
}

function Initialize-Log {
    try {
        $header = @(
            ''
            '============================================================'
            "$(Get-NowText) [INFO ] poc_health_report.ps1 start"
            "BaseDir: $BaseDir"
            "ScriptVersion: $ScriptVersion"
            "ReleaseRevision: $ReleaseRevision"
            '============================================================'
        )
        Add-Content -LiteralPath $LogPath -Value $header -Encoding UTF8
    } catch {}
}

function Write-LogLine {
    param(
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $safeMessage = Mask-SensitiveText -Text $Message
    $line = '{0} [{1}] {2}' -f (Get-NowText), $Level.ToUpper().PadRight(5), $safeMessage

    try {
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {}
}

function Write-Info { param([string]$Message) Write-LogLine -Level 'INFO' -Message $Message }


function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [string]$Default = ''
    )

    foreach ($name in $Names) {
        try {
            $prop = $Object.PSObject.Properties[$name]
            if ($null -ne $prop) {
                if ($null -ne $prop.Value) {
                    return [string]$prop.Value
                }
                return $Default
            }
        }
        catch {
        }
    }

    return $Default
}

function Write-Ok   { param([string]$Message) Write-LogLine -Level 'OK'   -Message $Message }
function Write-Warn { param([string]$Message) Write-LogLine -Level 'WARN' -Message $Message }
function Write-Err  { param([string]$Message) Write-LogLine -Level 'ERROR' -Message $Message }

function Get-DeviceUuid {
    try {
        $uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) {
            return $uuid.Trim()
        }
    } catch {
        Write-Warn ("Get-CimInstance UUID failed: {0}" -f $_.Exception.Message)
    }

    try {
        $uuid = (Get-WmiObject Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) {
            return $uuid.Trim()
        }
    } catch {
        Write-Warn ("Get-WmiObject UUID failed: {0}" -f $_.Exception.Message)
    }

    throw 'UUID acquisition failed.'
}

function Load-VirgoConfig {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw ("config.dpapi not found: {0}" -f $ConfigPath)
    }

    Add-Type -AssemblyName System.Security
    $encBytes = [System.IO.File]::ReadAllBytes($ConfigPath)
    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    $json = [System.Text.Encoding]::UTF8.GetString($plainBytes)
    Write-LogLine -Level 'DEBUG' -Message 'config loaded'

    $obj = $json | ConvertFrom-Json -ErrorAction Stop
    if (-not $obj.endpoint) { throw 'endpoint missing in config.dpapi' }
    if (-not $obj.secret)   { throw 'secret missing in config.dpapi' }

    return $obj
}

function Get-EffectiveDeviceIdentity {
    param([Parameter(Mandatory = $true)]$Config)

    $hardwareUuid = ''
    try {
        $hardwareUuid = Get-DeviceUuid
    }
    catch {
        if (($Config.PSObject.Properties.Name -contains 'hardwareUuid') -and
            -not [string]::IsNullOrWhiteSpace([string]$Config.hardwareUuid)) {
            $hardwareUuid = ([string]$Config.hardwareUuid).Trim()
            Write-Warn '現在のSMBIOS UUID取得に失敗したため、config.dpapi保存値を使用します。'
        }
        else {
            throw
        }
    }

    $deviceId = $hardwareUuid
    $mode = 'legacy-hardware-uuid'

    if (($Config.PSObject.Properties.Name -contains 'deviceId') -and
        -not [string]::IsNullOrWhiteSpace([string]$Config.deviceId)) {
        $deviceId = ([string]$Config.deviceId).Trim()
        $mode = if ($deviceId -eq $hardwareUuid) { 'hardware-uuid' } else { 'virgo-device-id' }
    }

    return [PSCustomObject]@{
        DeviceId     = $deviceId
        HardwareUuid = $hardwareUuid
        Mode         = $mode
    }
}

function Get-EffectiveEndpoint {
    param([Parameter(Mandatory = $true)]$Config)

    $envEndpoint = [Environment]::GetEnvironmentVariable('VIRGO_ENDPOINT', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($envEndpoint)) {
        Write-Info 'Using machine environment variable VIRGO_ENDPOINT.'
        return $envEndpoint.Trim()
    }

    Write-Warn 'Machine environment variable VIRGO_ENDPOINT is empty. Using config.dpapi endpoint.'
    return ([string]$Config.endpoint).Trim()
}

function Get-CustomerGroup {
    $group = [Environment]::GetEnvironmentVariable('VIRGO_CUSTOMER_GROUP', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($group)) {
        return $group.Trim()
    }

    throw 'Machine environment variable VIRGO_CUSTOMER_GROUP is not set.'
}

function Get-WindowsRelease {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.DisplayVersion) { return [string]$cv.DisplayVersion }
        if ($cv.ReleaseId)      { return [string]$cv.ReleaseId }
        return [string]$cv.CurrentBuild
    } catch {
        Write-Warn ("Windows version read failed: {0}" -f $_.Exception.Message)
        return ''
    }
}

function Convert-FromSecurityCenterProductState {
    param([int]$ProductState)
    if ($ProductState -eq 0) { return $false }
    return $true
}

function Get-AntivirusInfo {
    $result = [ordered]@{
        AntivirusVendor         = ''
        AntivirusProducts       = ''
        AntivirusDetected       = $false
        AntivirusLatestEvidence = ''
        AntivirusEvidenceStale  = $false
        ESETInstalled           = $false
        ESETLatestScan          = ''
        ESETScanStale           = $false
    }

    $displayNames = @()

    try {
        $products = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        if ($products) {
            foreach ($p in $products) {
                $name = [string]$p.displayName
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $displayNames += $name.Trim()
                }
                if ($name -match 'ESET') {
                    $result.ESETInstalled = $true
                }
                if (Convert-FromSecurityCenterProductState -ProductState ([int]$p.productState)) {
                    $result.AntivirusDetected = $true
                }
            }
        }
    } catch {
        Write-Warn ("SecurityCenter2 AntiVirusProduct read failed: {0}" -f $_.Exception.Message)
    }

    if ($displayNames.Count -gt 0) {
        $result.AntivirusProducts = ($displayNames -join ', ')
        $result.AntivirusVendor = $displayNames[0]
        $result.AntivirusLatestEvidence = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
        $result.AntivirusEvidenceStale = $false
    } else {
        try {
            $def = Get-MpComputerStatus -ErrorAction Stop
            $result.AntivirusProducts = 'Microsoft Defender'
            $result.AntivirusVendor = 'Microsoft Defender'
            $result.AntivirusDetected = [bool]$def.AntivirusEnabled
            if ($def.AntivirusSignatureLastUpdated) {
                $result.AntivirusLatestEvidence = ([datetime]$def.AntivirusSignatureLastUpdated).ToString('yyyy/MM/dd HH:mm:ss')
                $age = (New-TimeSpan -Start ([datetime]$def.AntivirusSignatureLastUpdated) -End (Get-Date)).TotalDays
                $result.AntivirusEvidenceStale = ($age -gt 14)
            }
        } catch {
            Write-Warn ("Defender status read failed: {0}" -f $_.Exception.Message)
        }
    }

    return [PSCustomObject]$result
}

function Get-VolumeInfo {
    $volumes = @()

    try {
        $items = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3" -ErrorAction Stop
        foreach ($v in $items) {
            $size = [double]($v.Size)
            $free = [double]($v.FreeSpace)
            $usedPct = if ($size -gt 0) { [math]::Round((($size - $free) / $size) * 100, 1) } else { 0 }
            $freeGb = if ($free -gt 0) { [math]::Round($free / 1GB, 1) } else { 0 }

            $volumes += [PSCustomObject]@{
                driveLetter = [string]$v.DeviceID
                volumeName  = [string]$v.VolumeName
                freeGb      = $freeGb
                usedPct     = $usedPct
                IsBackup    = $false
                IsTarget    = ([string]$v.DeviceID -eq 'C:')
                SmartHealth = 'OK'
            }
        }
    } catch {
        Write-Warn ("Volume info read failed: {0}" -f $_.Exception.Message)
    }

    return @($volumes)
}

function Parse-SmartctlDeviceBlock {
    param(
        [Parameter(Mandatory = $true)][string]$Text
    )

    $model = ''
    $status = '不明'
    $temp = '不明'
    $hours = '不明'

    $m = [regex]::Match($Text, '(?m)^Device Model:\s*(.+)$')
    if (-not $m.Success) { $m = [regex]::Match($Text, '(?m)^Model Number:\s*(.+)$') }
    if (-not $m.Success) { $m = [regex]::Match($Text, '(?m)^Model Family:\s*(.+)$') }
    if (-not $m.Success) { $m = [regex]::Match($Text, '(?m)^Product:\s*(.+)$') }
    if ($m.Success) { $model = $m.Groups[1].Value.Trim() }

    $m = [regex]::Match($Text, '(?m)^SMART overall-health self-assessment test result:\s*(.+)$')
    if ($m.Success) {
        $status = $m.Groups[1].Value.Trim()
    }
    else {
        $m = [regex]::Match($Text, '(?m)^SMART Health Status:\s*(.+)$')
        if ($m.Success) { $status = $m.Groups[1].Value.Trim() }
    }

    $m = [regex]::Match($Text, '(?m)^Temperature:\s*(\d+)')
    if ($m.Success) {
        $temp = $m.Groups[1].Value.Trim()
    }
    else {
        $m = [regex]::Match($Text, '(?m)^(194|190)\s+\S+.*?\s+(\d+)\s*$')
        if ($m.Success) { $temp = $m.Groups[2].Value.Trim() }
    }

    $m = [regex]::Match($Text, '(?m)^Power On Hours:\s*([0-9,]+)')
    if ($m.Success) {
        $hours = $m.Groups[1].Value.Replace(',', '').Trim()
    }
    else {
        $m = [regex]::Match($Text, '(?m)^9\s+\S+.*?\s+(\d+)\s*$')
        if (-not $m.Success) { $m = [regex]::Match($Text, '(?m)^Power_On_Hours.*?(\d+)\s*$') }
        if ($m.Success) { $hours = $m.Groups[$m.Groups.Count - 1].Value.Trim() }
    }

    return [PSCustomObject]@{
        model             = if ($model) { $model } else { 'Unknown' }
        mediaType         = 'Unknown'
        healthStatus      = if ($status) { $status } else { '不明' }
        operationalStatus = 'OK'
        temperature       = if ($temp) { $temp } else { '不明' }
        powerOnHours      = if ($hours) { $hours } else { '不明' }
    }
}

function Get-SmartctlDiskHealthInfo {
    $smartctl = Join-Path $BaseDir 'smartmontools\bin\smartctl.exe'
    $result = @()

    if (-not (Test-Path -LiteralPath $smartctl)) {
        Write-Warn ("smartctl not found: {0}" -f $smartctl)
        return @()
    }

    Write-Info ("smartctl found: {0}" -f $smartctl)

    try {
        $scan = & $smartctl --scan 2>$null
        if (-not $scan) {
            Write-Warn 'smartctl --scan returned no devices.'
            return @()
        }

        foreach ($line in $scan) {
            $scanLine = [string]$line
            if ([string]::IsNullOrWhiteSpace($scanLine)) { continue }

            $parts = @($scanLine -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if ($parts.Count -lt 1) { continue }

            $devicePath = [string]$parts[0]
            $args = @('-a', $devicePath)
            $dIndex = [Array]::IndexOf($parts, '-d')
            if ($dIndex -ge 0 -and ($dIndex + 1) -lt $parts.Count) {
                $args += @('-d', [string]$parts[$dIndex + 1])
            }

            try {
                $text = (& $smartctl @args 2>$null) -join [Environment]::NewLine
                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                $result += Parse-SmartctlDeviceBlock -Text $text
            }
            catch {
                Write-Warn ("smartctl parse failed for {0}: {1}" -f $devicePath, $_.Exception.Message)
            }
        }
    }
    catch {
        Write-Warn ("smartctl scan failed: {0}" -f $_.Exception.Message)
    }

    return @($result)
}

function Get-DiskHealthInfo {
    $physical = @()

    try {
        $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
        foreach ($d in $physicalDisks) {
            $health = [string]$d.HealthStatus
            $physical += [PSCustomObject]@{
                model             = [string]$d.FriendlyName
                mediaType         = [string]$d.MediaType
                healthStatus      = $health
                operationalStatus = ([string]($d.OperationalStatus -join ', '))
                temperature       = ''
                powerOnHours      = ''
            }
        }
    }
    catch {
        Write-Warn ("Get-PhysicalDisk failed: {0}" -f $_.Exception.Message)
    }

    $smart = @(Get-SmartctlDiskHealthInfo)
    if ($smart.Count -gt 0) {
        # 以前のSMART詳細取得を復旧。smartctlが取得できた場合はその詳細を優先する。
        return @($smart)
    }

    return @($physical)
}

function Get-RecentFileDate {
    param(
        [Parameter(Mandatory = $true)][string[]]$RootPaths,
        [Parameter(Mandatory = $true)][string[]]$Patterns
    )

    $latest = $null

    foreach ($root in $RootPaths) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        foreach ($pattern in $Patterns) {
            try {
                $files = Get-ChildItem -Path $root -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    if ($null -eq $latest -or $f.LastWriteTime -gt $latest) {
                        $latest = $f.LastWriteTime
                    }
                }
            } catch {}
        }
    }

    return $latest
}

function Test-IsBlacklistedDiskStatus {
    param(
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return $false
    }

    $s = $Status.Trim().ToLowerInvariant()

    $blacklist = @(
        'unhealthy',
        'error',
        'bad',
        'failing',
        'pred fail',
        'predfail',
        'degraded',
        'failed',
        'failure',
        'critical',
        'fault'
    )

    foreach ($word in $blacklist) {
        if ($s -like "*$word*") {
            return $true
        }
    }

    return $false
}

function Get-LatestBackupCandidate {
    param(
        [AllowNull()][AllowEmptyString()][string]$ReflectLatest,
        [Parameter(Mandatory = $true)][bool]$ReflectInstalled,
        [AllowNull()][AllowEmptyString()][string]$HasleoLatest,
        [Parameter(Mandatory = $true)][bool]$HasleoInstalled
    )

    $candidates = @()

    if ($ReflectInstalled -and -not [string]::IsNullOrWhiteSpace($ReflectLatest)) {
        try {
            $candidates += [PSCustomObject]@{
                Source = 'Reflect'
                Date   = [datetime]::Parse($ReflectLatest)
                Raw    = $ReflectLatest
            }
        }
        catch {
        }
    }

    if ($HasleoInstalled -and -not [string]::IsNullOrWhiteSpace($HasleoLatest)) {
        try {
            $candidates += [PSCustomObject]@{
                Source = 'Hasleo'
                Date   = [datetime]::Parse($HasleoLatest)
                Raw    = $HasleoLatest
            }
        }
        catch {
        }
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    return $candidates | Sort-Object Date -Descending | Select-Object -First 1
}

function Get-BackupInfo {
    param(
        [Parameter(Mandatory = $true)][array]$Volumes
    )

    $result = [ordered]@{
        MacriumInstalled   = $false
        MacriumLatestLog   = ''
        ReflectImageStale  = $false
        HasleoInstalled    = $false
        HasleoLatestImage  = ''
        HasleoImageStale   = $false
        BackupTargetDrives = @()

        BackupLatestSource = ''
        BackupLatestTime   = ''
        BackupOverallStale = $false
        BackupOverallOk    = $false
    }

    $rootCandidates = @()
    foreach ($v in $Volumes) {
        $drive = [string]$v.driveLetter
        if ($drive -match '^[A-Z]:$') {
            $rootCandidates += "$drive\"
        }
    }

    $result.MacriumInstalled =
        (Test-Path 'C:\Program Files\Macrium') -or
        (Test-Path 'C:\Program Files\Macrium\Reflect')

    $result.HasleoInstalled =
        (Test-Path 'C:\Program Files\Hasleo') -or
        (Test-Path 'C:\Program Files\Hasleo Backup Suite')

    $macriumRoots = @(
        'C:\ProgramData\Macrium',
        'C:\Reflect',
        'C:\Backup'
    ) + $rootCandidates

    $latestMacriumImage = Get-RecentFileDate -RootPaths $macriumRoots -Patterns @('*.mrimg', '*.mrbak')
    if ($latestMacriumImage) {
        $result.MacriumLatestLog = ([datetime]$latestMacriumImage).ToString('yyyy/MM/dd HH:mm:ss')
        $result.ReflectImageStale = ((New-TimeSpan -Start ([datetime]$latestMacriumImage) -End (Get-Date)).TotalDays -gt 14)
    }
    elseif ($result.MacriumInstalled) {
        $result.MacriumLatestLog = ''
        $result.ReflectImageStale = $true
    }

    if ($result.HasleoInstalled) {
        $hasleoRoots = @(
            'C:\Program Files\Hasleo',
            'C:\Program Files\Hasleo Backup Suite',
            'C:\ProgramData\Hasleo',
            'C:\Backup'
        ) + $rootCandidates

        $latestHasleo = Get-RecentFileDate -RootPaths $hasleoRoots -Patterns @('*.hbi', '*.adi', '*.pbd')
        if ($latestHasleo) {
            $result.HasleoLatestImage = ([datetime]$latestHasleo).ToString('yyyy/MM/dd HH:mm:ss')
            $result.HasleoImageStale = ((New-TimeSpan -Start ([datetime]$latestHasleo) -End (Get-Date)).TotalDays -gt 14)
        }
        else {
            $result.HasleoLatestImage = ''
            $result.HasleoImageStale = $true
        }
    }
    else {
        $result.HasleoLatestImage = ''
        $result.HasleoImageStale = $false
    }

    $latestCandidate = Get-LatestBackupCandidate `
        -ReflectLatest $result.MacriumLatestLog `
        -ReflectInstalled $result.MacriumInstalled `
        -HasleoLatest $result.HasleoLatestImage `
        -HasleoInstalled $result.HasleoInstalled

    if ($latestCandidate) {
        $result.BackupLatestSource = [string]$latestCandidate.Source
        $result.BackupLatestTime   = [string]$latestCandidate.Raw
        $result.BackupOverallStale = ((New-TimeSpan -Start ([datetime]$latestCandidate.Date) -End (Get-Date)).TotalDays -gt 14)
        $result.BackupOverallOk    = (-not $result.BackupOverallStale)
    }
    else {
        $result.BackupLatestSource = ''
        $result.BackupLatestTime   = ''
        $result.BackupOverallStale = $true
        $result.BackupOverallOk    = $false
    }

    $targetDrives = New-Object System.Collections.Generic.List[string]
    foreach ($v in $Volumes) {
        $drive = [string]$v.driveLetter
        if ([string]::IsNullOrWhiteSpace($drive)) { continue }

        if ($drive -eq 'C:') {
            $targetDrives.Add($drive)
            continue
        }

        $root = "$drive\"
        $isBackup = $false

        if ($result.MacriumInstalled) {
            $hasMr = Get-ChildItem -Path $root -Include '*.mrimg', '*.mrbak' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hasMr) { $isBackup = $true }
        }

        if (-not $isBackup -and $result.HasleoInstalled) {
            $hasHasleo = Get-ChildItem -Path $root -Include '*.hbi', '*.adi', '*.pbd' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hasHasleo) { $isBackup = $true }
        }

        if ($isBackup) {
            $targetDrives.Add($drive)
        }
    }

    $result.BackupTargetDrives = @($targetDrives | Select-Object -Unique)
    return [PSCustomObject]$result
}

function Apply-BackupFlagsToVolumes {
    param(
        [Parameter(Mandatory = $true)][array]$Volumes,
        [Parameter(Mandatory = $true)]$BackupInfo
    )

    $targets = @($BackupInfo.BackupTargetDrives | ForEach-Object { [string]$_ })

    foreach ($v in $Volumes) {
        $drive = [string]$v.driveLetter
        $isBackup = $targets -contains $drive
        $isTarget = ($drive -eq 'C:') -or $isBackup

        $v.IsBackup = $isBackup
        $v.IsTarget = $isTarget
    }

    return @($Volumes)
}

function Apply-SmartStatusToVolumes {
    param(
        [Parameter(Mandatory = $true)][array]$Volumes,
        [Parameter(Mandatory = $true)][array]$DiskHealth
    )

    $globalSmart = 'OK'

    foreach ($d in $DiskHealth) {
        $h = Get-OptionalPropertyValue -Object $d -Names @('healthStatus', 'HealthStatus') -Default ''
        $s = Get-OptionalPropertyValue -Object $d -Names @('Status', 'status', 'operationalStatus', 'OperationalStatus') -Default ''

        $statusToCheck = if (-not [string]::IsNullOrWhiteSpace($h)) { $h } else { $s }

        if (Test-IsBlacklistedDiskStatus -Status $statusToCheck) {
            $globalSmart = 'WARN'
            break
        }
    }

    foreach ($v in $Volumes) {
        $v.SmartHealth = $globalSmart
    }

    return @($Volumes)
}

function Get-HealthStatusAndAlerts {
    param(
        [Parameter(Mandatory = $true)]$Volumes,
        [Parameter(Mandatory = $true)]$DiskHealth,
        [Parameter(Mandatory = $true)]$Antivirus,
        [Parameter(Mandatory = $true)]$Backup
    )

    $alerts = New-Object System.Collections.Generic.List[string]
    $healthStatus = 'OK'

    foreach ($v in $Volumes) {
        if ($v.driveLetter -eq 'C:' -and [double]$v.freeGb -lt 20) {
            $alerts.Add("C drive free space low: $($v.freeGb)GB")
        }
    }

    foreach ($d in $DiskHealth) {
        $h = Get-OptionalPropertyValue -Object $d -Names @('healthStatus', 'HealthStatus') -Default ''
        $s = Get-OptionalPropertyValue -Object $d -Names @('Status', 'status', 'operationalStatus', 'OperationalStatus') -Default ''
        $statusToCheck = if (-not [string]::IsNullOrWhiteSpace($h)) { $h } else { $s }

        if (Test-IsBlacklistedDiskStatus -Status $statusToCheck) {
            $model = Get-OptionalPropertyValue -Object $d -Names @('model', 'Model', 'FriendlyName') -Default 'Unknown'
            $alerts.Add("Disk health warning: $model / $statusToCheck")
        }
    }

    if (-not [bool]$Antivirus.AntivirusDetected) {
        $alerts.Add('Antivirus not detected')
    }

    if (-not [bool]$Backup.BackupOverallOk) {
        if ([string]$Backup.BackupLatestSource -eq 'Hasleo') {
            $alerts.Add('Hasleo backup stale')
        }
        elseif ([string]$Backup.BackupLatestSource -eq 'Reflect') {
            $alerts.Add('Reflect backup stale')
        }
        else {
            $alerts.Add('Reflect backup stale')
        }
    }

    if ($alerts.Count -gt 0) {
        $healthStatus = 'WARN'
    }

    return [PSCustomObject]@{
        HealthStatus = $healthStatus
        Alerts       = @($alerts.ToArray())
    }
}

function ConvertTo-Base64Json {
    param([Parameter(Mandatory = $true)]$Object)

    $json = $Object | ConvertTo-Json -Compress -Depth 12
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    return [Convert]::ToBase64String($bytes)
}

function New-HmacSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Uuid,
        [Parameter(Mandatory = $true)][long]$Timestamp,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$PayloadBase64
    )

    $signData = '{0}|{1}|{2}|{3}' -f $Uuid, $Timestamp, $Nonce, $PayloadBase64
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
        $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signData))
        return [Convert]::ToBase64String($hash)
    }
    finally {
        $hmac.Dispose()
    }
}

function Invoke-SignedPost {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Uuid,
        [Parameter(Mandatory = $true)]$InnerPayload
    )

    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $nonce = [Guid]::NewGuid().ToString('N')
    $payloadBase64 = ConvertTo-Base64Json -Object $InnerPayload
    $signature = New-HmacSignature -Secret $Secret -Uuid $Uuid -Timestamp $timestamp -Nonce $nonce -PayloadBase64 $payloadBase64

    $outerBody = @{
        uuid          = $Uuid
        timestamp     = $timestamp
        nonce         = $nonce
        payloadBase64 = $payloadBase64
        signature     = $signature
    }

    $outerJson = $outerBody | ConvertTo-Json -Compress -Depth 10
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($outerJson)

    Write-LogLine -Level 'DEBUG' -Message ("POST Endpoint: {0}" -f $Endpoint)
    Write-LogLine -Level 'DEBUG' -Message ("POST Body: {0}" -f (Mask-SensitiveText -Text $outerJson))

    $response = Invoke-WebRequest -Uri $Endpoint -Method Post -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -UseBasicParsing -ErrorAction Stop
    $content = [string]$response.Content

    Write-LogLine -Level 'DEBUG' -Message ("Response Status: {0}" -f $response.StatusCode)
    Write-LogLine -Level 'DEBUG' -Message ("Response Body: {0}" -f (Mask-SensitiveText -Text $content))

    return [PSCustomObject]@{
        StatusCode = [int]$response.StatusCode
        Content    = $content
    }
}

Initialize-Log

try {
    Write-Info ("Checking config.dpapi: {0}" -f $ConfigPath)
    $config = Load-VirgoConfig
    $endpoint = Get-EffectiveEndpoint -Config $config
    $identity = Get-EffectiveDeviceIdentity -Config $config
    $deviceId = [string]$identity.DeviceId
    $hardwareUuid = [string]$identity.HardwareUuid
    $customerGroup = Get-CustomerGroup

    Write-Ok 'config.dpapi decrypted successfully.'
    Write-Info 'Endpoint resolved'
    Write-Info ("DeviceId: {0}" -f $deviceId)
    Write-Info ("HardwareUUID: {0}" -f $hardwareUuid)
    Write-Info ("IdentityMode: {0}" -f $identity.Mode)
    Write-Info ("CustomerGroup: {0}" -f $customerGroup)

    $antivirus = Get-AntivirusInfo
    $volumes = Get-VolumeInfo
    $backup = Get-BackupInfo -Volumes $volumes
    $volumes = Apply-BackupFlagsToVolumes -Volumes $volumes -BackupInfo $backup
    $diskHealth = Get-DiskHealthInfo
    $volumes = Apply-SmartStatusToVolumes -Volumes $volumes -DiskHealth $diskHealth
    $health = Get-HealthStatusAndAlerts -Volumes $volumes -DiskHealth $diskHealth -Antivirus $antivirus -Backup $backup

    $payload = [ordered]@{
        timestamp                = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
        customerGroup            = $customerGroup
        customerName             = $customerGroup
        customerEmail            = ''
        pcLocation               = ''
        pcUser                   = $env:USERNAME
        device                   = $env:COMPUTERNAME
        scriptVersion            = $ScriptVersion
        antivirusVendor          = [string]$antivirus.AntivirusVendor
        antivirusProducts        = [string]$antivirus.AntivirusProducts
        antivirusDetected        = [bool]$antivirus.AntivirusDetected
        antivirusLatestEvidence  = [string]$antivirus.AntivirusLatestEvidence
        antivirusEvidenceStale   = [bool]$antivirus.AntivirusEvidenceStale
        esetInstalled            = [bool]$antivirus.ESETInstalled
        macriumInstalled         = [bool]$backup.MacriumInstalled
        macriumLatestLog         = [string]$backup.MacriumLatestLog
        hasleoInstalled          = [bool]$backup.HasleoInstalled
        hasleoLatestImage        = [string]$backup.HasleoLatestImage
        hasleoImageStale         = [bool]$backup.HasleoImageStale
        volumes                  = @($volumes)
        diskHealth               = @($diskHealth)
        esetLatestScan           = [string]$antivirus.ESETLatestScan
        esetScanStale            = [bool]$antivirus.ESETScanStale
        windowsRelease           = (Get-WindowsRelease)
        reflectImageStale        = [bool]$backup.ReflectImageStale
        healthStatus             = [string]$health.HealthStatus
        alerts                   = @($health.Alerts)
        uuid                     = $deviceId
        hardwareUuid             = $hardwareUuid
        scriptHash               = 'LOCAL_TEST_UNSET_HASH'
    }

    Write-LogLine -Level 'DEBUG' -Message ("Inner Payload: " + (($payload | ConvertTo-Json -Compress -Depth 12)))

    $res = Invoke-SignedPost -Endpoint $endpoint -Secret ([string]$config.secret) -Uuid $deviceId -InnerPayload $payload

    if ($res.StatusCode -eq 200 -and $res.Content -match '^ok') {
        Write-Ok 'Health report sent successfully.'
    } else {
        Write-Warn ("Unexpected response: {0}" -f $res.Content)
    }
}
catch {
    Write-Err $_.Exception.Message
    Write-LogLine -Level 'ERROR' -Message ($_ | Out-String)
    exit 1
}
