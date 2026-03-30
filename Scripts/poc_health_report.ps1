#requires -Version 5.1
<#
Virgo Standard / Lite - poc_health_report.ps1

目的:
- PCの健康状態を収集
- C:\OpsCheck\config.dpapi を DPAPI(LocalMachine) で復号
- HMAC-SHA256 署名付きで GAS に送信
- ログは C:\OpsCheck\poc_health_report.log
- ログ内のデプロイURLは自動マスク

今回の修正:
- Hasleo 未導入なら Hasleo stale 判定を行わない
- volumes / diskHealth を管理画面・顧客画面の両方で使いやすい形式で送信
- smartctl が使える場合は温度 / 使用時間を補完
- PowerShell のハッシュ重複キーエラーを解消
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
            "$(Get-NowText) [INFO ] poc_health_report.ps1 実行開始"
            "BaseDir: $BaseDir"
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
    $line = "{0} [{1}] {2}" -f (Get-NowText), $Level.ToUpper().PadRight(5), $safeMessage

    try {
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {}
}

function Write-Info {
    param([string]$Message)
    Write-LogLine -Level 'INFO' -Message $Message
}

function Write-Warn {
    param([string]$Message)
    Write-LogLine -Level 'WARN' -Message $Message
}

function Write-Err {
    param([string]$Message)
    Write-LogLine -Level 'ERROR' -Message $Message
}

function Write-Ok {
    param([string]$Message)
    Write-LogLine -Level 'OK' -Message $Message
}

function Load-VirgoConfig {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "config.dpapi が見つかりません: $ConfigPath"
    }

    Add-Type -AssemblyName System.Security
    $encBytes = [System.IO.File]::ReadAllBytes($ConfigPath)

    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    $json = [System.Text.Encoding]::UTF8.GetString($plainBytes)
    Write-LogLine -Level 'DEBUG' -Message "config loaded"

    $obj = $json | ConvertFrom-Json -ErrorAction Stop
    if (-not $obj.endpoint) { throw 'config.dpapi に endpoint がありません。' }
    if (-not $obj.secret)   { throw 'config.dpapi に secret がありません。' }

    return $obj
}

function Get-EffectiveEndpoint {
    param([Parameter(Mandatory = $true)]$Config)

    $envEndpoint = [Environment]::GetEnvironmentVariable('VIRGO_ENDPOINT', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($envEndpoint)) {
        Write-Info 'Machine環境変数 VIRGO_ENDPOINT を使用します。'
        return $envEndpoint.Trim()
    }

    Write-Warn 'Machine環境変数 VIRGO_ENDPOINT が空のため、config.dpapi の endpoint を使用します。'
    return ([string]$Config.endpoint).Trim()
}

function Get-CustomerGroup {
    $group = [Environment]::GetEnvironmentVariable('VIRGO_CUSTOMER_GROUP', 'Machine')
    if ([string]::IsNullOrWhiteSpace($group)) {
        throw 'Machine環境変数 VIRGO_CUSTOMER_GROUP が未設定です。'
    }
    return $group.Trim()
}

function Get-DeviceUuid {
    try {
        $uuid = (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if ([string]::IsNullOrWhiteSpace($uuid)) {
            throw 'UUID が空です。'
        }
        return ([string]$uuid).Trim()
    }
    catch {
        throw "UUID の取得に失敗しました: $($_.Exception.Message)"
    }
}

function Get-WindowsRelease {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $displayVersion = [string]$cv.DisplayVersion
        $currentBuild   = [string]$cv.CurrentBuild
        $ubr            = [string]$cv.UBR

        if (-not [string]::IsNullOrWhiteSpace($displayVersion)) {
            return $displayVersion
        }

        if (-not [string]::IsNullOrWhiteSpace($currentBuild)) {
            if (-not [string]::IsNullOrWhiteSpace($ubr)) {
                return "$currentBuild.$ubr"
            }
            return $currentBuild
        }
    }
    catch {
        Write-Warn "Windows release read failed: $($_.Exception.Message)"
    }

    return ''
}

function Convert-FromSecurityCenterProductState {
    param([int]$ProductState)

    try {
        $enabledNibble = (($ProductState -shr 12) -band 0xF)
        return ($enabledNibble -in 1, 2, 3, 5, 6, 7)
    }
    catch {
        return $false
    }
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
    }
    catch {
        Write-Warn "SecurityCenter2 AntiVirusProduct read failed: $($_.Exception.Message)"
    }

    if ($displayNames.Count -gt 0) {
        $result.AntivirusProducts = ($displayNames -join ', ')
        $result.AntivirusVendor = $displayNames[0]
        $result.AntivirusLatestEvidence = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
        $result.AntivirusEvidenceStale = $false
    }
    else {
        try {
            $def = Get-MpComputerStatus -ErrorAction Stop
            $result.AntivirusProducts = 'Windows Defender'
            $result.AntivirusVendor = 'Windows Defender'
            $result.AntivirusDetected = [bool]$def.AntivirusEnabled

            if ($def.AntivirusSignatureLastUpdated) {
                $result.AntivirusLatestEvidence = ([datetime]$def.AntivirusSignatureLastUpdated).ToString('yyyy/MM/dd HH:mm:ss')
                $age = (New-TimeSpan -Start ([datetime]$def.AntivirusSignatureLastUpdated) -End (Get-Date)).TotalDays
                $result.AntivirusEvidenceStale = ($age -gt 14)
            }
        }
        catch {
            Write-Warn "Defender status read failed: $($_.Exception.Message)"
        }
    }

    return [PSCustomObject]$result
}

function Get-LogicalDisks {
    try {
        return @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3" -ErrorAction Stop)
    }
    catch {
        Write-Warn "Logical disk read failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-VolumeInfo {
    param(
        [Parameter(Mandatory = $true)][array]$LogicalDisks
    )

    $volumes = @()

    foreach ($v in $LogicalDisks) {
        try {
            if (-not $v.Size -or [double]$v.Size -le 0) { continue }

            $driveLetter = [string]$v.DeviceID
            $volumeName  = [string]$v.VolumeName
            $sizeBytes   = [double]$v.Size
            $freeBytes   = [double]$v.FreeSpace

            $sizeGb = [math]::Round(($sizeBytes / 1GB), 1)
            $freeGb = [math]::Round(($freeBytes / 1GB), 1)
            $usedGb = [math]::Round(($sizeGb - $freeGb), 1)
            $usedPct = if ($sizeGb -gt 0) {
                [math]::Round((($usedGb / $sizeGb) * 100), 1)
            }
            else {
                0
            }

            $volumes += [PSCustomObject]@{
                driveLetter = $driveLetter
                volumeName  = $volumeName
                usedPct     = $usedPct

                Drive       = $driveLetter.TrimEnd(':')
                SizeGB      = $sizeGb
                UsedGB      = $usedGb
                FreeGB      = $freeGb
                IsBackup    = $false
                IsTarget    = ($driveLetter -eq 'C:')
                SmartHealth = '正常'
            }
        }
        catch {
            Write-Warn "Volume item read failed: $($_.Exception.Message)"
        }
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
    if (-not $m.Success) { $m = [regex]::Match($Text, '(?m)^Model Family:\s*(.+)$') }
    if (-not $m.Success) { $m = [regex]::Match($Text, '(?m)^Product:\s*(.+)$') }
    if ($m.Success) { $model = $m.Groups[1].Value.Trim() }

    $m = [regex]::Match($Text, '(?m)^SMART overall-health self-assessment test result:\s*(.+)$')
    if ($m.Success) {
        $status = $m.Groups[1].Value.Trim()
    }
    else {
        $m = [regex]::Match($Text, '(?m)^SMART Health Status:\s*(.+)$')
        if ($m.Success) {
            $status = $m.Groups[1].Value.Trim()
        }
    }

    $m = [regex]::Match($Text, '(?m)^(194|190)\s+\S+.*?\s+(\d+)\s*$')
    if ($m.Success) {
        $temp = $m.Groups[2].Value.Trim()
    }
    else {
        $m = [regex]::Match($Text, '(?m)^Temperature:\s*(\d+)')
        if ($m.Success) {
            $temp = $m.Groups[1].Value.Trim()
        }
    }

    $m = [regex]::Match($Text, '(?m)^9\s+\S+.*?\s+(\d+)\s*$')
    if ($m.Success) {
        $hours = $m.Groups[1].Value.Trim()
    }
    else {
        $m = [regex]::Match($Text, '(?m)^Power_On_Hours.*?(\d+)\s*$')
        if ($m.Success) {
            $hours = $m.Groups[1].Value.Trim()
        }
    }

    return [PSCustomObject]@{
        Model        = if ($model) { $model } else { 'Unknown' }
        Status       = if ($status) { $status } else { '不明' }
        Temperature  = if ($temp) { $temp } else { '不明' }
        PowerOnHours = if ($hours) { $hours } else { '不明' }
    }
}

function Get-SmartctlDiskHealthInfo {
    $smartctl = Join-Path $BaseDir 'smartmontools\bin\smartctl.exe'
    $result = @()

    if (-not (Test-Path -LiteralPath $smartctl)) {
        Write-Warn "smartctl not found: $smartctl"
        return @()
    }

    Write-Info "smartctl found: $smartctl"

    try {
        $scan = & $smartctl --scan 2>$null
        if (-not $scan) {
            return @()
        }

        foreach ($line in $scan) {
            $scanLine = [string]$line
            if ([string]::IsNullOrWhiteSpace($scanLine)) { continue }

            $devicePath = ($scanLine -split '\s+')[0]
            if ([string]::IsNullOrWhiteSpace($devicePath)) { continue }

            try {
                $text = (& $smartctl -a $devicePath 2>$null) -join [Environment]::NewLine
                if ([string]::IsNullOrWhiteSpace($text)) { continue }

                $parsed = Parse-SmartctlDeviceBlock -Text $text
                $result += [PSCustomObject]@{
                    Model             = $parsed.Model
                    mediaType         = 'Unknown'
                    healthStatus      = $parsed.Status
                    operationalStatus = 'OK'
                    Status            = $parsed.Status
                    Temperature       = $parsed.Temperature
                    PowerOnHours      = $parsed.PowerOnHours
                }
            }
            catch {
                Write-Warn "smartctl parse failed for $devicePath : $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Warn "smartctl scan failed: $($_.Exception.Message)"
    }

    return @($result)
}

function Merge-DiskHealthInfo {
    param(
        [Parameter(Mandatory = $true)][array]$PhysicalDisks,
        [Parameter(Mandatory = $true)][array]$SmartctlDisks
    )

    $merged = @()

    if ($SmartctlDisks.Count -gt 0) {
        return @($SmartctlDisks)
    }

    foreach ($d in $PhysicalDisks) {
        $statusText = [string]$d.healthStatus
        if ([string]::IsNullOrWhiteSpace($statusText)) { $statusText = '不明' }

        $merged += [PSCustomObject]@{
            Model             = [string]$d.Model
            mediaType         = [string]$d.mediaType
            healthStatus      = $statusText
            operationalStatus = [string]$d.operationalStatus
            Status            = $statusText
            Temperature       = '不明'
            PowerOnHours      = '不明'
        }
    }

    return @($merged)
}

function Get-DiskHealthInfo {
    $physical = @()

    try {
        $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
        foreach ($d in $physicalDisks) {
            $health = [string]$d.HealthStatus
            $physical += [PSCustomObject]@{
                Model             = [string]$d.FriendlyName
                mediaType         = [string]$d.MediaType
                healthStatus      = $health
                operationalStatus = ([string]($d.OperationalStatus -join ', '))
                Status            = $health
                Temperature       = '不明'
                PowerOnHours      = '不明'
            }
        }
    }
    catch {
        Write-Warn "Get-PhysicalDisk failed: $($_.Exception.Message)"
    }

    $smart = Get-SmartctlDiskHealthInfo
    return @(Merge-DiskHealthInfo -PhysicalDisks $physical -SmartctlDisks $smart)
}

function Get-RecentFileDate {
    param(
        [Parameter(Mandatory = $true)][string[]]$RootPaths,
        [Parameter(Mandatory = $true)][string[]]$Patterns
    )

    $latest = $null

    foreach ($root in $RootPaths) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        if (-not (Test-Path -LiteralPath $root)) { continue }

        foreach ($pattern in $Patterns) {
            try {
                $files = Get-ChildItem -Path $root -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    if ($null -eq $latest -or $f.LastWriteTime -gt $latest) {
                        $latest = $f.LastWriteTime
                    }
                }
            }
            catch {}
        }
    }

    return $latest
}

function Get-BackupInfo {
    param(
        [Parameter(Mandatory = $true)][array]$LogicalDisks
    )

    $result = [ordered]@{
        MacriumInstalled   = $false
        MacriumLatestLog   = ''
        ReflectImageStale  = $false
        HasleoInstalled    = $false
        HasleoLatestImage  = ''
        HasleoImageStale   = $false
        BackupMonitorMode  = 'ReflectOnly'
        BackupTargetDrives = @()
    }

    $rootCandidates = @()
    foreach ($disk in $LogicalDisks) {
        $root = [string]$disk.DeviceID
        if ($root -match '^[A-Z]:$') {
            $rootCandidates += "$root\"
        }
    }

    $macriumInstalled =
        (Test-Path 'C:\Program Files\Macrium') -or
        (Test-Path 'C:\Program Files\Macrium\Reflect') -or
        (Get-Service -Name 'MacriumService' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName '*Macrium*' -ErrorAction SilentlyContinue)

    $hasleoInstalled =
        (Test-Path 'C:\Program Files\Hasleo') -or
        (Test-Path 'C:\Program Files\Hasleo Backup Suite') -or
        (Get-Service -Name 'Hasleo*' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName '*Hasleo*' -ErrorAction SilentlyContinue)

    $result.MacriumInstalled = [bool]$macriumInstalled
    $result.HasleoInstalled  = [bool]$hasleoInstalled

    $macriumRoots = @(
        'C:\ProgramData\Macrium',
        'C:\Reflect',
        'C:\Backup'
    ) + $rootCandidates

    $latestMacrium = Get-RecentFileDate -RootPaths $macriumRoots -Patterns @('*.mrimg', '*.mrbak', '*.html', '*.log')
    if ($latestMacrium) {
        $result.MacriumLatestLog = ([datetime]$latestMacrium).ToString('yyyy/MM/dd HH:mm:ss')
        $result.ReflectImageStale = ((New-TimeSpan -Start ([datetime]$latestMacrium) -End (Get-Date)).TotalDays -gt 14)
    }
    elseif ($result.MacriumInstalled) {
        $result.MacriumLatestLog = ''
        $result.ReflectImageStale = $false
    }

    if ($result.HasleoInstalled) {
        $result.BackupMonitorMode = if ($result.MacriumInstalled) { 'ReflectAndHasleo' } else { 'HasleoOnly' }

        $hasleoRoots = @(
            'C:\Program Files\Hasleo',
            'C:\Program Files\Hasleo Backup Suite',
            'C:\ProgramData\Hasleo',
            'C:\Backup'
        ) + $rootCandidates

        $latestHasleo = Get-RecentFileDate -RootPaths $hasleoRoots -Patterns @('*.hbi', '*.adi', '*.pbd', '*.log')
        if ($latestHasleo) {
            $result.HasleoLatestImage = ([datetime]$latestHasleo).ToString('yyyy/MM/dd HH:mm:ss')
            $result.HasleoImageStale = ((New-TimeSpan -Start ([datetime]$latestHasleo) -End (Get-Date)).TotalDays -gt 14)
        }
        else {
            $result.HasleoLatestImage = ''
            $result.HasleoImageStale = $false
        }
    }
    else {
        $result.HasleoLatestImage = ''
        $result.HasleoImageStale = $false
        $result.BackupMonitorMode = if ($result.MacriumInstalled) { 'ReflectOnly' } else { 'None' }
    }

    $targetDrives = New-Object System.Collections.Generic.List[string]

    foreach ($disk in $LogicalDisks) {
        try {
            $drive = [string]$disk.DeviceID
            if (-not $drive) { continue }

            if ($drive -eq 'C:') {
                $targetDrives.Add($drive)
                continue
            }

            $root = "$drive\"
            $isBackup = $false

            if ($result.MacriumInstalled) {
                $hasMrimg = Get-ChildItem -Path $root -Include '*.mrimg','*.mrbak' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($hasMrimg) { $isBackup = $true }
            }

            if (-not $isBackup -and $result.HasleoInstalled) {
                $hasHasleo = Get-ChildItem -Path $root -Include '*.hbi', '*.adi', '*.pbd' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($hasHasleo) { $isBackup = $true }
            }

            if ($isBackup) {
                $targetDrives.Add($drive)
            }
        }
        catch {}
    }

    $result.BackupTargetDrives = @($targetDrives | Select-Object -Unique)
    return [PSCustomObject]$result
}

function Apply-BackupFlagsToVolumes {
    param(
        [Parameter(Mandatory = $true)][array]$Volumes,
        [Parameter(Mandatory = $true)]$BackupInfo
    )

    $targets = @($BackupInfo.BackupTargetDrives | ForEach-Object {
        ([string]$_).TrimEnd(':').ToUpperInvariant()
    })

    foreach ($v in $Volumes) {
        $driveKey = [string]$v.Drive
        $isBackup = $targets -contains $driveKey.ToUpperInvariant()
        $isTarget = ($driveKey -eq 'C') -or $isBackup

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

    $globalSmart = '正常'
    $warnCount = @(
        $DiskHealth | Where-Object {
            $s = [string]$_.Status
            $h = [string]$_.healthStatus
            ($s -and $s -notin @('PASSED', 'OK', 'Healthy', '正常', '不明')) -or
            ($h -and $h -notin @('PASSED', 'OK', 'Healthy', '正常', '不明'))
        }
    ).Count

    if ($warnCount -gt 0) {
        $globalSmart = '要注意'
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
        if ($v.Drive -eq 'C' -and [double]$v.FreeGB -lt 20) {
            $alerts.Add("C drive free space low: $($v.FreeGB)GB")
        }
    }

    foreach ($d in $DiskHealth) {
        $h = [string]$d.healthStatus
        $s = [string]$d.Status
        $statusToCheck = if (-not [string]::IsNullOrWhiteSpace($h)) { $h } else { $s }

        if (
            (-not [string]::IsNullOrWhiteSpace($statusToCheck)) -and
            ($statusToCheck -notin @('Healthy', '正常', 'PASSED', 'OK', '不明'))
        ) {
            $model = if ($d.Model) { $d.Model } else { 'Unknown' }
            $alerts.Add("Disk health warning: $model / $statusToCheck")
        }
    }

    if (-not [bool]$Antivirus.AntivirusDetected) {
        $alerts.Add('Antivirus not detected')
    }

    if ([bool]$Backup.MacriumInstalled -and [bool]$Backup.ReflectImageStale) {
        $alerts.Add('Reflect backup stale')
    }

    if ([bool]$Backup.HasleoInstalled -and [bool]$Backup.HasleoImageStale) {
        $alerts.Add('Hasleo backup stale')
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

    $signData = "$Uuid|$Timestamp|$Nonce|$PayloadBase64"
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
    $nonce = ([Guid]::NewGuid().ToString('N'))
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

    Write-LogLine -Level 'DEBUG' -Message "POST Endpoint: $Endpoint"
    Write-LogLine -Level 'DEBUG' -Message "POST Body: $(Mask-SensitiveText -Text $outerJson)"

    $response = Invoke-WebRequest `
        -Uri $Endpoint `
        -Method Post `
        -ContentType 'application/json; charset=utf-8' `
        -Body $bodyBytes `
        -UseBasicParsing `
        -ErrorAction Stop

    $content = [string]$response.Content

    Write-LogLine -Level 'DEBUG' -Message "Response Status: $($response.StatusCode)"
    Write-LogLine -Level 'DEBUG' -Message "Response Body: $(Mask-SensitiveText -Text $content)"

    return [PSCustomObject]@{
        StatusCode = [int]$response.StatusCode
        Content    = $content
    }
}

Initialize-Log

try {
    Write-Info "config.dpapi を確認しています: $ConfigPath"
    $config = Load-VirgoConfig
    $endpoint = Get-EffectiveEndpoint -Config $config
    $uuid = Get-DeviceUuid
    $customerGroup = Get-CustomerGroup

    Write-Ok 'config.dpapi の復号に成功しました。'
    Write-Info 'Endpoint resolved'
    Write-Info "UUID: $uuid"
    Write-Info "CustomerGroup: $customerGroup"

    $logicalDisks = Get-LogicalDisks
    $antivirus = Get-AntivirusInfo
    $volumes = Get-VolumeInfo -LogicalDisks $logicalDisks
    $diskHealth = Get-DiskHealthInfo
    $backup = Get-BackupInfo -LogicalDisks $logicalDisks

    $volumes = Apply-BackupFlagsToVolumes -Volumes $volumes -BackupInfo $backup
    $volumes = Apply-SmartStatusToVolumes -Volumes $volumes -DiskHealth $diskHealth

    $health = Get-HealthStatusAndAlerts `
        -Volumes $volumes `
        -DiskHealth $diskHealth `
        -Antivirus $antivirus `
        -Backup $backup

    $payload = [ordered]@{
        timestamp                = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
        customerGroup            = $customerGroup
        customerName             = $customerGroup
        customerEmail            = ''
        pcLocation               = ''
        pcUser                   = $env:USERNAME
        device                   = $env:COMPUTERNAME
        scriptVersion            = 'virgo-health-v4-logmask-1.2'
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
        uuid                     = $uuid
        scriptHash               = 'LOCAL_TEST_UNSET_HASH'
    }

    Write-LogLine -Level 'DEBUG' -Message ("Inner Payload: " + (($payload | ConvertTo-Json -Compress -Depth 12)))

    $res = Invoke-SignedPost `
        -Endpoint $endpoint `
        -Secret ([string]$config.secret) `
        -Uuid $uuid `
        -InnerPayload $payload

    if ($res.StatusCode -eq 200 -and $res.Content -match '^ok') {
        Write-Ok '生データ送信は成功しました。'
    }
    else {
        Write-Warn "応答が想定外です: $($res.Content)"
    }
}
catch {
    Write-Err $_.Exception.Message
    Write-LogLine -Level 'ERROR' -Message ($_ | Out-String)
    exit 1
}
