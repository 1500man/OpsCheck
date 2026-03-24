#requires -Version 5.1
<#
Virgo Standard V4 - poc_health_report.ps1
- S.M.A.R.T. / セキュリティ / バックアップ鮮度を収集
- config.dpapi を復号し endpoint / secret を取得
- JSON payload を Base64 化
- HMAC-SHA256 署名
- GAS へ HTTPS POST
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$TargetDir     = 'C:\OpsCheck'
$ConfigPath    = Join-Path $TargetDir 'config.dpapi'
$ScriptVersion = '4.9.1'

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Throw-HealthError([string]$Message) {
    throw $Message
}

function Start-Jitter {
    $seconds = Get-Random -Minimum 1 -Maximum 300
    Start-Sleep -Seconds $seconds
}

function Get-DeviceUuid {
    try {
        $uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) { return $uuid.Trim() }
    } catch {}

    try {
        $uuid = (Get-WmiObject Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) { return $uuid.Trim() }
    } catch {}

    Throw-HealthError 'UUID の取得に失敗しました。'
}

function Get-LoggedOnUser {
    try {
        $userName = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if (-not [string]::IsNullOrWhiteSpace($userName)) {
            if ($userName -match '\\') { return $userName.Split('\')[-1] }
            return $userName
        }
    } catch {}
    return $env:USERNAME
}

function Get-WindowsRelease {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.DisplayVersion) { return [string]$cv.DisplayVersion }
        if ($cv.ReleaseId)      { return [string]$cv.ReleaseId }
        return "$($cv.CurrentBuild).$($cv.UBR)"
    } catch {
        return '不明'
    }
}

function Read-ProtectedConfig {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        Throw-HealthError "config.dpapi が見つかりません: $ConfigPath"
    }

    Add-Type -AssemblyName System.Security

    try {
        $encryptedBytes = [System.IO.File]::ReadAllBytes($ConfigPath)
        $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedBytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $plainText = [System.Text.Encoding]::UTF8.GetString($plainBytes)
        if ([string]::IsNullOrWhiteSpace($plainText)) {
            Throw-HealthError 'config.dpapi の復号結果が空です。'
        }

        try {
            $config = $plainText | ConvertFrom-Json -ErrorAction Stop
            $endpoint = [string]$config.endpoint
            $secret   = [string]$config.secret
        }
        catch {
            $endpoint = [Environment]::GetEnvironmentVariable('VIRGO_ENDPOINT', 'Machine')
            $secret   = $plainText
        }

        if ([string]::IsNullOrWhiteSpace($endpoint)) {
            $endpoint = [Environment]::GetEnvironmentVariable('VIRGO_ENDPOINT', 'Machine')
        }
        if ([string]::IsNullOrWhiteSpace($endpoint)) { Throw-HealthError 'endpoint が取得できません。' }
        if ([string]::IsNullOrWhiteSpace($secret))   { Throw-HealthError 'secret が取得できません。' }

        [PSCustomObject]@{
            Endpoint = $endpoint
            Secret   = $secret
        }
    }
    catch {
        Throw-HealthError "config.dpapi の復号に失敗しました。$($_.Exception.Message)"
    }
}

function Get-SecurityDetails {
    $result = [ordered]@{
        Vendor        = '未検出'
        Products      = ''
        ProductDetected = $false
        RtpEnabled    = $false
        SigUpToDate   = $false
        LastScanTime  = '不明'
        RecentThreats = '不明'
        EsetInstalled = $false
        EsetScanStale = $false
    }

    try {
        $wmiAv = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop
    } catch {
        $wmiAv = @()
    }

    if ($null -eq $wmiAv) { $wmiAv = @() }
    $thirdParty = @($wmiAv | Where-Object { $_.displayName -and $_.displayName -notmatch 'Defender' })

    if ($thirdParty.Count -gt 0) {
        $displayNames = @($thirdParty | ForEach-Object { [string]$_.displayName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $result.Products = ($displayNames -join ' / ')
        $result.Vendor = $result.Products
        $result.ProductDetected = $true
        $result.RtpEnabled = $true
        $result.SigUpToDate = $true
        $result.RecentThreats = '特になし (サードパーティAV監視)'
        $result.LastScanTime = '自動監視中'

        $esetProduct = $thirdParty | Where-Object { $_.displayName -match 'ESET' } | Select-Object -First 1
        if ($null -ne $esetProduct) {
            $result.EsetInstalled = $true
            $result.Vendor = [string]$esetProduct.displayName
            try {
                $esetService = Get-Service -Name 'ekrn' -ErrorAction Stop
                if ($esetService.Status -eq 'Running') {
                    $result.RtpEnabled = $true
                    $result.SigUpToDate = $true
                    $result.RecentThreats = '特になし (ESETにて保護中)'
                    $result.LastScanTime = '自動監視中'
                    $result.EsetScanStale = $false
                } else {
                    $result.RtpEnabled = $false
                    $result.SigUpToDate = $false
                    $result.RecentThreats = 'ESETサービス停止の可能性'
                    $result.LastScanTime = '不明'
                    $result.EsetScanStale = $true
                }
            } catch {
                $result.RtpEnabled = $true
                $result.SigUpToDate = $true
                $result.RecentThreats = '特になし (ESET WMI検出)'
                $result.LastScanTime = '自動監視中'
                $result.EsetScanStale = $false
            }
        }

        return [PSCustomObject]$result
    }

    $defenderPresent = @($wmiAv | Where-Object { $_.displayName -match 'Defender' }).Count -gt 0
    if ($defenderPresent) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $result.Vendor = 'Microsoft Defender'
            $result.Products = 'Microsoft Defender'
            $result.ProductDetected = $true
            $result.RtpEnabled = [bool]$mp.RealTimeProtectionEnabled

            $sigDate = $mp.AntivirusSignatureLastUpdated
            if ($sigDate -and ((Get-Date) - $sigDate).TotalDays -lt 3) {
                $result.SigUpToDate = $true
            }

            $scanDate = $null
            if ($mp.QuickScanStartTime -and $mp.QuickScanStartTime.Year -gt 2000) {
                $scanDate = $mp.QuickScanStartTime
            }
            if ($mp.FullScanStartTime -and $mp.FullScanStartTime.Year -gt 2000) {
                if ($null -eq $scanDate -or $mp.FullScanStartTime -gt $scanDate) {
                    $scanDate = $mp.FullScanStartTime
                }
            }
            if ($scanDate) {
                $result.LastScanTime = $scanDate.ToString('yyyy/MM/dd HH:mm')
            }

            try {
                $threat = Get-MpThreatDetection -ErrorAction Stop |
                    Sort-Object InitialDetectionTime -Descending |
                    Select-Object -First 1
                if ($threat) {
                    $result.RecentThreats = "検知あり: $($threat.ThreatName)"
                } else {
                    $result.RecentThreats = '特になし'
                }
            } catch {
                $result.RecentThreats = '特になし'
            }
        }
        catch {
            $result.Vendor = 'Microsoft Defender'
            $result.Products = 'Microsoft Defender'
            $result.ProductDetected = $true
            $result.RtpEnabled = $false
            $result.SigUpToDate = $false
            $result.RecentThreats = 'Defender状態取得失敗'
        }
    }

    [PSCustomObject]$result
}

function Get-SmartCtlPath {
    $candidates = @(
        (Join-Path $TargetDir 'smartmontools\bin\smartctl.exe'),
        "${env:ProgramFiles}\smartmontools\bin\smartctl.exe",
        "${env:ProgramFiles(x86)}\smartmontools\bin\smartctl.exe"
    )

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) { return $path }
    }

    try {
        $cmd = Get-Command 'smartctl' -ErrorAction Stop
        return $cmd.Source
    } catch {
        return ''
    }
}

function Get-DiskHealth {
    $diskHealth = New-Object System.Collections.Generic.List[object]
    $alerts = New-Object System.Collections.Generic.List[string]
    $smartCtlPath = Get-SmartCtlPath

    try {
        $physicalDisks = @(Get-WmiObject Win32_DiskDrive -ErrorAction Stop)
    } catch {
        $physicalDisks = @()
    }

    if ($smartCtlPath) {
        foreach ($pd in $physicalDisks) {
            $diskInfo = [ordered]@{
                Model        = [string]$pd.Model
                Status       = '不明'
                Temperature  = '不明'
                PowerOnHours = '不明'
            }

            $pdNum = [string]$pd.DeviceID -replace '\D', ''
            $smartDevice = "/dev/pd$pdNum"

            try {
                $smartOutput = & $smartCtlPath -a $smartDevice 2>$null
            } catch {
                $smartOutput = $null
            }

            if ($smartOutput) {
                foreach ($line in $smartOutput) {
                    $trim = [string]$line
                    if ($trim -match 'SMART overall-health self-assessment test result:\s*(.*)') {
                        $diskInfo.Status = $matches[1].Trim()
                    } elseif ($trim -match 'SMART Health Status:\s*(.*)') {
                        $diskInfo.Status = $matches[1].Trim()
                    } elseif ($trim -match '^Temperature:\s+(\d+)\s+Celsius') {
                        $diskInfo.Temperature = $matches[1]
                    } elseif ($trim -match '^Power On Hours:\s+([\d,]+)') {
                        $diskInfo.PowerOnHours = $matches[1].Replace(',', '')
                    } else {
                        $parts = $trim -split '\s+'
                        if ($parts.Count -ge 10) {
                            if ($parts[0] -eq '194' -and $parts[1] -match 'Temperature') {
                                $diskInfo.Temperature = $parts[9]
                            } elseif ($parts[0] -eq '9' -and $parts[1] -match 'Power_On_Hours') {
                                $diskInfo.PowerOnHours = $parts[9]
                            }
                        }
                    }
                }
            }

            if ($diskInfo.Status -notin @('PASSED', 'OK', 'Healthy', '正常', '不明')) {
                $alerts.Add("[$($diskInfo.Model)] S.M.A.R.T.異常")
            }

            $diskHealth.Add([PSCustomObject]$diskInfo)
        }
    }
    else {
        try {
            $fallbackDisks = @(Get-PhysicalDisk -ErrorAction Stop)
            foreach ($d in $fallbackDisks) {
                $statusText = if ($d.HealthStatus) { [string]$d.HealthStatus } else { '不明' }
                if ($statusText -notin @('Healthy', '正常', 'OK', '不明')) {
                    $alerts.Add("[$($d.FriendlyName)] S.M.A.R.T.要確認")
                }

                $diskHealth.Add([PSCustomObject]@{
                    Model        = [string]$d.FriendlyName
                    Status       = $statusText
                    Temperature  = '不明'
                    PowerOnHours = '不明'
                })
            }
        }
        catch {
            $alerts.Add('smartmontools未検出')
        }
    }

    [PSCustomObject]@{
        Items  = @($diskHealth)
        Alerts = @($alerts)
    }
}

function Get-LogicalDisks {
    try {
        @(Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3" -ErrorAction Stop)
    } catch {
        @()
    }
}

function Get-LatestBackupFile {
    param(
        [Parameter(Mandatory = $true)][array]$LogicalDisks,
        [Parameter(Mandatory = $true)][string[]]$Patterns
    )

    $best = $null
    foreach ($disk in $LogicalDisks) {
        $root = [string]$disk.DeviceID
        if (-not $root) { continue }
        foreach ($pattern in $Patterns) {
            try {
                $found = Get-ChildItem -Path "$root\" -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1
                if ($found -and ($null -eq $best -or $found.LastWriteTime -gt $best.LastWriteTime)) {
                    $best = $found
                }
            } catch {}
        }
    }
    return $best
}

function Get-BackupFreshness {
    param([array]$LogicalDisks)

    $macriumFile = Get-LatestBackupFile -LogicalDisks $LogicalDisks -Patterns @('*.mrimg')
    $hasleoFile  = Get-LatestBackupFile -LogicalDisks $LogicalDisks -Patterns @('*.pbd')

    $macInstalled = $null -ne $macriumFile
    $macLast = if ($macInstalled) { $macriumFile.LastWriteTime.ToString('yyyy/MM/dd HH:mm') } else { '' }
    $macStale = if ($macInstalled) { ((Get-Date) - $macriumFile.LastWriteTime).TotalDays -gt 14 } else { $false }

    $hasInstalled = $null -ne $hasleoFile
    $hasLast = if ($hasInstalled) { $hasleoFile.LastWriteTime.ToString('yyyy/MM/dd HH:mm') } else { '' }
    $hasStale = if ($hasInstalled) { ((Get-Date) - $hasleoFile.LastWriteTime).TotalDays -gt 14 } else { $false }

    [PSCustomObject]@{
        MacriumInstalled  = $macInstalled
        MacriumLatestLog  = $macLast
        ReflectImageStale = $macStale
        HasleoInstalled   = $hasInstalled
        HasleoLatestImage = $hasLast
        HasleoImageStale  = $hasStale
    }
}

function Get-TargetVolumes {
    param(
        [array]$LogicalDisks,
        [array]$DiskHealthItems
    )

    $volumes = New-Object System.Collections.Generic.List[object]
    $globalSmart = if (@($DiskHealthItems | Where-Object { $_.Status -notin @('PASSED', 'OK', 'Healthy', '正常', '不明') }).Count -gt 0) { '要注意' } else { '正常' }

    foreach ($d in $LogicalDisks) {
        if (-not $d.Size -or [double]$d.Size -le 0) { continue }

        $driveLetter = [string]$d.DeviceID
        $sizeGb = [math]::Round(([double]$d.Size / 1GB), 1)
        $freeGb = [math]::Round(([double]$d.FreeSpace / 1GB), 1)
        $usedGb = [math]::Round(($sizeGb - $freeGb), 1)

        $isBackup = $false
        try {
            $hasMacrium = Get-ChildItem -Path "$driveLetter\" -Filter '*.mrimg' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            $hasHasleo  = Get-ChildItem -Path "$driveLetter\" -Filter '*.pbd'   -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            $isBackup = ($null -ne $hasMacrium) -or ($null -ne $hasHasleo)
        } catch {}

        $isTarget = ($driveLetter -eq 'C:') -or $isBackup
        if (-not $isTarget) { continue }

        $volumes.Add([PSCustomObject]@{
            Drive       = $driveLetter.Replace(':', '')
            SizeGB      = $sizeGb
            UsedGB      = $usedGb
            FreeGB      = $freeGb
            IsBackup    = $isBackup
            IsTarget    = $true
            SmartHealth = $globalSmart
        })
    }

    @($volumes)
}

function Compute-Signature {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Uuid,
        [Parameter(Mandatory = $true)][string]$UnixTimestamp,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$PayloadBase64
    )

    $signData = "$Uuid|$UnixTimestamp|$Nonce|$PayloadBase64"
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
        $hashBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signData))
        [Convert]::ToBase64String($hashBytes)
    }
    finally {
        $hmac.Dispose()
    }
}

try {
    Start-Jitter

    $customerGroup = [Environment]::GetEnvironmentVariable('VIRGO_CUSTOMER_GROUP', 'Machine')
    if ([string]::IsNullOrWhiteSpace($customerGroup)) {
        Throw-HealthError 'VIRGO_CUSTOMER_GROUP が未設定です。'
    }

    $config = Read-ProtectedConfig
    $endpoint = [string]$config.Endpoint
    $deviceSecret = [string]$config.Secret

    $uuid           = Get-DeviceUuid
    $hostName       = $env:COMPUTERNAME
    $pcUser         = Get-LoggedOnUser
    $timestampLocal = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')

    $alerts = New-Object System.Collections.Generic.List[string]
    $healthStatus = '正常'

    $security = Get-SecurityDetails
    if (-not $security.ProductDetected) {
        $alerts.Add('セキュリティ: AV製品が検出されません')
    }
    if ($security.ProductDetected -and -not $security.RtpEnabled) {
        $alerts.Add('セキュリティ: 保護機能が無効です')
    }
    if ($security.ProductDetected -and -not $security.SigUpToDate) {
        $alerts.Add('セキュリティ: 定義ファイルが古い可能性があります')
    }
    if ($security.RecentThreats -match '^検知あり') {
        $alerts.Add("セキュリティ: $($security.RecentThreats)")
    }

    $logicalDisks      = Get-LogicalDisks
    $diskHealthResult  = Get-DiskHealth
    foreach ($a in $diskHealthResult.Alerts) {
        $alerts.Add([string]$a)
    }

    $backupInfo = Get-BackupFreshness -LogicalDisks $logicalDisks
    if ($backupInfo.ReflectImageStale) {
        $alerts.Add('バックアップ: (R) 14日以上更新されていません')
    }
    if ($backupInfo.HasleoImageStale) {
        $alerts.Add('バックアップ: (H) 14日以上更新されていません')
    }

    $volumes = Get-TargetVolumes -LogicalDisks $logicalDisks -DiskHealthItems $diskHealthResult.Items
    foreach ($v in $volumes) {
        if ($v.SizeGB -gt 0 -and (($v.FreeGB / $v.SizeGB) -lt 0.1)) {
            $alerts.Add("[$($v.Drive):] 容量不足")
        }
    }

    if ($alerts.Count -gt 0) {
        $healthStatus = '警告'
    }

    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    $scriptHash = (Get-FileHash -Path $scriptPath -Algorithm SHA256).Hash

    $innerPayload = [ordered]@{
        customerGroup           = $customerGroup
        device                  = $hostName
        pcUser                  = $pcUser
        uuid                    = $uuid
        timestamp               = $timestampLocal
        scriptVersion           = $ScriptVersion
        scriptHash              = $scriptHash

        antivirusVendor         = $security.Vendor
        antivirusProducts       = $security.Products
        antivirusDetected       = [bool]$security.ProductDetected
        antivirusEvidenceStale  = [bool](-not $security.SigUpToDate)
        antivirusLatestEvidence = $security.RecentThreats

        esetInstalled           = [bool]$security.EsetInstalled
        esetLatestScan          = $security.LastScanTime
        esetScanStale           = [bool]$security.EsetScanStale

        macriumInstalled        = [bool]$backupInfo.MacriumInstalled
        macriumLatestLog        = $backupInfo.MacriumLatestLog
        reflectImageStale       = [bool]$backupInfo.ReflectImageStale

        hasleoInstalled         = [bool]$backupInfo.HasleoInstalled
        hasleoLatestImage       = $backupInfo.HasleoLatestImage
        hasleoImageStale        = [bool]$backupInfo.HasleoImageStale

        volumes                 = @($volumes)
        diskHealth              = @($diskHealthResult.Items)
        windowsRelease          = Get-WindowsRelease
        healthStatus            = $healthStatus
        alerts                  = @($alerts)
    }

    $innerJson     = $innerPayload | ConvertTo-Json -Compress -Depth 8
    $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($innerJson))

    $unixTimestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $nonce         = [Guid]::NewGuid().ToString()
    $signature     = Compute-Signature -Secret $deviceSecret -Uuid $uuid -UnixTimestamp $unixTimestamp -Nonce $nonce -PayloadBase64 $payloadBase64

    $outerPayload = [ordered]@{
        signature     = $signature
        uuid          = $uuid
        timestamp     = $unixTimestamp
        nonce         = $nonce
        payloadBase64 = $payloadBase64
    }

    $outerJson = $outerPayload | ConvertTo-Json -Compress -Depth 6
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($outerJson)

    Invoke-RestMethod -Uri $endpoint -Method Post -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -ErrorAction Stop | Out-Null
    exit 0
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}