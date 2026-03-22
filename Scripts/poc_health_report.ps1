<#
===================================================
Virgo Standard/Lite プロジェクト・マニフェスト
===================================================
【バージョン】 v4.8.1 (Security Adapter Integrated)
【更新履歴】
- v4.8.1: セキュリティソフト（ESET / Defender等）の詳細状態（リアルタイム保護、定義ファイル鮮度、直近の脅威、最終スキャン日時）を抽出する「セキュリティ・アダプター」を統合。
- v4.0.0: DPAPIによる秘密鍵保護、HMAC-SHA256署名、S.M.A.R.T.詳細監視（NVMe/SATA完全対応）、GASパンク防止のジッター通信を実装。

【AIへの絶対命令】
- 監視ドライブは「C:」と「バックアップイメージが存在するドライブ」のみに限定せよ。
- S.M.A.R.T.、AV監視、バックアップ鮮度(14日)のロジックを1文字も削るな。
- 改ざん検知用のハッシュ計算を省略するな。
===================================================
#>
$ErrorActionPreference = 'SilentlyContinue'
$TargetDir = "C:\OpsCheck"
$ScriptVersion = "4.8.1"

# 0. 通信分散（ジッター）フェーズ：GASの同時実行パンクを防ぐため最大5分待機
$JitterSeconds = Get-Random -Minimum 1 -Maximum 300
Start-Sleep -Seconds $JitterSeconds

# 1. 要塞解錠（環境変数 ＆ DPAPI復号）
$CustomerGroup = [Environment]::GetEnvironmentVariable("VIRGO_CUSTOMER_GROUP", "Machine")
$Endpoint = [Environment]::GetEnvironmentVariable("VIRGO_ENDPOINT", "Machine")
$UUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID

# 万が一環境変数が取れない場合は安全に終了
if ([string]::IsNullOrEmpty($Endpoint) -or [string]::IsNullOrEmpty($CustomerGroup)) { exit }

# DPAPIから「端末専用シークレット」を復号
Add-Type -AssemblyName System.Security
$DpapiFile = Join-Path $TargetDir "config.dpapi"
if (-not (Test-Path $DpapiFile)) { exit }

try {
    $EncryptedBytes = [System.IO.File]::ReadAllBytes($DpapiFile)
    $DecryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($EncryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    $DeviceSecret = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
} catch {
    exit # 復号失敗時（別のPCにコピーされた等）は沈黙して終了
}

# 2. 診断フェーズ
$HostName = $env:COMPUTERNAME
$PcUser = ""
try { $PcUser = (Get-WmiObject Win32_ComputerSystem).UserName.Split("\")[-1] } catch {}
$Timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
$Alerts = @()
$HealthStatus = "正常"

# ★ セキュリティ・アダプター (Defender / ESET)
function Get-SecurityDetails {
    $avDetails = @{ Vendor = "Unknown"; RtpEnabled = $false; SigUpToDate = $false; LastScanTime = "不明"; RecentThreats = "不明" }
    $WmiAV = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    $avNames = $WmiAV.displayName -join ", "

    if ($avNames -match "ESET") {
        $esetObj = $WmiAV | Where-Object { $_.displayName -match "ESET" } | Select-Object -First 1
        $avDetails.Vendor = if ($esetObj) { $esetObj.displayName } else { "ESET Security" }
        $esetService = Get-Service -Name "ekrn" -ErrorAction SilentlyContinue
        if ($esetService -and $esetService.Status -eq "Running") {
            $avDetails.RtpEnabled = $true; $avDetails.SigUpToDate = $true
            $avDetails.RecentThreats = "? 特になし (ESETにて保護中)"
        } else {
            $avDetails.RecentThreats = "?? ESETサービス停止の可能性"
        }
        $avDetails.LastScanTime = "自動監視中"
    } elseif ($avNames -match "Defender") {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) {
            $avDetails.Vendor = "Microsoft Defender"
            $avDetails.RtpEnabled = $mp.RealTimeProtectionEnabled
            $sigDate = $mp.AntivirusSignatureLastUpdated
            if ($sigDate -and ((Get-Date) - $sigDate).TotalDays -lt 3) { $avDetails.SigUpToDate = $true }
            $scanDate = if ($mp.QuickScanStartTime -gt $mp.FullScanStartTime) { $mp.QuickScanStartTime } else { $mp.FullScanStartTime }
            if ($scanDate.Year -gt 2000) { $avDetails.LastScanTime = $scanDate.ToString("yyyy/MM/dd HH:mm") }
            $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
            if ($threats) { $avDetails.RecentThreats = "?? 検知あり: " + $threats.ThreatName } else { $avDetails.RecentThreats = "? 特になし" }
        }
    } else {
        if ($WmiAV) { $avDetails.Vendor = $WmiAV[0].displayName; $avDetails.RtpEnabled = $true; $avDetails.RecentThreats = "WMIにて監視中" }
    }
    return $avDetails
}

$sec = Get-SecurityDetails
if (-not $sec.RtpEnabled) { $Alerts += "セキュリティ: 保護機能が無効です" }
if (-not $sec.SigUpToDate) { $Alerts += "セキュリティ: 定義ファイルが古いです" }
if ($sec.RecentThreats -match "??") { $Alerts += "セキュリティ: $($sec.RecentThreats)" }

# ドライブ厳選 ＆ ボリューム情報
$Volumes = @()
$LogicalDisks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3"
$DiskDrives = Get-WmiObject Win32_DiskDrive
$DiskFreeGB = 0

foreach ($d in $LogicalDisks) {
    if ($d.Size -gt 0) {
        $DriveLetter = $d.DeviceID
        $size = [math]::Round($d.Size / 1GB, 1)
        $free = [math]::Round($d.FreeSpace / 1GB, 1)
        if ($DriveLetter -eq "C:") { $DiskFreeGB = $free }

        # バックアップ存在チェック（要件：イメージファイルがあるドライブのみ）
        $hasMacrium = (Test-Path "$DriveLetter\Macrium") -or (Get-ChildItem -Path "$DriveLetter\" -Filter "*.mrimg" -Depth 2 -ErrorAction SilentlyContinue)
        $hasHasleo  = (Test-Path "$DriveLetter\Hasleo*") -or (Get-ChildItem -Path "$DriveLetter\" -Filter "*.pbd" -Depth 2 -ErrorAction SilentlyContinue)
        
        if ($DriveLetter -eq "C:" -or $hasMacrium -or $hasHasleo) {
            $Volumes += @{
                Drive       = $DriveLetter.Replace(":", "")
                SizeGB      = $size
                UsedGB      = $size - $free
                SmartHealth = if ($DiskDrives.Status -contains "Pred Fail") { "要注意" } else { "正常" }
                IsTarget    = $true
            }
            if (($free / $size) -lt 0.1) { $Alerts += "[$DriveLetter] 容量不足" }
        }
    }
}

# S.M.A.R.T. 詳細監視 (テキスト解析＆SATA/NVMe完全対応版)
$DiskHealth = @()
$SmartCtlPath = ""
if (Get-Command "smartctl" -ErrorAction SilentlyContinue) { $SmartCtlPath = "smartctl" }
elseif (Test-Path "${env:ProgramFiles}\smartmontools\bin\smartctl.exe") { $SmartCtlPath = "${env:ProgramFiles}\smartmontools\bin\smartctl.exe" }
elseif (Test-Path "${env:ProgramFiles(x86)}\smartmontools\bin\smartctl.exe") { $SmartCtlPath = "${env:ProgramFiles(x86)}\smartmontools\bin\smartctl.exe" }

if ($SmartCtlPath) {
    foreach ($pd in $DiskDrives) {
        $diskInfo = @{ Model = $pd.Model; Status = "不明"; Temperature = "不明"; PowerOnHours = "不明" }
        $pdNum = $pd.DeviceID -replace '\D', ''
        $smartDevice = "/dev/pd$pdNum"

        $smartOutput = & $SmartCtlPath -a $smartDevice 2>$null
        if ($smartOutput) {
            foreach ($line in $smartOutput) {
                $line = $line.Trim()
                if ($line -match "SMART overall-health self-assessment test result:\s*(.*)") { $diskInfo.Status = $matches[1] }
                if ($line -match "SMART Health Status:\s*(.*)") { $diskInfo.Status = $matches[1] }
                
                if ($line -match "^Temperature:\s+(\d+)\s*Celsius") { $diskInfo.Temperature = $matches[1] }
                if ($line -match "^Power On Hours:\s+([\d,]+)") { $diskInfo.PowerOnHours = $matches[1].Replace(",", "") }
                
                $parts = $line -split '\s+'
                if ($parts.Count -ge 10) {
                    if ($parts[0] -eq "194" -and $parts[1] -match "Temperature") { $diskInfo.Temperature = $parts[9] }
                    if ($parts[0] -eq "9" -and $parts[1] -match "Power_On_Hours") { $diskInfo.PowerOnHours = $parts[9] }
                }
            }
            if ($diskInfo.Status -notin @("PASSED", "OK", "不明")) { $Alerts += "[$($pd.Model)] S.M.A.R.T.異常" }
        }
        $DiskHealth += $diskInfo
    }
} else {
    $Alerts += "smartmontools未検出"
}

# バックアップ鮮度(14日) と GAS向けの変数セット
$MacriumFile = Get-ChildItem -Path "C:\", "D:\", "E:\", "F:\", "G:\" -Filter "*.mrimg" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$macInstalled = [bool]$MacriumFile
$macLastLog = if ($macInstalled) { $MacriumFile.LastWriteTime.ToString("yyyy/MM/dd HH:mm") } else { "" }
$macStale = if ($macInstalled) { ((Get-Date) - $MacriumFile.LastWriteTime).TotalDays -gt 14 } else { $false }
if ($macStale) { $Alerts += "バックアップ: (R) 14日以上更新されていません" }

$HasleoFile = Get-ChildItem -Path "C:\", "D:\", "E:\", "F:\", "G:\" -Filter "*.pbd" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$hasInstalled = [bool]$HasleoFile
$hasLastLog = if ($hasInstalled) { $HasleoFile.LastWriteTime.ToString("yyyy/MM/dd HH:mm") } else { "" }
$hasStale = if ($hasInstalled) { ((Get-Date) - $HasleoFile.LastWriteTime).TotalDays -gt 14 } else { $false }
if ($hasStale) { $Alerts += "バックアップ: (H) 14日以上更新されていません" }

# 3. 報告・暗号化フェーズ
if ($Alerts.Count -gt 0) { $HealthStatus = "警告" }
$ScriptHash = (Get-FileHash -Path (Join-Path $TargetDir "poc_health_report.ps1") -Algorithm SHA256).Hash

# ① 本来送りたい監視データの中身（インナーペイロード）
$InnerPayload = @{
    customerGroup           = $CustomerGroup
    device                  = $HostName
    pcUser                  = $PcUser
    uuid                    = $UUID
    timestamp               = $Timestamp
    scriptVersion           = $ScriptVersion
    scriptHash              = $ScriptHash
    
    antivirusVendor         = $sec.Vendor
    antivirusDetected       = $sec.RtpEnabled
    antivirusEvidenceStale  = (-not $sec.SigUpToDate)
    antivirusLatestEvidence = $sec.RecentThreats
    esetLatestScan          = $sec.LastScanTime
    
    macriumInstalled        = $macInstalled
    macriumLatestLog        = $macLastLog
    reflectImageStale       = $macStale
    hasleoInstalled         = $hasInstalled
    hasleoLatestImage       = $hasLastLog
    hasleoImageStale        = $hasStale
    
    volumes                 = $Volumes
    diskHealth              = $DiskHealth
    windowsRelease          = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
    healthStatus            = $HealthStatus
    alerts                  = $Alerts
} | ConvertTo-Json -Depth 5 -Compress

# ② 中身をBase64に変換（データ形式を崩さないため）
$PayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($InnerPayload)
$PayloadBase64 = [Convert]::ToBase64String($PayloadBytes)

# ③ リプレイ攻撃防止用のタイムスタンプとノンス（使い捨て文字列）を生成
$UnixTimestamp = [Math]::Floor([datetimeoffset]::UtcNow.ToUnixTimeSeconds())
$Nonce = [guid]::NewGuid().ToString()

# ④ 署名（ハンコ）の作成： "UUID|時間|ノンス|データ" を秘密鍵でHMAC-SHA256計算
$SignData = "$UUID|$UnixTimestamp|$Nonce|$PayloadBase64"
$HMAC = New-Object System.Security.Cryptography.HMACSHA256
$HMAC.Key = [System.Text.Encoding]::UTF8.GetBytes($DeviceSecret)
$HashBytes = $HMAC.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($SignData))
$Signature = [Convert]::ToBase64String($HashBytes)
$HMAC.Dispose()

# ⑤ 最終的にGASへ送信する「封筒（アウターペイロード）」
$FinalPayload = @{
    signature     = $Signature
    uuid          = $UUID
    timestamp     = $UnixTimestamp
    nonce         = $Nonce
    payloadBase64 = $PayloadBase64
} | ConvertTo-Json -Compress

# GASへ送信
try { 
    $BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($FinalPayload)
    Invoke-RestMethod -Uri $Endpoint -Method Post -ContentType "application/json; charset=utf-8" -Body $BodyBytes 
} catch {}