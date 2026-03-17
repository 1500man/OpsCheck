<#
===================================================
Virgo Premium V3 プロジェクト・マニフェスト（設計図）
===================================================
【設計思想】PCにパスワードを持たせず、改ざんを許さない最高強度の監視。
【AI(Gemini)への絶対命令】
- 監視ドライブは「C:」と「バックアップイメージが存在するドライブ」のみに限定せよ。
- S.M.A.R.T.、AV監視、バックアップ鮮度(14日)のロジックを1文字も削るな。
- 改ざん検知用のハッシュ計算を省略するな。
===================================================
#>
$ErrorActionPreference = 'SilentlyContinue'
$TargetDir = "C:\OpsCheck\Scripts"

# 0. 通信分散（ジッター）フェーズ：GASの同時実行パンクを防ぐため最大5分待機
$JitterSeconds = Get-Random -Minimum 1 -Maximum 300
Start-Sleep -Seconds $JitterSeconds

# 1. 要塞解錠（ MasterKey + UUID ）
$MasterKey = [Environment]::GetEnvironmentVariable("VIRGO_MASTER_KEY", "Machine")
$UUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$EncFile = Join-Path $TargetDir "system_config.enc"

$EncryptedText = Get-Content $EncFile -Raw
$Hasher = [System.Security.Cryptography.SHA256]::Create()
$KeyBytes = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$MasterKey-$UUID"))

try {
    $SecureString = $EncryptedText | ConvertTo-SecureString -Key $KeyBytes
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $Config = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)) | ConvertFrom-Json
} catch { exit } 
finally { if ($null -ne $BSTR) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) } }

# 2. 診断フェーズ
$HostName = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
$Alerts = @()
$HealthStatus = "正常"

# AV監視
$AvProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
$AvVendor = if ($AvProducts) { ($AvProducts | Select-Object -ExpandProperty displayName) -join ", " } else { "Defender/未検出" }

# ドライブ厳選 ＆ S.M.A.R.T. (簡易WMI版)
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
        $hasMacrium = (Test-Path "$DriveLetter\Macrium") -or (Get-ChildItem -Path "$DriveLetter\" -Filter "*.mrimg" -Depth 2)
        $hasHasleo  = (Test-Path "$DriveLetter\Hasleo*") -or (Get-ChildItem -Path "$DriveLetter\" -Filter "*.pbd" -Depth 2)
        
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

# ★【復元】S.M.A.R.T. 詳細監視 (smartmontools連携: SATA/NVMe両対応)
$DiskHealth = @()
$SmartCtlPath = ""
if (Get-Command "smartctl" -ErrorAction SilentlyContinue) { $SmartCtlPath = "smartctl" }
elseif (Test-Path "${env:ProgramFiles}\smartmontools\bin\smartctl.exe") { $SmartCtlPath = "${env:ProgramFiles}\smartmontools\bin\smartctl.exe" }
elseif (Test-Path "${env:ProgramFiles(x86)}\smartmontools\bin\smartctl.exe") { $SmartCtlPath = "${env:ProgramFiles(x86)}\smartmontools\bin\smartctl.exe" }

if ($SmartCtlPath) {
    foreach ($pd in $DiskDrives) {
        $diskInfo = @{
            Model = $pd.Model
            Status = "不明"
            Temperature = "不明"
            PowerOnHours = "不明"
        }
        # 出力を配列として受け取り、1行ずつ確実に解析する
        $smartOutputArray = & $SmartCtlPath -a $pd.DeviceID 2>$null
        if ($smartOutputArray) {
            foreach ($line in $smartOutputArray) {
                if ($line -match "SMART overall-health self-assessment test result:\s*(.*)") {
                    $diskInfo.Status = $matches[1].Trim()
                } elseif ($line -match "SMART Health Status:\s*(.*)") {
                    $diskInfo.Status = $matches[1].Trim()
                } elseif ($line -match "Temperature_Celsius.*-\s+(\d+)(\s|$)") {
                    $diskInfo.Temperature = $matches[1]
                } elseif ($line -match "Temperature:\s+(\d+) Celsius") {
                    $diskInfo.Temperature = $matches[1]
                } elseif ($line -match "Power_On_Hours.*-\s+(\d+)(\s|$)") {
                    $diskInfo.PowerOnHours = $matches[1]
                } elseif ($line -match "Power On Hours:\s+([\d,]+)") {
                    $diskInfo.PowerOnHours = $matches[1].Replace(",", "")
                }
            }
            if ($diskInfo.Status -notin @("PASSED", "OK", "不明")) { $Alerts += "[$($pd.Model)] S.M.A.R.T.異常" }
        }
        $DiskHealth += $diskInfo
    }
} else {
    $Alerts += "smartmontools未検出"
}

# バックアップ鮮度(14日)
$MacriumFile = Get-ChildItem -Path "C:\", "D:\", "E:\", "F:\", "G:\" -Filter "*.mrimg" -Recurse -Depth 3 | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$MacriumTime = if ($MacriumFile) { $MacriumFile.LastWriteTime } else { $null }
if ($MacriumTime -and ((Get-Date) - $MacriumTime).TotalDays -gt 14) { $Alerts += "Reflectバックアップ遅延" }

# 3. 報告フェーズ
if ($Alerts.Count -gt 0) { $HealthStatus = "警告" }
$ScriptHash = (Get-FileHash -Path (Join-Path $TargetDir "poc_health_report.ps1") -Algorithm SHA256).Hash

$Payload = @{
    action            = "report"
    customerGroup     = $Config.customerGroup
    device            = $HostName
    timestamp         = $Timestamp
    diskFreeGB        = $DiskFreeGB
    scriptHash        = $ScriptHash
    authToken         = $Config.authToken
    antivirusVendor   = $AvVendor
    lastUpdate        = $Timestamp
    alerts            = $Alerts
    volumes           = $Volumes
    diskHealth        = $DiskHealth  # ★追加：ダッシュボード用SMART情報
    healthStatus      = $HealthStatus
} | ConvertTo-Json -Depth 5 -Compress

try { Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload)) } catch {}