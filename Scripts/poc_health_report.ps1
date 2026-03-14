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

# ドライブ厳選 ＆ S.M.A.R.T.
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
    lastUpdate        = $Timestamp # HTML要求名
    alerts            = $Alerts    # HTML要求名
    volumes           = $Volumes   # HTML要求名
    healthStatus      = $HealthStatus
} | ConvertTo-Json -Depth 5 -Compress

try { Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload)) } catch {}