# ===================================================
# ?? AI（Gemini）への絶対遵守事項 ??
# 【忘却禁止】S.M.A.R.T.、アンチウイルス、バックアップ監視のフル機能を落とさない
# 【忘却禁止】監視対象はCドライブとバックアップ先のみに厳選する
# ===================================================
# Virgo Premium - Health Report (V3.13 究極完全復元版)
# ===================================================
$ErrorActionPreference = 'SilentlyContinue'
$TargetDir = "C:\OpsCheck\Scripts"

# ==========================================
# 1. 要塞解錠フェーズ（V3セキュリティ）
# ==========================================
$MasterKey = [Environment]::GetEnvironmentVariable("VIRGO_MASTER_KEY", "Machine")
if ([string]::IsNullOrEmpty($MasterKey)) { exit }

$UUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$EncFile = Join-Path $TargetDir "system_config.enc"
if (!(Test-Path $EncFile)) { exit }

$EncryptedText = Get-Content $EncFile -Raw
$Hasher = [System.Security.Cryptography.SHA256]::Create()
$KeyBytes = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$MasterKey-$UUID"))

try {
    $SecureString = $EncryptedText | ConvertTo-SecureString -Key $KeyBytes
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $ConfigJson = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $Config = $ConfigJson | ConvertFrom-Json
} catch { exit } 
finally { if ($null -ne $BSTR -and $BSTR -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) } }

# ==========================================
# 2. 基本情報・ハッシュ計算フェーズ
# ==========================================
$HostName = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
$Alerts = @()
$HealthStatus = "正常"

$OS = Get-WmiObject Win32_OperatingSystem
$WindowsRelease = $OS.Caption + " (" + $OS.Version + ")"
$MemFreeGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)

$ScriptPath = Join-Path $TargetDir "poc_health_report.ps1"
$ScriptHash = "UNKNOWN"
if (Test-Path $ScriptPath) {
    $ScriptHash = (Get-FileHash -Path $ScriptPath -Algorithm SHA256).Hash
}

# ==========================================
# 3. アンチウイルス（セキュリティ）監視フェーズ
# ==========================================
$AvProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
$AvVendor = "Windows Defender"
$AvStatus = "有効"
$IsAvDetected = $false

if ($AvProducts) {
    $AvVendor = ($AvProducts | Select-Object -ExpandProperty displayName) -join ", "
    $IsAvDetected = $true
} else {
    $Alerts += "アンチウイルスソフトが検出できません"
}

# ==========================================
# 4. ドライブ厳選 ＆ S.M.A.R.T. 監視フェーズ
# ==========================================
$Volumes = @()
$LogicalDisks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3"
$DiskDrives = Get-WmiObject Win32_DiskDrive # S.M.A.R.T.取得用
$DiskFreeGB = 0

foreach ($d in $LogicalDisks) {
    if ($d.Size -gt 0) {
        $DriveLetter = $d.DeviceID
        $volName = $d.VolumeName
        $size = [math]::Round($d.Size / 1GB, 1)
        $free = [math]::Round($d.FreeSpace / 1GB, 1)
        $used = $size - $free
        $freePct = [math]::Round(($free / $size) * 100, 1)

        if ($DriveLetter -eq "C:") { $DiskFreeGB = $free }

        # S.M.A.R.T. ステータスの簡易取得
        $smartHealth = "正常"
        if ($DiskDrives.Status -contains "Pred Fail" -or $DiskDrives.Status -contains "Error") {
            $smartHealth = "異常 (S.M.A.R.T.)"
        }

        # 監視対象の厳選判定
        $isTarget = $false
        $hasMacrium = $false
        $hasHasleo = $false

        if ($DriveLetter -eq "C:") {
            $isTarget = $true
        } else {
            if ($volName -match "Hasleo|Macrium|Backup") { $isTarget = $true }
            
            $hasMacrium = (Test-Path "$DriveLetter\Macrium") -or (Get-ChildItem -Path "$DriveLetter\" -Filter "*.mrimg" -Depth 2 -ErrorAction SilentlyContinue)
            $hasHasleo  = (Test-Path "$DriveLetter\Hasleo") -or (Test-Path "$DriveLetter\Hasleo Backup") -or (Get-ChildItem -Path "$DriveLetter\" -Filter "*.pbd" -Depth 2 -ErrorAction SilentlyContinue)
            
            if ($hasMacrium -or $hasHasleo) { $isTarget = $true }
        }

        if ($isTarget) {
            $Volumes += @{
                Drive       = $DriveLetter.Replace(":", "")
                SizeGB      = $size
                UsedGB      = $used
                SmartHealth = $smartHealth
                SmartTemp   = "--"
                UsageHours  = "--"
                IsTarget    = $true
            }

            # 容量不足アラート
            if ($freePct -lt 10) {
                $Alerts += "[$DriveLetter ドライブ] の空き容量が不足しています ($freePct %)"
            }
            if ($smartHealth -ne "正常") {
                $Alerts += "[$DriveLetter ドライブ] でディスクの物理的な異常(S.M.A.R.T.)を検知しました"
            }
        }
    }
}

# ==========================================
# 5. バックアップ鮮度（経過日数）監視フェーズ
# ==========================================
$ReflectImageStale = $false
$HasleoImageStale = $false
$MacriumLatest = ""
$HasleoLatest = ""

# Macrium (.mrimg) の最新チェック
$mrimgFiles = Get-ChildItem -Path "C:\", "D:\", "E:\", "F:\", "G:\" -Filter "*.mrimg" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($mrimgFiles) {
    $MacriumLatest = $mrimgFiles.LastWriteTime.ToString("yyyy/MM/dd HH:mm")
    if ((Get-Date) - $mrimgFiles.LastWriteTime -gt [timespan]::FromDays(14)) {
        $ReflectImageStale = $true
        $Alerts += "Reflectバックアップが14日以上更新されていません"
    }
}

# Hasleo (.pbd) の最新チェック
$pbdFiles = Get-ChildItem -Path "C:\", "D:\", "E:\", "F:\", "G:\" -Filter "*.pbd" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($pbdFiles) {
    $HasleoLatest = $pbdFiles.LastWriteTime.ToString("yyyy/MM/dd HH:mm")
    if ((Get-Date) - $pbdFiles.LastWriteTime -gt [timespan]::FromDays(14)) {
        $HasleoImageStale = $true
        $Alerts += "Hasleoバックアップが14日以上更新されていません"
    }
}

# アラートがあればステータスを警告にする
if ($Alerts.Count -gt 0) { $HealthStatus = "警告" }

# ==========================================
# 6. GASへのセキュア報告フェーズ
# ==========================================
$Payload = @{
    action                  = "report"
    customerGroup           = $Config.customerGroup
    device                  = $HostName
    uuid                    = $Config.uuid
    usbSerial               = $Config.usbSerial
    timestamp               = $Timestamp
    diskFreeGB              = $DiskFreeGB
    memFreeGB               = $MemFreeGB
    scriptHash              = $ScriptHash
    authToken               = $Config.authToken
    windowsRelease          = $WindowsRelease
    antivirusVendor         = $AvVendor
    antivirusStatus         = $AvStatus
    antivirusDetected       = $IsAvDetected
    macriumInstalled        = [bool]$MacriumLatest
    macriumLatestLog        = $MacriumLatest
    reflectImageStale       = $ReflectImageStale
    hasleoInstalled         = [bool]$HasleoLatest
    hasleoLatestImage       = $HasleoLatest
    hasleoImageStale        = $HasleoImageStale
    volumes                 = $Volumes
    alerts                  = $Alerts
    healthStatus            = $HealthStatus
} | ConvertTo-Json -Depth 5 -Compress

try {
    Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload))
} catch {}