# ===================================================
# Virgo Premium - Health Report (V3.10 ドライブ完全取得版)
# ===================================================
$ErrorActionPreference = 'SilentlyContinue'
$TargetDir = "C:\OpsCheck\Scripts"

# 1. 要塞解錠フェーズ
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

# 2. フル診断＆自己ハッシュ取得フェーズ
$HostName = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")

$Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$DiskFreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
$OS = Get-WmiObject Win32_OperatingSystem
$MemFreeGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)

# ★ 全ドライブ（内蔵・USB等）の容量情報を取得
$Volumes = @()
$LogicalDisks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3"
foreach ($d in $LogicalDisks) {
    if ($d.Size -gt 0) {
        $size = [math]::Round($d.Size / 1GB, 1)
        $free = [math]::Round($d.FreeSpace / 1GB, 1)
        $used = $size - $free
        $Volumes += @{
            Drive       = $d.DeviceID.Replace(":", "")
            SizeGB      = $size
            UsedGB      = $used
            SmartHealth = "正常" # フル版統合までのダミー
            SmartTemp   = "--"   # フル版統合までのダミー
            UsageHours  = "--"   # フル版統合までのダミー
            IsTarget    = $true  # すべてのドライブをダッシュボードに表示
        }
    }
}

$ScriptPath = Join-Path $TargetDir "poc_health_report.ps1"
$ScriptHash = "UNKNOWN"
if (Test-Path $ScriptPath) {
    $ScriptHash = (Get-FileHash -Path $ScriptPath -Algorithm SHA256).Hash
}

# 3. GASへのセキュア報告フェーズ
$Payload = @{
    action        = "report"
    customerGroup = $Config.customerGroup
    device        = $HostName
    uuid          = $Config.uuid
    usbSerial     = $Config.usbSerial
    timestamp     = $Timestamp
    diskFreeGB    = $DiskFreeGB
    memFreeGB     = $MemFreeGB
    scriptHash    = $ScriptHash
    authToken     = $Config.authToken
    volumes       = $Volumes  # 取得した全ドライブ情報をセット
    diskHealth    = @()
    alerts        = @()
    healthStatus  = "正常"
} | ConvertTo-Json -Depth 5 -Compress

try {
    Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload))
} catch {}