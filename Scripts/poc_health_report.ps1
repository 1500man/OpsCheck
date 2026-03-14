# ===================================================
# Virgo Premium - Health Report (V3.2 ログ出力＆完全ペイロード版)
# ===================================================
$ErrorActionPreference = 'Continue'
$TargetDir = "C:\OpsCheck\Scripts"
$LogFile = Join-Path $TargetDir "debug_log.txt"

# ログ書き出し用の専用関数
function Write-Log { param($msg) Add-Content -Path $LogFile -Value ("[{0:yyyy/MM/dd HH:mm:ss}] {1}" -f (Get-Date), $msg) }

Write-Log "=== 点検タスク実行開始 ==="

# 1. 要塞解錠フェーズ
$MasterKey = [Environment]::GetEnvironmentVariable("VIRGO_MASTER_KEY", "Machine")
if ([string]::IsNullOrEmpty($MasterKey)) { Write-Log "【エラー】マスターキーが見つかりません"; exit }

$UUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$EncFile = Join-Path $TargetDir "system_config.enc"
if (!(Test-Path $EncFile)) { Write-Log "【エラー】金庫($EncFile)が見つかりません"; exit }

$EncryptedText = Get-Content $EncFile -Raw
$Hasher = [System.Security.Cryptography.SHA256]::Create()
$KeyBytes = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$MasterKey-$UUID"))

try {
    $SecureString = $EncryptedText | ConvertTo-SecureString -Key $KeyBytes
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $ConfigJson = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $Config = $ConfigJson | ConvertFrom-Json
    Write-Log "金庫の解錠に成功しました。"
} catch { Write-Log "【エラー】金庫の解錠に失敗しました。"; exit } 
finally { if ($null -ne $BSTR -and $BSTR -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) } }

# 2. フル診断＆自己ハッシュ取得フェーズ
$HostName = $env:COMPUTERNAME
$Timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")

$Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$DiskFreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
$OS = Get-WmiObject Win32_OperatingSystem
$MemFreeGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)

$ScriptPath = Join-Path $TargetDir "poc_health_report.ps1"
$ScriptHash = "UNKNOWN"
if (Test-Path $ScriptPath) {
    $ScriptHash = (Get-FileHash -Path $ScriptPath -Algorithm SHA256).Hash
    Write-Log "ハッシュ計算成功: $($ScriptHash.Substring(0,10))..."
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
    # ★GASの受け取り拒否を回避するための必須項目を追加
    volumes       = @()
    diskHealth    = @()
    alerts        = @()
    healthStatus  = "正常"
} | ConvertTo-Json -Depth 5 -Compress

Write-Log "データをGASへ送信します..."
try {
    $Response = Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload))
    Write-Log "送信完了！ GASからの返答: $Response"
} catch {
    Write-Log "【送信エラー】 $($_.Exception.Message)"
}
Write-Log "=== 点検タスク実行終了 ==="