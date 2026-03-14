# ===================================================
# Virgo Premium - Health Report (v3.0 高度セキュリティ版)
# ===================================================
$ErrorActionPreference = 'Continue'
$TargetDir = "C:\OpsCheck\Scripts"

# 1. 要塞解錠フェーズ（金庫からURLとトークンを取り出す）
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

# 簡易診断（Cドライブ空き容量と空きメモリ）
$Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$DiskFreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
$OS = Get-WmiObject Win32_OperatingSystem
$MemFreeGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)

# ★【NEW】スクリプト自身のデジタル指紋（ハッシュ値）を計算
# これにより、1文字でも改ざんされると全く違う文字列になり、GAS側で異常検知が可能になります。
$ScriptHash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash

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
    scriptHash    = $ScriptHash  # ★計算した指紋を同梱
    authToken     = $Config.authToken
} | ConvertTo-Json -Compress

try {
    # 金庫から取り出したURL(endpoint)へ送信
    Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload))
} catch {
    # 失敗時はエラーを出さずに静かに終了（翌日の報告を待つ）
}