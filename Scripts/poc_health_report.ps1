# ===================================================
# Virgo Premium - Updater (V3.3 本番ログ送信版)
# ===================================================
$ErrorActionPreference = 'SilentlyContinue'
$TargetDir = "C:\OpsCheck\Scripts"

# 1. 要塞解錠フェーズ
$MasterKey = [Environment]::GetEnvironmentVariable("VIRGO_MASTER_KEY", "Machine")
$UUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$EncFile = Join-Path $TargetDir "system_config.enc"
if (!(Test-Path $EncFile)) { exit }

$EncryptedText = Get-Content $EncFile -Raw
$Hasher = [System.Security.Cryptography.SHA256]::Create()
$KeyBytes = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$MasterKey-$UUID"))
try {
    $SecureString = $EncryptedText | ConvertTo-SecureString -Key $KeyBytes
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $Config = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)) | ConvertFrom-Json
} catch { exit }
finally { if ($null -ne $BSTR) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) } }

# 2. GitHubから更新ファイルをダウンロード
$Files = @("poc_health_report.ps1", "update_opscheck_from_github.ps1")
$Headers = @{ "Authorization" = "token $($Config.githubToken)" }
$SuccessCount = 0

foreach ($f in $Files) {
    $Url = "https://raw.githubusercontent.com/1500man/OpsCheck/main/Scripts/$f"
    try {
        Invoke-RestMethod -Uri $Url -Headers $Headers -OutFile (Join-Path $TargetDir $f) -UseBasicParsing
        $SuccessCount++
    } catch {}
}

# 3. GASへアップデートログを送信
if ($SuccessCount -gt 0) {
    $Payload = @{
        action = "updateLog"
        timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
        customerGroup = $Config.customerGroup
        device = $env:COMPUTERNAME
        status = "SUCCESS"
        message = "$SuccessCount 個のファイルを更新しました"
    } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload)) } catch {}
}