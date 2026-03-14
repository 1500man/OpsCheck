# ===================================================
# Virgo Premium - Secure Auto Updater (v1.1)
# ===================================================
$ErrorActionPreference = 'Continue'
$TargetDir = "C:\OpsCheck\Scripts"
$RepoOwner = "1500man"
$RepoName = "OpsCheck"
$Branch = "main"

# 1. 要塞解錠フェーズ（金庫からGitHubトークンを取り出す）
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

# 金庫からトークンを取得！
$GitHubToken = $Config.githubToken
if ([string]::IsNullOrEmpty($GitHubToken)) { exit }

# 2. GitHubからのダウンロード処理
$FilesToSync = @("poc_health_report.ps1", "update_opscheck_from_github.ps1")
$Headers = @{ "Authorization" = "token $GitHubToken" }

foreach ($file in $FilesToSync) {
    $Url = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch/$file"
    $DestPath = Join-Path $TargetDir $file
    try {
        Invoke-RestMethod -Uri $Url -Headers $Headers -OutFile $DestPath -UseBasicParsing
    } catch {}
}