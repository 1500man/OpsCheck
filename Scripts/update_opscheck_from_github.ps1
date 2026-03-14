<#
===================================================
Virgo Premium V3 プロジェクト・マニフェスト（設計図）
===================================================
【1. セキュリティ要件】
- パスワードは保持しない。MasterKey(環境変数) + UUID で設定ファイルを復号する。
- スクリプト自身のSHA256ハッシュを計算し、改ざん検知（FIM）を行う。

【2. 更新（Updater）要件】
- GitHubから最新の ps1 を2つ取得する。
- 失敗時はエラーを隠さず表示し、原因（404, Unauthorized等）を特定する。
- 更新成功時はGASへログを送信する。

【3. 診断（HealthReport）要件】
- 監視ドライブ厳選：C:ドライブ ＋ (Hasleo/Macriumのバックアップが存在するドライブ)。
- フル診断：S.M.A.R.T.、アンチウイルス、14日間のバックアップ鮮度チェック。
- GAS連携：変数名は HTML側（lastUpdate, alerts）に完全に合わせる。

【AI(Gemini)への絶対命令】
- 変更を加える際は、上記【1?3】の機能を1文字たりとも削るな。
- 焦り、早合点、一部のみのコード出力を禁止する。
===================================================
#>
$ErrorActionPreference = 'Continue'
$TargetDir = "C:\OpsCheck\Scripts"

# 1. 要塞解錠フェーズ
$MasterKey = [Environment]::GetEnvironmentVariable("VIRGO_MASTER_KEY", "Machine")
$UUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$EncFile = Join-Path $TargetDir "system_config.enc"

if (!(Test-Path $EncFile)) { 
    Write-Error "CRITICAL: system_config.enc が見つかりません。セットアップをやり直してください。"
    exit 
}

$EncryptedText = Get-Content $EncFile -Raw
$Hasher = [System.Security.Cryptography.SHA256]::Create()
$KeyBytes = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$MasterKey-$UUID"))

try {
    $SecureString = $EncryptedText | ConvertTo-SecureString -Key $KeyBytes
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $Config = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)) | ConvertFrom-Json
} catch {
    Write-Error "CRITICAL: 金庫の解錠に失敗しました。MasterKeyまたはUUIDが不一致です。"
    exit
} finally {
    if ($null -ne $BSTR) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) }
}

# 2. GitHubからのダウンロード実行
$Files = @("poc_health_report.ps1", "update_opscheck_from_github.ps1")
$SuccessCount = 0
$Headers = @{}
if (![string]::IsNullOrEmpty($Config.githubToken)) {
    $Headers["Authorization"] = "token $($Config.githubToken)"
}

foreach ($f in $Files) {
    # ユーザーリポジトリのURL構成を厳守
    $Url = "https://raw.githubusercontent.com/1500man/OpsCheck/main/Scripts/$f"
    $Dest = Join-Path $TargetDir $f
    
    Write-Host "Updating: $f ..." -ForegroundColor Cyan
    try {
        Invoke-RestMethod -Uri $Url -Headers $Headers -OutFile $Dest -UseBasicParsing
        Write-Host "Success: $f" -ForegroundColor Green
        $SuccessCount++
    } catch {
        Write-Error "UPDATE FAILED: $f - $($_.Exception.Message)"
    }
}

# 3. GAS報告
if ($SuccessCount -gt 0) {
    $Payload = @{
        action = "updateLog"
        timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
        customerGroup = $Config.customerGroup
        device = $env:COMPUTERNAME
        status = "SUCCESS"
        message = "$SuccessCount ファイル更新完了（V3.15）"
    } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $Config.endpoint -Method Post -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload)) } catch {}
}
Write-Host "--- 全工程終了 ---" -ForegroundColor Yellow