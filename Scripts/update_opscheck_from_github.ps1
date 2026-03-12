<#
OpsCheck script updater (run on client PC)
Supports both Public and Private GitHub repositories.
#>

param(
  [ValidateSet("public", "private")]
  [string]$AccessMode = "private",
  [string]$RepoOwner = "1500man",
  [string]$RepoName = "OpsCheck",
  [string]$Branch = "main",
  [string]$PublicZipUrl = "https://github.com/1500man/OpsCheck/archive/refs/heads/main.zip",
  [string]$GitHubToken = ""
)

$ErrorActionPreference = "Stop"

$targetRoot = "C:\OpsCheck"
$targetScripts = Join-Path $targetRoot "Scripts"
$tempRoot = Join-Path $env:TEMP ("opscheck_update_" + (Get-Date -Format "yyyyMMddHHmmss"))
$zipPath = Join-Path $tempRoot "repo.zip"

$clientInfoPath = Join-Path $targetScripts "client_info.json"
$systemConfigPath = Join-Path $targetScripts "system_config.json"

function Resolve-DownloadSpec {
  if ($AccessMode -eq "private") {
    if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
      Write-Warning "================================================================"
      Write-Warning "【警告】GitHubトークンが指定されていません！"
      Write-Warning "手動でアップデートをテストする場合は、以下のように引数を付けて実行してください。"
      Write-Warning "> .\update_opscheck_from_github.ps1 -GitHubToken `"あなたのトークン`""
      Write-Warning "※警告: スクリプト内に直接トークンを書き込んでGitHubへPushすると、GitHub側で自動検知され即座にトークンが無効化されるため、絶対に行わないでください。"
      Write-Warning "================================================================"
      throw "GitHubトークン不足のため、アップデートを中断します。"
    }
    return @{ 
      Uri = "https://api.github.com/repos/$RepoOwner/$RepoName/zipball/$Branch"
      Headers = @{ Authorization = "Bearer $GitHubToken"; Accept = "application/vnd.github+json"; "User-Agent" = "OpsCheckUpdater" }
      Note = "private"
    }
  }
  return @{ 
    Uri = $PublicZipUrl
    Headers = @{}
    Note = "public"
  }
}

function Send-UpdateExecutionLog {
  param(
    [string]$Status,
    [string]$Message
  )

  try {
    if (-not (Test-Path $systemConfigPath) -or -not (Test-Path $clientInfoPath)) {
      Write-Warning "[WARN] 設定ファイルが見つからないため、ログ送信をスキップします。"
      return
    }

    $sysCfg = Get-Content -Path $systemConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $cliCfg = Get-Content -Path $clientInfoPath -Raw -Encoding UTF8 | ConvertFrom-Json

    if ([string]::IsNullOrWhiteSpace($sysCfg.endpoint)) { return }

    $payload = [PSCustomObject]@{
      action        = "updateLog"
      customerGroup = $cliCfg.customerGroup
      device        = $cliCfg.deviceName
      timestamp     = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
      status        = $Status
      message       = $Message
      sharedSecret  = $sysCfg.sharedSecret
    }

    $body = $payload | ConvertTo-Json -Depth 5
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    Invoke-RestMethod -Uri ($sysCfg.endpoint) -Method Post -ContentType "application/json; charset=utf-8" -Body $bytes -TimeoutSec 20 | Out-Null
    Write-Host "[INFO] アップデート結果をGASへ送信しました。"
  } catch {
    Write-Warning "[WARN] ログの送信に失敗しました: $($_.Exception.Message)"
  }
}

$runStatus = "Success"
$runMessage = "Update completed successfully."
$backupDir = ""
$failed = $false

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  if (-not (Test-Path $targetScripts)) { New-Item -ItemType Directory -Path $targetScripts -Force | Out-Null }

  $download = Resolve-DownloadSpec
  Write-Host "[INFO] Downloading ($($download.Note)): $($download.Uri)"
  Invoke-WebRequest -Uri $download.Uri -OutFile $zipPath -UseBasicParsing -Headers $download.Headers

  Write-Host "[INFO] Expanding archive..."
  Expand-Archive -Path $zipPath -DestinationPath $tempRoot -Force

  $repoRoot = Get-ChildItem -Path $tempRoot -Directory | Select-Object -First 1
  if (-not $repoRoot) { throw "Zip内にリポジトリフォルダが見つかりません。" }

  # ★修正: 余計なVBSファイルをリストから除外しました
  $files = @(
    "poc_health_report.ps1",
    "update_opscheck_from_github.ps1"
  )

  $backupDir = Join-Path $targetScripts ("backup_" + (Get-Date -Format "yyyyMMddHHmmss"))
  New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

  foreach ($rel in $files) {
    $src1 = Join-Path $repoRoot.FullName $rel
    $src2 = Join-Path $repoRoot.FullName ("scripts\" + $rel)
    
    $src = if (Test-Path $src1) { $src1 } elseif (Test-Path $src2) { $src2 } else { $null }

    if (-not $src) {
      Write-Warning "[WARN] GitHubリポジトリ内にファイルが見つかりません: $rel"
      continue
    }

    $dest = Join-Path $targetScripts $rel
    if (Test-Path $dest) {
      Copy-Item -Path $dest -Destination (Join-Path $backupDir $rel) -Force
    }
    Copy-Item -Path $src -Destination $dest -Force
    Write-Host "[INFO] Updated: $dest"
  }

  Write-Host "[INFO] アップデート完了。バックアップ先: $backupDir" -ForegroundColor Green
} catch {
  $failed = $true
  $runStatus = "Error"
  $runMessage = $_.Exception.Message
  Write-Error "[ERROR] アップデート失敗: $runMessage"
} finally {
  Send-UpdateExecutionLog -Status $runStatus -Message $runMessage
  if (Test-Path $tempRoot) { Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($failed) { exit 1 }