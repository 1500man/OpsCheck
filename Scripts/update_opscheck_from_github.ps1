# ===================================================
# Virgo Premium - Auto Updater from GitHub
# ===================================================
param (
    [string]$AccessMode = "private",
    [string]$RepoOwner = "1500man",
    [string]$RepoName = "OpsCheck",
    [string]$Branch = "main",
    [string]$GitHubToken = ""
)

$ErrorActionPreference = 'Continue'
$TargetDir = "C:\OpsCheck\Scripts"

# GitHubから持ってくるファイルのリスト
# ※今後、新しいスクリプトを追加したらここにファイル名を書き足すだけで全PCに配られます
$FilesToSync = @(
    "poc_health_report.ps1",
    "update_opscheck_from_github.ps1" # 自分自身もアップデートできるようにしておく
)

# 保存先フォルダがなければ作成
if (!(Test-Path $TargetDir)) { New-Item $TargetDir -ItemType Directory -Force | Out-Null }

Write-Host "GitHubからの同期を開始します..." -ForegroundColor Cyan

foreach ($file in $FilesToSync) {
    # GitHubのRawデータ取得用URL
    $Url = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch/$file"
    $DestPath = Join-Path $TargetDir $file

    # プライベートリポジトリ用の認証ヘッダー
    $Headers = @{}
    if ($AccessMode -eq "private" -and !([string]::IsNullOrWhiteSpace($GitHubToken))) {
        $Headers["Authorization"] = "token $GitHubToken"
    }

    try {
        # GitHubからファイルをダウンロードして上書き保存
        Invoke-RestMethod -Uri $Url -Headers $Headers -OutFile $DestPath -UseBasicParsing
        Write-Host "[SUCCESS] $file を最新版に更新しました。" -ForegroundColor Green
    } catch {
        Write-Warning "[ERROR] $file のダウンロードに失敗しました: $($_.Exception.Message)"
    }
}