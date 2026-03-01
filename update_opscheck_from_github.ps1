# OpsCheck script updater (run on client PC)
# Supports both:
#   - Public repo ZIP URL
#   - Private repo via GitHub API + token (no git client required)
#
# Usage example (private):
#   setx GITHUB_TOKEN "ghp_xxx"
#   powershell.exe -ExecutionPolicy Bypass -File "C:\OpsCheck\scripts\update_opscheck_from_github.ps1" -AccessMode private -RepoOwner YOUR_ORG -RepoName YOUR_REPO -Branch main

param(
  [ValidateSet("public", "private")]
  [string]$AccessMode = "public",
  [string]$RepoOwner = "OWNER",
  [string]$RepoName = "REPO",
  [string]$Branch = "main",
  [string]$PublicZipUrl = "https://github.com/OWNER/REPO/archive/refs/heads/main.zip",
  [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"

$targetRoot = "C:\OpsCheck"
$targetScripts = Join-Path $targetRoot "scripts"
$tempRoot = Join-Path $env:TEMP ("opscheck_update_" + (Get-Date -Format "yyyyMMddHHmmss"))
$zipPath = Join-Path $tempRoot "repo.zip"
$clientConfigPath = Join-Path $targetScripts "client_config.json"

function Resolve-DownloadSpec {
  if ($AccessMode -eq "private") {
    if ([string]::IsNullOrWhiteSpace($Token)) {
      throw "Private mode requires token. Set GITHUB_TOKEN env var or pass -Token."
    }

    return @{ 
      Uri = "https://api.github.com/repos/$RepoOwner/$RepoName/zipball/$Branch"
      Headers = @{ Authorization = "Bearer $Token"; Accept = "application/vnd.github+json"; "User-Agent" = "OpsCheckUpdater" }
      Note = "private"
    }
  }

  return @{ 
    Uri = $PublicZipUrl
    Headers = @{}
    Note = "public"
  }
}

function Load-ClientConfig {
  if (-not (Test-Path $clientConfigPath)) {
    return $null
  }

  try {
    return (Get-Content -Path $clientConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json)
  } catch {
    Write-Warning "[WARN] Failed to parse client config: $($_.Exception.Message)"
    return $null
  }
}

function Send-UpdateExecutionLog {
  param(
    [string]$Status,
    [string]$Message
  )

  try {
    $cfg = Load-ClientConfig
    if (-not $cfg -or [string]::IsNullOrWhiteSpace([string]$cfg.endpoint)) {
      Write-Warning "[WARN] Update log was not sent (endpoint missing in client_config.json)."
      return
    }

    $device = if ([string]::IsNullOrWhiteSpace([string]$cfg.deviceName)) { $env:COMPUTERNAME } else { [string]$cfg.deviceName }
    $payload = [PSCustomObject]@{
      dataType = "updateLog"
      customerName = [string]$cfg.customerName
      device = $device
      timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
      status = $Status
      message = $Message
      authToken = [string]$cfg.sharedSecret
    }

    $body = $payload | ConvertTo-Json -Depth 5
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    Invoke-RestMethod -Uri ([string]$cfg.endpoint) -Method Post -ContentType "application/json; charset=utf-8" -Body $bytes -TimeoutSec 20 | Out-Null
    Write-Host "[INFO] Update log sent to GAS."
  } catch {
    Write-Warning "[WARN] Failed to send update log: $($_.Exception.Message)"
  }
}

$runStatus = "Success"
$runMessage = "Update completed successfully."
$backupDir = ""
$failed = $false

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $targetScripts -Force | Out-Null

  $download = Resolve-DownloadSpec
  Write-Host "[INFO] Downloading ($($download.Note)): $($download.Uri)"
  Invoke-WebRequest -Uri $download.Uri -OutFile $zipPath -UseBasicParsing -Headers $download.Headers

  Write-Host "[INFO] Expanding archive"
  Expand-Archive -Path $zipPath -DestinationPath $tempRoot -Force

  $repoRoot = Get-ChildItem -Path $tempRoot -Directory | Select-Object -First 1
  if (-not $repoRoot) {
    throw "Repository folder was not found in expanded archive."
  }

  $files = @(
    "scripts/poc_health_report.ps1",
    "scripts/run_health_report_hidden.vbs",
    "scripts/run_updater_hidden.vbs",
    "scripts/client_config.sample.json",
    "scripts/update_opscheck_from_github.ps1"
  )

  $backupDir = Join-Path $targetScripts ("backup_" + (Get-Date -Format "yyyyMMddHHmmss"))
  New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

  foreach ($rel in $files) {
    $src = Join-Path $repoRoot.FullName $rel
    if (-not (Test-Path $src)) {
      Write-Warning "[WARN] Not found in archive: $rel"
      continue
    }

    $dest = Join-Path $targetRoot ($rel -replace '/', '\\')
    $destDir = Split-Path -Parent $dest
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null

    if (Test-Path $dest) {
      Copy-Item -Path $dest -Destination (Join-Path $backupDir (Split-Path $dest -Leaf)) -Force
    }

    Copy-Item -Path $src -Destination $dest -Force
    Write-Host "[INFO] Updated: $dest"
  }

  $samplePath = Join-Path $targetScripts "client_config.sample.json"
  if (-not (Test-Path $clientConfigPath) -and (Test-Path $samplePath)) {
    Copy-Item -Path $samplePath -Destination $clientConfigPath -Force
    Write-Host "[INFO] Created config template: $clientConfigPath"
  }

  Write-Host "[INFO] Done. Backup folder: $backupDir"
  $runMessage = if ([string]::IsNullOrWhiteSpace($backupDir)) {
    "Update completed successfully."
  } else {
    "Update completed successfully. Backup folder: $backupDir"
  }
} catch {
  $failed = $true
  $runStatus = "Error"
  $runMessage = $_.Exception.Message
  Write-Error "[ERROR] Update failed: $runMessage"
} finally {
  Send-UpdateExecutionLog -Status $runStatus -Message $runMessage
}

if ($failed) {
  exit 1
}
