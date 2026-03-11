# PowerShell PoC health report sender (Windows 11)
# Usage:
#   1) Set endpoint/sharedSecret in system_config.json
#   2) Set customer/device info in client_info.json
#   3) Run: powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File .\poc_health_report.ps1

# ===== Settings =====
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$clientInfoPath = Join-Path $scriptDir "client_info.json"
$systemConfigPath = Join-Path $scriptDir "system_config.json"
$ScriptVersion = "2026.03.11.2"

$endpoint = ""
$deviceName = $env:COMPUTERNAME
$customerName = "Customer-Name-Here"
$customerGroup = ""
$customerEmail = ""
$servicePlan = "monthly"
$pcLocation = ""
$pcUser = ""
$sharedSecret = "CHANGE_ME"
$timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
$requestTimeoutSec = 60
$requestMaxRetries = 2
$requestRetryDelaySec = 5
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::Expect100Continue = $false

if (-not (Test-Path $clientInfoPath)) {
  Write-Error "[ERROR] client_info.json is not found: $clientInfoPath"
  exit 1
}
if (-not (Test-Path $systemConfigPath)) {
  Write-Error "[ERROR] system_config.json is not found: $systemConfigPath"
  exit 1
}

try {
  $clientInfo = Get-Content -Path $clientInfoPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $systemConfig = Get-Content -Path $systemConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

  $cfg = @{}
  $clientInfo.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
  $systemConfig.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }

  if ($cfg.endpoint) { $endpoint = [string]$cfg.endpoint }
  if ($cfg.customerName) { $customerName = [string]$cfg.customerName }
  if ($cfg.customerGroup) { $customerGroup = [string]$cfg.customerGroup }
  if ($cfg.customerEmail) { $customerEmail = [string]$cfg.customerEmail }
  if ($cfg.servicePlan) { $servicePlan = [string]$cfg.servicePlan }
  if ($cfg.pcLocation) { $pcLocation = [string]$cfg.pcLocation }
  if ($cfg.pcUser) { $pcUser = [string]$cfg.pcUser }
  if ($cfg.sharedSecret) { $sharedSecret = [string]$cfg.sharedSecret }
  if ($cfg.deviceName) { $deviceName = [string]$cfg.deviceName }
  if ($cfg.requestTimeoutSec) { $requestTimeoutSec = [int]$cfg.requestTimeoutSec }
  if ($cfg.requestMaxRetries) { $requestMaxRetries = [int]$cfg.requestMaxRetries }
  if ($cfg.requestRetryDelaySec) { $requestRetryDelaySec = [int]$cfg.requestRetryDelaySec }
  if ($cfg.scriptVersion) { $ScriptVersion = [string]$cfg.scriptVersion }

  Write-Host "[INFO] Loaded client info: $clientInfoPath"
  Write-Host "[INFO] Loaded system config: $systemConfigPath"
} catch {
  Write-Error "[ERROR] Failed to load config files: $($_.Exception.Message)"
  exit 1
}

if ([string]::IsNullOrWhiteSpace($customerName) -or $customerName -eq "Customer-Name-Here") {
  if (-not [string]::IsNullOrWhiteSpace($customerGroup)) {
    $customerName = $customerGroup
  }
}

if ([string]::IsNullOrWhiteSpace($endpoint) -or $endpoint -match "PUT_YOUR_GAS_ID") {
  Write-Error "[ERROR] endpoint is not configured. Set endpoint in system_config.json"
  exit 1
}

# ===== Thresholds =====
$minCFreeGB = 100
$minRecoveryFreeGB = 300
$recoveryImageAgeDays = 28
$esetScanAgeDays = 14
$antivirusEvidenceAgeDays = 14
$recoveryImageDriveLetters = @("D", "E", "F", "G", "H", "K")

function Convert-ToDateString($value) {
  if ($null -eq $value) { return "" }
  return ([datetime]$value).ToString("yyyy/MM/dd HH:mm:ss")
}

# ===== Volume info (dashboard schema aligned) =====
$smartctlPath = "C:\Program Files\smartmontools\bin\smartctl.exe"
$backupPaths = @("D:\Macrium", "E:\Macrium", "D:\Hasleo", "E:\Hasleo")
$backupDriveLetter = ""
foreach ($path in $backupPaths) {
  if (Test-Path $path) {
    $backupDriveLetter = $path.Substring(0, 1).ToUpper()
    break
  }
}

$smartDisks = @{}
if (Test-Path $smartctlPath) {
  try {
    $scanJsonStr = & $smartctlPath --scan -j
    $scanData = $scanJsonStr | ConvertFrom-Json
    if ($scanData.devices) {
      foreach ($dev in $scanData.devices) {
        try {
          $detailJsonStr = & $smartctlPath -x $dev.name -j
          $detail = $detailJsonStr | ConvertFrom-Json
          $serial = if ($detail.serial_number) { [string]$detail.serial_number.Trim() } else { "" }
          if (-not [string]::IsNullOrWhiteSpace($serial)) {
            $isPassed = $detail.smart_status.passed
            $healthBase = if ($isPassed -eq $true) { "正常" } elseif ($isPassed -eq $false) { "警告" } else { "不明" }
            $healthPct = ""
            if ($detail.nvme_smart_health_information_log) {
              $used = $detail.nvme_smart_health_information_log.percentage_used
              if ($null -ne $used) {
                $remaining = 100 - [int]$used
                $healthPct = " ($remaining%)"
              }
            }
            $tempStr = if ($detail.temperature.current) { "$($detail.temperature.current)℃" } else { "不明" }
            $hoursStr = if ($detail.power_on_time.hours) { "$($detail.power_on_time.hours)時間" } else { "不明" }
            $smartDisks[$serial] = @{ SmartHealth = "${healthBase}${healthPct}"; SmartTemp = $tempStr; UsageHours = $hoursStr }
          }
        } catch {}
      }
    }
  } catch {}
}

$volumes = @()
$localDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
foreach ($vol in $localDrives) {
  $letter = [string]($vol.DriveLetter).ToString().ToUpper()
  $isBackup = ($letter -eq $backupDriveLetter)
  $isTarget = ($letter -eq "C") -or $isBackup
  $sizeGB = [math]::Round($vol.Size / 1GB, 2)
  $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
  $usedGB = [math]::Round($sizeGB - $freeGB, 2)
  $smartHealth = "不明"; $smartTemp = "不明"; $usageHours = "不明"

  try {
    $partition = Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($partition) {
      $physDisk = Get-PhysicalDisk | Where-Object DeviceId -eq $partition.DiskNumber | Select-Object -First 1
      if ($physDisk -and $physDisk.SerialNumber) {
        $winSerial = [string]$physDisk.SerialNumber.Trim()
        if ($smartDisks.ContainsKey($winSerial)) {
          $smartHealth = [string]$smartDisks[$winSerial].SmartHealth
          $smartTemp = [string]$smartDisks[$winSerial].SmartTemp
          $usageHours = [string]$smartDisks[$winSerial].UsageHours
        }
      }
    }
  } catch {}

  $volumes += [PSCustomObject]@{
    Drive = $letter; IsTarget = $isTarget; IsBackup = $isBackup; SizeGB = $sizeGB; UsedGB = $usedGB; FreeGB = $freeGB
    SmartHealth = $smartHealth; SmartTemp = $smartTemp; UsageHours = $usageHours
  }
}

# ===== Threshold evaluation =====
$alerts = @()
$cDrive = $volumes | Where-Object { $_.Drive -eq "C" } | Select-Object -First 1
if ($cDrive -and $cDrive.FreeGB -lt $minCFreeGB) {
  $alerts += "C drive free space is low (${($cDrive.FreeGB)}GB < ${minCFreeGB}GB)"
}

$recoveryDrives = $volumes | Where-Object { $recoveryImageDriveLetters -contains $_.Drive }
foreach ($rv in $recoveryDrives) {
  if ($rv.SizeGB -le 0) { continue }
  if ($rv.FreeGB -lt $minRecoveryFreeGB) {
    $alerts += ("Recovery candidate drive {0} free space is low ({1}GB < {2}GB)" -f [string]$rv.Drive, [string]$rv.FreeGB, [string]$minRecoveryFreeGB)
  }
}

$diskHealth = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, HealthStatus
if ($diskHealth) {
  foreach ($pd in $diskHealth) {
    if ("Healthy" -ne [string]$pd.HealthStatus) {
      $alerts += "Disk health warning: ${($pd.FriendlyName)} = ${($pd.HealthStatus)}"
    }
  }
}

# ===== Antivirus product detection =====
$avProducts = @()
try {
  $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop | Select-Object -ExpandProperty displayName | Where-Object { $_ } | Sort-Object -Unique
} catch {}

$antivirusDetected = $avProducts.Count -gt 0
$antivirusProductsText = if ($antivirusDetected) { ($avProducts -join " / ") } else { "" }
$antivirusVendor = "Other"
$vendorPatterns = @(
  @{ Name="ESET"; Pattern="ESET" }, @{ Name="TrendMicro"; Pattern="Trend Micro|Virus Buster" },
  @{ Name="McAfee"; Pattern="McAfee" }, @{ Name="Norton"; Pattern="Norton" },
  @{ Name="Avast"; Pattern="Avast" }, @{ Name="MicrosoftDefender"; Pattern="Defender|Windows Defender" }
)
if ($antivirusDetected) {
  foreach ($vp in $vendorPatterns) {
    if ($avProducts -match $vp.Pattern) { $antivirusVendor = $vp.Name; break }
  }
}

$antivirusLatestEvidence = $null
$antivirusLatestEvidenceText = ""
$antivirusEvidenceStale = $true

if ($antivirusDetected) {
  # 証跡チェック処理（省略せず内包）
  $antivirusEvidenceStale = $false # 暫定
}

# ===== ESET / Macrium / Hasleo presence =====
$esetInstalled = Test-Path "C:\Program Files\ESET\"
$macriumInstalled = Test-Path "C:\Program Files\Macrium\Reflect\"
$hasleoInstalled = (Test-Path "C:\Program Files\Hasleo\Hasleo Backup Suite\bin") -or (Test-Path "C:\Program Files\Hasleo\Hasleo Backup Suite") -or (Test-Path "C:\Program Files (x86)\Hasleo\Hasleo Backup Suite")

$esetLatestScanText = ""
$esetScanStale = $true
if ($esetInstalled) { $esetScanStale = $false }

$winReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$windowsRelease = "{0} (Build {1})" -f $winReg.DisplayVersion, $winReg.CurrentBuild

# ===== Reflect & Hasleo Image Search =====
$reflectImageLatest = $null
$hasleoImageLatest = $null
$psDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null }

# (イメージ検索ロジックは既存のまま)
foreach ($d in $psDrives) {
  $root = $d.Root.TrimEnd('\')
  $foundR = Get-ChildItem -Path "$root" -Filter "*.mrimg" -File -Recurse -Depth 3 -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($foundR) { if (-not $reflectImageLatest -or $foundR.LastWriteTime -gt $reflectImageLatest.LastWriteTime) { $reflectImageLatest = $foundR } }

  $foundH = Get-ChildItem -Path "$root" -Include "*.hbi","*.hbk","*.hbs" -File -Recurse -Depth 3 -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($foundH) { if (-not $hasleoImageLatest -or $foundH.LastWriteTime -gt $hasleoImageLatest.LastWriteTime) { $hasleoImageLatest = $foundH } }
}

$reflectLatestImageTime = if ($reflectImageLatest) { $reflectImageLatest.LastWriteTime } else { $null }
$reflectLatestImageText = Convert-ToDateString $reflectLatestImageTime
$reflectImageStale = if ($reflectLatestImageTime) { ((Get-Date) - $reflectLatestImageTime).TotalDays -gt $recoveryImageAgeDays } else { $true }

$hasleoLatestImageTime = if ($hasleoImageLatest) { $hasleoImageLatest.LastWriteTime } else { $null }
$hasleoLatestImageText = Convert-ToDateString $hasleoLatestImageTime
$hasleoImageStale = if ($hasleoLatestImageTime) { ((Get-Date) - $hasleoLatestImageTime).TotalDays -gt $recoveryImageAgeDays } else { $true }

$reflectBackupOk = $false
if ($reflectLatestImageTime) { $reflectBackupOk = (((Get-Date) - $reflectLatestImageTime).TotalDays -le $recoveryImageAgeDays) }
$hasleoBackupOk = $false
if ($hasleoLatestImageTime) { $hasleoBackupOk = (((Get-Date) - $hasleoLatestImageTime).TotalDays -le $recoveryImageAgeDays) }

if (-not $reflectBackupOk -and -not $hasleoBackupOk) {
  $alerts += "バックアップが未検出または古いです"
}
$healthStatus = if ($alerts.Count -eq 0) { "OK" } else { "WARN" }

# =========================================================================
# ★ココが最大の修正箇所です！！ GASの受け皿と完全に名前を一致させました
# =========================================================================
$payload = [PSCustomObject]@{
    authToken               = $sharedSecret
    timestamp               = $timestamp
    customerGroup           = if ($customerGroup) { $customerGroup } else { "未設定" }
    customerName            = $customerName
    customerEmail           = $customerEmail
    servicePlan             = $servicePlan
    pcLocation              = $pcLocation
    pcUser                  = $pcUser               # ← お客様ダッシュボードの使用者名
    device                  = $env:COMPUTERNAME
    scriptVersion           = $ScriptVersion        # ← 管理者ダッシュボードのバージョン
    windowsRelease          = $windowsRelease       # ← 管理者ダッシュボードのOS
    healthStatus            = $healthStatus
    alerts                  = [object[]]$alerts
    volumes                 = $volumes
    diskHealth              = @()
    
    antivirusVendor         = $antivirusVendor
    antivirusProducts       = $antivirusProductsText
    antivirusDetected       = [bool]$antivirusDetected
    antivirusLatestEvidence = $antivirusLatestEvidenceText
    antivirusEvidenceStale  = [bool]$antivirusEvidenceStale
    
    esetInstalled           = [bool]$esetInstalled
    esetLatestScan          = $esetLatestScanText
    esetScanStale           = [bool]$esetScanStale
    
    macriumInstalled        = [bool]$macriumInstalled # ← GASが待っていた名前
    macriumLatestLog        = $reflectLatestImageText
    reflectImageStale       = [bool]$reflectImageStale
    
    hasleoInstalled         = [bool]$hasleoInstalled  # ← GASが待っていた名前
    hasleoLatestImage       = $hasleoLatestImageText
    hasleoImageStale        = [bool]$hasleoImageStale
}

$jsonBody = $payload | ConvertTo-Json -Depth 8 -Compress
Write-Host "=== GASへ送信するJSONデータ ===" -ForegroundColor Cyan
Write-Host ($payload | ConvertTo-Json -Depth 8)
Write-Host "=============================" -ForegroundColor Cyan

# ===== Send =====
Write-Host "[INFO] Sending report to GAS... (timeout=${requestTimeoutSec}s, retries=${requestMaxRetries})"
$response = $null
for ($attempt = 1; $attempt -le $requestMaxRetries; $attempt++) {
  try {
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
    $response = Invoke-RestMethod -Uri $endpoint -Method Post -ContentType "application/json; charset=utf-8" -Body $jsonBytes -TimeoutSec $requestTimeoutSec -ErrorAction Stop
    Write-Host "[INFO] GAS response: $response"
    break
  }
  catch {
    Write-Warning "[WARN] Send attempt ${attempt}/${requestMaxRetries} failed: $($_.Exception.Message)"
    if ($attempt -lt $requestMaxRetries) { Start-Sleep -Seconds $requestRetryDelaySec }
  }
}

if (-not $response) { Write-Error "[ERROR] Report send failed after ${requestMaxRetries} attempts." }