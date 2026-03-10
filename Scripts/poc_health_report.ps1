# PowerShell PoC health report sender (Windows 11)
# Usage:
#   1) Set endpoint/sharedSecret in system_config.json
#   2) Set customer/device info in client_info.json
#   3) Run: powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File .\poc_health_report.ps1

# ===== Settings =====
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$clientInfoPath = Join-Path $scriptDir "client_info.json"
$systemConfigPath = Join-Path $scriptDir "system_config.json"
$ScriptVersion = "2026.03.01.1"

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

  # Merge both configs in memory. system_config values override on key conflict.
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

# Keep backward compatibility: if customerName is not explicitly set, reuse customerGroup.
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

# --- 1) バックアップドライブの特定 ---
$backupPaths = @("D:\Macrium", "E:\Macrium", "D:\Hasleo", "E:\Hasleo")
$backupDriveLetter = ""
foreach ($path in $backupPaths) {
  if (Test-Path $path) {
    $backupDriveLetter = $path.Substring(0, 1).ToUpper()
    break
  }
}

# --- 2) smartctl で物理ディスク情報を取得（シリアル番号辞書） ---
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

            $smartDisks[$serial] = @{
              SmartHealth = "${healthBase}${healthPct}"
              SmartTemp   = $tempStr
              UsageHours  = $hoursStr
            }
          }
        } catch {
          # smartctl詳細取得失敗時はスキップ
        }
      }
    }
  } catch {
    # smartctl全体失敗時はスキップ
  }
}

# --- 3) Windowsドライブ情報にSMART情報を合体 ---
$volumes = @()
$localDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }

foreach ($vol in $localDrives) {
  $letter = [string]($vol.DriveLetter).ToString().ToUpper()
  $isBackup = ($letter -eq $backupDriveLetter)
  $isTarget = ($letter -eq "C") -or $isBackup

  $sizeGB = [math]::Round($vol.Size / 1GB, 2)
  $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
  $usedGB = [math]::Round($sizeGB - $freeGB, 2)

  $smartHealth = "不明"
  $smartTemp = "不明"
  $usageHours = "不明"

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
  } catch {
    # 個別ドライブ失敗時は不明のまま
  }

  $volumes += [PSCustomObject]@{
    Drive       = $letter
    IsTarget    = $isTarget
    IsBackup    = $isBackup
    SizeGB      = $sizeGB
    UsedGB      = $usedGB
    FreeGB      = $freeGB
    SmartHealth = $smartHealth
    SmartTemp   = $smartTemp
    UsageHours  = $usageHours
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
  # Skip placeholder/offline volumes (e.g. removable drive letters with 0 byte size)
  if ($rv.SizeGB -le 0) {
    continue
  }

  if ($rv.FreeGB -lt $minRecoveryFreeGB) {
    $alerts += ("Recovery candidate drive {0} free space is low ({1}GB < {2}GB)" -f [string]$rv.Drive, [string]$rv.FreeGB, [string]$minRecoveryFreeGB)
  }
}

foreach ($pd in $diskHealth) {
  if ("Healthy" -ne [string]$pd.HealthStatus) {
    $alerts += "Disk health warning: ${($pd.FriendlyName)} = ${($pd.HealthStatus)}"
  }
}

# ===== Antivirus product detection (multi-vendor) =====
$avProducts = @()
try {
  $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop |
    Select-Object -ExpandProperty displayName |
    Where-Object { $_ } |
    Sort-Object -Unique
} catch {
  $avProducts = @()
}

$antivirusDetected = $avProducts.Count -gt 0
$antivirusProductsText = if ($antivirusDetected) { ($avProducts -join " / ") } else { "" }

$antivirusVendor = ""
$vendorPatterns = @(
  @{ Name = "ESET"; Pattern = "ESET" },
  @{ Name = "TrendMicro"; Pattern = "Trend Micro|Virus Buster" },
  @{ Name = "McAfee"; Pattern = "McAfee" },
  @{ Name = "VirusSecurityZERO"; Pattern = "Virus Security|ZERO" },
  @{ Name = "SuperSecurity"; Pattern = "Super Security" },
  @{ Name = "Norton"; Pattern = "Norton" },
  @{ Name = "AVG"; Pattern = "AVG" },
  @{ Name = "Kingsoft"; Pattern = "Kingsoft" },
  @{ Name = "Avast"; Pattern = "Avast" },
  @{ Name = "MicrosoftDefender"; Pattern = "Defender|Windows Defender" }
)

if ($antivirusDetected) {
  foreach ($vp in $vendorPatterns) {
    if ($avProducts -match $vp.Pattern) {
      $antivirusVendor = $vp.Name
      break
    }
  }
  if (-not $antivirusVendor) {
    $antivirusVendor = "Other"
  }
}

$antivirusLatestEvidence = $null
$antivirusLatestEvidenceText = ""
$antivirusEvidenceStale = $null

$avLogSources = @(
  @{ Pattern = "ESET"; Paths = @(
      "C:\ProgramData\ESET\ESET Security\Logs",
      "C:\ProgramData\ESET\ESET Endpoint Antivirus\Logs",
      "C:\ProgramData\ESET\ESET Endpoint Security\Logs"
    ) },
  @{ Pattern = "Trend Micro|Virus Buster"; Paths = @(
      "C:\ProgramData\Trend Micro",
      "C:\ProgramData\TrendMicro"
    ) },
  @{ Pattern = "McAfee"; Paths = @(
      "C:\ProgramData\McAfee"
    ) },
  @{ Pattern = "Norton"; Paths = @(
      "C:\ProgramData\Norton"
    ) },
  @{ Pattern = "AVG"; Paths = @(
      "C:\ProgramData\AVG"
    ) },
  @{ Pattern = "Avast"; Paths = @(
      "C:\ProgramData\Avast Software"
    ) },
  @{ Pattern = "Kingsoft"; Paths = @(
      "C:\ProgramData\Kingsoft"
    ) },
  @{ Pattern = "Defender|Windows Defender"; Paths = @(
      "C:\ProgramData\Microsoft\Windows Defender\Scans",
      "C:\ProgramData\Microsoft\Windows Defender\Support"
    ) }
)

if ($antivirusDetected) {
  $targetPaths = @()
  foreach ($av in $avProducts) {
    foreach ($src in $avLogSources) {
      if ([string]$av -match $src.Pattern) {
        $targetPaths += $src.Paths
      }
    }
  }
  $targetPaths = $targetPaths | Select-Object -Unique

  foreach ($p in $targetPaths) {
    if (Test-Path $p) {
      $candidate = Get-ChildItem -Path $p -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
      if ($candidate) {
        if (-not $antivirusLatestEvidence -or $candidate.LastWriteTime -gt $antivirusLatestEvidence) {
          $antivirusLatestEvidence = $candidate.LastWriteTime
        }
      }
    }
  }

  $antivirusLatestEvidenceText = Convert-ToDateString $antivirusLatestEvidence
  $antivirusEvidenceStale = if ($antivirusLatestEvidence) {
    ((Get-Date) - $antivirusLatestEvidence).TotalDays -gt $antivirusEvidenceAgeDays
  } else { $true }

  if ($antivirusEvidenceStale) {
    $alerts += "Antivirus evidence is older than ${antivirusEvidenceAgeDays} days or not found"
  }
}

# ===== ESET / Macrium presence =====
$esetInstalled = Test-Path "C:\Program Files\ESET\"
$macriumInstalled = Test-Path "C:\Program Files\Macrium\Reflect\"
$hasleoInstalled = (Test-Path "C:\Program Files\Hasleo\Hasleo Backup Suite\") -or (Test-Path "C:\Program Files (x86)\Hasleo\Hasleo Backup Suite\")

# ===== ESET detail =====
$esetService = Get-Service -Name "ekrn" -ErrorAction SilentlyContinue
$esetServiceStatus = if ($esetService) { $esetService.Status.ToString() } else { "NotFound" }

$esetLatestScan = $null
$esetLatestScanText = ""
$esetScanStale = $null

if ($esetInstalled) {
  $esetLogCandidates = @(
    "C:\ProgramData\ESET\ESET Security\Logs",
    "C:\ProgramData\ESET\ESET Endpoint Antivirus\Logs",
    "C:\ProgramData\ESET\ESET Endpoint Security\Logs"
  )
  $esetLogPath = $esetLogCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  $esetLatestScan = if ($esetLogPath) {
    Get-ChildItem $esetLogPath -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 | ForEach-Object { $_.LastWriteTime }
  } else { $null }
  $esetLatestScanText = Convert-ToDateString $esetLatestScan
  $esetScanStale = if ($esetLatestScan) {
    ((Get-Date) - $esetLatestScan).TotalDays -gt $esetScanAgeDays
  } else { $true }
  if ($esetScanStale) {
    $alerts += "ESET scan evidence is older than ${esetScanAgeDays} days"
  }
}

# ===== Windows release info =====
$winReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$windowsRelease = "{0} (Build {1})" -f $winReg.DisplayVersion, $winReg.CurrentBuild

# ===== Reflect image latest creation (search across changing drive letters) =====
$reflectImageLatest = $null
$psDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null }

foreach ($d in $psDrives) {
  $root = $d.Root.TrimEnd('\\')
  $candidateRoots = @(
    "$root\\",
    "$root\\Macrium",
    "$root\\Reflect",
    "$root\\Backup",
    "$root\\Backups",
    "$root\\Image",
    "$root\\Images"
  ) | Select-Object -Unique

  foreach ($searchRoot in $candidateRoots) {
    if (Test-Path $searchRoot) {
      $found = Get-ChildItem -Path $searchRoot -Filter "*.mrimg" -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
      if ($found) {
        if (-not $reflectImageLatest -or $found.LastWriteTime -gt $reflectImageLatest.LastWriteTime) {
          $reflectImageLatest = $found
        }
      }
    }
  }
}

$reflectLatestImageTime = if ($reflectImageLatest) { $reflectImageLatest.LastWriteTime } else { $null }
$reflectLatestImageText = Convert-ToDateString $reflectLatestImageTime
$reflectImageStale = if ($reflectLatestImageTime) {
  ((Get-Date) - $reflectLatestImageTime).TotalDays -gt $recoveryImageAgeDays
} else { $true }
if ($reflectImageStale) {
  $alerts += "Reflect image is older than ${recoveryImageAgeDays} days or not found"
}

# ===== Hasleo Backup image latest creation =====
$hasleoImageLatest = $null
$hasleoImagePatterns = @("*.hbi", "*.hbk", "*.hbc", "*.hbs", "*.dbi")
$hasleoLatestPath = ""
$hasleoEvidenceFound = $false

# Prefer Hasleo-specific roots first (including extensionless backup files)
$hasleoPreferredRoots = @()
foreach ($d in $psDrives) {
  $root = $d.Root.TrimEnd('\')
  $hasleoPreferredRoots += @(
    "$root\hasleo_imagebackup",
    "$root\Hasleo",
    "$root\Hasleo Backup Suite",
    "$root\Hasleorecovery",
    "$root\HasleoRecovery"
  )
}
$hasleoPreferredRoots = $hasleoPreferredRoots | Select-Object -Unique

foreach ($searchRoot in $hasleoPreferredRoots) {
  if (-not (Test-Path $searchRoot)) { continue }

  foreach ($pattern in $hasleoImagePatterns) {
    $found = Get-ChildItem -Path $searchRoot -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 1
    if ($found) {
      if (-not $hasleoImageLatest -or $found.LastWriteTime -gt $hasleoImageLatest.LastWriteTime) {
        $hasleoImageLatest = $found
      }
    }
  }

  if (-not $hasleoImageLatest) {
    # Some Hasleo outputs may not expose a standard extension, so fallback to newest file under Hasleo-specific roots.
    $fallbackFound = Get-ChildItem -Path $searchRoot -File -Recurse -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 1
    if ($fallbackFound) {
      if (-not $hasleoImageLatest -or $fallbackFound.LastWriteTime -gt $hasleoImageLatest.LastWriteTime) {
        $hasleoImageLatest = $fallbackFound
      }
    }
  }
}

# If nothing was found in Hasleo-specific roots, search common backup roots with Hasleo extensions only.
if (-not $hasleoImageLatest) {
  foreach ($d in $psDrives) {
    $root = $d.Root.TrimEnd('\')
    $candidateRoots = @(
      "$root\Backup",
      "$root\Backups",
      "$root\Image",
      "$root\Images",
      "$root\Hasleorecovery",
      "$root\HasleoRecovery"
    ) | Select-Object -Unique

    foreach ($searchRoot in $candidateRoots) {
      if (-not (Test-Path $searchRoot)) { continue }

      foreach ($pattern in $hasleoImagePatterns) {
        $found = Get-ChildItem -Path $searchRoot -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending |
          Select-Object -First 1
        if ($found) {
          if (-not $hasleoImageLatest -or $found.LastWriteTime -gt $hasleoImageLatest.LastWriteTime) {
            $hasleoImageLatest = $found
          }
        }
      }
    }
  }
}

$hasleoLatestImageTime = if ($hasleoImageLatest) { $hasleoImageLatest.LastWriteTime } else { $null }
$hasleoLatestImageText = Convert-ToDateString $hasleoLatestImageTime
if ($hasleoImageLatest) {
  $hasleoLatestPath = [string]$hasleoImageLatest.FullName
  $hasleoEvidenceFound = $true
}
$hasleoImageStale = $null
if ($hasleoInstalled) {
  if (-not $hasleoEvidenceFound) {
    $hasleoImageStale = $true
    $alerts += "Hasleo image evidence not found"
  } else {
    $hasleoImageStale = ((Get-Date) - $hasleoLatestImageTime).TotalDays -gt $recoveryImageAgeDays
    if ($hasleoImageStale) {
      $alerts += "Hasleo image is older than ${recoveryImageAgeDays} days"
    }
  }
}

$healthStatus = if ($alerts.Count -eq 0) { "OK" } else { "WARN" }

# ===== Payload (GASが受け取れる名前に完全に一致させる) =====
$finalHealth = if ($alerts.Count -eq 0) { "正常" } else { "警告" }

$alertsForJson = if ($alerts.Count -eq 0) { @("特になし") } else { @($alerts) }

$payload = [PSCustomObject]@{
    timestamp     = $timestamp
    customerGroup = if ($customerGroup) { $customerGroup } else { "未設定" }
    device        = $env:COMPUTERNAME
    health        = $finalHealth
    alerts        = [object[]]$alertsForJson
    volumes       = $volumes
    avStatus      = if ($antivirusDetected) { "正常" } else { "未検出" }
    eset          = if ($esetInstalled) { "正常" } else { "未検出" }
    macrium       = if ($macriumInstalled) { "正常" } else { "未検出" }
    hasleo        = if ($hasleoInstalled) { "正常" } else { "未検出" }
}

# 送信直前に中身を確認するためのログ出力
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

if (-not $response) {
  Write-Error "[ERROR] Report send failed after ${requestMaxRetries} attempts."
}




