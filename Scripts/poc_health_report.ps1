# PowerShell PoC health report sender (Windows 11)
# Usage:
#   1) Replace $endpoint with your GAS Web App URL
#   2) Set $customerName / $sharedSecret
#   3) Run: powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File .\poc_health_report.ps1

# ===== Settings =====
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $scriptDir "client_config.json"
$scriptVersion = "2026.03.01.1"

$endpoint = ""
$deviceName = $env:COMPUTERNAME
$customerName = "Customer-Name-Here"
$sharedSecret = "CHANGE_ME"
$timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
$requestTimeoutSec = 60
$requestMaxRetries = 2
$requestRetryDelaySec = 5
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::Expect100Continue = $false

if (Test-Path $configPath) {
  try {
    $cfg = Get-Content -Path $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($cfg.endpoint) { $endpoint = [string]$cfg.endpoint }
    if ($cfg.customerName) { $customerName = [string]$cfg.customerName }
    if ($cfg.sharedSecret) { $sharedSecret = [string]$cfg.sharedSecret }
    if ($cfg.deviceName) { $deviceName = [string]$cfg.deviceName }
    if ($cfg.requestTimeoutSec) { $requestTimeoutSec = [int]$cfg.requestTimeoutSec }
    if ($cfg.requestMaxRetries) { $requestMaxRetries = [int]$cfg.requestMaxRetries }
    if ($cfg.requestRetryDelaySec) { $requestRetryDelaySec = [int]$cfg.requestRetryDelaySec }
    Write-Host "[INFO] Loaded client config: $configPath"
  } catch {
    Write-Warning "[WARN] Failed to load client config ($configPath): $($_.Exception.Message)"
  }
}

if ([string]::IsNullOrWhiteSpace($endpoint) -or $endpoint -match "PUT_YOUR_GAS_ID") {
  Write-Error "[ERROR] endpoint is not configured. Set endpoint in client_config.json"
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

# ===== Volume info =====
$volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.Size -gt 0 } | ForEach-Object {
  $sizeGB = [Math]::Round($_.Size / 1GB, 2)
  $freeGB = [Math]::Round($_.SizeRemaining / 1GB, 2)
  [PSCustomObject]@{
    Drive = $_.DriveLetter
    FileSystem = $_.FileSystem
    SizeGB = $sizeGB
    FreeGB = $freeGB
    UsedGB = [Math]::Round($sizeGB - $freeGB, 2)
    DiskNumber = $null
    UsageHours = $null
  }
}

# ===== Physical disk health / usage hours =====
$diskHealth = @()
try {
  $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
  foreach ($disk in $physicalDisks) {
    $powerOnHours = $null
    try {
      $reliability = Get-StorageReliabilityCounter -PhysicalDisk $disk -ErrorAction Stop
      $powerOnHours = $reliability.PowerOnHours
    } catch {
      $powerOnHours = $null
    }

    $diskHealth += [PSCustomObject]@{
      DeviceId = $disk.DeviceId
      FriendlyName = $disk.FriendlyName
      MediaType = $disk.MediaType
      HealthStatus = $disk.HealthStatus
      OperationalStatus = ($disk.OperationalStatus -join ',')
      SizeGB = [Math]::Round($disk.Size / 1GB, 2)
      PowerOnHours = $powerOnHours
    }
  }
} catch {
  $diskHealth = @()
}

# ===== Volume to disk mapping (for usage hours in VolumesJSON) =====
foreach ($v in $volumes) {
  try {
    $partition = Get-Partition -DriveLetter $v.Drive -ErrorAction Stop | Select-Object -First 1
    if ($partition) {
      $diskNumber = [int]$partition.DiskNumber
      $v.DiskNumber = $diskNumber
      $matchedDisk = $diskHealth | Where-Object { $_.DeviceId -eq $diskNumber } | Select-Object -First 1
      if ($matchedDisk -and $null -ne $matchedDisk.PowerOnHours) {
        $v.UsageHours = [int64]$matchedDisk.PowerOnHours
      }
    }
  } catch {
    # leave DiskNumber / UsageHours as null
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

# ===== Payload =====
$payload = [PSCustomObject]@{
  device = $deviceName
  customerName = $customerName
  scriptVersion = $scriptVersion
  timestamp = $timestamp
  volumes = $volumes
  diskHealth = $diskHealth
  windowsRelease = $windowsRelease
  healthStatus = $healthStatus
  alerts = $alerts
  minCFreeGB = $minCFreeGB
  minRecoveryFreeGB = $minRecoveryFreeGB
  recoveryDrives = $recoveryImageDriveLetters
  antivirusDetected = $antivirusDetected
  antivirusVendor = $antivirusVendor
  antivirusProducts = $antivirusProductsText
  antivirusLatestEvidence = $antivirusLatestEvidenceText
  antivirusEvidenceStale = $antivirusEvidenceStale
  esetInstalled = $esetInstalled
  esetServiceStatus = $esetServiceStatus
  esetLatestScan = $esetLatestScanText
  esetScanStale = $esetScanStale
  macriumInstalled = $macriumInstalled
  macriumLatestLog = $reflectLatestImageText
  reflectImageStale = $reflectImageStale
  hasleoInstalled = $hasleoInstalled
  hasleoLatestImage = $hasleoLatestImageText
  hasleoLatestPath = $hasleoLatestPath
  hasleoImageStale = $hasleoImageStale
  authToken = $sharedSecret
}

# ===== Send =====
$jsonBody = $payload | ConvertTo-Json -Depth 8
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
    Write-Warning "[WARN] Send attempt ${attempt}/${requestMaxRetries} failed (Invoke-RestMethod): $($_.Exception.Message)"

    try {
      $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
      $fallback = Invoke-WebRequest -Uri $endpoint -Method Post -ContentType "application/json; charset=utf-8" -Body $jsonBytes -TimeoutSec $requestTimeoutSec -UseBasicParsing -ErrorAction Stop
      $response = $fallback.Content
      Write-Host "[INFO] GAS response (fallback): $response"
      break
    }
    catch {
      Write-Warning "[WARN] Send attempt ${attempt}/${requestMaxRetries} fallback failed (Invoke-WebRequest): $($_.Exception.Message)"
    }

    if ($attempt -lt $requestMaxRetries) {
      Start-Sleep -Seconds $requestRetryDelaySec
    }
  }
}

if (-not $response) {
  Write-Error "[ERROR] Report send failed after ${requestMaxRetries} attempts. Check endpoint/network/proxy settings."
}
