# ====================================================================
# Virgo Premium - Secure Health Report (v2.0 要塞解錠 ＋ フル診断版)
# ====================================================================
$ErrorActionPreference = 'Stop'
$ScriptVersion = "2026.03.14.Encrypted"

# ====================================================================
# 1. 要塞解錠フェーズ（パスワードを一切持たずに金庫を開ける）
# ====================================================================
$MasterKey = [Environment]::GetEnvironmentVariable("VIRGO_MASTER_KEY", "Machine")
if ([string]::IsNullOrEmpty($MasterKey)) { exit }

$UUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
$EncFile = "C:\OpsCheck\Scripts\system_config.enc"
if (!(Test-Path $EncFile)) { exit }

$EncryptedText = Get-Content $EncFile -Raw
$Hasher = [System.Security.Cryptography.SHA256]::Create()
$KeyBytes = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$MasterKey-$UUID"))

try {
    $SecureString = $EncryptedText | ConvertTo-SecureString -Key $KeyBytes
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $ConfigJson = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $Config = $ConfigJson | ConvertFrom-Json
} catch {
    exit 
} finally {
    if ($null -ne $BSTR -and $BSTR -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) }
}

# 金庫から取り出した情報を変数にセット
$endpoint      = $Config.endpoint
$sharedSecret  = $Config.authToken
$customerGroup = $Config.customerGroup
$usbSerial     = $Config.usbSerial
$deviceName    = $env:COMPUTERNAME
$timestamp     = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")

# ====================================================================
# 2. 健康診断フェーズ（元々の高度な診断ロジック）
# ====================================================================
$minCFreeGB = 100
$minRecoveryFreeGB = 300
$recoveryImageAgeDays = 28
$recoveryImageDriveLetters = @("D", "E", "F", "G", "H", "K")

function Convert-ToDateString($value) { if ($null -eq $value) { return "" }; return ([datetime]$value).ToString("yyyy/MM/dd HH:mm:ss") }

# ===== SMARTディスク情報 =====
$smartctlPath = "C:\Program Files\smartmontools\bin\smartctl.exe"
$backupDriveLetter = ""
foreach ($path in @("D:\Macrium", "E:\Macrium", "D:\Hasleo", "E:\Hasleo")) {
  if (Test-Path $path) { $backupDriveLetter = $path.Substring(0, 1).ToUpper(); break }
}

$smartDisks = @{}
if (Test-Path $smartctlPath) {
  try {
    $scanData = & $smartctlPath --scan -j | ConvertFrom-Json
    if ($scanData.devices) {
      foreach ($dev in $scanData.devices) {
        try {
          $detail = & $smartctlPath -x $dev.name -j | ConvertFrom-Json
          $serial = if ($detail.serial_number) { [string]$detail.serial_number.Trim() } else { "" }
          if (-not [string]::IsNullOrWhiteSpace($serial)) {
            $isPassed = $detail.smart_status.passed
            $healthBase = if ($isPassed -eq $true) { "正常" } elseif ($isPassed -eq $false) { "警告" } else { "不明" }
            $healthPct = if ($detail.nvme_smart_health_information_log.percentage_used -ne $null) { " (" + (100 - [int]$detail.nvme_smart_health_information_log.percentage_used) + "%)" } else { "" }
            $tempStr = if ($detail.temperature.current) { "$($detail.temperature.current)℃" } else { "不明" }
            $hoursStr = if ($detail.power_on_time.hours) { "$($detail.power_on_time.hours)時間" } else { "不明" }
            $smartDisks[$serial] = @{ SmartHealth = "${healthBase}${healthPct}"; SmartTemp = $tempStr; UsageHours = $hoursStr }
          }
        } catch {}
      }
    }
  } catch {}
}

# ===== ボリューム情報取得 =====
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
  $volumes += [PSCustomObject]@{ Drive=$letter; IsTarget=$isTarget; IsBackup=$isBackup; SizeGB=$sizeGB; UsedGB=$usedGB; FreeGB=$freeGB; SmartHealth=$smartHealth; SmartTemp=$smartTemp; UsageHours=$usageHours }
}

$alerts = @()
$cDrive = $volumes | Where-Object { $_.Drive -eq "C" } | Select-Object -First 1
if ($cDrive -and $cDrive.FreeGB -lt $minCFreeGB) { $alerts += "C drive free space is low (${($cDrive.FreeGB)}GB < ${minCFreeGB}GB)" }

$diskHealth = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, HealthStatus
if ($diskHealth) {
  foreach ($pd in $diskHealth) { if ("Healthy" -ne [string]$pd.HealthStatus) { $alerts += "Disk health warning: ${($pd.FriendlyName)} = ${($pd.HealthStatus)}" } }
}

# ===== セキュリティソフト確認 =====
$avProducts = @()
try { $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop | Select-Object -ExpandProperty displayName | Where-Object { $_ } | Sort-Object -Unique } catch {}
$antivirusDetected = $avProducts.Count -gt 0
$antivirusProductsText = if ($antivirusDetected) { ($avProducts -join " / ") } else { "" }

# ===== バックアップソフト確認（Cドライブ除外爆速検索） =====
$macriumInstalled = Test-Path "C:\Program Files\Macrium\Reflect\"
$hasleoInstalled = (Test-Path "C:\Program Files*\Hasleo*") -or (Test-Path "C:\Program Files*\Hasleo Backup Suite*")

$reflectImageLatest = $null; $hasleoImageLatest = $null
if ($macriumInstalled -or $hasleoInstalled) {
    $psDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null -and $_.Name -ne "C" }
    foreach ($d in $psDrives) {
      $root = $d.Root.TrimEnd('\')
      if ($macriumInstalled) {
          $foundR = Get-ChildItem -Path "$root" -Filter "*.mrimg" -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
          if ($foundR) { if (-not $reflectImageLatest -or $foundR.LastWriteTime -gt $reflectImageLatest.LastWriteTime) { $reflectImageLatest = $foundR } }
      }
      if ($hasleoInstalled) {
          foreach ($ext in @("*.hbi", "*.hbk", "*.hbc", "*.hbs", "*.dbi")) {
              $foundH = Get-ChildItem -Path "$root" -Filter $ext -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
              if ($foundH) { if (-not $hasleoImageLatest -or $foundH.LastWriteTime -gt $hasleoImageLatest.LastWriteTime) { $hasleoImageLatest = $foundH } }
          }
      }
    }
}

$hasleoLatestImageTime = if ($hasleoImageLatest) { $hasleoImageLatest.LastWriteTime } else { $null }
if (-not $hasleoLatestImageTime -and $hasleoInstalled) { $alerts += "Hasleoバックアップが未検出または古いです" }

$healthStatus = if ($alerts.Count -eq 0) { "OK" } else { "WARN" }

# ====================================================================
# 3. 結合＆GASへの送信フェーズ
# ====================================================================
$payload = [PSCustomObject]@{
    action                  = "report"
    authToken               = $sharedSecret
    uuid                    = $UUID
    usbSerial               = $usbSerial
    timestamp               = $timestamp
    customerGroup           = $customerGroup
    device                  = $deviceName
    scriptVersion           = $ScriptVersion
    healthStatus            = $healthStatus
    alerts                  = [object[]]$alerts
    volumes                 = $volumes
    antivirusDetected       = [bool]$antivirusDetected
    antivirusProducts       = $antivirusProductsText
    hasleoInstalled         = [bool]$hasleoInstalled
    hasleoLatestImage       = Convert-ToDateString $hasleoLatestImageTime
}

$jsonBody = $payload | ConvertTo-Json -Depth 8 -Compress

try {
    Invoke-RestMethod -Uri $endpoint -Method Post -ContentType "application/json; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -TimeoutSec 60
    Write-Host "`n[SUCCESS] フル健康診断＆暗号化報告が完了しました！" -ForegroundColor Green
} catch {
    Write-Error "GASへの送信に失敗しました。"
}