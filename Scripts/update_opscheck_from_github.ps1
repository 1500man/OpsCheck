#requires -Version 5.1
param(
    [switch]$SkipPendingPromote
)

<#
Virgo Standard V4 - update_opscheck_from_github.ps1
- GitHub Release から最新版を取得
- HTML誤保存をブロック
- updater 自身は .pending へ退避し、安全に昇格
- 更新ログを HMAC 署名付きで GAS へ送信
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$TargetDir = 'C:\OpsCheck'
$ConfigPath = Join-Path $TargetDir 'config.dpapi'
$ScriptVersion = '5.0.0'

$ReleaseOwner = if ($env:VIRGO_RELEASE_OWNER) { $env:VIRGO_RELEASE_OWNER } else { '1500man' }
$ReleaseRepo  = if ($env:VIRGO_RELEASE_REPO)  { $env:VIRGO_RELEASE_REPO }  else { 'Virgo-Release' }
$ReleaseBaseUrl = "https://github.com/$ReleaseOwner/$ReleaseRepo/releases/latest/download"

$FilesToDeploy = @(
    'poc_health_report.ps1',
    'update_opscheck_from_github.ps1'
)

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Ok([string]$Message) {
    Write-Host "[ OK ] $Message" -ForegroundColor Green
}

function Throw-UpdateError([string]$Message) {
    throw $Message
}

function Ensure-TargetDirectory {
    if (-not (Test-Path -LiteralPath $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
}

function Get-CurrentScriptPath {
    if ($PSCommandPath) { return $PSCommandPath }
    return $MyInvocation.MyCommand.Path
}

function Get-DeviceUuid {
    try {
        $uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) { return $uuid.Trim() }
    } catch {}

    try {
        $uuid = (Get-WmiObject Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) { return $uuid.Trim() }
    } catch {}

    Throw-UpdateError 'UUID の取得に失敗しました。'
}

function Read-ProtectedConfig {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        Throw-UpdateError "config.dpapi が見つかりません: $ConfigPath"
    }

    Add-Type -AssemblyName System.Security

    try {
        $encryptedBytes = [System.IO.File]::ReadAllBytes($ConfigPath)
        $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedBytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $plainText = [System.Text.Encoding]::UTF8.GetString($plainBytes)
        if ([string]::IsNullOrWhiteSpace($plainText)) {
            Throw-UpdateError 'config.dpapi の復号結果が空です。'
        }

        try {
            $config = $plainText | ConvertFrom-Json -ErrorAction Stop
            $endpoint = [string]$config.endpoint
            $secret   = [string]$config.secret
        }
        catch {
            $endpoint = [Environment]::GetEnvironmentVariable('VIRGO_ENDPOINT', 'Machine')
            $secret   = $plainText
        }

        if ([string]::IsNullOrWhiteSpace($endpoint)) {
            $endpoint = [Environment]::GetEnvironmentVariable('VIRGO_ENDPOINT', 'Machine')
        }
        if ([string]::IsNullOrWhiteSpace($endpoint)) { Throw-UpdateError 'endpoint が取得できません。' }
        if ([string]::IsNullOrWhiteSpace($secret))   { Throw-UpdateError 'secret が取得できません。' }

        [PSCustomObject]@{
            Endpoint = $endpoint
            Secret   = $secret
        }
    }
    catch {
        Throw-UpdateError "config.dpapi の復号に失敗しました。$($_.Exception.Message)"
    }
}

function Get-WebErrorMessage {
    param(
        [Parameter(Mandatory = $true)][System.Exception]$Exception,
        [string]$Url
    )

    try {
        if ($Exception.Response -and $Exception.Response.StatusCode) {
            $statusCode = [int]$Exception.Response.StatusCode
            $statusText = [string]$Exception.Response.StatusDescription
            switch ($statusCode) {
                401 { return "HTTP 401 Unauthorized: $Url" }
                403 { return "HTTP 403 Forbidden: $Url" }
                404 { return "HTTP 404 Not Found: $Url" }
                default { return "HTTP $statusCode $statusText: $Url" }
            }
        }
    } catch {}

    return $Exception.Message
}

function Test-DownloadedFileLooksValid {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Throw-UpdateError "ダウンロードファイルが存在しません: $Path"
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -le 0) {
        Throw-UpdateError "ダウンロードファイルが 0 バイトです: $Path"
    }

    $headLines = @()
    try {
        $headLines = Get-Content -LiteralPath $Path -TotalCount 5 -Encoding UTF8 -ErrorAction Stop
    } catch {
        Throw-UpdateError "ダウンロードファイルの検査に失敗しました: $Path / $($_.Exception.Message)"
    }

    $joined = ($headLines -join "`n").TrimStart()
    if ($joined -match '^(<!DOCTYPE|<html|<head|<body)') {
        Throw-UpdateError "HTML が取得されました。Release asset ではなくエラーページの可能性があります: $Path"
    }
}

function Promote-PendingAssets {
    param([string]$CurrentScriptPath)

    foreach ($file in $FilesToDeploy) {
        $dest = Join-Path $TargetDir $file
        $pending = "$dest.pending"

        if (-not (Test-Path -LiteralPath $pending)) { continue }

        if ($dest -ieq $CurrentScriptPath) {
            continue
        }

        try {
            $backup = "$dest.bak"
            if (Test-Path -LiteralPath $dest) {
                Copy-Item -LiteralPath $dest -Destination $backup -Force -ErrorAction Stop
            }
            Move-Item -LiteralPath $pending -Destination $dest -Force -ErrorAction Stop
            Write-Ok "保留更新を適用しました: $file"
        }
        catch {
            Write-Warn "保留更新の適用に失敗しました: $file / $($_.Exception.Message)"
        }
    }
}

function Start-SelfPromotionHelper {
    param(
        [Parameter(Mandatory = $true)][string]$CurrentScriptPath,
        [Parameter(Mandatory = $true)][string]$PendingPath
    )

    $helperPath = Join-Path $TargetDir 'apply_pending_self_update.ps1'
    $helperContent = @'
param(
    [Parameter(Mandatory = $true)][string]$CurrentScript,
    [Parameter(Mandatory = $true)][string]$PendingScript,
    [Parameter(Mandatory = $true)][int]$ParentPid
)

$deadline = (Get-Date).AddMinutes(2)
while ((Get-Process -Id $ParentPid -ErrorAction SilentlyContinue) -and ((Get-Date) -lt $deadline)) {
    Start-Sleep -Seconds 1
}

if (-not (Test-Path -LiteralPath $PendingScript)) {
    exit 1
}

try {
    $backup = "$CurrentScript.bak"
    if (Test-Path -LiteralPath $CurrentScript) {
        Copy-Item -LiteralPath $CurrentScript -Destination $backup -Force -ErrorAction Stop
    }

    Copy-Item -LiteralPath $PendingScript -Destination "$CurrentScript.new" -Force -ErrorAction Stop
    Move-Item -LiteralPath "$CurrentScript.new" -Destination $CurrentScript -Force -ErrorAction Stop
    Remove-Item -LiteralPath $PendingScript -Force -ErrorAction SilentlyContinue

    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $CurrentScript,
        "-SkipPendingPromote"
    ) | Out-Null
    exit 0
}
catch {
    exit 1
}
'@

    Set-Content -LiteralPath $helperPath -Value $helperContent -Encoding UTF8 -Force

    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $helperPath,
        '-CurrentScript', $CurrentScriptPath,
        '-PendingScript', $PendingPath,
        '-ParentPid', $PID
    ) | Out-Null
}

function Maybe-Promote-SelfPending {
    param([Parameter(Mandatory = $true)][string]$CurrentScriptPath)

    if ($SkipPendingPromote) { return }

    $pendingPath = "$CurrentScriptPath.pending"
    if (-not (Test-Path -LiteralPath $pendingPath)) { return }

    Write-Info "自分自身の保留更新を検出しました。昇格処理を開始します。"
    Start-SelfPromotionHelper -CurrentScriptPath $CurrentScriptPath -PendingPath $pendingPath
    exit 0
}

function Compute-Signature {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Uuid,
        [Parameter(Mandatory = $true)][string]$UnixTimestamp,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$PayloadBase64
    )

    $signData = "$Uuid|$UnixTimestamp|$Nonce|$PayloadBase64"
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
        $hashBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signData))
        [Convert]::ToBase64String($hashBytes)
    }
    finally {
        $hmac.Dispose()
    }
}

function Send-UpdateLog {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$DeviceSecret,
        [Parameter(Mandatory = $true)][string]$Uuid,
        [Parameter(Mandatory = $true)][string]$CustomerGroup,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][int]$SuccessCount,
        [Parameter(Mandatory = $true)][string]$SuccessFiles,
        [Parameter(Mandatory = $true)][int]$FailedCount,
        [Parameter(Mandatory = $true)][string]$FailedFiles,
        [Parameter(Mandatory = $true)][string]$Errors
    )

    $innerPayload = [ordered]@{
        action       = 'updateLog'
        device       = $env:COMPUTERNAME
        customerGroup= $CustomerGroup
        uuid         = $Uuid
        timestamp    = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
        updaterVer   = $ScriptVersion
        message      = $Message
        successCount = $SuccessCount
        successFiles = $SuccessFiles
        failedCount  = $FailedCount
        failedFiles  = $FailedFiles
        errors       = $Errors
    }

    $innerJson     = $innerPayload | ConvertTo-Json -Compress -Depth 6
    $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($innerJson))
    $unixTimestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $nonce         = [Guid]::NewGuid().ToString()
    $signature     = Compute-Signature -Secret $DeviceSecret -Uuid $Uuid -UnixTimestamp $unixTimestamp -Nonce $nonce -PayloadBase64 $payloadBase64

    $outerPayload = [ordered]@{
        signature     = $signature
        uuid          = $Uuid
        timestamp     = $unixTimestamp
        nonce         = $nonce
        payloadBase64 = $payloadBase64
    }

    $outerJson = $outerPayload | ConvertTo-Json -Compress -Depth 6
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($outerJson)

    try {
        Invoke-RestMethod -Uri $Endpoint -Method Post -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warn "更新ログ送信に失敗しました: $($_.Exception.Message)"
    }
}

function Download-And-StageAsset {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$CurrentScriptPath
    )

    $url = "$ReleaseBaseUrl/$FileName"
    $dest = Join-Path $TargetDir $FileName
    $tmp  = "$dest.tmp"

    try {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }

        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -ErrorAction Stop
        Test-DownloadedFileLooksValid -Path $tmp

        if ($dest -ieq $CurrentScriptPath) {
            $pending = "$dest.pending"
            Move-Item -LiteralPath $tmp -Destination $pending -Force -ErrorAction Stop
            return [PSCustomObject]@{
                File    = $FileName
                Success = $true
                Error   = ''
                StagedAsPending = $true
            }
        }

        $backup = "$dest.bak"
        if (Test-Path -LiteralPath $dest) {
            Copy-Item -LiteralPath $dest -Destination $backup -Force -ErrorAction Stop
        }
        Move-Item -LiteralPath $tmp -Destination $dest -Force -ErrorAction Stop

        return [PSCustomObject]@{
            File    = $FileName
            Success = $true
            Error   = ''
            StagedAsPending = $false
        }
    }
    catch {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }

        return [PSCustomObject]@{
            File    = $FileName
            Success = $false
            Error   = (Get-WebErrorMessage -Exception $_.Exception -Url $url)
            StagedAsPending = $false
        }
    }
}

try {
    Ensure-TargetDirectory
    $currentScriptPath = Get-CurrentScriptPath

    Promote-PendingAssets -CurrentScriptPath $currentScriptPath
    Maybe-Promote-SelfPending -CurrentScriptPath $currentScriptPath

    $config = Read-ProtectedConfig
    $endpoint = [string]$config.Endpoint
    $deviceSecret = [string]$config.Secret
    $customerGroup = [Environment]::GetEnvironmentVariable('VIRGO_CUSTOMER_GROUP', 'Machine')
    if ([string]::IsNullOrWhiteSpace($customerGroup)) {
        $customerGroup = ''
    }

    $uuid = Get-DeviceUuid

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($file in $FilesToDeploy) {
        Write-Info "更新取得中: $file"
        $result = Download-And-StageAsset -FileName $file -CurrentScriptPath $currentScriptPath
        $results.Add($result)

        if ($result.Success) {
            if ($result.StagedAsPending) {
                Write-Ok "$file は .pending として保留更新しました。"
            } else {
                Write-Ok "$file を更新しました。"
            }
        } else {
            Write-Warn "$file の更新に失敗しました。$($result.Error)"
        }
    }

    $successes = @($results | Where-Object { $_.Success })
    $failures  = @($results | Where-Object { -not $_.Success })

    $successFiles = ($successes | ForEach-Object { $_.File }) -join ', '
    $failedFiles  = ($failures  | ForEach-Object { $_.File }) -join ', '
    $errors       = ($failures  | ForEach-Object { "$($_.File): $($_.Error)" }) -join ' | '

    $message = if ($failures.Count -eq 0) {
        '更新処理完了: すべて成功'
    } else {
        '更新処理完了: 一部失敗'
    }

    Send-UpdateLog `
        -Endpoint $endpoint `
        -DeviceSecret $deviceSecret `
        -Uuid $uuid `
        -CustomerGroup $customerGroup `
        -Message $message `
        -SuccessCount $successes.Count `
        -SuccessFiles $successFiles `
        -FailedCount $failures.Count `
        -FailedFiles $failedFiles `
        -Errors $errors

    if ($failures.Count -gt 0) {
        exit 1
    }

    exit 0
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}