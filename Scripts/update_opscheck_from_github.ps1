#requires -Version 5.1
<#
Virgo Standard/Lite - update_opscheck_from_github.ps1

目的:
- GitHub Release(latest) から最新スクリプトを取得
- poc_health_report.ps1 を安全に更新
- update_opscheck_from_github.ps1 自身は .pending に保存して次回起動時に昇格
- 更新結果を GAS に updateLog として送信
- ログ内の URL は自動マスク
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$BaseDir        = 'C:\OpsCheck'
$ConfigPath     = Join-Path $BaseDir 'config.dpapi'
$LogPath        = Join-Path $BaseDir 'update_opscheck.log'
$HealthPath     = Join-Path $BaseDir 'poc_health_report.ps1'
$UpdaterPath    = Join-Path $BaseDir 'update_opscheck_from_github.ps1'
$PendingPath    = Join-Path $BaseDir 'update_opscheck_from_github.ps1.pending'

# Release 配布URL
$HealthReleaseUrl  = 'https://github.com/1500man/Virgo-Release/releases/latest/download/poc_health_report.ps1'
$UpdaterReleaseUrl = 'https://github.com/1500man/Virgo-Release/releases/latest/download/update_opscheck_from_github.ps1'

$UpdaterVersion = 'virgo-updater-v6.0.0'

function Get-NowText {
    return (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
}

function Mask-UrlInText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $Text
    }

    $masked = $Text
    $masked = $masked -replace 'https://script\.google\.com/macros/s/[^/\s"]+/exec', 'https://script.google.com/macros/s/***masked***/exec'
    $masked = $masked -replace 'https://github\.com/[^/\s"]+/[^/\s"]+/releases/latest/download/[^"\s]+', 'https://github.com/***masked***/releases/latest/download/***masked***'
    return $masked
}

function Mask-SensitiveText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $Text
    }

    $masked = $Text
    $masked = $masked -replace '"secret"\s*:\s*"[^"]+"', '"secret":"***masked***"'
    $masked = $masked -replace '"signature"\s*:\s*"[^"]+"', '"signature":"***masked***"'
    $masked = $masked -replace '"payloadBase64"\s*:\s*"[^"]+"', '"payloadBase64":"***masked***"'
    $masked = Mask-UrlInText -Text $masked
    return $masked
}

function Initialize-Log {
    try {
        $header = @(
            ''
            '============================================================'
            "$(Get-NowText) [INFO ] update_opscheck_from_github.ps1 実行開始"
            "BaseDir: $BaseDir"
            "UpdaterVersion: $UpdaterVersion"
            '============================================================'
        )
        Add-Content -LiteralPath $LogPath -Value $header -Encoding UTF8
    } catch {}
}

function Write-LogLine {
    param(
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $safeMessage = Mask-SensitiveText -Text $Message
    $line = "{0} [{1}] {2}" -f (Get-NowText), $Level.ToUpper().PadRight(5), $safeMessage
    try {
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {}
}

function Write-Info {
    param([string]$Message)
    Write-LogLine -Level 'INFO' -Message $Message
}

function Write-Ok {
    param([string]$Message)
    Write-LogLine -Level 'OK' -Message $Message
}

function Write-Warn {
    param([string]$Message)
    Write-LogLine -Level 'WARN' -Message $Message
}

function Write-Err {
    param([string]$Message)
    Write-LogLine -Level 'ERROR' -Message $Message
}

function Load-VirgoConfig {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "config.dpapi が見つかりません: $ConfigPath"
    }

    Add-Type -AssemblyName System.Security
    $encBytes = [System.IO.File]::ReadAllBytes($ConfigPath)

    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    $json = [System.Text.Encoding]::UTF8.GetString($plainBytes)
    Write-LogLine -Level 'DEBUG' -Message 'config loaded'

    $obj = $json | ConvertFrom-Json -ErrorAction Stop
    if (-not $obj.endpoint) { throw 'config.dpapi に endpoint がありません。' }
    if (-not $obj.secret)   { throw 'config.dpapi に secret がありません。' }

    return $obj
}

function Get-EffectiveEndpoint {
    param([Parameter(Mandatory = $true)]$Config)

    $envEndpoint = [Environment]::GetEnvironmentVariable('VIRGO_ENDPOINT', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($envEndpoint)) {
        Write-Info 'Machine環境変数 VIRGO_ENDPOINT を使用します。'
        return $envEndpoint.Trim()
    }

    Write-Warn 'Machine環境変数 VIRGO_ENDPOINT が空のため、config.dpapi の endpoint を使用します。'
    return ([string]$Config.endpoint).Trim()
}

function Get-CustomerGroup {
    $group = [Environment]::GetEnvironmentVariable('VIRGO_CUSTOMER_GROUP', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($group)) {
        return $group.Trim()
    }
    return $env:COMPUTERNAME
}

function Get-DeviceUuid {
    try {
        $uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) {
            return $uuid.Trim()
        }
    } catch {
        Write-Warn "Get-CimInstance UUID failed: $($_.Exception.Message)"
    }

    try {
        $uuid = (Get-WmiObject Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        if (-not [string]::IsNullOrWhiteSpace($uuid)) {
            return $uuid.Trim()
        }
    } catch {
        Write-Warn "Get-WmiObject UUID failed: $($_.Exception.Message)"
    }

    throw 'UUID の取得に失敗しました。'
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }

    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
    } catch {
        Write-Warn "Hash取得失敗: $Path / $($_.Exception.Message)"
        return ''
    }
}

function Test-DownloadedScriptIsHtml {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $true
    }

    try {
        $firstLines = Get-Content -LiteralPath $Path -TotalCount 5 -ErrorAction Stop
        $joined = ($firstLines -join "`n")
        if ($joined -match '<!DOCTYPE' -or $joined -match '<html' -or $joined -match '<HTML') {
            return $true
        }
        return $false
    } catch {
        Write-Warn "HTML検査失敗: $Path / $($_.Exception.Message)"
        return $true
    }
}

function Download-ReleaseAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$DestinationTemp
    )

    Write-Info "ダウンロード開始: $Url"

    Invoke-WebRequest -Uri $Url -OutFile $DestinationTemp -UseBasicParsing -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $DestinationTemp)) {
        throw "ダウンロードファイルが存在しません: $DestinationTemp"
    }

    if (Test-DownloadedScriptIsHtml -Path $DestinationTemp) {
        Remove-Item -LiteralPath $DestinationTemp -Force -ErrorAction SilentlyContinue
        throw "ダウンロード結果が HTML でした。Release asset URL または公開状態を確認してください。"
    }

    Write-Ok "ダウンロード成功: $DestinationTemp"
}

function Promote-PendingUpdaterIfExists {
    if (-not (Test-Path -LiteralPath $PendingPath)) {
        return
    }

    Write-Info ".pending の昇格処理を開始します。"

    if (Test-DownloadedScriptIsHtml -Path $PendingPath) {
        Write-Warn ".pending が HTML だったため破棄します。"
        Remove-Item -LiteralPath $PendingPath -Force -ErrorAction SilentlyContinue
        return
    }

    try {
        Copy-Item -LiteralPath $PendingPath -Destination $UpdaterPath -Force
        Remove-Item -LiteralPath $PendingPath -Force -ErrorAction SilentlyContinue
        Write-Ok 'updater 自身を .pending から昇格しました。'
    } catch {
        Write-Warn "updater 昇格に失敗しました: $($_.Exception.Message)"
    }
}

function New-Nonce {
    return ([Guid]::NewGuid().ToString('N'))
}

function New-UnixTime {
    return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function ConvertTo-Base64Json {
    param([Parameter(Mandatory = $true)]$Object)

    $json = $Object | ConvertTo-Json -Compress -Depth 10
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    return [Convert]::ToBase64String($bytes)
}

function New-HmacSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Uuid,
        [Parameter(Mandatory = $true)][long]$Timestamp,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$PayloadBase64
    )

    $signData = "$Uuid|$Timestamp|$Nonce|$PayloadBase64"
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
        $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signData))
        return [Convert]::ToBase64String($hash)
    }
    finally {
        $hmac.Dispose()
    }
}

function Send-UpdateLogToGas {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Uuid,
        [Parameter(Mandatory = $true)][hashtable]$InnerPayload
    )

    $timestamp = New-UnixTime
    $nonce = New-Nonce
    $payloadBase64 = ConvertTo-Base64Json -Object $InnerPayload
    $signature = New-HmacSignature -Secret $Secret -Uuid $Uuid -Timestamp $timestamp -Nonce $nonce -PayloadBase64 $payloadBase64

    $outerBody = @{
        uuid          = $Uuid
        timestamp     = $timestamp
        nonce         = $nonce
        payloadBase64 = $payloadBase64
        signature     = $signature
    }

    $outerJson = $outerBody | ConvertTo-Json -Compress -Depth 10
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($outerJson)

    Write-LogLine -Level 'DEBUG' -Message "POST Endpoint: $Endpoint"
    Write-LogLine -Level 'DEBUG' -Message "POST Body: $outerJson"

    $response = Invoke-WebRequest -Uri $Endpoint -Method Post -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -UseBasicParsing -ErrorAction Stop
    $content = [string]$response.Content

    Write-LogLine -Level 'DEBUG' -Message "Response Status: $($response.StatusCode)"
    Write-LogLine -Level 'DEBUG' -Message "Response Body: $content"

    return [PSCustomObject]@{
        StatusCode = [int]$response.StatusCode
        Content    = $content
    }
}

Initialize-Log

$successFiles = New-Object System.Collections.Generic.List[string]
$failedFiles  = New-Object System.Collections.Generic.List[string]
$errorDetails = New-Object System.Collections.Generic.List[string]

try {
    Promote-PendingUpdaterIfExists

    $config = Load-VirgoConfig
    $endpoint = Get-EffectiveEndpoint -Config $config
    $uuid = Get-DeviceUuid
    $customerGroup = Get-CustomerGroup

    Write-Info "UpdaterVersion: $UpdaterVersion"
    Write-Info "UUID: $uuid"
    Write-Info "CustomerGroup: $customerGroup"

    $tmpHealth  = Join-Path $env:TEMP ('virgo_health_'  + [guid]::NewGuid().ToString('N') + '.tmp')
    $tmpUpdater = Join-Path $env:TEMP ('virgo_updater_' + [guid]::NewGuid().ToString('N') + '.tmp')

    # 1) health script 更新
    try {
        Download-ReleaseAsset -Url $HealthReleaseUrl -DestinationTemp $tmpHealth

        $newHash = Get-FileSha256 -Path $tmpHealth
        $oldHash = Get-FileSha256 -Path $HealthPath

        if ($newHash -and $oldHash -and $newHash -eq $oldHash) {
            Write-Info 'poc_health_report.ps1 は最新です。'
        } else {
            Copy-Item -LiteralPath $tmpHealth -Destination $HealthPath -Force
            Write-Ok 'poc_health_report.ps1 を更新しました。'
        }

        $successFiles.Add('poc_health_report.ps1') | Out-Null
    }
    catch {
        $msg = "poc_health_report.ps1 更新失敗: $($_.Exception.Message)"
        Write-Err $msg
        $failedFiles.Add('poc_health_report.ps1') | Out-Null
        $errorDetails.Add($msg) | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $tmpHealth -Force -ErrorAction SilentlyContinue
    }

    # 2) updater 自身の更新
    try {
        Download-ReleaseAsset -Url $UpdaterReleaseUrl -DestinationTemp $tmpUpdater

        $newHash = Get-FileSha256 -Path $tmpUpdater
        $oldHash = Get-FileSha256 -Path $UpdaterPath

        if ($newHash -and $oldHash -and $newHash -eq $oldHash) {
            Write-Info 'update_opscheck_from_github.ps1 は最新です。'
        } else {
            Copy-Item -LiteralPath $tmpUpdater -Destination $PendingPath -Force
            Write-Ok 'updater 自身の新バージョンを .pending に保存しました。'
        }

        $successFiles.Add('update_opscheck_from_github.ps1') | Out-Null
    }
    catch {
        $msg = "update_opscheck_from_github.ps1 更新失敗: $($_.Exception.Message)"
        Write-Err $msg
        $failedFiles.Add('update_opscheck_from_github.ps1') | Out-Null
        $errorDetails.Add($msg) | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $tmpUpdater -Force -ErrorAction SilentlyContinue
    }

    $message =
        if ($failedFiles.Count -eq 0) {
            '更新処理完了: すべて成功'
        } elseif ($successFiles.Count -gt 0) {
            '更新処理完了: 一部成功'
        } else {
            '更新処理失敗: すべて失敗'
        }

    $updateLogPayload = @{
        action        = 'updateLog'
        device        = $env:COMPUTERNAME
        customerGroup = $customerGroup
        uuid          = $uuid
        timestamp     = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
        updaterVer    = $UpdaterVersion
        message       = $message
        successCount  = $successFiles.Count
        successFiles  = @($successFiles.ToArray())
        failedCount   = $failedFiles.Count
        failedFiles   = @($failedFiles.ToArray())
        errors        = ($errorDetails -join ' | ')
    }

    try {
        $res = Send-UpdateLogToGas -Endpoint $endpoint -Secret ([string]$config.secret) -Uuid $uuid -InnerPayload $updateLogPayload
        if ($res.StatusCode -eq 200 -and $res.Content -match '^ok') {
            Write-Ok 'updateLog の送信に成功しました。'
        } else {
            Write-Warn "updateLog 応答が想定外です: $($res.Content)"
        }
    }
    catch {
        Write-Warn "updateLog 送信失敗: $($_.Exception.Message)"
    }
}
catch {
    Write-Err $_.Exception.Message
    Write-LogLine -Level 'ERROR' -Message ($_ | Out-String)
    exit 1
}