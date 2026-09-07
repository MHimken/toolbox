#Requires -Version 7.2
#Requires -Module Az.Accounts
<#
.SYNOPSIS
    Repairs Intune primary-user assignments from daily sign-in aggregates.
.DESCRIPTION
    Runs weekly in Azure Automation. The runbook requires 28 complete daily collection partitions,
    combines their device/user counts, and assigns the highest-count user to each company-owned
    Windows device. Equal counts are resolved by the latest successful sign-in.
.PARAMETER Preview
    Calculates and audits recommendations without changing Intune assignments.
.NOTES
    Runtime: PowerShell 7.2
    Required module: Az.Accounts
    Graph application permission: DeviceManagementManagedDevices.ReadWrite.All
    Azure role: Storage Table Data Contributor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$AnalysisEndDate,

    [ValidateRange(1, 90)]
    [int]$DaysToAnalyze = 28,

    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,62}$')]
    [string]$AggregateTableName = 'PrimaryUserDaily',

    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,62}$')]
    [string]$StateTableName = 'PrimaryUserState',

    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,62}$')]
    [string]$AuditTableName = 'PrimaryUserAudit',

    [string]$ManagedIdentityClientId,

    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5,

    [ValidateRange(1, 48)]
    [int]$StaleLockHours = 12,

    [switch]$Preview
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:StorageBaseUri = 'https://{0}.table.core.windows.net' -f $StorageAccountName
$script:StorageToken = $null
$script:GraphToken = $null
$script:RunId = '{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0, 8))

function ConvertFrom-SecureAccessToken {
    param([Parameter(Mandatory = $true)][object]$Token)

    if ($Token -isnot [securestring]) { return [string]$Token }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Initialize-ManagedIdentity {
    Import-Module Az.Accounts -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($ManagedIdentityClientId)) {
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    } else {
        Connect-AzAccount -Identity -AccountId $ManagedIdentityClientId -ErrorAction Stop | Out-Null
    }
    $script:StorageToken = ConvertFrom-SecureAccessToken -Token (Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/' -ErrorAction Stop).Token
    $script:GraphToken = ConvertFrom-SecureAccessToken -Token (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/' -ErrorAction Stop).Token
}

function Get-StorageHeaders {
    param([switch]$ForWrite)

    $headers = @{
        Authorization  = 'Bearer {0}' -f $script:StorageToken
        Accept         = 'application/json;odata=nometadata'
        'x-ms-date'    = [datetime]::UtcNow.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
        'x-ms-version' = '2023-11-03'
    }
    if ($ForWrite) { $headers['Content-Type'] = 'application/json; charset=utf-8' }
    return $headers
}

function Invoke-RestWithRetry {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Post', 'Put', 'Delete')][string]$Method,
        [Parameter(Mandatory = $true)][uri]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [AllowNull()][byte[]]$Body
    )

    for ($attempt = 1; $attempt -le $MaximumRetryCount; $attempt++) {
        try {
            $parameters = @{ Uri = $Uri; Method = $Method; Headers = $Headers; ErrorAction = 'Stop' }
            if ($null -ne $Body) { $parameters.Body = $Body }
            return Invoke-WebRequest @parameters
        } catch {
            $response = $_.Exception.Response
            $statusCode = if ($null -ne $response) { [int]$response.StatusCode } else { 0 }
            if ($attempt -eq $MaximumRetryCount -or ($statusCode -ne 429 -and $statusCode -lt 500)) { throw }
            $retryAfter = 0
            if ($null -ne $response -and $null -ne $response.Headers) {
                [void][int]::TryParse([string]$response.Headers['Retry-After'], [ref]$retryAfter)
            }
            if ($retryAfter -le 0) { $retryAfter = [math]::Min([math]::Pow(2, $attempt), 30) }
            Start-Sleep -Seconds $retryAfter
        }
    }
}

function ConvertTo-EntityUri {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey,
        [Parameter(Mandatory = $true)][string]$RowKey
    )

    $partition = $PartitionKey.Replace("'", "''")
    $row = $RowKey.Replace("'", "''")
    return [uri]('{0}/{1}(PartitionKey=''{2}'',RowKey=''{3}'')' -f $script:StorageBaseUri, $TableName, $partition, $row)
}

function Set-TableEntity {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][hashtable]$Entity
    )

    $uri = ConvertTo-EntityUri -TableName $TableName -PartitionKey $Entity.PartitionKey -RowKey $Entity.RowKey
    $body = [Text.Encoding]::UTF8.GetBytes(($Entity | ConvertTo-Json -Compress))
    Invoke-RestWithRetry -Method Put -Uri $uri -Headers (Get-StorageHeaders -ForWrite) -Body $body | Out-Null
}

function Get-TableEntity {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey,
        [Parameter(Mandatory = $true)][string]$RowKey
    )

    try {
        $uri = ConvertTo-EntityUri -TableName $TableName -PartitionKey $PartitionKey -RowKey $RowKey
        return (Invoke-RestWithRetry -Method Get -Uri $uri -Headers (Get-StorageHeaders)).Content | ConvertFrom-Json
    } catch {
        if ($null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return $null }
        throw
    }
}

function Get-TableEntitiesByPartition {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey
    )

    $nextPartitionKey = $null
    $nextRowKey = $null
    do {
        $filter = [uri]::EscapeDataString("PartitionKey eq '$($PartitionKey.Replace("'", "''"))'")
        $uri = '{0}/{1}()?$filter={2}' -f $script:StorageBaseUri, $TableName, $filter
        if (-not [string]::IsNullOrWhiteSpace($nextPartitionKey)) {
            $uri += '&NextPartitionKey={0}&NextRowKey={1}' -f [uri]::EscapeDataString($nextPartitionKey), [uri]::EscapeDataString($nextRowKey)
        }
        $response = Invoke-RestWithRetry -Method Get -Uri $uri -Headers (Get-StorageHeaders)
        foreach ($entity in @(($response.Content | ConvertFrom-Json).value)) { Write-Output $entity }
        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
    } while (-not [string]::IsNullOrWhiteSpace($nextPartitionKey))
}

function Enter-AnalysisLock {
    $existingLock = Get-TableEntity -TableName $StateTableName -PartitionKey 'Analysis' -RowKey 'Active'
    if ($null -ne $existingLock) {
        $lockTime = ([datetime]$existingLock.StartedAt).ToUniversalTime()
        if ($lockTime -gt [datetime]::UtcNow.AddHours(-$StaleLockHours)) {
            throw "Analysis run $($existingLock.RunId) has held the lock since $($existingLock.StartedAt)."
        }
        $headers = Get-StorageHeaders
        $headers['If-Match'] = '*'
        $lockUri = ConvertTo-EntityUri -TableName $StateTableName -PartitionKey 'Analysis' -RowKey 'Active'
        Invoke-RestWithRetry -Method Delete -Uri $lockUri -Headers $headers | Out-Null
        Write-Warning "Removed stale analysis lock for run $($existingLock.RunId)."
    }

    $headers = Get-StorageHeaders -ForWrite
    $headers['If-None-Match'] = '*'
    $body = [Text.Encoding]::UTF8.GetBytes((@{
        PartitionKey = 'Analysis'
        RowKey       = 'Active'
        RunId        = $script:RunId
        StartedAt    = [datetime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress))
    $uri = '{0}/{1}' -f $script:StorageBaseUri, $StateTableName
    try {
        Invoke-RestWithRetry -Method Post -Uri $uri -Headers $headers -Body $body | Out-Null
    } catch {
        if ($null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 409) {
            throw 'Another weekly analysis acquired the lock first.'
        }
        throw
    }
}

function Exit-AnalysisLock {
    $lock = Get-TableEntity -TableName $StateTableName -PartitionKey 'Analysis' -RowKey 'Active'
    if ($null -eq $lock -or [string]$lock.RunId -ne $script:RunId) { return }
    $headers = Get-StorageHeaders
    $headers['If-Match'] = '*'
    $uri = ConvertTo-EntityUri -TableName $StateTableName -PartitionKey 'Analysis' -RowKey 'Active'
    Invoke-RestWithRetry -Method Delete -Uri $uri -Headers $headers | Out-Null
}

function Invoke-GraphGet {
    param([Parameter(Mandatory = $true)][uri]$Uri)

    for ($attempt = 1; $attempt -le $MaximumRetryCount; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers @{ Authorization = "Bearer $script:GraphToken" } -ErrorAction Stop
        } catch {
            $response = $_.Exception.Response
            $statusCode = if ($null -ne $response) { [int]$response.StatusCode } else { 0 }
            if ($attempt -eq $MaximumRetryCount -or ($statusCode -ne 429 -and $statusCode -lt 500)) { throw }
            $retryAfter = 0
            if ($null -ne $response -and $null -ne $response.Headers) {
                [void][int]::TryParse([string]$response.Headers['Retry-After'], [ref]$retryAfter)
            }
            if ($retryAfter -le 0) { $retryAfter = [math]::Min([math]::Pow(2, $attempt), 30) }
            Start-Sleep -Seconds $retryAfter
        }
    }
}

function Invoke-GraphBatch {
    param([Parameter(Mandatory = $true)][object[]]$Requests)

    $pending = @($Requests)
    $results = [Collections.Generic.List[object]]::new()
    for ($attempt = 1; $attempt -le $MaximumRetryCount -and $pending.Count -gt 0; $attempt++) {
        $body = [Text.Encoding]::UTF8.GetBytes((@{ requests = $pending } | ConvertTo-Json -Depth 8 -Compress))
        $response = $null
        for ($batchAttempt = 1; $batchAttempt -le $MaximumRetryCount; $batchAttempt++) {
            try {
                $response = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/beta/$batch' -Headers @{
                    Authorization = "Bearer $script:GraphToken"
                    'Content-Type' = 'application/json'
                } -Body $body -ErrorAction Stop
                break
            } catch {
                $httpResponse = $_.Exception.Response
                $statusCode = if ($null -ne $httpResponse) { [int]$httpResponse.StatusCode } else { 0 }
                if ($batchAttempt -eq $MaximumRetryCount -or ($statusCode -ne 429 -and $statusCode -lt 500)) { throw }
                $retryAfter = 0
                if ($null -ne $httpResponse -and $null -ne $httpResponse.Headers) {
                    [void][int]::TryParse([string]$httpResponse.Headers['Retry-After'], [ref]$retryAfter)
                }
                if ($retryAfter -le 0) { $retryAfter = [int][math]::Min([math]::Pow(2, $batchAttempt), 30) }
                Start-Sleep -Seconds $retryAfter
            }
        }
        $retry = [Collections.Generic.List[object]]::new()
        foreach ($request in $pending) {
            $item = @($response.responses | Where-Object { [string]$_.id -eq [string]$request.id })[0]
            if ($null -eq $item) {
                $results.Add([pscustomobject]@{ Request = $request; Status = 0; Error = 'No batch response was returned.' })
            } elseif ([int]$item.status -ge 200 -and [int]$item.status -lt 300) {
                $results.Add([pscustomobject]@{ Request = $request; Status = [int]$item.status; Error = $null })
            } elseif (([int]$item.status -eq 429 -or [int]$item.status -ge 500) -and $attempt -lt $MaximumRetryCount) {
                $retry.Add($request)
            } else {
                $message = if ($null -ne $item.body -and $null -ne $item.body.error) { [string]$item.body.error.message } else { 'Graph batch request failed.' }
                $results.Add([pscustomobject]@{ Request = $request; Status = [int]$item.status; Error = $message })
            }
        }
        $pending = @($retry)
        if ($pending.Count -gt 0) { Start-Sleep -Seconds ([math]::Min([math]::Pow(2, $attempt), 30)) }
    }
    return $results
}

function Write-AuditEntity {
    param(
        [Parameter(Mandatory = $true)][string]$RowKey,
        [Parameter(Mandatory = $true)][hashtable]$Properties
    )

    $entity = @{ PartitionKey = $script:RunId; RowKey = $RowKey }
    foreach ($key in $Properties.Keys) { $entity[$key] = $Properties[$key] }
    Set-TableEntity -TableName $AuditTableName -Entity $entity
}

Initialize-ManagedIdentity
Enter-AnalysisLock
$startedAt = [datetime]::UtcNow
$summary = @{ DevicesEvaluated = 0; ChangesNeeded = 0; Updated = 0; Failed = 0; Unchanged = 0 }

try {
    $endDate = if ([string]::IsNullOrWhiteSpace($AnalysisEndDate)) {
        [datetime]::UtcNow.Date.AddDays(-1)
    } else {
        [datetime]::ParseExact(
            $AnalysisEndDate,
            'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        )
    }
    if ($endDate -ge [datetime]::UtcNow.Date) { throw 'AnalysisEndDate must identify a completed UTC day.' }

    $dateKeys = [Collections.Generic.List[string]]::new()
    $missingDates = [Collections.Generic.List[string]]::new()
    for ($offset = $DaysToAnalyze - 1; $offset -ge 0; $offset--) {
        $date = $endDate.AddDays(-$offset)
        $dateKey = $date.ToString('yyyyMMdd')
        $dateKeys.Add($dateKey)
        $state = Get-TableEntity -TableName $StateTableName -PartitionKey 'Collection' -RowKey $dateKey
        if ($null -eq $state -or [string]$state.Status -ne 'Complete') { $missingDates.Add($date.ToString('yyyy-MM-dd')) }
    }
    if ($missingDates.Count -gt 0) {
        throw "No assignments were changed because collection is incomplete for: $($missingDates -join ', ')."
    }

    $countsByDevice = @{}
    foreach ($dateKey in $dateKeys) {
        foreach ($row in @(Get-TableEntitiesByPartition -TableName $AggregateTableName -PartitionKey $dateKey)) {
            $deviceId = ([string]$row.DeviceId).ToLowerInvariant()
            $userId = ([string]$row.UserId).ToLowerInvariant()
            if (-not $countsByDevice.ContainsKey($deviceId)) { $countsByDevice[$deviceId] = @{} }
            if (-not $countsByDevice[$deviceId].ContainsKey($userId)) {
                $countsByDevice[$deviceId][$userId] = [pscustomobject]@{ UserId = [string]$row.UserId; Count = [int64]0; LatestSignIn = [datetime]::MinValue }
            }
            $candidate = $countsByDevice[$deviceId][$userId]
            $candidate.Count += [int64]$row.SignInCount
            $latest = ([datetime]$row.LatestSignIn).ToUniversalTime()
            if ($latest -gt $candidate.LatestSignIn) { $candidate.LatestSignIn = $latest }
        }
    }

    $winners = @{}
    foreach ($deviceId in $countsByDevice.Keys) {
        $winners[$deviceId] = @($countsByDevice[$deviceId].Values | Sort-Object -Property @(
            @{ Expression = 'Count'; Descending = $true },
            @{ Expression = 'LatestSignIn'; Descending = $true },
            @{ Expression = 'UserId'; Descending = $false }
        ))[0]
    }
    $countsByDevice = $null

    $requests = [Collections.Generic.List[object]]::new()
    $requestMetadata = @{}
    $requestId = 0
    $filter = [uri]::EscapeDataString("operatingSystem eq 'Windows' and managedDeviceOwnerType eq 'Company'")
    $deviceUri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$filter={0}&$select=id,azureADDeviceId,deviceName,userId&$top=1000' -f $filter
    while (-not [string]::IsNullOrWhiteSpace($deviceUri)) {
        $page = Invoke-GraphGet -Uri $deviceUri
        foreach ($device in @($page.value)) {
            $azureDeviceId = ([string]$device.azureADDeviceId).ToLowerInvariant()
            if (-not $winners.ContainsKey($azureDeviceId)) { continue }
            $summary.DevicesEvaluated++
            $winner = $winners[$azureDeviceId]
            if ([string]$device.userId -eq [string]$winner.UserId) {
                $summary.Unchanged++
                Write-AuditEntity -RowKey ([string]$device.id) -Properties @{
                    DeviceId = [string]$device.id; AzureDeviceId = [string]$device.azureADDeviceId; DeviceName = [string]$device.deviceName
                    PreviousUserId = [string]$device.userId; RecommendedUserId = [string]$winner.UserId; SignInCount = [int64]$winner.Count
                    LatestSignIn = $winner.LatestSignIn.ToString('o'); Outcome = 'Unchanged'; Preview = [bool]$Preview
                }
                continue
            }

            $summary.ChangesNeeded++
            if ($Preview) {
                Write-AuditEntity -RowKey ([string]$device.id) -Properties @{
                    DeviceId = [string]$device.id; AzureDeviceId = [string]$device.azureADDeviceId; DeviceName = [string]$device.deviceName
                    PreviousUserId = [string]$device.userId; RecommendedUserId = [string]$winner.UserId; SignInCount = [int64]$winner.Count
                    LatestSignIn = $winner.LatestSignIn.ToString('o'); Outcome = 'Preview'; Preview = $true
                }
                continue
            }

            $requestId++
            $id = [string]$requestId
            $request = [pscustomobject]@{
                id      = $id
                method  = 'POST'
                url     = "/deviceManagement/managedDevices/$($device.id)/users/`$ref"
                headers = @{ 'Content-Type' = 'application/json' }
                body    = @{ '@odata.id' = "https://graph.microsoft.com/beta/users/$($winner.UserId)" }
            }
            $requests.Add($request)
            $requestMetadata[$id] = [pscustomobject]@{ Device = $device; Winner = $winner }

            if ($requests.Count -eq 20) {
                foreach ($result in @(Invoke-GraphBatch -Requests @($requests))) {
                    $metadata = $requestMetadata[[string]$result.Request.id]
                    $outcome = if ($null -eq $result.Error) { $summary.Updated++; 'Updated' } else { $summary.Failed++; 'Failed' }
                    Write-AuditEntity -RowKey ([string]$metadata.Device.id) -Properties @{
                        DeviceId = [string]$metadata.Device.id; AzureDeviceId = [string]$metadata.Device.azureADDeviceId; DeviceName = [string]$metadata.Device.deviceName
                        PreviousUserId = [string]$metadata.Device.userId; RecommendedUserId = [string]$metadata.Winner.UserId; SignInCount = [int64]$metadata.Winner.Count
                        LatestSignIn = $metadata.Winner.LatestSignIn.ToString('o'); Outcome = $outcome; HttpStatus = [int]$result.Status
                        ErrorMessage = [string]$result.Error; Preview = $false
                    }
                }
                $requests.Clear()
                $requestMetadata.Clear()
            }
        }
        $deviceUri = [string]$page.'@odata.nextLink'
    }

    if ($requests.Count -gt 0) {
        foreach ($result in @(Invoke-GraphBatch -Requests @($requests))) {
            $metadata = $requestMetadata[[string]$result.Request.id]
            $outcome = if ($null -eq $result.Error) { $summary.Updated++; 'Updated' } else { $summary.Failed++; 'Failed' }
            Write-AuditEntity -RowKey ([string]$metadata.Device.id) -Properties @{
                DeviceId = [string]$metadata.Device.id; AzureDeviceId = [string]$metadata.Device.azureADDeviceId; DeviceName = [string]$metadata.Device.deviceName
                PreviousUserId = [string]$metadata.Device.userId; RecommendedUserId = [string]$metadata.Winner.UserId; SignInCount = [int64]$metadata.Winner.Count
                LatestSignIn = $metadata.Winner.LatestSignIn.ToString('o'); Outcome = $outcome; HttpStatus = [int]$result.Status
                ErrorMessage = [string]$result.Error; Preview = $false
            }
        }
    }

    Set-TableEntity -TableName $StateTableName -Entity @{
        PartitionKey = 'AnalysisRuns'; RowKey = $script:RunId; Status = if ($summary.Failed -gt 0) { 'CompletedWithErrors' } else { 'Complete' }
        StartedAt = $startedAt.ToString('o'); CompletedAt = [datetime]::UtcNow.ToString('o'); AnalysisEndDate = $endDate.ToString('yyyy-MM-dd')
        DaysAnalyzed = $DaysToAnalyze; Preview = [bool]$Preview; DevicesEvaluated = $summary.DevicesEvaluated; ChangesNeeded = $summary.ChangesNeeded
        Updated = $summary.Updated; Failed = $summary.Failed; Unchanged = $summary.Unchanged
    }
    Write-Output "Analysis $script:RunId complete. Evaluated: $($summary.DevicesEvaluated); changes: $($summary.ChangesNeeded); updated: $($summary.Updated); failed: $($summary.Failed); unchanged: $($summary.Unchanged)."
} catch {
    Set-TableEntity -TableName $StateTableName -Entity @{
        PartitionKey = 'AnalysisRuns'; RowKey = $script:RunId; Status = 'Failed'; StartedAt = $startedAt.ToString('o')
        CompletedAt = [datetime]::UtcNow.ToString('o'); ErrorMessage = $_.Exception.Message; Preview = [bool]$Preview
    }
    throw
} finally {
    try { Exit-AnalysisLock }
    catch { Write-Warning "The analysis lock could not be released. $($_.Exception.Message)" }
}