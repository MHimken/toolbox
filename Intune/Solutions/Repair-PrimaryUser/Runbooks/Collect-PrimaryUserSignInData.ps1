#Requires -Version 7.2
#Requires -Module Az.Accounts
<#
.SYNOPSIS
    Collects Windows sign-in aggregates for one UTC day or an inclusive date range.
.DESCRIPTION
    Runs in Azure Automation with a managed identity. The runbook streams Microsoft Graph sign-in
    pages, counts successful Windows Sign In events by device and user, and replaces the selected
    date partitions in Azure Table Storage one day at a time. A separate state row for each date
    prevents completed days from being collected twice. A failed day stops the range; rerunning the
    same range skips completed dates unless ForceRecollect is supplied.
.PARAMETER StorageAccountName
    Storage account containing the solution tables.
.PARAMETER CollectionDate
    UTC date to collect, or the first date of a range, in yyyy-MM-dd format. Defaults to the previous
    completed UTC day when CollectionEndDate is omitted.
.PARAMETER CollectionEndDate
    Optional inclusive last UTC date in yyyy-MM-dd format. Requires CollectionDate. Both dates must
    identify completed UTC days and the end date must be on or after the start date.
.PARAMETER ForceRecollect
    Set to true to replace a partition even when its state is Complete. Defaults to false.
.PARAMETER RetentionDays
    Days of aggregates to keep, counted back from the last collected date. After a successful job,
    all older aggregate rows and collection state rows are deleted in batches of up to 100 rows,
    including days that never completed. Defaults to 35.
.NOTES
    Runtime: PowerShell 7.2 or later
    Required module: Az.Accounts
    Graph application permission: AuditLog.Read.All
    Azure role: Storage Table Data Contributor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$CollectionDate,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$CollectionEndDate,

    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,62}$')]
    [string]$AggregateTableName = 'PrimaryUserDaily',

    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,62}$')]
    [string]$StateTableName = 'PrimaryUserState',

    [string]$ManagedIdentityClientId,

    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5,

    [ValidateRange(29, 365)]
    [int]$RetentionDays = 35,

    [bool]$ForceRecollect = $false
)

Set-StrictMode -Version Latest
$script:OriginalErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
$script:StorageBaseUri = 'https://{0}.table.core.windows.net' -f $StorageAccountName
$script:StorageToken = $null
$script:GraphToken = $null

function ConvertFrom-SecureAccessToken {
    param([Parameter(Mandatory = $true)][object]$Token)

    if ($Token -isnot [securestring]) {
        return [string]$Token
    }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

# StrictMode throws on missing properties, so optional response members are read through this helper.
function Get-OptionalProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-HttpStatusCode {
    param([Parameter(Mandatory = $true)][Management.Automation.ErrorRecord]$ErrorRecord)

    $response = Get-OptionalProperty -InputObject $ErrorRecord.Exception -Name 'Response'
    if ($null -eq $response) { return 0 }
    return [int]$response.StatusCode
}

function Test-RetryableError {
    param([Parameter(Mandatory = $true)][Management.Automation.ErrorRecord]$ErrorRecord)

    $statusCode = Get-HttpStatusCode -ErrorRecord $ErrorRecord
    if ($statusCode -eq 429 -or $statusCode -ge 500) { return $true }
    $exception = $ErrorRecord.Exception
    return $statusCode -eq 0 -and (
        $exception -is [Net.Http.HttpRequestException] -or
        $exception -is [IO.IOException] -or
        $exception -is [TimeoutException] -or
        $exception -is [Threading.Tasks.TaskCanceledException])
}

function Get-RetryDelaySeconds {
    param(
        [Parameter(Mandatory = $true)][Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory = $true)][int]$Attempt
    )

    $delay = 0
    $response = Get-OptionalProperty -InputObject $ErrorRecord.Exception -Name 'Response'
    if ($response -is [Net.Http.HttpResponseMessage] -and $null -ne $response.Headers.RetryAfter) {
        $retryAfter = $response.Headers.RetryAfter
        if ($null -ne $retryAfter.Delta) {
            $delay = $retryAfter.Delta.TotalSeconds
        } elseif ($null -ne $retryAfter.Date) {
            $delay = ($retryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds
        }
    }
    if ($delay -le 0) { $delay = [math]::Min([math]::Pow(2, $Attempt), 30) }
    return [int][math]::Ceiling($delay)
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
    if ($ForWrite) {
        $headers['Content-Type'] = 'application/json; charset=utf-8'
    }
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
            if ($attempt -eq $MaximumRetryCount -or -not (Test-RetryableError -ErrorRecord $_)) { throw }
            Start-Sleep -Seconds (Get-RetryDelaySeconds -ErrorRecord $_ -Attempt $attempt)
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

function Remove-TableEntity {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey,
        [Parameter(Mandatory = $true)][string]$RowKey
    )

    $headers = Get-StorageHeaders
    $headers['If-Match'] = '*'
    $uri = ConvertTo-EntityUri -TableName $TableName -PartitionKey $PartitionKey -RowKey $RowKey
    try {
        Invoke-RestWithRetry -Method Delete -Uri $uri -Headers $headers | Out-Null
    } catch {
        if ((Get-HttpStatusCode -ErrorRecord $_) -ne 404) { throw }
    }
}

# Deletes up to 100 rows of one partition in a single entity group transaction.
function Invoke-TableBatchDelete {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey,
        [Parameter(Mandatory = $true)][ValidateCount(1, 100)][string[]]$RowKeys
    )

    $batchBoundary = 'batch_{0}' -f [guid]::NewGuid()
    $changesetBoundary = 'changeset_{0}' -f [guid]::NewGuid()
    $payload = [Text.StringBuilder]::new()
    [void]$payload.Append("--$batchBoundary`r`nContent-Type: multipart/mixed; boundary=$changesetBoundary`r`n`r`n")
    $contentId = 0
    foreach ($rowKey in $RowKeys) {
        $contentId++
        $entityUri = ConvertTo-EntityUri -TableName $TableName -PartitionKey $PartitionKey -RowKey $rowKey
        [void]$payload.Append("--$changesetBoundary`r`nContent-Type: application/http`r`nContent-Transfer-Encoding: binary`r`n`r`n")
        [void]$payload.Append("DELETE $($entityUri.AbsoluteUri) HTTP/1.1`r`nContent-ID: $contentId`r`nAccept: application/json;odata=minimalmetadata`r`nIf-Match: *`r`nDataServiceVersion: 3.0;`r`n`r`n")
    }
    [void]$payload.Append("--$changesetBoundary--`r`n--$batchBoundary--`r`n")

    $headers = Get-StorageHeaders
    $headers['Content-Type'] = "multipart/mixed; boundary=$batchBoundary"
    $headers['DataServiceVersion'] = '3.0;'
    $headers['MaxDataServiceVersion'] = '3.0;NetFx'
    $body = [Text.Encoding]::UTF8.GetBytes($payload.ToString())
    $response = Invoke-RestWithRetry -Method Post -Uri ('{0}/$batch' -f $script:StorageBaseUri) -Headers $headers -Body $body
    $responseText = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }

    $operationStatusCodes = @([regex]::Matches($responseText, '(?m)^HTTP/1\.1 (\d{3})') | ForEach-Object { [int]$_.Groups[1].Value })
    $failedStatusCodes = @($operationStatusCodes | Where-Object { $_ -ge 300 })
    if ($operationStatusCodes.Count -gt 0 -and $failedStatusCodes.Count -eq 0) { return }
    # A row already deleted by a retried or concurrent request rolls back the whole changeset.
    if ($failedStatusCodes -contains 404) {
        foreach ($rowKey in $RowKeys) { Remove-TableEntity -TableName $TableName -PartitionKey $PartitionKey -RowKey $rowKey }
        return
    }
    $responseExcerpt = $responseText.Substring(0, [math]::Min($responseText.Length, 1000))
    throw "Batch delete failed for partition '$PartitionKey' in table '$TableName'. $responseExcerpt"
}

# Streams matching keys page by page and deletes them in per-partition batches of up to 100 rows.
function Remove-TableEntityByFilter {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$Filter
    )

    $removedCount = 0
    $pendingPartitionKey = $null
    $pendingRowKeys = [Collections.Generic.List[string]]::new()
    $nextPartitionKey = $null
    $nextRowKey = $null
    do {
        $uri = '{0}/{1}()?$filter={2}&$select=PartitionKey,RowKey' -f $script:StorageBaseUri, $TableName, [uri]::EscapeDataString($Filter)
        if (-not [string]::IsNullOrWhiteSpace($nextPartitionKey)) {
            $uri += '&NextPartitionKey={0}&NextRowKey={1}' -f [uri]::EscapeDataString($nextPartitionKey), [uri]::EscapeDataString($nextRowKey)
        }
        $response = Invoke-RestWithRetry -Method Get -Uri $uri -Headers (Get-StorageHeaders)
        foreach ($entity in @(($response.Content | ConvertFrom-Json).value)) {
            $entityPartitionKey = [string]$entity.PartitionKey
            if ($pendingRowKeys.Count -gt 0 -and ($entityPartitionKey -cne $pendingPartitionKey -or $pendingRowKeys.Count -eq 100)) {
                Invoke-TableBatchDelete -TableName $TableName -PartitionKey $pendingPartitionKey -RowKeys $pendingRowKeys.ToArray()
                $removedCount += $pendingRowKeys.Count
                $pendingRowKeys.Clear()
            }
            $pendingPartitionKey = $entityPartitionKey
            $pendingRowKeys.Add([string]$entity.RowKey)
        }
        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
    } while (-not [string]::IsNullOrWhiteSpace($nextPartitionKey))

    if ($pendingRowKeys.Count -gt 0) {
        Invoke-TableBatchDelete -TableName $TableName -PartitionKey $pendingPartitionKey -RowKeys $pendingRowKeys.ToArray()
        $removedCount += $pendingRowKeys.Count
    }
    return $removedCount
}

function Remove-TablePartition {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey
    )

    $partitionFilter = "PartitionKey eq '$($PartitionKey.Replace("'", "''"))'"
    Remove-TableEntityByFilter -TableName $TableName -Filter $partitionFilter | Out-Null
}

function Get-CollectionState {
    param([Parameter(Mandatory = $true)][string]$DateKey)

    $uri = ConvertTo-EntityUri -TableName $StateTableName -PartitionKey 'Collection' -RowKey $DateKey
    try {
        $response = Invoke-RestWithRetry -Method Get -Uri $uri -Headers (Get-StorageHeaders)
        return $response.Content | ConvertFrom-Json
    } catch {
        if ((Get-HttpStatusCode -ErrorRecord $_) -eq 404) { return $null }
        throw
    }
}

function Invoke-GraphGet {
    param([Parameter(Mandatory = $true)][uri]$Uri)

    for ($attempt = 1; $attempt -le $MaximumRetryCount; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers @{ Authorization = "Bearer $script:GraphToken" } -ErrorAction Stop
        } catch {
            if ($attempt -eq $MaximumRetryCount -or -not (Test-RetryableError -ErrorRecord $_)) { throw }
            Start-Sleep -Seconds (Get-RetryDelaySeconds -ErrorRecord $_ -Attempt $attempt)
        }
    }
}

function Remove-ExpiredDailyPartitions {
    param([Parameter(Mandatory = $true)][datetime]$CurrentDate)

    # Date partition keys sort chronologically, so one range query finds every expired day,
    # including days left incomplete by failed collections.
    $expiredDate = $CurrentDate.AddDays(-$RetentionDays).ToString('yyyyMMdd')
    $aggregateRowCount = Remove-TableEntityByFilter -TableName $AggregateTableName -Filter "PartitionKey lt '$expiredDate'"
    $stateRowCount = Remove-TableEntityByFilter -TableName $StateTableName -Filter "PartitionKey eq 'Collection' and RowKey lt '$expiredDate'"
    if ($aggregateRowCount -gt 0 -or $stateRowCount -gt 0) {
        Write-Output "Removed $aggregateRowCount aggregate rows and $stateRowCount collection state rows dated before $expiredDate."
    }
}

function Invoke-DailyCollection {
    param([Parameter(Mandatory = $true)][datetime]$TargetDate)

    $dateKey = $targetDate.ToString('yyyyMMdd')
    $state = Get-CollectionState -DateKey $dateKey
    if ($null -ne $state -and [string]$state.Status -eq 'Complete' -and -not $ForceRecollect) {
        Write-Output "The $($targetDate.ToString('yyyy-MM-dd')) partition is already complete. Nothing to do."
        return
    }

    $startedAt = [datetime]::UtcNow.ToString('o')
    Set-TableEntity -TableName $StateTableName -Entity @{
        PartitionKey = 'Collection'
        RowKey       = $dateKey
        Status       = 'Collecting'
        StartedAt    = $startedAt
        EventCount   = 0
        AggregateRows = 0
    }
    Remove-TablePartition -TableName $AggregateTableName -PartitionKey $dateKey

    $windowStart = $targetDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $windowEnd = $targetDate.AddDays(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signInFilter = "createdDateTime ge $windowStart and createdDateTime lt $windowEnd and appDisplayName eq 'Windows Sign In'"
    $requestUri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter={0}&$select=createdDateTime,userId,deviceDetail,status&$top=1000' -f [uri]::EscapeDataString($signInFilter)
    $aggregates = @{}
    $eventCount = 0

    while (-not [string]::IsNullOrWhiteSpace($requestUri)) {
        $page = Invoke-GraphGet -Uri $requestUri
        if ($null -eq $page -or $null -eq $page.value) { throw 'Microsoft Graph returned an invalid sign-in page.' }
        foreach ($signIn in @($page.value)) {
            $deviceId = [string]$signIn.deviceDetail.deviceId
            $userId = [string]$signIn.userId
            $parsedDeviceId = [guid]::Empty
            $parsedUserId = [guid]::Empty
            if ($null -eq $signIn.status -or [int64]$signIn.status.errorCode -ne 0 -or
                -not [guid]::TryParse($deviceId, [ref]$parsedDeviceId) -or
                -not [guid]::TryParse($userId, [ref]$parsedUserId)) { continue }

            $deviceId = $parsedDeviceId.ToString('D')
            $userId = $parsedUserId.ToString('D')
            $key = '{0}|{1}' -f $deviceId, $userId
            $signInTime = ([datetime]$signIn.createdDateTime).ToUniversalTime()
            if (-not $aggregates.ContainsKey($key)) {
                $aggregates[$key] = [pscustomobject]@{ DeviceId = $deviceId; UserId = $userId; Count = 0; LatestSignIn = [datetime]::MinValue }
            }
            $aggregates[$key].Count++
            if ($signInTime -gt $aggregates[$key].LatestSignIn) { $aggregates[$key].LatestSignIn = $signInTime }
            $eventCount++
        }
        $requestUri = [string](Get-OptionalProperty -InputObject $page -Name '@odata.nextLink')
    }

    foreach ($aggregate in $aggregates.Values) {
        Set-TableEntity -TableName $AggregateTableName -Entity @{
            PartitionKey = $dateKey
            RowKey       = ('{0}|{1}' -f $aggregate.DeviceId.ToLowerInvariant(), $aggregate.UserId.ToLowerInvariant())
            DeviceId     = $aggregate.DeviceId
            UserId       = $aggregate.UserId
            SignInCount  = [int]$aggregate.Count
            LatestSignIn = $aggregate.LatestSignIn.ToString('o')
        }
    }

    Set-TableEntity -TableName $StateTableName -Entity @{
        PartitionKey  = 'Collection'
        RowKey        = $dateKey
        Status        = 'Complete'
        StartedAt     = $startedAt
        CompletedAt   = [datetime]::UtcNow.ToString('o')
        EventCount    = $eventCount
        AggregateRows = $aggregates.Count
    }

    Write-Output "Collected $eventCount successful sign-ins into $($aggregates.Count) aggregate rows for $($targetDate.ToString('yyyy-MM-dd'))."
}

try {
    $todayUtc = [datetime]::UtcNow.Date
    if (-not [string]::IsNullOrWhiteSpace($CollectionEndDate) -and [string]::IsNullOrWhiteSpace($CollectionDate)) {
        throw 'CollectionDate is required when CollectionEndDate is supplied.'
    }
    $firstDate = if ([string]::IsNullOrWhiteSpace($CollectionDate)) {
        $todayUtc.AddDays(-1)
    } else {
        [datetime]::ParseExact(
            $CollectionDate,
            'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        )
    }
    $lastDate = if ([string]::IsNullOrWhiteSpace($CollectionEndDate)) {
        $firstDate
    } else {
        [datetime]::ParseExact(
            $CollectionEndDate,
            'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        )
    }
    if ($lastDate -lt $firstDate) {
        throw 'CollectionEndDate must be on or after CollectionDate.'
    }
    if ($lastDate -ge $todayUtc) {
        throw 'CollectionDate and CollectionEndDate must identify completed UTC days.'
    }

    Initialize-ManagedIdentity
    for ($targetDate = $firstDate; $targetDate -le $lastDate; $targetDate = $targetDate.AddDays(1)) {
        Invoke-DailyCollection -TargetDate $targetDate
    }
    Remove-ExpiredDailyPartitions -CurrentDate $lastDate
} finally {
    $ErrorActionPreference = $script:OriginalErrorActionPreference
}