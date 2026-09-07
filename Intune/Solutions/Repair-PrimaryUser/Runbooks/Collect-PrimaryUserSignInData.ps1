#Requires -Version 7.2
#Requires -Module Az.Accounts
<#
.SYNOPSIS
    Collects one UTC day of Windows sign-in aggregates for primary-user analysis.
.DESCRIPTION
    Runs in Azure Automation with a managed identity. The runbook streams Microsoft Graph sign-in
    pages, counts successful Windows Sign In events by device and user, and replaces the selected
    date partition in Azure Table Storage. A separate state row prevents completed days from being
    collected twice.
.PARAMETER StorageAccountName
    Storage account containing the solution tables.
.PARAMETER CollectionDate
    UTC date to collect in yyyy-MM-dd format. Defaults to the previous completed UTC day.
.PARAMETER ForceRecollect
    Replaces a partition even when its state is Complete.
.NOTES
    Runtime: PowerShell 7.2
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

    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,62}$')]
    [string]$AggregateTableName = 'PrimaryUserDaily',

    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,62}$')]
    [string]$StateTableName = 'PrimaryUserState',

    [string]$ManagedIdentityClientId,

    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5,

    [ValidateRange(29, 365)]
    [int]$RetentionDays = 35,

    [switch]$ForceRecollect
)

Set-StrictMode -Version Latest
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
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Put', 'Delete')][string]$Method,
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

function Remove-TablePartition {
    param(
        [Parameter(Mandatory = $true)][string]$TableName,
        [Parameter(Mandatory = $true)][string]$PartitionKey
    )

    foreach ($entity in @(Get-TableEntitiesByPartition -TableName $TableName -PartitionKey $PartitionKey)) {
        $headers = Get-StorageHeaders
        $headers['If-Match'] = '*'
        $uri = ConvertTo-EntityUri -TableName $TableName -PartitionKey $PartitionKey -RowKey ([string]$entity.RowKey)
        Invoke-RestWithRetry -Method Delete -Uri $uri -Headers $headers | Out-Null
    }
}

function Get-CollectionState {
    param([Parameter(Mandatory = $true)][string]$DateKey)

    $uri = ConvertTo-EntityUri -TableName $StateTableName -PartitionKey 'Collection' -RowKey $DateKey
    try {
        $response = Invoke-RestWithRetry -Method Get -Uri $uri -Headers (Get-StorageHeaders)
        return $response.Content | ConvertFrom-Json
    } catch {
        if ($null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return $null }
        throw
    }
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

function Remove-ExpiredDailyPartitions {
    param([Parameter(Mandatory = $true)][datetime]$CurrentDate)

    $expiredDate = $CurrentDate.AddDays(-$RetentionDays).ToString('yyyyMMdd')
    $filter = [uri]::EscapeDataString("PartitionKey eq 'Collection' and RowKey lt '$expiredDate' and Status eq 'Complete'")
    $uri = '{0}/{1}()?$filter={2}' -f $script:StorageBaseUri, $StateTableName, $filter
    $response = Invoke-RestWithRetry -Method Get -Uri $uri -Headers (Get-StorageHeaders)
    foreach ($state in @(($response.Content | ConvertFrom-Json).value)) {
        Remove-TablePartition -TableName $AggregateTableName -PartitionKey ([string]$state.RowKey)
        $headers = Get-StorageHeaders
        $headers['If-Match'] = '*'
        $stateUri = ConvertTo-EntityUri -TableName $StateTableName -PartitionKey 'Collection' -RowKey ([string]$state.RowKey)
        Invoke-RestWithRetry -Method Delete -Uri $stateUri -Headers $headers | Out-Null
        Write-Output "Removed expired aggregate partition $($state.RowKey)."
    }
}

Initialize-ManagedIdentity

$targetDate = if ([string]::IsNullOrWhiteSpace($CollectionDate)) {
    [datetime]::UtcNow.Date.AddDays(-1)
} else {
    [datetime]::ParseExact(
        $CollectionDate,
        'yyyy-MM-dd',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    )
}
if ($targetDate -ge [datetime]::UtcNow.Date) {
    throw 'CollectionDate must identify a completed UTC day.'
}

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
$filter = "createdDateTime ge $windowStart and createdDateTime lt $windowEnd and appDisplayName eq 'Windows Sign In'"
$requestUri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter={0}&$select=createdDateTime,userId,deviceDetail,status&$top=1000' -f [uri]::EscapeDataString($filter)
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
    $requestUri = [string]$page.'@odata.nextLink'
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

Remove-ExpiredDailyPartitions -CurrentDate $targetDate
Write-Output "Collected $eventCount successful sign-ins into $($aggregates.Count) aggregate rows for $($targetDate.ToString('yyyy-MM-dd'))."