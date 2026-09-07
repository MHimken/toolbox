<#
.SYNOPSIS
    Reconciles local administrator lookup names by using an Azure Automation managed identity.
.DESCRIPTION
    Reads AdminUserNames and AdminGroups, resolves Microsoft Entra SIDs through Microsoft Graph,
    promotes newer Active Directory and local candidates, and consolidates duplicate SID rows.
    A replacement row is written before obsolete rows are deleted so interrupted runs converge safely.
.PARAMETER StorageAccountName
    Azure Storage account containing the lookup tables.
.PARAMETER ManagedIdentityClientId
    Optional client ID of a user-assigned managed identity. Omit it for the system-assigned identity.
.NOTES
    Runtime: PowerShell 7
    Required modules: Az.Accounts
    Storage role: Storage Table Data Contributor, scoped as narrowly as practical
    Graph application permissions: User.Read.All and Group.Read.All
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [string]$ManagedIdentityClientId,

    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 4,

    [ValidateSet('AdminUserNames', 'AdminGroups')]
    [string[]]$TableNames = @('AdminUserNames', 'AdminGroups')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:StorageBaseUri = 'https://{0}.table.core.windows.net' -f $StorageAccountName
$script:StorageToken = $null
$script:GraphToken = $null
$script:RowsCreatedOrUpdated = 0
$script:RowsDeleted = 0
$script:PartitionsSkipped = 0
$script:ResolutionFailures = 0
$script:EntraObjectsResolved = 0
$script:EntraObjectsUnresolved = 0

function ConvertFrom-SecureAccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Token
    )

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
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'This runbook requires a PowerShell 7 Azure Automation runtime.'
    }

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
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ForWrite
    )

    $headers = @{
        Authorization  = 'Bearer {0}' -f $script:StorageToken
        Accept         = 'application/json;odata=nometadata'
        'x-ms-date'    = [datetime]::UtcNow.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
        'x-ms-version' = '2023-11-03'
    }
    if ($ForWrite) {
        $headers['Content-Type'] = 'application/json'
    }
    return $headers
}

function Invoke-RestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Put', 'Delete')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [uri]$Uri,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [byte[]]$Body
    )

    for ($attempt = 1; $attempt -le $MaximumRetryCount; $attempt++) {
        try {
            $parameters = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                ErrorAction = 'Stop'
            }
            if ($null -ne $Body) {
                $parameters.Body = $Body
            }
            return Invoke-WebRequest @parameters
        } catch {
            $response = $_.Exception.Response
            $statusCode = if ($null -ne $response) { [int]$response.StatusCode } else { 0 }
            if ($attempt -eq $MaximumRetryCount -or ($statusCode -ne 429 -and $statusCode -lt 500)) {
                throw
            }

            $retryAfter = 0
            if ($null -ne $response -and $null -ne $response.Headers) {
                [void][int]::TryParse([string]$response.Headers['Retry-After'], [ref]$retryAfter)
            }
            if ($retryAfter -le 0) {
                $retryAfter = [math]::Min([math]::Pow(2, $attempt), 30)
            }
            Start-Sleep -Seconds $retryAfter
        }
    }
}

function Get-TableEntities {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName
    )

    $entities = [Collections.Generic.List[object]]::new()
    $nextPartitionKey = $null
    $nextRowKey = $null
    do {
        $query = '$select=PartitionKey,RowKey,Timestamp,UserPrincipalName,LocalOrEntraOrAD,ObservedAt,ResolutionState,CandidateObservedAt,CandidateGroupName,CandidateSamAccountName,CandidateUserPrincipalName'
        if (-not [string]::IsNullOrWhiteSpace($nextPartitionKey)) {
            $query += '&NextPartitionKey=' + [uri]::EscapeDataString($nextPartitionKey)
            if (-not [string]::IsNullOrWhiteSpace($nextRowKey)) {
                $query += '&NextRowKey=' + [uri]::EscapeDataString($nextRowKey)
            }
        }

        $uri = '{0}/{1}()?{2}' -f $script:StorageBaseUri, $TableName, $query
        $response = Invoke-RestWithRetry -Method Get -Uri $uri -Headers (Get-StorageHeaders)
        foreach ($entity in @(($response.Content | ConvertFrom-Json).value)) {
            $entities.Add($entity)
        }
        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
    } while (-not [string]::IsNullOrWhiteSpace($nextPartitionKey))

    return $entities
}

function ConvertTo-EntityUri {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$PartitionKey,
        [Parameter(Mandatory = $true)]
        [string]$RowKey
    )

    $escapedPartitionKey = $PartitionKey.Replace("'", "''")
    $escapedRowKey = $RowKey.Replace("'", "''")
    return [uri]('{0}/{1}(PartitionKey=''{2}'',RowKey=''{3}'')' -f $script:StorageBaseUri, $TableName, $escapedPartitionKey, $escapedRowKey)
}

function ConvertTo-UtcDateTime {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    $parsed = [datetime]::MinValue
    if ($null -ne $Value -and [datetime]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return [datetime]::MinValue
}

function Get-EntityValue {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Entity,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Entity.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-ObservedAt {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Entity,
        [Parameter(Mandatory = $false)]
        [switch]$Candidate
    )

    if ($Candidate) {
        return ConvertTo-UtcDateTime -Value (Get-EntityValue -Entity $Entity -Name 'CandidateObservedAt')
    }
    $observedAt = ConvertTo-UtcDateTime -Value (Get-EntityValue -Entity $Entity -Name 'ObservedAt')
    if ($observedAt -ne [datetime]::MinValue) {
        return $observedAt
    }
    return ConvertTo-UtcDateTime -Value (Get-EntityValue -Entity $Entity -Name 'Timestamp')
}

function Select-CanonicalEntity {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entities
    )

    return @($Entities | Sort-Object -Property @(
        @{ Expression = { if ([string](Get-EntityValue -Entity $_ -Name 'ResolutionState') -eq 'Resolved') { 1 } else { 0 } }; Descending = $true },
        @{ Expression = { Get-ObservedAt -Entity $_ }; Descending = $true },
        @{ Expression = { [string]$_.RowKey }; Descending = $true }
    ))[0]
}

function Test-Sid {
    param([string]$Value)
    return $Value -match '^S-\d-(?:\d+-)+\d+$'
}

function Test-LookupName {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    return -not [string]::IsNullOrWhiteSpace($Value) -and
        $Value.Length -le 128 -and
        $Value -notmatch '[/\\#?\x00-\x1F\x7F]' -and
        -not (Test-Sid -Value $Value)
}

function Convert-EntraSidToObjectId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid
    )

    if ($Sid -notmatch '^S-1-12-1-(\d+)-(\d+)-(\d+)-(\d+)$') {
        throw "'$Sid' is not a supported Microsoft Entra SID."
    }

    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($component in $Matches[1..4]) {
        $number = [uint32]::Parse($component, [Globalization.CultureInfo]::InvariantCulture)
        $bytes.AddRange([BitConverter]::GetBytes($number))
    }
    return [guid]::new($bytes.ToArray()).ToString()
}

function Get-GraphObject {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('AdminUserNames', 'AdminGroups')]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$Sid
    )

    $objectId = Convert-EntraSidToObjectId -Sid $Sid
    if ($TableName -eq 'AdminGroups') {
        $uri = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=id,displayName' -f $objectId
    } else {
        $uri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=id,userPrincipalName,onPremisesSamAccountName' -f $objectId
    }

    $response = Invoke-RestWithRetry -Method Get -Uri $uri -Headers @{
        Authorization = 'Bearer {0}' -f $script:GraphToken
        Accept        = 'application/json'
    }
    return $response.Content | ConvertFrom-Json
}

function Get-NewCanonicalEntity {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('AdminUserNames', 'AdminGroups')]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [object[]]$Entities
    )

    $canonical = Select-CanonicalEntity -Entities $Entities
    $source = [string]$canonical.LocalOrEntraOrAD
    $partitionKey = [string]$canonical.PartitionKey

    if ($source -eq 'E') {
        $graphObject = Get-GraphObject -TableName $TableName -Sid $partitionKey
        if ($TableName -eq 'AdminGroups') {
            $name = [string]$graphObject.displayName
            $upn = $null
        } else {
            $upn = [string]$graphObject.userPrincipalName
            $name = [string]$graphObject.onPremisesSamAccountName
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = $upn
            }
        }
        $observedAt = [datetime]::UtcNow
    } else {
        $candidates = @($Entities | Where-Object {
            [string]$_.LocalOrEntraOrAD -eq $source -and
            (Get-ObservedAt -Entity $_ -Candidate) -gt (Get-ObservedAt -Entity $canonical)
        } | Sort-Object -Property @{ Expression = { Get-ObservedAt -Entity $_ -Candidate }; Descending = $true })

        if ($candidates.Count -eq 0) {
            if ($Entities.Count -eq 1) {
                return [pscustomobject]@{
                    Entity    = $canonical
                    Changed   = $false
                    ClearRows = $false
                }
            }

            $observedAt = Get-ObservedAt -Entity $canonical
            if ($observedAt -eq [datetime]::MinValue) {
                $observedAt = [datetime]::UtcNow
            }
            $normalized = [ordered]@{
                PartitionKey            = $partitionKey
                RowKey                  = [string]$canonical.RowKey
                LocalOrEntraOrAD        = $source
                'ObservedAt@odata.type' = 'Edm.DateTime'
                ObservedAt              = $observedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
                ResolutionState         = if (Test-Sid -Value ([string]$canonical.RowKey)) { 'DomainUnavailable' } else { 'Resolved' }
            }
            if ($TableName -eq 'AdminUserNames') {
                $normalized.UserPrincipalName = [string](Get-EntityValue -Entity $canonical -Name 'UserPrincipalName')
            }
            return [pscustomobject]@{
                Entity    = [pscustomobject]$normalized
                Changed   = $true
                ClearRows = $true
            }
        }

        $candidate = $candidates[0]
        if ($TableName -eq 'AdminGroups') {
            $name = [string](Get-EntityValue -Entity $candidate -Name 'CandidateGroupName')
            $upn = $null
        } else {
            $name = [string](Get-EntityValue -Entity $candidate -Name 'CandidateSamAccountName')
            $upn = [string](Get-EntityValue -Entity $candidate -Name 'CandidateUserPrincipalName')
        }
        $observedAt = Get-ObservedAt -Entity $candidate -Candidate
    }

    if (-not (Test-LookupName -Value $name)) {
        throw "The proposed $TableName name for SID '$partitionKey' is invalid."
    }
    if ($TableName -eq 'AdminUserNames' -and ([string]::IsNullOrWhiteSpace($upn) -or $upn.Length -gt 1024)) {
        throw "The proposed user principal name for SID '$partitionKey' is invalid."
    }

    $entity = [ordered]@{
        PartitionKey             = $partitionKey
        RowKey                   = $name
        LocalOrEntraOrAD         = $source
        'ObservedAt@odata.type'  = 'Edm.DateTime'
        ObservedAt               = $observedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
        ResolutionState          = 'Resolved'
    }
    if ($TableName -eq 'AdminUserNames') {
        $entity.UserPrincipalName = $upn
    }

    $sameValue = [string]::Equals([string]$canonical.RowKey, $name, [StringComparison]::OrdinalIgnoreCase)
    if ($TableName -eq 'AdminUserNames') {
        $sameValue = $sameValue -and [string]::Equals([string]$canonical.UserPrincipalName, $upn, [StringComparison]::OrdinalIgnoreCase)
    }
    $alreadyCanonical = $sameValue -and
        [string](Get-EntityValue -Entity $canonical -Name 'ResolutionState') -eq 'Resolved' -and
        [string]::IsNullOrWhiteSpace([string](Get-EntityValue -Entity $canonical -Name 'CandidateObservedAt')) -and
        $Entities.Count -eq 1

    return [pscustomobject]@{
        Entity    = [pscustomobject]$entity
        Changed   = -not $alreadyCanonical
        ClearRows = $Entities.Count -gt 1 -or -not [string]::Equals([string]$canonical.RowKey, $name, [StringComparison]::Ordinal)
    }
}

function Set-CanonicalEntity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [psobject]$Entity
    )

    $uri = ConvertTo-EntityUri -TableName $TableName -PartitionKey ([string]$Entity.PartitionKey) -RowKey ([string]$Entity.RowKey)
    $body = [Text.Encoding]::UTF8.GetBytes(($Entity | ConvertTo-Json -Depth 4 -Compress))
    Invoke-RestWithRetry -Method Put -Uri $uri -Headers (Get-StorageHeaders -ForWrite) -Body $body | Out-Null
    $script:RowsCreatedOrUpdated++
}

function Remove-LookupEntity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [psobject]$Entity
    )

    $headers = Get-StorageHeaders
    $headers['If-Match'] = '*'
    $uri = ConvertTo-EntityUri -TableName $TableName -PartitionKey ([string]$Entity.PartitionKey) -RowKey ([string]$Entity.RowKey)
    Invoke-RestWithRetry -Method Delete -Uri $uri -Headers $headers | Out-Null
    $script:RowsDeleted++
}

function Invoke-PartitionReconciliation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [object[]]$Entities
    )

    $partitionKey = [string]$Entities[0].PartitionKey
    if (-not (Test-Sid -Value $partitionKey)) {
        Write-Warning "Skipping invalid SID partition '$partitionKey' in $TableName."
        $script:PartitionsSkipped++
        return
    }

    $canonical = Select-CanonicalEntity -Entities $Entities
    $isEntra = [string]$canonical.LocalOrEntraOrAD -eq 'E'
    $entraObjectId = if ($isEntra) {
        try {
            Convert-EntraSidToObjectId -Sid $partitionKey
        } catch {
            'invalid'
        }
    } else {
        $null
    }

    try {
        $result = Get-NewCanonicalEntity -TableName $TableName -Entities $Entities
    } catch {
        if ($isEntra) {
            Write-Warning "Could not resolve Microsoft Entra object '$entraObjectId' with SID '$partitionKey' in ${TableName}: $($_.Exception.Message)"
            $script:EntraObjectsUnresolved++
        } else {
            Write-Warning "Could not reconcile SID '$partitionKey' in ${TableName}: $($_.Exception.Message)"
        }
        $script:ResolutionFailures++
        return
    }


    if ($isEntra) {
        $objectType = if ($TableName -eq 'AdminGroups') { 'group' } else { 'user' }
        Write-Output "Resolved Microsoft Entra $objectType '$entraObjectId' with SID '$partitionKey' to '$($result.Entity.RowKey)'."
        $script:EntraObjectsResolved++
    }

    if (-not $result.Changed -and -not $result.ClearRows) {
        $script:PartitionsSkipped++
        return
    }

    $target = $result.Entity
    if ($PSCmdlet.ShouldProcess("$TableName/$partitionKey", "Upsert canonical row '$($target.RowKey)'")) {
        Set-CanonicalEntity -TableName $TableName -Entity $target
    }

    foreach ($obsolete in $Entities) {
        if ([string]$obsolete.RowKey -ceq [string]$target.RowKey) {
            continue
        }
        if ($PSCmdlet.ShouldProcess("$TableName/$partitionKey/$($obsolete.RowKey)", 'Delete obsolete lookup row')) {
            Remove-LookupEntity -TableName $TableName -Entity $obsolete
        }
    }
}

Initialize-ManagedIdentity
foreach ($tableName in $TableNames) {
    $entities = @(Get-TableEntities -TableName $tableName)
    foreach ($partition in @($entities | Group-Object -Property PartitionKey)) {
        Invoke-PartitionReconciliation -TableName $tableName -Entities @($partition.Group)
    }
}

Write-Output ('Reconciliation complete: {0} rows created or updated, {1} obsolete rows deleted, {2} unchanged partitions skipped, {3} resolution failures, {4} Entra objects resolved, and {5} Entra objects unresolved.' -f
    $script:RowsCreatedOrUpdated,
    $script:RowsDeleted,
    $script:PartitionsSkipped,
    $script:ResolutionFailures,
    $script:EntraObjectsResolved,
    $script:EntraObjectsUnresolved)
