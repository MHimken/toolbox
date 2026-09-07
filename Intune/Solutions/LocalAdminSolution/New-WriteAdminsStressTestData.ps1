<#
.SYNOPSIS
    Creates deterministic Azure Table entities for Excel Power Query stress testing.
.DESCRIPTION
    Generates linked local administrator, user, and group entities across multiple synthetic
    computers. The generated entities follow the Write-AdminsToAZTable schema and are upserted
    into the configured Azure Tables when Execute is specified. Repeated runs update the same
    deterministic entities. The script can also remove generated stress-test entities or clear
    every entity from all three solution tables.
.PARAMETER StorageAccountName
    Azure Storage account containing the target tables.
.PARAMETER SasToken
    SAS token with read, add, update, and delete permissions. When omitted, the token is read
    from the remediation script in the same folder.
.PARAMETER ComputerCount
    Number of deterministic synthetic computers to create.
.PARAMETER EntriesPerComputer
    Number of local administrator entries to create for each synthetic computer.
.PARAMETER EntryCount
    Optional exact main-table entry count. Supported stress levels are 5000, 10000, 15000, and
    20000. When supplied, this overrides ComputerCount and uses EntriesPerComputer to distribute
    entries across the required number of synthetic computers.
.PARAMETER Execute
    Writes the generated entities to Azure Table Storage. Without this switch, the script only
    reports the number of entities that would be generated.
.PARAMETER IncludeReconciliationScenarios
    Adds Entra and domain SID fallbacks, a newer AD rename candidate, and a legacy duplicate row.
.PARAMETER EntraGroupObjectIds
    Optional Microsoft Entra group object IDs to include as unresolved local group names. Duplicate
    IDs are ignored. When supplied, other synthetic principals use local or domain identities so
    runbook validation is limited to the specified Entra groups.
.PARAMETER RemoveStressData
    Removes entities identified by the deterministic stress-test computer, user, and group names.
.PARAMETER ClearTables
    Removes every entity from LocalAdminCollection, AdminUserNames, and AdminGroups. The tables
    themselves are retained.
.PARAMETER Force
    Suppresses the confirmation prompt for removal operations. WhatIf is still honored.
.PARAMETER ThrottleLimit
    Maximum number of concurrent Azure Table upsert requests.
.PARAMETER LogPath
    Directory in which the log file is created.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.LINK
    .\changelog.md
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$StorageAccountName = '<storage-account-name>',
    [string]$SasToken,
    [ValidateRange(1, 10000)]
    [int]$ComputerCount = 834,
    [ValidateRange(1, 1000)]
    [int]$EntriesPerComputer = 12,
    [ValidateSet(5000, 10000, 15000, 20000)]
    [int]$EntryCount,
    [switch]$Execute,
    [switch]$IncludeReconciliationScenarios,
    [guid[]]$EntraGroupObjectIds = @(),
    [switch]$RemoveStressData,
    [switch]$ClearTables,
    [switch]$Force,
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 12,
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null
)

function Write-Log {
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        [ValidateSet('1', '2', '3')]
        [int]$Type
    )
    if ($Script:LogFile) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($Script:ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $Script:LogFile
        } elseif ($Script:ToConsole) {
            switch ($Type) {
                1 { Write-Host "T:$Type C:$Component M:$Message" }
                2 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Yellow -ForegroundColor Black }
                3 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Red -ForegroundColor White }
                default { Write-Host "T:$Type C:$Component M:$Message" }
            }
        }
    }
}

function Initialize-Script {
    $pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $pwsh7Path) {
        throw 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
    }
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'This script must run in PowerShell 7. Start the script with pwsh.exe.'
    }

    $script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $definedScriptName = 'New-WriteAdminsStressTestData'
    $sanitizedScriptName = $definedScriptName -replace '\s+', ''
    if (-not $LogFile) {
        $script:ResolvedLogFile = "$($sanitizedScriptName)_$($script:DateTime).log"
    } else {
        $script:ResolvedLogFile = $LogFile
    }

    if (-not (Test-Path -LiteralPath $LogPath)) {
        $null = New-Item -Path $LogPath -ItemType Directory -Force
    }
    $script:LogFile = Join-Path -Path $LogPath -ChildPath $script:ResolvedLogFile
    $script:ToConsole = $false
}

function Get-ConfiguredSasToken {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Token
    )

    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $resolvedToken = $Token.TrimStart('?')
        if ($resolvedToken -eq '<sas-token>') {
            throw 'SasToken is not configured.'
        }
        return $resolvedToken
    }

    $remediationPath = Join-Path -Path $PSScriptRoot -ChildPath 'Remediation\Remediate-Write-AdminsToAZTable.ps1'
    if (-not (Test-Path -LiteralPath $remediationPath)) {
        throw 'SasToken was not provided and the remediation script was not found in the solution folder.'
    }

    $remediationContent = Get-Content -LiteralPath $remediationPath -Raw
    $tokenMatch = [regex]::Match($remediationContent, '\$sasToken\s*=\s*''([^'']+)''')
    if (-not $tokenMatch.Success) {
        throw 'The SAS token could not be read from the remediation script.'
    }

    $resolvedToken = $tokenMatch.Groups[1].Value.TrimStart('?')
    if ($resolvedToken -eq '<sas-token>') {
        throw 'SasToken is not configured. Pass it using the SasToken parameter.'
    }
    return $resolvedToken
}

function Get-SyntheticSid {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Computer', 'User', 'Group')]
        [string]$Type,
        [Parameter(Mandatory = $true)]
        [int]$Index,
        [Parameter(Mandatory = $false)]
        [ValidateSet('L', 'E', 'A')]
        [string]$Source = 'A'
    )

    if ($Source -eq 'E' -and $Type -ne 'Computer') {
        return 'S-1-12-1-{0}-{1}-{2}-{3}' -f (1000000000 + $Index), (1100000000 + $Index), (1200000000 + $Index), (1300000000 + $Index)
    }

    $authority = switch ($Type) {
        'Computer' { 920000001 }
        'User' { 930000001 }
        'Group' { 940000001 }
    }
    return 'S-1-5-21-{0}-950000002-960000003-{1}' -f $authority, (1000 + $Index)
}

function ConvertTo-EntraSid {
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ObjectId
    )

    $bytes = $ObjectId.ToByteArray()
    return 'S-1-12-1-{0}-{1}-{2}-{3}' -f
        [BitConverter]::ToUInt32($bytes, 0),
        [BitConverter]::ToUInt32($bytes, 4),
        [BitConverter]::ToUInt32($bytes, 8),
        [BitConverter]::ToUInt32($bytes, 12)
}

function New-TestEntitySets {
    param(
        [Parameter(Mandatory = $true)]
        [int]$NumberOfComputers,
        [Parameter(Mandatory = $true)]
        [int]$NumberOfEntriesPerComputer,
        [int]$TargetEntryCount = 0,
        [guid[]]$EntraObjectIds = @()
    )

    $generationTime = [datetime]::UtcNow
    $administratorGroupNames = @(
        'Administrators',
        'Administratoren',
        'Administrateurs',
        'Administradores',
        'Amministratori',
        'Beheerders'
    )
    $mainEntities = [System.Collections.Generic.List[object]]::new()
    $userEntities = [System.Collections.Generic.List[object]]::new()
    $groupEntities = [System.Collections.Generic.List[object]]::new()
    $principalIndex = 0
    $groupIndex = 0
    $entraGroupIndex = 0
    $syntheticSources = if ($EntraObjectIds.Count -gt 0) { @('L', 'A') } else { @('L', 'E', 'A') }
    $resolvedNumberOfComputers = if ($TargetEntryCount -gt 0) {
        [int][math]::Ceiling($TargetEntryCount / [double]$NumberOfEntriesPerComputer)
    } else {
        $NumberOfComputers
    }

    for ($computerIndex = 1; $computerIndex -le $resolvedNumberOfComputers; $computerIndex++) {
        $computerSid = Get-SyntheticSid -Type Computer -Index $computerIndex
        $computerName = 'STRESS{0:D4}' -f $computerIndex
        $joinCode = [string](1 + (($computerIndex - 1) % 3))
        $administratorGroupName = $administratorGroupNames[($computerIndex - 1) % $administratorGroupNames.Count]
        $entriesForComputer = if ($TargetEntryCount -gt 0) {
            [math]::Min($NumberOfEntriesPerComputer, $TargetEntryCount - $principalIndex)
        } else {
            $NumberOfEntriesPerComputer
        }

        for ($entryNumber = 1; $entryNumber -le $entriesForComputer; $entryNumber++) {
            $principalIndex++
            $scenario = (($entryNumber - 1) % 8) + 1
            $scenarioCycle = [int][math]::Floor(($entryNumber - 1) / 8)
            $scenarioBaseIndex = [int](($computerIndex * 100000) + ($scenarioCycle * 10))
            $source = $syntheticSources[($principalIndex - 1) % $syntheticSources.Count]
            $isGroup = $scenario -in @(2, 4, 5, 7)
            $membershipType = if ($scenario -in @(3, 4, 6)) { 'Transitive' } else { 'Direct' }
            $parentGroupIndex = if ($scenario -in @(3, 4)) { $scenarioBaseIndex + 2 } else { $scenarioBaseIndex + 5 }
            $assignedThroughGroupId = if ($membershipType -eq 'Transitive') {
                Get-SyntheticSid -Type Group -Index $parentGroupIndex -Source A
            } else {
                $null
            }
            $reportTimestamp = $generationTime.AddMinutes(-(($principalIndex * 17) % 360)).AddSeconds(-(($computerIndex * 13 + $entryNumber) % 60))

            $mainEntity = [ordered]@{
                PartitionKey                     = $computerSid
                RowKey                           = [string]$entryNumber
                Computername                     = $computerName
                EntraOrHybrid                    = $joinCode
                'LastReportTimeStamp@odata.type' = 'Edm.DateTime'
                LastReportTimeStamp              = $reportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                LocalAdminGroupName              = $administratorGroupName
                MembershipType                   = $membershipType
                Removed                          = if (($principalIndex * 37) % 19 -eq 0) { 1 } else { 0 }
            }
            if ($membershipType -eq 'Transitive') {
                $mainEntity.AssignedThroughGroupID = $assignedThroughGroupId
            }

            if ($isGroup) {
                $groupIndex++
                if ($scenario -eq 7 -and $entraGroupIndex -lt $EntraObjectIds.Count) {
                    $source = 'E'
                    $groupSid = ConvertTo-EntraSid -ObjectId $EntraObjectIds[$entraGroupIndex]
                    $groupName = $groupSid
                    $entraGroupIndex++
                } else {
                    $source = if ($scenario -in @(2, 4, 5)) { 'A' } else { $source }
                    $groupPrincipalIndex = switch ($scenario) {
                        2 { $scenarioBaseIndex + 2 }
                        4 { $scenarioBaseIndex + 4 }
                        5 { $scenarioBaseIndex + 5 }
                        default { $scenarioBaseIndex + 7 }
                    }
                    $groupSid = Get-SyntheticSid -Type Group -Index $groupPrincipalIndex -Source $source
                    $groupName = 'StressGroup{0:D6}' -f $groupPrincipalIndex
                }
                if ($IncludeReconciliationScenarios -and $principalIndex -eq 4) {
                    $groupEntities.Add([pscustomobject][ordered]@{
                        TableName    = 'AdminGroups'
                        PartitionKey = $groupSid
                        RowKey       = 'LegacyStressGroup000004'
                        Entity       = [pscustomobject][ordered]@{
                            PartitionKey     = $groupSid
                            RowKey           = 'LegacyStressGroup000004'
                            LocalOrEntraOrAD = $source
                            StressData       = 1
                        }
                    })
                }
                $mainEntity.PrincipalID = $groupSid
                $mainEntity.PrincipalType = 'Group'
                $groupEntities.Add([pscustomobject][ordered]@{
                    TableName       = 'AdminGroups'
                    PartitionKey    = $groupSid
                    RowKey          = $groupName
                    Entity          = [pscustomobject][ordered]@{
                        PartitionKey     = $groupSid
                        RowKey           = $groupName
                        LocalOrEntraOrAD = $source
                        'ObservedAt@odata.type' = 'Edm.DateTime'
                        ObservedAt       = $reportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                        ResolutionState  = if ($source -eq 'E') { 'EntraPending' } else { 'Resolved' }
                        StressData       = 1
                    }
                })
            } else {
                if ($scenario -in @(1, 3, 6)) {
                    $source = 'A'
                    $userPrincipalIndex = $scenarioBaseIndex + 1
                } else {
                    $userPrincipalIndex = $scenarioBaseIndex + 8
                }
                $userSid = Get-SyntheticSid -Type User -Index $userPrincipalIndex -Source $source
                $samAccountName = 'StressUsr{0:D6}' -f $userPrincipalIndex
                if ($IncludeReconciliationScenarios -and $source -eq 'E' -and $principalIndex -eq 2) {
                    $samAccountName = $userSid
                } elseif ($IncludeReconciliationScenarios -and $source -eq 'A' -and $principalIndex -eq 3) {
                    $samAccountName = $userSid
                }
                $mainEntity.PrincipalID = $userSid
                $mainEntity.PrincipalType = 'User'
                if ($source -eq 'L') {
                    $mainEntity['LocalAccountLastPasswordChange@odata.type'] = 'Edm.DateTime'
                    $mainEntity.LocalAccountLastPasswordChange = [datetime]::UtcNow.AddDays(-($principalIndex % 365)).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                $userEntities.Add([pscustomobject][ordered]@{
                    TableName       = 'AdminUserNames'
                    PartitionKey    = $userSid
                    RowKey          = $samAccountName
                    Entity          = [pscustomobject][ordered]@{
                        PartitionKey      = $userSid
                        RowKey            = $samAccountName
                        UserPrincipalName = if ($source -eq 'L') { 'N/A' } else { '{0}@stress.example' -f $samAccountName.ToLowerInvariant() }
                        LocalOrEntraOrAD  = $source
                        'ObservedAt@odata.type' = 'Edm.DateTime'
                        ObservedAt        = $reportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                        ResolutionState   = if ($source -eq 'E') { 'EntraPending' } elseif ($samAccountName -eq $userSid) { 'DomainUnavailable' } else { 'Resolved' }
                        StressData        = 1
                    }
                })
                if ($IncludeReconciliationScenarios -and $source -eq 'A' -and $principalIndex -eq 6) {
                    $candidateEntity = $userEntities[$userEntities.Count - 1].Entity
                    $candidateEntity | Add-Member -NotePropertyName 'CandidateObservedAt@odata.type' -NotePropertyValue 'Edm.DateTime'
                    $candidateEntity | Add-Member -NotePropertyName CandidateObservedAt -NotePropertyValue $generationTime.AddMinutes(5).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                    $candidateEntity | Add-Member -NotePropertyName CandidateSamAccountName -NotePropertyValue 'RenamedStressUsr000006'
                    $candidateEntity | Add-Member -NotePropertyName CandidateUserPrincipalName -NotePropertyValue 'renamedstressusr000006@stress.example'
                }
            }

            $mainEntities.Add([pscustomobject][ordered]@{
                TableName    = 'LocalAdminCollection'
                PartitionKey = $computerSid
                RowKey       = [string]$entryNumber
                Entity       = [pscustomobject]$mainEntity
            })
        }
    }

    if ($entraGroupIndex -lt $EntraObjectIds.Count) {
        throw "The selected computer and entry counts provide $entraGroupIndex Entra group slots, but $($EntraObjectIds.Count) Entra group IDs were supplied."
    }

    return [pscustomobject]@{
        MainEntities  = $mainEntities
        UserEntities  = $userEntities
        GroupEntities = $groupEntities
        ComputerCount = $resolvedNumberOfComputers
    }
}

function Get-TableEntities {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $entities = [System.Collections.Generic.List[object]]::new()
    $nextPartitionKey = $null
    $nextRowKey = $null

    do {
        $query = $Token
        if (-not [string]::IsNullOrWhiteSpace($nextPartitionKey)) {
            $query += '&NextPartitionKey=' + [System.Uri]::EscapeDataString($nextPartitionKey)
            if (-not [string]::IsNullOrWhiteSpace($nextRowKey)) {
                $query += '&NextRowKey=' + [System.Uri]::EscapeDataString($nextRowKey)
            }
        }

        $uri = 'https://{0}.table.core.windows.net/{1}()?{2}' -f $AccountName, $TableName, $query
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers @{
            Accept         = 'application/json;odata=nometadata'
            'x-ms-version' = '2023-11-03'
        }
        $page = $response.Content | ConvertFrom-Json

        foreach ($entity in @($page.value)) {
            $entities.Add([pscustomobject]@{
                TableName    = $TableName
                PartitionKey = [string]$entity.PartitionKey
                RowKey       = [string]$entity.RowKey
                Entity       = $entity
            })
        }

        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
    } while (-not [string]::IsNullOrWhiteSpace($nextPartitionKey))

    return $entities
}

function Invoke-TableEntityRequests {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Entities,
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [int]$MaximumConcurrency,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Put', 'Delete')]
        [string]$Operation = 'Put'
    )

    $entityArray = @($Entities)
    if ($entityArray.Count -eq 0) {
        return 0
    }

    $workerCount = [Math]::Min($MaximumConcurrency, $entityArray.Count)
    $chunkSize = [Math]::Ceiling($entityArray.Count / $workerCount)
    $chunks = [System.Collections.Generic.List[object]]::new()
    for ($offset = 0; $offset -lt $entityArray.Count; $offset += $chunkSize) {
        $lastIndex = [Math]::Min($offset + $chunkSize - 1, $entityArray.Count - 1)
        $chunks.Add([pscustomobject]@{ Items = @($entityArray[$offset..$lastIndex]) })
    }

    $results = $chunks | ForEach-Object -ThrottleLimit $workerCount -Parallel {
        $handler = [System.Net.Http.SocketsHttpHandler]::new()
        $handler.MaxConnectionsPerServer = 1
        $handler.PooledConnectionLifetime = [timespan]::FromMinutes(5)
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [timespan]::FromSeconds(100)
        $succeeded = 0
        $errors = [System.Collections.Generic.List[string]]::new()

        try {
            foreach ($item in $_.Items) {
                $encodedPartitionKey = [System.Uri]::EscapeDataString($item.PartitionKey.Replace("'", "''"))
                $encodedRowKey = [System.Uri]::EscapeDataString($item.RowKey.Replace("'", "''"))
                $uri = "https://{0}.table.core.windows.net/{1}(PartitionKey='{2}',RowKey='{3}')?{4}" -f $using:AccountName, $item.TableName, $encodedPartitionKey, $encodedRowKey, $using:Token
                $payload = if ($using:Operation -eq 'Put') { $item.Entity | ConvertTo-Json -Depth 4 -Compress } else { $null }
                $completed = $false

                for ($attempt = 1; $attempt -le 3 -and -not $completed; $attempt++) {
                    $method = if ($using:Operation -eq 'Delete') { [System.Net.Http.HttpMethod]::Delete } else { [System.Net.Http.HttpMethod]::Put }
                    $request = [System.Net.Http.HttpRequestMessage]::new($method, $uri)
                    $request.Headers.TryAddWithoutValidation('Accept', 'application/json;odata=nometadata') | Out-Null
                    $request.Headers.TryAddWithoutValidation('DataServiceVersion', '3.0;NetFx') | Out-Null
                    $request.Headers.TryAddWithoutValidation('MaxDataServiceVersion', '3.0;NetFx') | Out-Null
                    $request.Headers.TryAddWithoutValidation('x-ms-version', '2023-11-03') | Out-Null
                    if ($using:Operation -eq 'Delete') {
                        $request.Headers.TryAddWithoutValidation('If-Match', '*') | Out-Null
                    } else {
                        $request.Content = [System.Net.Http.StringContent]::new($payload, [System.Text.Encoding]::UTF8, 'application/json')
                    }
                    $response = $null

                    try {
                        $response = $client.SendAsync($request).GetAwaiter().GetResult()
                        if ($response.IsSuccessStatusCode) {
                            $completed = $true
                            $succeeded++
                        } elseif ($using:Operation -eq 'Delete' -and [int]$response.StatusCode -eq 404) {
                            $completed = $true
                        } elseif ($attempt -eq 3 -or [int]$response.StatusCode -notin @(408, 429, 500, 502, 503, 504)) {
                            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                            $errors.Add("$($item.TableName) $($item.PartitionKey)/$($item.RowKey): HTTP $([int]$response.StatusCode) $responseBody")
                            break
                        }
                    } catch {
                        if ($attempt -eq 3) {
                            $errors.Add("$($item.TableName) $($item.PartitionKey)/$($item.RowKey): $($_.Exception.Message)")
                        }
                    } finally {
                        if ($null -ne $response) {
                            $response.Dispose()
                        }
                        $request.Dispose()
                    }

                    if (-not $completed -and $attempt -lt 3) {
                        [System.Threading.Tasks.Task]::Delay(500 * $attempt).GetAwaiter().GetResult()
                    }
                }
            }
        } finally {
            $client.Dispose()
            $handler.Dispose()
        }

        [pscustomobject]@{
            Succeeded = $succeeded
            Errors    = @($errors)
        }
    }

    $allErrors = @($results | ForEach-Object { $_.Errors })
    if ($allErrors.Count -gt 0) {
        throw ('{0} entity operations failed. First errors: {1}' -f $allErrors.Count, (($allErrors | Select-Object -First 5) -join ' | '))
    }

    return [int](($results | Measure-Object -Property Succeeded -Sum).Sum)
}

try {
    Initialize-Script

    $selectedOperations = @($Execute, $RemoveStressData, $ClearTables).Where({ $_ }).Count
    if ($selectedOperations -gt 1) {
        throw 'Execute, RemoveStressData, and ClearTables cannot be used together.'
    }

    if (($Execute -or $RemoveStressData -or $ClearTables) -and
        ([string]::IsNullOrWhiteSpace($StorageAccountName) -or $StorageAccountName -eq '<storage-account-name>')) {
        throw 'StorageAccountName is not configured.'
    }

    if ($RemoveStressData -or $ClearTables) {
        $resolvedSasToken = Get-ConfiguredSasToken -Token $SasToken
        Write-Log -Message 'Reading all Azure Table entities for cleanup.' -Component 'Cleanup' -Type 1

        $mainEntities = @(Get-TableEntities -TableName 'LocalAdminCollection' -AccountName $StorageAccountName -Token $resolvedSasToken)
        $userEntities = @(Get-TableEntities -TableName 'AdminUserNames' -AccountName $StorageAccountName -Token $resolvedSasToken)
        $groupEntities = @(Get-TableEntities -TableName 'AdminGroups' -AccountName $StorageAccountName -Token $resolvedSasToken)

        if ($RemoveStressData) {
            $mainEntities = @($mainEntities | Where-Object { $_.Entity.Computername -like 'STRESS*' })
            $userEntities = @($userEntities | Where-Object { $_.Entity.StressData -eq 1 -or $_.RowKey -like 'StressUsr*' })
            $groupEntities = @($groupEntities | Where-Object { $_.Entity.StressData -eq 1 -or $_.RowKey -like '*StressGroup*' })
            $operationName = 'Remove stress-test data'
        } else {
            $operationName = 'Clear all solution table data'
        }

        $totalRemovalCount = $mainEntities.Count + $userEntities.Count + $groupEntities.Count
        $targetDescription = "$totalRemovalCount entities from LocalAdminCollection, AdminUserNames, and AdminGroups"
        $approved = if ($Force -and -not $WhatIfPreference) {
            $true
        } else {
            $PSCmdlet.ShouldProcess($targetDescription, $operationName)
        }

        if (-not $approved) {
            Write-Output "No entities were removed. Selected target: $targetDescription."
            exit 0
        }

        $removedMain = Invoke-TableEntityRequests -Entities $mainEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete
        $removedUsers = Invoke-TableEntityRequests -Entities $userEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete
        $removedGroups = Invoke-TableEntityRequests -Entities $groupEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete

        $message = "SUCCESS: Removed $removedMain main rows, $removedUsers user rows, and $removedGroups group rows."
        Write-Log -Message $message -Component 'Summary' -Type 1
        Write-Output $message
        exit 0
    }

    Write-Log -Message 'Generating deterministic stress-test entities.' -Component 'Initialize' -Type 1

    $uniqueEntraGroupObjectIds = [System.Collections.Generic.List[guid]]::new()
    $seenEntraGroupObjectIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($objectId in $EntraGroupObjectIds) {
        if ($seenEntraGroupObjectIds.Add($objectId.ToString())) {
            $uniqueEntraGroupObjectIds.Add($objectId)
        }
    }

    $entitySets = New-TestEntitySets `
        -NumberOfComputers $ComputerCount `
        -NumberOfEntriesPerComputer $EntriesPerComputer `
        -TargetEntryCount $(if ($PSBoundParameters.ContainsKey('EntryCount')) { $EntryCount } else { 0 }) `
        -EntraObjectIds $uniqueEntraGroupObjectIds.ToArray()
    $mainCount = $entitySets.MainEntities.Count
    $userCount = $entitySets.UserEntities.Count
    $groupCount = $entitySets.GroupEntities.Count
    $totalCount = $mainCount + $userCount + $groupCount
    $generatedComputerCount = $entitySets.ComputerCount

    if (-not $Execute) {
        $message = "DRY RUN: Would upsert $mainCount main rows, $userCount user rows, and $groupCount group rows across $generatedComputerCount computers, including $($uniqueEntraGroupObjectIds.Count) specified Entra groups. Use -Execute to write the data."
        Write-Log -Message $message -Component 'Summary' -Type 1
        Write-Output $message
        exit 0
    }

    $resolvedSasToken = Get-ConfiguredSasToken -Token $SasToken
    Write-Log -Message "Uploading $totalCount entities to Azure Table Storage." -Component 'Upload' -Type 1

    $uploadedUsers = Invoke-TableEntityRequests -Entities $entitySets.UserEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit
    $uploadedGroups = Invoke-TableEntityRequests -Entities $entitySets.GroupEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit
    $uploadedMain = Invoke-TableEntityRequests -Entities $entitySets.MainEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit

    $message = "SUCCESS: Upserted $uploadedMain main rows, $uploadedUsers user rows, and $uploadedGroups group rows across $generatedComputerCount synthetic computers, including $($uniqueEntraGroupObjectIds.Count) specified Entra groups."
    Write-Log -Message $message -Component 'Summary' -Type 1
    Write-Output $message
    exit 0
} catch {
    if ($script:LogFile) {
        Write-Log -Message $_.Exception.Message -Component 'Error' -Type 3
    }
    Write-Error "Stress-test data generation failed. $($_.Exception.Message)"
    exit 1
}
