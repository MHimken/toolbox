<#
.SYNOPSIS
    Creates deterministic Azure Table entities for Excel Power Query stress testing.
.DESCRIPTION
    Generates linked local administrator, device, user, and group entities across multiple synthetic
    computers. Optional governance rules and review actions exercise the human-facing Review and
    Governance views. The generated entities follow the LocalAdminSolution schema and are upserted
    into the configured Azure Tables when Execute is specified. Repeated runs update the same
    deterministic entities. The script can also remove generated stress-test entities or clear
    every entity from the four inventory solution tables and, when governance parameters are supplied,
    from the generated governance scenario tables.
.PARAMETER StorageAccountName
    Azure Storage account containing the target tables.
.PARAMETER SasToken
    SAS token with read, add, update, and delete permissions. When omitted, the token is read
    from the remediation script in the same folder.
.PARAMETER GovernanceStorageAccountName
    Governance Storage account containing allow-rule and review-action tables.
.PARAMETER GovernanceSasToken
    Governance account SAS with the permissions required by the selected operation.
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
.PARAMETER IncludeGovernanceScenarios
    Adds deterministic active allow/deny rules, pending and expired rules, a rule conflict, and
    review actions covering requested, queued, in-progress, awaiting-inventory, succeeded, and failed states.
.PARAMETER EntraGroupObjectIds
    Optional Microsoft Entra group object IDs to include as unresolved local group names. Duplicate
    IDs are ignored. When supplied, other synthetic principals use local or domain identities so
    runbook validation is limited to the specified Entra groups.
.PARAMETER LegacyNaming
    Uses the original STRESS, StressUsr, StressGroup, and stress.example naming profile instead of
    the default fictional Contoso international profile.
.PARAMETER RemoveStressData
    Removes explicitly marked synthetic entities and legacy entities identified by their original
    deterministic computer, user, and group name prefixes.
.PARAMETER ClearTables
    Removes every entity from LocalAdminCollection, LocalAdminDevices, AdminUserNames, and AdminGroups. The tables
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
    [string]$GovernanceStorageAccountName,
    [string]$GovernanceSasToken,
    [ValidateRange(1, 10000)]
    [int]$ComputerCount = 834,
    [ValidateRange(1, 1000)]
    [int]$EntriesPerComputer = 12,
    [ValidateSet(5000, 10000, 15000, 20000)]
    [int]$EntryCount,
    [switch]$Execute,
    [switch]$IncludeReconciliationScenarios,
    [switch]$IncludeGovernanceScenarios,
    [guid[]]$EntraGroupObjectIds = @(),
    [switch]$LegacyNaming,
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
    $definedScriptName = 'New-LocalAdminSolutionStressTestData'
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

    $remediationPath = Join-Path -Path $PSScriptRoot -ChildPath 'Remediation\Remediate-LocalAdminSolution.ps1'
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

function Get-SyntheticComputerName {
    param([int]$Index)

    if ($LegacyNaming) {
        return 'STRESS{0:D4}' -f $Index
    }

    $sites = @('BER', 'LON', 'AMS', 'PAR', 'MAD', 'MIL', 'WAW', 'DUB', 'ZRH', 'VIE')
    $deviceTypes = @('LT', 'WS', 'VDI', 'KSK')
    $site = $sites[($Index - 1) % $sites.Count]
    $deviceType = $deviceTypes[[int][math]::Floor(($Index - 1) / $sites.Count) % $deviceTypes.Count]
    return '{0}-{1}-{2:D4}' -f $site, $deviceType, $Index
}

function ConvertTo-Base36 {
    param([long]$Value)

    $characters = '0123456789abcdefghijklmnopqrstuvwxyz'
    if ($Value -eq 0) {
        return '0'
    }

    $result = ''
    while ($Value -gt 0) {
        $result = $characters[[int]($Value % 36)] + $result
        $Value = [math]::Floor($Value / 36)
    }
    return $result
}

function Get-SyntheticUserName {
    param([int]$Index)

    if ($LegacyNaming) {
        return 'StressUsr{0:D6}' -f $Index
    }

    $firstNames = @('anna', 'ben', 'clara', 'daniel', 'elena', 'felix', 'grace', 'henry', 'ines', 'jonas', 'karla', 'lucas', 'maya', 'noah', 'olivia', 'paul', 'quinn', 'sara', 'theo', 'zoe')
    $lastNames = @('adler', 'bauer', 'becker', 'brown', 'chen', 'davis', 'evans', 'fischer', 'garcia', 'hughes', 'ivanov', 'jensen', 'keller', 'khan', 'lewis', 'martin', 'meyer', 'novak', 'patel', 'rossi', 'schmidt', 'smith', 'taylor', 'wagner', 'walker', 'wang', 'wilson')
    $firstName = $firstNames[$Index % $firstNames.Count]
    $lastName = $lastNames[[int][math]::Floor($Index / $firstNames.Count) % $lastNames.Count]
    $suffix = ConvertTo-Base36 -Value $Index
    $nameStem = '{0}.{1}' -f $firstName, $lastName
    $maximumStemLength = 19 - $suffix.Length
    if ($nameStem.Length -gt $maximumStemLength) {
        $nameStem = $nameStem.Substring(0, $maximumStemLength)
    }
    return '{0}-{1}' -f $nameStem, $suffix
}

function Get-SyntheticGroupName {
    param(
        [int]$Index,
        [ValidateSet('L', 'E', 'A')]
        [string]$Source
    )

    if ($LegacyNaming) {
        return 'StressGroup{0:D6}' -f $Index
    }

    $sites = @('Berlin', 'London', 'Amsterdam', 'Paris', 'Madrid', 'Milan', 'Warsaw', 'Dublin', 'Zurich', 'Vienna')
    $roles = @('Endpoint-Admins', 'Helpdesk-Tier2', 'Workplace-Engineers', 'Field-Support', 'Deployment-Operators', 'Security-Operations')
    $site = $sites[$Index % $sites.Count]
    $role = $roles[[int][math]::Floor($Index / $sites.Count) % $roles.Count]
    $suffix = ConvertTo-Base36 -Value $Index
    $groupName = switch ($Source) {
        'L' { 'Local-{0}-{1}-{2}' -f $site, $role, $suffix }
        'E' { 'Cloud-{0}-{1}-{2}' -f $site, $role, $suffix }
        default { 'GG-{0}-{1}-{2}' -f $site, $role, $suffix }
    }
    return $groupName
}

function Get-SyntheticUserPrincipalName {
    param(
        [string]$SamAccountName,
        [ValidateSet('L', 'E', 'A')]
        [string]$Source
    )

    if ($Source -eq 'L') {
        return 'N/A'
    }

    $domainName = if ($LegacyNaming) { 'stress.example' } else { 'contoso.example' }
    return '{0}@{1}' -f $SamAccountName.ToLowerInvariant(), $domainName
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
    $deviceEntities = [System.Collections.Generic.List[object]]::new()
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
        $computerName = Get-SyntheticComputerName -Index $computerIndex
        $joinCode = [string](1 + (($computerIndex - 1) % 3))
        $administratorGroupName = $administratorGroupNames[($computerIndex - 1) % $administratorGroupNames.Count]
        $entriesForComputer = if ($TargetEntryCount -gt 0) {
            [math]::Min($NumberOfEntriesPerComputer, $TargetEntryCount - $principalIndex)
        } else {
            $NumberOfEntriesPerComputer
        }
        $deviceReportTimestamp = $generationTime.AddMinutes(-(($computerIndex * 11) % 360))
        $joinStateName = switch ($joinCode) {
            '1' { 'Entra joined' }
            '2' { 'Hybrid joined' }
            '3' { 'Domain joined' }
        }
        $entraDeviceId = if ($joinCode -in @('1', '2')) {
            [guid]::Parse(('00000000-0000-0000-0000-{0:D12}' -f $computerIndex)).ToString()
        } else {
            ''
        }
        $collectorRowKey = "C_$computerSid"
        $collectorEntity = [ordered]@{
            PartitionKey                      = 'v1'
            RowKey                            = $collectorRowKey
            ObservationType                   = 'Collector'
            ComputerName                      = $computerName
            ComputerSid                       = $computerSid
            DeviceKeyType                     = 'ComputerSid'
            JoinState                         = $joinStateName
            CollectorVersion                  = 'StressData'
            SchemaVersion                     = 2
            CollectorPresent                  = $true
            InventoryHash                     = "stress-$computerIndex-$entriesForComputer"
            'LastReportUtc@odata.type'         = 'Edm.DateTime'
            LastReportUtc                     = $deviceReportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            'LastInventoryChangeUtc@odata.type' = 'Edm.DateTime'
            LastInventoryChangeUtc             = $deviceReportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            StressData                        = 1
            SyntheticProfile                  = if ($LegacyNaming) { 'LegacyStress' } else { 'ContosoInternational' }
        }
        if ($entraDeviceId) {
            $collectorEntity.EntraDeviceId = $entraDeviceId
        }
        $deviceEntities.Add([pscustomobject][ordered]@{
            TableName    = 'LocalAdminDevices'
            PartitionKey = 'v1'
            RowKey       = $collectorRowKey
            Entity       = [pscustomobject]$collectorEntity
        })

        if ($entraDeviceId) {
            $entraRowKey = "E_$entraDeviceId"
            $deviceEntities.Add([pscustomobject][ordered]@{
                TableName    = 'LocalAdminDevices'
                PartitionKey = 'v1'
                RowKey       = $entraRowKey
                Entity       = [pscustomobject][ordered]@{
                    PartitionKey                    = 'v1'
                    RowKey                          = $entraRowKey
                    ObservationType                 = 'Entra'
                    EntraDeviceId                   = $entraDeviceId
                    EntraObjectId                   = [guid]::Parse(('10000000-0000-0000-0000-{0:D12}' -f $computerIndex)).ToString()
                    EntraDisplayName                = $computerName
                    OperatingSystem                 = 'Windows'
                    AccountEnabled                  = $true
                    EntraPresent                    = $true
                    EntraSyncGeneration             = 'stress-data'
                    'EntraObservedUtc@odata.type'    = 'Edm.DateTime'
                    EntraObservedUtc                = $deviceReportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                    SchemaVersion                   = 2
                    StressData                      = 1
                    SyntheticProfile                = if ($LegacyNaming) { 'LegacyStress' } else { 'ContosoInternational' }
                }
            })
        }

        if (($computerIndex % 3) -ne 0) {
            $managedDeviceId = [guid]::Parse(('20000000-0000-0000-0000-{0:D12}' -f $computerIndex)).ToString()
            $intuneRowKey = "I_$managedDeviceId"
            $intuneEntity = [ordered]@{
                PartitionKey                    = 'v1'
                RowKey                          = $intuneRowKey
                ObservationType                 = 'Intune'
                IntuneManagedDeviceId            = $managedDeviceId
                IntuneDeviceName                 = $computerName
                OperatingSystem                 = 'Windows'
                ComplianceState                 = if (($computerIndex % 5) -eq 0) { 'noncompliant' } else { 'compliant' }
                ManagementAgent                 = 'mdm'
                Ownership                       = 'company'
                IntunePresent                   = $true
                IntuneSyncGeneration             = 'stress-data'
                'IntuneObservedUtc@odata.type'   = 'Edm.DateTime'
                IntuneObservedUtc               = $deviceReportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                'IntuneLastSyncUtc@odata.type'   = 'Edm.DateTime'
                IntuneLastSyncUtc               = $deviceReportTimestamp.AddMinutes(-15).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                SchemaVersion                   = 2
                StressData                      = 1
                SyntheticProfile                = if ($LegacyNaming) { 'LegacyStress' } else { 'ContosoInternational' }
            }
            if ($entraDeviceId) {
                $intuneEntity.EntraDeviceId = $entraDeviceId
            }
            $deviceEntities.Add([pscustomobject][ordered]@{
                TableName    = 'LocalAdminDevices'
                PartitionKey = 'v1'
                RowKey       = $intuneRowKey
                Entity       = [pscustomobject]$intuneEntity
            })
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
                LocalAdminGroupName              = $administratorGroupName
                MembershipType                   = $membershipType
                Removed                          = if (($principalIndex * 37) % 19 -eq 0) { 1 } else { 0 }
                StressData                       = 1
                SyntheticProfile                 = if ($LegacyNaming) { 'LegacyStress' } else { 'ContosoInternational' }
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
                    $groupName = Get-SyntheticGroupName -Index $groupPrincipalIndex -Source $source
                }
                if ($IncludeReconciliationScenarios -and $principalIndex -eq 4) {
                    $legacyGroupName = if ($LegacyNaming) { 'LegacyStressGroup000004' } else { 'GG-Berlin-Legacy-Endpoint-Admins' }
                    $groupEntities.Add([pscustomobject][ordered]@{
                        TableName    = 'AdminGroups'
                        PartitionKey = $groupSid
                        RowKey       = $legacyGroupName
                        Entity       = [pscustomobject][ordered]@{
                            PartitionKey     = $groupSid
                            RowKey           = $legacyGroupName
                            LocalOrEntraOrAD = $source
                            StressData       = 1
                            SyntheticProfile = if ($LegacyNaming) { 'LegacyStress' } else { 'ContosoInternational' }
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
                        SyntheticProfile = if ($LegacyNaming) { 'LegacyStress' } else { 'ContosoInternational' }
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
                $samAccountName = Get-SyntheticUserName -Index $userPrincipalIndex
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
                        UserPrincipalName = Get-SyntheticUserPrincipalName -SamAccountName $samAccountName -Source $source
                        LocalOrEntraOrAD  = $source
                        'ObservedAt@odata.type' = 'Edm.DateTime'
                        ObservedAt        = $reportTimestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                        ResolutionState   = if ($source -eq 'E') { 'EntraPending' } elseif ($samAccountName -eq $userSid) { 'DomainUnavailable' } else { 'Resolved' }
                        StressData        = 1
                        SyntheticProfile  = if ($LegacyNaming) { 'LegacyStress' } else { 'ContosoInternational' }
                    }
                })
                if ($IncludeReconciliationScenarios -and $source -eq 'A' -and $principalIndex -eq 6) {
                    $candidateEntity = $userEntities[$userEntities.Count - 1].Entity
                    $candidateSamAccountName = if ($LegacyNaming) { 'RenamedStressUsr000006' } else { 'sara.meyer006' }
                    $candidateEntity | Add-Member -NotePropertyName 'CandidateObservedAt@odata.type' -NotePropertyValue 'Edm.DateTime'
                    $candidateEntity | Add-Member -NotePropertyName CandidateObservedAt -NotePropertyValue $generationTime.AddMinutes(5).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                    $candidateEntity | Add-Member -NotePropertyName CandidateSamAccountName -NotePropertyValue $candidateSamAccountName
                    $candidateEntity | Add-Member -NotePropertyName CandidateUserPrincipalName -NotePropertyValue (Get-SyntheticUserPrincipalName -SamAccountName $candidateSamAccountName -Source A)
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
        DeviceEntities = $deviceEntities
        UserEntities  = $userEntities
        GroupEntities = $groupEntities
        ComputerCount = $resolvedNumberOfComputers
    }
}

function New-GovernanceTestEntitySets {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$InventoryEntitySets
    )

    $mainRows = @($InventoryEntitySets.MainEntities | Select-Object -First 8)
    if ($mainRows.Count -lt 6) {
        throw 'At least six inventory rows are required to generate governance scenarios.'
    }

    $generationTime = [datetime]::UtcNow
    $ruleEntities = [System.Collections.Generic.List[object]]::new()
    $actionEntities = [System.Collections.Generic.List[object]]::new()
    $ruleDefinitions = @(
        @{ Index = 0; Id = '00000000-0000-4000-8000-000000000101'; Effect = 'Allow'; Status = 'Active'; Reason = 'Approved helpdesk access scenario' }
        @{ Index = 1; Id = '00000000-0000-4000-8000-000000000102'; Effect = 'Deny'; Status = 'Active'; Reason = 'Explicit governance denial scenario' }
        @{ Index = 2; Id = '00000000-0000-4000-8000-000000000103'; Effect = 'Allow'; Status = 'PendingApproval'; Reason = 'Pending approval scenario' }
        @{ Index = 3; Id = '00000000-0000-4000-8000-000000000104'; Effect = 'Allow'; Status = 'Expired'; Reason = 'Expired exception scenario'; Expired = $true }
        @{ Index = 4; Id = '00000000-0000-4000-8000-000000000105'; Effect = 'Allow'; Status = 'Active'; Reason = 'Device-prefix approval scenario'; DeviceScopeType = 'ComputerPrefix'; DeviceScopeValue = 'BER-' }
        @{ Index = 5; Id = '00000000-0000-4000-8000-000000000106'; Effect = 'Allow'; Status = 'Active'; Reason = 'Conflict allow scenario' }
        @{ Index = 5; Id = '00000000-0000-4000-8000-000000000107'; Effect = 'Deny'; Status = 'Active'; Reason = 'Conflict deny scenario' }
    )

    foreach ($definition in $ruleDefinitions) {
        $target = $mainRows[$definition.Index].Entity
        $validFrom = $generationTime.AddDays(-30)
        $validUntil = if ($definition.Expired) { $generationTime.AddDays(-1) } else { $generationTime.AddDays(30) }
        $rule = [ordered]@{
            PartitionKey          = 'org'
            RowKey               = $definition.Id
            RuleScope            = 'Governance'
            Effect               = $definition.Effect
            PrincipalType        = [string]$target.PrincipalType
            MatchType            = 'SID'
            PrincipalValue       = [string]$target.PrincipalID
            PrincipalSource      = 'Any'
            MembershipScope      = 'Any'
            DeviceScopeType      = if ($definition.DeviceScopeType) { $definition.DeviceScopeType } else { 'Any' }
            DeviceScopeValue     = if ($definition.DeviceScopeValue) { $definition.DeviceScopeValue } else { '' }
            AllowedEntraJoined   = $true
            AllowedHybridJoined  = $true
            AllowedDomainJoined  = $true
            Status               = $definition.Status
            Reason               = $definition.Reason
            TicketReference      = "LAS-TEST-$($definition.Id.Substring($definition.Id.Length - 3))"
            Owner                = 'Synthetic governance test'
            CreatedBy            = 'stress-test'
            'CreatedAtUtc@odata.type' = 'Edm.DateTime'
            CreatedAtUtc         = $generationTime.AddDays(-31).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            'ValidFromUtc@odata.type' = 'Edm.DateTime'
            ValidFromUtc         = $validFrom.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            'ValidUntilUtc@odata.type' = 'Edm.DateTime'
            ValidUntilUtc        = $validUntil.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            SchemaVersion        = 1
            StressData           = 1
            SyntheticProfile     = 'GovernanceHumanValidation'
        }
        $ruleEntities.Add([pscustomobject][ordered]@{
            TableName    = 'LocalAdminAllowRules'
            PartitionKey = 'org'
            RowKey       = $definition.Id
            Entity       = [pscustomobject]$rule
        })
    }

    $ownerKey = 'entra:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222'
    $statuses = @('Requested', 'Queued', 'InProgress', 'AwaitingInventory', 'Succeeded', 'Failed')
    for ($index = 0; $index -lt $statuses.Count; $index++) {
        $target = $mainRows[$index].Entity
        $sequence = $index + 1
        $actionId = '00000000-0000-4000-8000-{0:D12}' -f (200 + $sequence)
        $correlation = '00000000-0000-4000-8000-{0:D12}' -f (300 + $sequence)
        $action = [ordered]@{
            PartitionKey          = $ownerKey
            RowKey               = $actionId
            CorrelationId        = $correlation
            IdempotencyKey       = "stress-action-$sequence"
            ActionType           = if (($sequence % 2) -eq 0) { 'RemoveLocalAdministrator' } else { 'ReviewLocalAdministrator' }
            Status               = $statuses[$index]
            TargetComputerSid    = [string]$target.PartitionKey
            TargetPrincipalId    = [string]$target.PrincipalID
            ExpectedChange       = if (($sequence % 2) -eq 0) { 'Principal absent from local Administrators group' } else { 'Review acknowledgement recorded' }
            Justification        = "Synthetic human-validation action in $($statuses[$index]) state."
            RequestedByOwnerKey  = $ownerKey
            'CreatedAtUtc@odata.type' = 'Edm.DateTime'
            CreatedAtUtc         = $generationTime.AddHours(-$sequence).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            SchemaVersion        = 1
            StressData           = 1
            SyntheticProfile     = 'GovernanceHumanValidation'
        }
        $actionEntities.Add([pscustomobject][ordered]@{
            TableName    = 'LocalAdminReviewActions'
            PartitionKey = $ownerKey
            RowKey       = $actionId
            Entity       = [pscustomobject]$action
        })
    }

    return [pscustomobject]@{
        RuleEntities   = $ruleEntities
        ActionEntities = $actionEntities
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

function Test-IsStressDataEntity {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Main', 'User', 'Group')]
        [string]$EntityType,
        [Parameter(Mandatory = $true)]
        [psobject]$Entity,
        [Parameter(Mandatory = $true)]
        [string]$RowKey
    )

    if ($Entity.StressData -eq 1) {
        return $true
    }

    $isStressData = switch ($EntityType) {
        'Main' { [string]$Entity.Computername -like 'STRESS*' }
        'User' { $RowKey -like 'StressUsr*' }
        'Group' { $RowKey -like '*StressGroup*' }
    }
    return $isStressData
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
    if ($IncludeGovernanceScenarios -and
        ([string]::IsNullOrWhiteSpace($GovernanceStorageAccountName) -or $GovernanceStorageAccountName -eq '<storage-account-name>')) {
        throw 'GovernanceStorageAccountName is required when IncludeGovernanceScenarios is selected.'
    }
    if ($IncludeGovernanceScenarios -and ($Execute -or $RemoveStressData -or $ClearTables) -and
        [string]::IsNullOrWhiteSpace($GovernanceSasToken)) {
        throw 'GovernanceSasToken is required for governance scenario Azure operations.'
    }

    if ($RemoveStressData -or $ClearTables) {
        $resolvedSasToken = Get-ConfiguredSasToken -Token $SasToken
        Write-Log -Message 'Reading all Azure Table entities for cleanup.' -Component 'Cleanup' -Type 1

        $mainEntities = @(Get-TableEntities -TableName 'LocalAdminCollection' -AccountName $StorageAccountName -Token $resolvedSasToken)
        $deviceEntities = @(Get-TableEntities -TableName 'LocalAdminDevices' -AccountName $StorageAccountName -Token $resolvedSasToken)
        $userEntities = @(Get-TableEntities -TableName 'AdminUserNames' -AccountName $StorageAccountName -Token $resolvedSasToken)
        $groupEntities = @(Get-TableEntities -TableName 'AdminGroups' -AccountName $StorageAccountName -Token $resolvedSasToken)
        $ruleEntities = @()
        $actionEntities = @()
        if ($IncludeGovernanceScenarios) {
            $resolvedGovernanceSasToken = Get-ConfiguredSasToken -Token $GovernanceSasToken
            $ruleEntities = @(Get-TableEntities -TableName 'LocalAdminAllowRules' -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceSasToken)
            $actionEntities = @(Get-TableEntities -TableName 'LocalAdminReviewActions' -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceSasToken)
        }

        if ($RemoveStressData) {
            $allMainEntities = $mainEntities
            $mainEntities = @($allMainEntities | Where-Object { Test-IsStressDataEntity -EntityType Main -Entity $_.Entity -RowKey $_.RowKey })
            $stressMainEntityKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($mainEntity in $mainEntities) {
                [void]$stressMainEntityKeys.Add(('{0}|{1}' -f $mainEntity.PartitionKey, $mainEntity.RowKey))
            }
            $productionPrincipalIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($mainEntity in $allMainEntities) {
                if ($stressMainEntityKeys.Contains(('{0}|{1}' -f $mainEntity.PartitionKey, $mainEntity.RowKey))) {
                    continue
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$mainEntity.Entity.PrincipalID)) {
                    [void]$productionPrincipalIds.Add([string]$mainEntity.Entity.PrincipalID)
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$mainEntity.Entity.AssignedThroughGroupID)) {
                    [void]$productionPrincipalIds.Add([string]$mainEntity.Entity.AssignedThroughGroupID)
                }
            }

            $stressUserIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $stressGroupIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($mainEntity in $mainEntities) {
                if ([string]$mainEntity.Entity.PrincipalType -eq 'User') {
                    [void]$stressUserIds.Add([string]$mainEntity.Entity.PrincipalID)
                } elseif ([string]$mainEntity.Entity.PrincipalType -eq 'Group') {
                    [void]$stressGroupIds.Add([string]$mainEntity.Entity.PrincipalID)
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$mainEntity.Entity.AssignedThroughGroupID)) {
                    [void]$stressGroupIds.Add([string]$mainEntity.Entity.AssignedThroughGroupID)
                }
            }

            $userEntities = @($userEntities | Where-Object {
                -not $productionPrincipalIds.Contains($_.PartitionKey) -and
                ((Test-IsStressDataEntity -EntityType User -Entity $_.Entity -RowKey $_.RowKey) -or $stressUserIds.Contains($_.PartitionKey))
            })
            $groupEntities = @($groupEntities | Where-Object {
                -not $productionPrincipalIds.Contains($_.PartitionKey) -and
                ((Test-IsStressDataEntity -EntityType Group -Entity $_.Entity -RowKey $_.RowKey) -or $stressGroupIds.Contains($_.PartitionKey))
            })
            $deviceEntities = @($deviceEntities | Where-Object { $_.Entity.StressData -eq 1 })
            $ruleEntities = @($ruleEntities | Where-Object { $_.Entity.StressData -eq 1 })
            $actionEntities = @($actionEntities | Where-Object { $_.Entity.StressData -eq 1 })
            $operationName = 'Remove stress-test data'
        } else {
            $operationName = 'Clear all solution table data'
        }

        $totalRemovalCount = $mainEntities.Count + $deviceEntities.Count + $userEntities.Count + $groupEntities.Count + $ruleEntities.Count + $actionEntities.Count
        $targetDescription = "$totalRemovalCount entities from the selected inventory and governance tables"
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
        $removedDevices = Invoke-TableEntityRequests -Entities $deviceEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete
        $removedUsers = Invoke-TableEntityRequests -Entities $userEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete
        $removedGroups = Invoke-TableEntityRequests -Entities $groupEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete
        $removedRules = if ($IncludeGovernanceScenarios) {
            Invoke-TableEntityRequests -Entities $ruleEntities -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete
        } else { 0 }
        $removedActions = if ($IncludeGovernanceScenarios) {
            Invoke-TableEntityRequests -Entities $actionEntities -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceSasToken -MaximumConcurrency $ThrottleLimit -Operation Delete
        } else { 0 }

        $message = "SUCCESS: Removed $removedMain main rows, $removedDevices device observation rows, $removedUsers user rows, $removedGroups group rows, $removedRules governance rules, and $removedActions review actions."
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
    $governanceEntitySets = if ($IncludeGovernanceScenarios) {
        New-GovernanceTestEntitySets -InventoryEntitySets $entitySets
    } else {
        [pscustomobject]@{ RuleEntities = @(); ActionEntities = @() }
    }
    $mainCount = $entitySets.MainEntities.Count
    $deviceCount = $entitySets.DeviceEntities.Count
    $userCount = $entitySets.UserEntities.Count
    $groupCount = $entitySets.GroupEntities.Count
    $ruleCount = $governanceEntitySets.RuleEntities.Count
    $actionCount = $governanceEntitySets.ActionEntities.Count
    $totalCount = $mainCount + $deviceCount + $userCount + $groupCount + $ruleCount + $actionCount
    $generatedComputerCount = $entitySets.ComputerCount

    if (-not $Execute) {
        $message = "DRY RUN: Would upsert $mainCount main rows, $deviceCount device observation rows, $userCount user rows, $groupCount group rows, $ruleCount governance rules, and $actionCount review actions across $generatedComputerCount computers, including $($uniqueEntraGroupObjectIds.Count) specified Entra groups. Use -Execute to write the data."
        Write-Log -Message $message -Component 'Summary' -Type 1
        Write-Output $message
        exit 0
    }

    $resolvedSasToken = Get-ConfiguredSasToken -Token $SasToken
    Write-Log -Message "Uploading $totalCount entities to Azure Table Storage." -Component 'Upload' -Type 1

    $uploadedUsers = Invoke-TableEntityRequests -Entities $entitySets.UserEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit
    $uploadedGroups = Invoke-TableEntityRequests -Entities $entitySets.GroupEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit
    $uploadedMain = Invoke-TableEntityRequests -Entities $entitySets.MainEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit
    $uploadedDevices = Invoke-TableEntityRequests -Entities $entitySets.DeviceEntities -AccountName $StorageAccountName -Token $resolvedSasToken -MaximumConcurrency $ThrottleLimit
    $uploadedRules = 0
    $uploadedActions = 0
    if ($IncludeGovernanceScenarios) {
        $resolvedGovernanceSasToken = Get-ConfiguredSasToken -Token $GovernanceSasToken
        $uploadedRules = Invoke-TableEntityRequests -Entities $governanceEntitySets.RuleEntities -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceSasToken -MaximumConcurrency $ThrottleLimit
        $uploadedActions = Invoke-TableEntityRequests -Entities $governanceEntitySets.ActionEntities -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceSasToken -MaximumConcurrency $ThrottleLimit
    }

    $message = "SUCCESS: Upserted $uploadedMain main rows, $uploadedDevices device observation rows, $uploadedUsers user rows, $uploadedGroups group rows, $uploadedRules governance rules, and $uploadedActions review actions across $generatedComputerCount synthetic computers, including $($uniqueEntraGroupObjectIds.Count) specified Entra groups."
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
