<#
.SYNOPSIS
    Exports the resolved local administrator Azure Table data to an interactive HTML report.
.DESCRIPTION
    Reads every page from LocalAdminCollection, AdminUserNames, and AdminGroups, resolves user
    and group SIDs to names, translates device join states, and writes a self-contained HTML
    snapshot. The SAS token is used during export and is not stored in the generated report.
.PARAMETER StorageAccountName
    Azure Storage account containing the three solution tables.
.PARAMETER SasToken
    Read-enabled SAS token. When omitted, the token is read from the remediation script.
.PARAMETER GovernanceStorageAccountName
    Optional governance Storage account containing allow rules and review actions.
.PARAMETER GovernanceSasToken
    Optional read-only SAS token for the governance Storage account.
.PARAMETER OutputPath
    Path of the generated standalone HTML report.
.PARAMETER OpenReport
    Opens the generated report in the default browser.
.PARAMETER LogPath
    Directory in which the log file is created.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.LINK
    ..\changelog.md
#>

[CmdletBinding()]
param(
    [string]$StorageAccountName = '<storage-account-name>',
    [string]$SasToken,
    [string]$GovernanceStorageAccountName,
    [string]$GovernanceSasToken,
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'LocalAdminResolved.html'),
    [switch]$OpenReport,
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
    if (-not $LogFile) {
        $script:ResolvedLogFile = "Export-LocalAdminResolvedHtml_$($script:DateTime).log"
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
    param([string]$Token)

    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $resolvedToken = $Token.TrimStart('?')
        if ($resolvedToken -eq '<sas-token>') {
            throw 'SasToken is not configured.'
        }
        return $resolvedToken
    }

    $solutionRoot = Split-Path -Path $PSScriptRoot -Parent
    $remediationPath = Join-Path -Path $solutionRoot -ChildPath 'Remediation\Remediate-LocalAdminSolution.ps1'
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

function Get-AzureTableEntities {
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
        foreach ($entity in @(($response.Content | ConvertFrom-Json).value)) {
            $entities.Add($entity)
        }
        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
    } while (-not [string]::IsNullOrWhiteSpace($nextPartitionKey))

    return $entities
}

function Select-CanonicalLookupEntities {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entities
    )

    $canonicalSort = @(
        @{ Expression = { if ([string]$_.ResolutionState -eq 'Resolved') { 1 } else { 0 } }; Descending = $true },
        @{ Expression = {
            $value = if ($null -ne $_.ObservedAt) { $_.ObservedAt } else { $_.Timestamp }
            $parsed = [datetimeoffset]::MinValue
            if ($null -ne $value) { [void][datetimeoffset]::TryParse([string]$value, [ref]$parsed) }
            $parsed
        }; Descending = $true },
        @{ Expression = { [string]$_.RowKey }; Descending = $true }
    )

    return @($Entities | Group-Object -Property PartitionKey | ForEach-Object {
        $sortedRows = @($_.Group | Sort-Object -Property $canonicalSort)
        $sortedRows[0]
    })
}

function ConvertTo-ResolvedData {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$MainEntities,
        [Parameter(Mandatory = $true)]
        [object[]]$UserEntities,
        [Parameter(Mandatory = $true)]
        [object[]]$GroupEntities,
        [Parameter(Mandatory = $true)]
        [object[]]$DeviceEntities
    )

    $usersBySid = @{}
    foreach ($user in $UserEntities) {
        $usersBySid[[string]$user.PartitionKey] = $user
    }
    $groupsBySid = @{}
    foreach ($group in $GroupEntities) {
        $groupsBySid[[string]$group.PartitionKey] = $group
    }
    $devicesByComputerSid = @{}
    foreach ($device in $DeviceEntities) {
        if (-not [string]::IsNullOrWhiteSpace([string]$device.ComputerSid)) {
            $devicesByComputerSid[[string]$device.ComputerSid] = $device
        }
    }

    $resolved = foreach ($entity in $MainEntities) {
        $principalSid = [string]$entity.PrincipalID
        $principalType = [string]$entity.PrincipalType
        $membershipType = [string]$entity.MembershipType
        $userSid = if ($principalType -eq 'User') { $principalSid } else { '' }
        $groupSid = if ($principalType -eq 'Group') { $principalSid } else { '' }
        $assignedThroughGroupSid = [string]$entity.AssignedThroughGroupID
        $device = $devicesByComputerSid[[string]$entity.PartitionKey]
        $joinState = switch ([string]$entity.EntraOrHybrid) {
            '1' { 'Entra joined' }
            '2' { 'Hybrid joined' }
            '3' { 'Domain joined' }
            default { if ($null -eq $entity.EntraOrHybrid) { $null } else { "Unknown ($($entity.EntraOrHybrid))" } }
        }
        $userName = if ($userSid -and $usersBySid.ContainsKey($userSid)) { [string]$usersBySid[$userSid].RowKey } else { $userSid }
        $groupName = if ($groupSid -and $groupsBySid.ContainsKey($groupSid)) { [string]$groupsBySid[$groupSid].RowKey } else { $groupSid }
        $assignedThroughGroupName = if ($assignedThroughGroupSid -and $groupsBySid.ContainsKey($assignedThroughGroupSid)) { [string]$groupsBySid[$assignedThroughGroupSid].RowKey } else { $assignedThroughGroupSid }

        [pscustomobject][ordered]@{
            ComputerName                   = if ($null -ne $device) { [string]$device.ComputerName } else { [string]$entity.Computername }
            SID                            = [string]$entity.PartitionKey
            RowKey                         = [int]$entity.RowKey
            JoinState                      = if ($null -ne $device -and -not [string]::IsNullOrWhiteSpace([string]$device.JoinState)) { [string]$device.JoinState } else { $joinState }
            LastReportUtc                  = if ($null -ne $device) { $device.LastReportUtc } else { $null }
            ReportingState                 = 'Not calculated'
            LocalAdminGroupName            = [string]$entity.LocalAdminGroupName
            Removed                        = [int]$entity.Removed
            UserName                       = $userName
            GroupName                      = $groupName
            MembershipType                 = $membershipType
            AddedThroughGroupName          = $assignedThroughGroupName
            LocalAccountLastPasswordChange = $entity.LocalAccountLastPasswordChange
            Timestamp                      = $entity.Timestamp
            _UserSID                       = $userSid
            _GroupSID                      = $groupSid
            _AssignedThroughGroupSID       = $assignedThroughGroupSid
        }

    }

    return @($resolved | Sort-Object RowKey)
}

function ConvertTo-UserDetails {
    param([object[]]$Entities)
    return @($Entities | ForEach-Object {
        [pscustomobject][ordered]@{
            UserID              = [string]$_.PartitionKey
            SamAccountName      = [string]$_.RowKey
            UserPrincipalName   = [string]$_.UserPrincipalName
            LocalOrEntraOrAD    = [string]$_.LocalOrEntraOrAD
            Timestamp           = $_.Timestamp
        }
    })
}

function ConvertTo-GroupDetails {
    param([object[]]$Entities)
    return @($Entities | ForEach-Object {
        [pscustomobject][ordered]@{
            GroupID           = [string]$_.PartitionKey
            GroupName         = [string]$_.RowKey
            LocalOrEntraOrAD  = [string]$_.LocalOrEntraOrAD
            Timestamp         = $_.Timestamp
        }
    })
}

try {
    Initialize-Script
    if ([string]::IsNullOrWhiteSpace($StorageAccountName) -or $StorageAccountName -eq '<storage-account-name>') {
        throw 'StorageAccountName is not configured.'
    }
    $resolvedSasToken = Get-ConfiguredSasToken -Token $SasToken
    Write-Log -Message 'Reading all three Azure tables.' -Component 'Read' -Type 1

    $mainEntities = @(Get-AzureTableEntities -TableName 'LocalAdminCollection' -AccountName $StorageAccountName -Token $resolvedSasToken)
    $userEntities = @(Get-AzureTableEntities -TableName 'AdminUserNames' -AccountName $StorageAccountName -Token $resolvedSasToken)
    $groupEntities = @(Get-AzureTableEntities -TableName 'AdminGroups' -AccountName $StorageAccountName -Token $resolvedSasToken)
    $deviceEntities = @(Get-AzureTableEntities -TableName 'LocalAdminDevices' -AccountName $StorageAccountName -Token $resolvedSasToken)
    $governanceRules = @()
    $reviewActions = @()
    if (-not [string]::IsNullOrWhiteSpace($GovernanceStorageAccountName) -or -not [string]::IsNullOrWhiteSpace($GovernanceSasToken)) {
        if ([string]::IsNullOrWhiteSpace($GovernanceStorageAccountName) -or [string]::IsNullOrWhiteSpace($GovernanceSasToken)) {
            throw 'GovernanceStorageAccountName and GovernanceSasToken must be provided together.'
        }
        $resolvedGovernanceToken = $GovernanceSasToken.TrimStart('?')
        $governanceRules = @(Get-AzureTableEntities -TableName 'LocalAdminAllowRules' -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceToken)
        $reviewActions = @(Get-AzureTableEntities -TableName 'LocalAdminReviewActions' -AccountName $GovernanceStorageAccountName -Token $resolvedGovernanceToken)
    }
    $reportData = [ordered]@{
        generatedAt = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        raw = [ordered]@{
            main    = $mainEntities
            users   = $userEntities
            groups  = $groupEntities
            devices = $deviceEntities
            rules   = $governanceRules
            actions = $reviewActions
        }
    }

    $templatePath = Join-Path -Path $PSScriptRoot -ChildPath 'index.html'
    if (-not (Test-Path -LiteralPath $templatePath)) {
        throw "The HTML template was not found at $templatePath."
    }
    $json = ($reportData | ConvertTo-Json -Depth 8 -Compress).Replace('<', '\u003c')
    $styles = Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'styles.css') -Raw
    $apiContract = (Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'apiContract.js') -Raw) -replace '(?m)^export\s+', ''
    $dataService = (Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'dataService.js') -Raw) -replace '(?m)^import .*\r?\n', '' -replace '(?m)^export\s+', ''
    $connection = (Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'connection.js') -Raw) -replace '(?m)^import .*\r?\n', '' -replace '(?m)^export\s+', ''
    $application = (Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'app.js') -Raw) -replace '(?ms)^import .*?;\r?\n', ''
    $snapshotStorage = @'
function loadConnection() { return null; }
function loadLastSuccessfulRun() { return null; }
function loadPreferences() { return { version: 1, staleThresholdDays: 90, reviewWindowDays: 90, pageSize: 50, defaultView: 'summary', groupByComputer: true, timeDisplay: 'local', csvFilenamePrefix: 'LocalAdmin' }; }
function loadRecoveryProfile() { return null; }
function removeConnection() { return true; }
function removeRecoveryProfile() { return false; }
function saveConnection() { return false; }
function saveLastSuccessfulRun() { return false; }
function savePreferences() { return false; }
async function generateRecoveryProfile() { throw new Error('Recovery profiles are unavailable in generated snapshots.'); }
async function importRecoveryProfile() { throw new Error('Recovery profiles are unavailable in generated snapshots.'); }
function hasCompleteEntraConfig() { return false; }
class EntraAuthClient {}
class ProfileApiError extends Error {}
class ProfileClient {}
class AdminClient {}
class AdminModeController {}
const adminIdleTimeoutMinutes = 15;
function isAdminSessionError() { return false; }
function previewMatches() { return { rows: 0, computers: 0 }; }
function proposalFromReviewRow() { return {}; }
function validateProposalDraft() { return ['Governance proposals are unavailable in generated snapshots.']; }
'@
    $html = Get-Content -LiteralPath $templatePath -Raw
    $html = $html.Replace('__REPORT_DATA__', $json)
    $html = $html.Replace('<link rel="stylesheet" href="styles.css">', "<style>`n$styles`n</style>")
    $html = $html.Replace('  <script src="vendor/msal-browser.min.js"></script>', '')
    $html = $html.Replace('  <script src="vendor/msal-redirect-bridge.min.js"></script>', '')
    $html = $html.Replace('<script type="module" src="bootstrap.js?v=20261012-1"></script>', "<script>`n$apiContract`n$dataService`n$connection`n$snapshotStorage`n$application`n</script>")
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
        $null = New-Item -Path $outputDirectory -ItemType Directory -Force
    }
    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8

    $message = "SUCCESS: Exported $($mainEntities.Count) resolved rows, $($deviceEntities.Count) device observations, $($userEntities.Count) users, and $($groupEntities.Count) groups to $OutputPath."
    Write-Log -Message $message -Component 'Export' -Type 1
    Write-Output $message
    if ($OpenReport) {
        Start-Process -FilePath $OutputPath
    }
    exit 0
} catch {
    if ($script:LogFile) {
        Write-Log -Message $_.Exception.Message -Component 'Error' -Type 3
    }
    Write-Error "HTML report export failed. $($_.Exception.Message)"
    exit 1
}