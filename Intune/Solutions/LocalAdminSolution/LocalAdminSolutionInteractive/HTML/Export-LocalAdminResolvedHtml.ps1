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

function Get-JavaScriptModuleImports {
    param([string]$Source, [string]$ModuleName)
    $pattern = '(?ms)^import\s*\{(?<names>[^}]*)\}\s*from\s*''\./(?<module>[A-Za-z0-9_.-]+?\.js)(?:\?[^'']*)?'';[ \t]*\r?\n?'
    $imports = foreach ($match in [regex]::Matches($Source, $pattern)) {
        $bindings = foreach ($part in ($match.Groups['names'].Value -split ',')) {
            $binding = $part.Trim()
            if (-not $binding) { continue }
            if ($binding -notmatch '^(?<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+(?<alias>[A-Za-z_][A-Za-z0-9_]*))?$') {
                throw "Unsupported import binding '$binding' in $ModuleName."
            }
            [pscustomobject]@{ Name = $Matches['name']; Alias = if ($Matches['alias']) { $Matches['alias'] } else { $Matches['name'] } }
        }
        [pscustomobject]@{ Module = $match.Groups['module'].Value; Bindings = @($bindings); Text = $match.Value }
    }
    $remaining = $Source
    foreach ($import in $imports) { $remaining = $remaining.Replace($import.Text, '') }
    if ($remaining -match '(?m)^\s*import[\s{*]' -or $remaining -match '\bimport\s*\(') {
        throw "$ModuleName contains an import form that the snapshot bundler does not support."
    }
    return @($imports)
}

function ConvertTo-SnapshotModuleScript {
    param(
        [Parameter(Mandatory)][string]$ModuleName,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][hashtable]$AvailableExports,
        [switch]$Entry
    )
    if ($Source -match '(?m)^\s*export\s*(\{|default\b|\*)') {
        throw "$ModuleName uses an export form that the snapshot bundler does not support."
    }
    $body = $Source
    $prelude = foreach ($import in (Get-JavaScriptModuleImports -Source $Source -ModuleName $ModuleName)) {
        if (-not $AvailableExports.ContainsKey($import.Module)) {
            throw "$ModuleName imports $($import.Module), which is neither inlined nor stubbed in the snapshot."
        }
        $missing = @($import.Bindings | Where-Object { $AvailableExports[$import.Module] -notcontains $_.Name } | ForEach-Object Name)
        if ($missing.Count) {
            throw "$ModuleName imports $($missing -join ', ') from $($import.Module), which the snapshot does not provide."
        }
        $body = $body.Replace($import.Text, '')
        $names = $import.Bindings | ForEach-Object { if ($_.Name -eq $_.Alias) { $_.Name } else { "$($_.Name): $($_.Alias)" } }
        "const { $($names -join ', ') } = __snapshotModules['$($import.Module)'];"
    }
    $exports = @([regex]::Matches($Source, '(?m)^export\s+(?:async\s+)?(?:function\*?|const|let|class)\s+([A-Za-z_][A-Za-z0-9_]*)') | ForEach-Object { $_.Groups[1].Value })
    $AvailableExports[$ModuleName] = $exports
    $body = $body -replace '(?m)^export\s+', ''
    $preludeText = @($prelude) -join "`n"
    if ($Entry) {
        return "(async () => {`n$preludeText`n$body`n})().catch(error => { console.error(error); });"
    }
    return "__snapshotModules['$ModuleName'] = (() => {`n$preludeText`n$body`nreturn { $($exports -join ', ') };`n})();"
}

function New-LocalAdminSnapshotHtml {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$ReportData,
        [string]$SourceRoot = $PSScriptRoot
    )
    $readSource = { param($Name) Get-Content -LiteralPath (Join-Path -Path $SourceRoot -ChildPath $Name) -Raw -Encoding UTF8 }
    # Modules that are safe offline are inlined; live, profile, and Admin-mode modules are replaced by inert stubs.
    $stubs = [ordered]@{
        'storage.js'       = [ordered]@{
            loadConnection          = 'loadConnection() { return null; }'
            loadLastSuccessfulRun   = 'loadLastSuccessfulRun() { return null; }'
            loadPreferences         = 'loadPreferences() { return { version: 1, staleThresholdDays: 90, reviewWindowDays: 90, pageSize: 50, defaultView: ''summary'', groupByComputer: true, timeDisplay: ''local'', csvFilenamePrefix: ''LocalAdmin'', tableLayouts: {} }; }'
            loadRecoveryProfile     = 'loadRecoveryProfile() { return null; }'
            removeConnection        = 'removeConnection() { return true; }'
            removeRecoveryProfile   = 'removeRecoveryProfile() { return false; }'
            saveConnection          = 'saveConnection() { return false; }'
            saveLastSuccessfulRun   = 'saveLastSuccessfulRun() { return false; }'
            savePreferences         = 'savePreferences() { return false; }'
            saveRecoveryProfile     = 'saveRecoveryProfile() { return false; }'
            generateRecoveryProfile = 'async generateRecoveryProfile() { throw new Error(''Recovery profiles are unavailable in generated snapshots.''); }'
            importRecoveryProfile   = 'async importRecoveryProfile() { throw new Error(''Recovery profiles are unavailable in generated snapshots.''); }'
        }
        'auth.js'          = [ordered]@{
            hasCompleteEntraConfig = 'hasCompleteEntraConfig() { return false; }'
            EntraAuthClient        = 'EntraAuthClient: class {}'
        }
        'profileClient.js' = [ordered]@{
            ProfileApiError = 'ProfileApiError: class extends Error {}'
            ProfileClient   = 'ProfileClient: class {}'
        }
        'adminMode.js'     = [ordered]@{
            AdminClient             = 'AdminClient: class {}'
            AdminModeController     = 'AdminModeController: class {}'
            adminIdleTimeoutMinutes = 'adminIdleTimeoutMinutes: 15'
            isAdminSessionError     = 'isAdminSessionError() { return false; }'
            normalizeSidInput       = 'normalizeSidInput(value) { return String(value ?? '''').trim(); }'
            previewRuleFromProposal = 'previewRuleFromProposal() { return {}; }'
            previewRuleMatches      = 'previewRuleMatches() { return { rows: 0, computers: 0, entries: [] }; }'
            proposalFromReviewRow   = 'proposalFromReviewRow() { return {}; }'
            validateProposalDraft   = 'validateProposalDraft() { return [''Governance proposals are unavailable in generated snapshots.'']; }'
        }
    }
    $available = @{}
    $scripts = [System.Collections.Generic.List[string]]::new()
    $scripts.Add("'use strict';`nconst __snapshotModules = Object.create(null);")
    foreach ($module in $stubs.Keys) {
        $available[$module] = @($stubs[$module].Keys)
        $scripts.Add("__snapshotModules['$module'] = Object.freeze({ $(@($stubs[$module].Values) -join ', ') });")
    }
    foreach ($module in @('apiContract.js', 'dataService.js', 'connection.js', 'tableLayout.js', 'identityLookup.js')) {
        $scripts.Add((ConvertTo-SnapshotModuleScript -ModuleName $module -Source (& $readSource $module) -AvailableExports $available))
    }
    $scripts.Add((ConvertTo-SnapshotModuleScript -ModuleName 'app.js' -Source (& $readSource 'app.js') -AvailableExports $available -Entry))
    $bundle = $scripts -join "`n"
    if ($bundle -match '(?i)</script') {
        throw 'The snapshot JavaScript contains a closing script tag and cannot be embedded safely.'
    }

    $json = ($ReportData | ConvertTo-Json -Depth 8 -Compress).Replace('<', '\u003c')
    $styles = & $readSource 'styles.css'
    $html = & $readSource 'index.html'
    $requiredReplacements = [ordered]@{
        '__REPORT_DATA__'                                         = $json
        '<link rel="stylesheet" href="styles.css">'               = "<style>`n$styles`n</style>"
        '  <script src="vendor/msal-browser.min.js"></script>'    = ''
        '  <script src="vendor/msal-redirect-bridge.min.js"></script>' = ''
    }
    foreach ($marker in $requiredReplacements.Keys) {
        if (-not $html.Contains($marker)) { throw "The HTML template no longer contains '$marker'." }
        $html = $html.Replace($marker, $requiredReplacements[$marker])
    }
    $bootstrap = [regex]::Match($html, '<script type="module" src="bootstrap\.js(?:\?[^"]*)?"></script>')
    if (-not $bootstrap.Success) { throw 'The HTML template no longer contains the bootstrap.js module script.' }
    $html = $html.Remove($bootstrap.Index, $bootstrap.Length).Insert($bootstrap.Index, "<script>`n$bundle`n</script>")
    if ($html -match '(?i)<(script|link|img|iframe)\b[^>]*\b(src|href)\s*=') {
        throw 'The generated snapshot still references an external resource.'
    }
    return $html
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
    $html = New-LocalAdminSnapshotHtml -ReportData $reportData
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
