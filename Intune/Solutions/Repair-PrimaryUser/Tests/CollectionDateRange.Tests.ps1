#Requires -Version 7.2
<#
.SYNOPSIS
    Exercises single-day and date-range collection without Azure credentials.
.DESCRIPTION
    Runs the collector's parameters, main flow, and daily aggregation with mocked service boundaries.
.NOTES
    Run with pwsh -NoProfile -File .\Tests\CollectionDateRange.Tests.ps1. Pester is not required.
#>

Set-StrictMode -Version Latest
$collectorPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Runbooks\Collect-PrimaryUserSignInData.ps1'
$collectorTokens = $null
$collectorParseIssues = $null
$collectorAst = [Management.Automation.Language.Parser]::ParseFile($collectorPath, [ref]$collectorTokens, [ref]$collectorParseIssues)
if ($collectorParseIssues.Count) { throw ($collectorParseIssues | Out-String) }
$collectorSource = $collectorAst.Extent.Text
$serviceFunctions = @(
    'Initialize-ManagedIdentity', 'Get-CollectionState', 'Set-TableEntity',
    'Remove-TablePartition', 'Invoke-GraphGet', 'Remove-ExpiredDailyPartitions'
)
# Remove only the service implementations so parent-scope mocks handle those calls.
foreach ($serviceFunction in @($collectorAst.FindAll({
    param($syntaxNode)
    $syntaxNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $syntaxNode.Name -in $serviceFunctions
}, $true) | Sort-Object { $_.Extent.StartOffset } -Descending)) {
    $collectorSource = $collectorSource.Remove($serviceFunction.Extent.StartOffset,
        $serviceFunction.Extent.EndOffset - $serviceFunction.Extent.StartOffset)
}
$collectorSource = $collectorSource -replace '(?m)^#Requires -Module Az.Accounts\r?\n', ''
$collectorUnderTest = [scriptblock]::Create($collectorSource)
$collectorTestState = @{}

function Test-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Reset-CollectorTestData {
    $collectorTestState.States = @{}
    $collectorTestState.Aggregates = @{}
    $collectorTestState.GraphDates = [Collections.Generic.List[string]]::new()
    $collectorTestState.RemovedDates = [Collections.Generic.List[string]]::new()
    $collectorTestState.CleanupDates = [Collections.Generic.List[string]]::new()
    $collectorTestState.FailDateKey = ''
    $collectorTestState.IdentityConnections = 0
}

function Invoke-ExpectedCollectorFailure {
    param([hashtable]$Parameters, [string]$ExpectedMessage)
    $previousPreference = $ErrorActionPreference
    try {
        & $collectorUnderTest -StorageAccountName 'rpucollectiontest' @Parameters | Out-Null
    } catch {
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") { throw }
        Test-Condition ($ErrorActionPreference -eq $previousPreference) 'The error preference must be restored after failure.'
        return
    }
    throw "Expected collector failure containing '$ExpectedMessage'."
}

function Initialize-ManagedIdentity { $collectorTestState.IdentityConnections++ }
function Get-CollectionState {
    param([string]$DateKey)
    return $collectorTestState.States[$DateKey]
}
function Set-TableEntity {
    param([string]$TableName, [hashtable]$Entity)
    if ($TableName -eq 'PrimaryUserState') {
        $collectorTestState.States[$Entity.RowKey] = [pscustomobject]$Entity.Clone()
    } else {
        $collectorTestState.Aggregates[$Entity.PartitionKey] = $Entity.Clone()
    }
}
function Remove-TablePartition {
    param([string]$TableName, [string]$PartitionKey)
    Test-Condition ($TableName -eq 'PrimaryUserDaily') 'Only the selected aggregate partition should be replaced.'
    $collectorTestState.RemovedDates.Add($PartitionKey)
    $collectorTestState.Aggregates.Remove($PartitionKey)
}
function Remove-ExpiredDailyPartitions {
    param([datetime]$CurrentDate)
    $collectorTestState.CleanupDates.Add($CurrentDate.ToString('yyyyMMdd'))
}
function Invoke-GraphGet {
    param([uri]$Uri)
    $decodedQuery = [uri]::UnescapeDataString($Uri.Query)
    $windowCapture = [regex]::Match($decodedQuery, 'createdDateTime ge (\d{4}-\d{2}-\d{2})T00:00:00Z and createdDateTime lt (\d{4}-\d{2}-\d{2})T00:00:00Z')
    Test-Condition $windowCapture.Success 'Every Graph request must cover a single complete UTC day.'
    $windowDate = [datetime]::ParseExact($windowCapture.Groups[1].Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    Test-Condition ($windowCapture.Groups[2].Value -eq $windowDate.AddDays(1).ToString('yyyy-MM-dd')) 'Graph windows must end at the following midnight.'
    $dateKey = $windowDate.ToString('yyyyMMdd')
    $collectorTestState.GraphDates.Add($dateKey)
    if ($dateKey -eq $collectorTestState.FailDateKey) { throw 'Simulated Graph collection failure' }
    $dailyEventCount = 1 + ($windowDate.Day % 3)
    [pscustomobject]@{
        value = @(
            for ($eventIndex = 0; $eventIndex -lt $dailyEventCount; $eventIndex++) {
                [pscustomobject]@{
                    userId = '11111111-1111-1111-1111-111111111111'
                    deviceDetail = [pscustomobject]@{ deviceId = '22222222-2222-2222-2222-222222222222' }
                    status = [pscustomobject]@{ errorCode = 0 }
                    createdDateTime = $windowDate.AddHours(12).AddMinutes($eventIndex).ToString('yyyy-MM-ddTHH:mm:ssZ')
                }
            }
        )
    }
}

Reset-CollectorTestData
& $collectorUnderTest -StorageAccountName 'rpucollectiontest' | Out-Null
$yesterdayKey = [datetime]::UtcNow.Date.AddDays(-1).ToString('yyyyMMdd')
Test-Condition ($collectorTestState.GraphDates.Count -eq 1 -and $collectorTestState.GraphDates[0] -eq $yesterdayKey) 'The scheduled default must still collect only yesterday.'

Reset-CollectorTestData
& $collectorUnderTest -StorageAccountName 'rpucollectiontest' -CollectionDate '2024-02-28' -CollectionEndDate '2024-03-01' | Out-Null
Test-Condition (($collectorTestState.GraphDates -join ',') -eq '20240228,20240229,20240301') 'An inclusive range must traverse leap days and month boundaries in order.'
Test-Condition (($collectorTestState.CleanupDates -join ',') -eq '20240301') 'Retention cleanup must run once per job, relative to the last collected date.'
foreach ($dateKey in @('20240228', '20240229', '20240301')) {
    $expectedEventCount = 1 + ([int]$dateKey.Substring(6, 2) % 3)
    Test-Condition ($collectorTestState.States[$dateKey].Status -eq 'Complete') 'Each day needs an independent completion state.'
    Test-Condition ($collectorTestState.Aggregates[$dateKey].SignInCount -eq $expectedEventCount) 'Aggregates must not leak between dates.'
}

Reset-CollectorTestData
foreach ($dateKey in @('20240228', '20240301')) {
    $collectorTestState.States[$dateKey] = [pscustomobject]@{ Status = 'Complete' }
}
$collectorTestState.States['20240229'] = [pscustomobject]@{ Status = 'Collecting' }
& $collectorUnderTest -StorageAccountName 'rpucollectiontest' -CollectionDate '2024-02-28' -CollectionEndDate '2024-03-01' -ForceRecollect $false | Out-Null
Test-Condition (($collectorTestState.GraphDates -join ',') -eq '20240229') 'Boolean false must skip completed days without returning from the entire range.'

Reset-CollectorTestData
$collectorTestState.FailDateKey = '20240229'
$rangeParameters = @{ CollectionDate = '2024-02-28'; CollectionEndDate = '2024-03-01' }
Invoke-ExpectedCollectorFailure -Parameters $rangeParameters -ExpectedMessage 'Simulated Graph collection failure'
Test-Condition ($collectorTestState.States['20240228'].Status -eq 'Complete' -and
    $collectorTestState.States['20240229'].Status -eq 'Collecting' -and
    -not $collectorTestState.States.ContainsKey('20240301')) 'Failure must preserve earlier completion and stop before later dates.'
$collectorTestState.FailDateKey = ''
& $collectorUnderTest -StorageAccountName 'rpucollectiontest' @rangeParameters | Out-Null
Test-Condition (($collectorTestState.GraphDates -join ',') -eq '20240228,20240229,20240229,20240301') 'Retry must collect only the failed and remaining days.'
Test-Condition ($collectorTestState.States['20240301'].Status -eq 'Complete') 'The resumed range must reach its inclusive end.'
$collectorTestState.GraphDates.Clear()
& $collectorUnderTest -StorageAccountName 'rpucollectiontest' @rangeParameters -ForceRecollect $true | Out-Null
Test-Condition (($collectorTestState.GraphDates -join ',') -eq '20240228,20240229,20240301') 'ForceRecollect must rebuild all completed days in the range.'

Reset-CollectorTestData
& $collectorUnderTest -StorageAccountName 'rpucollectiontest' -CollectionDate '2024-02-29' -CollectionEndDate '2024-02-29' | Out-Null
Test-Condition ($collectorTestState.GraphDates.Count -eq 1) 'Equal bounds must collect exactly one day.'
Reset-CollectorTestData
& $collectorUnderTest -StorageAccountName 'rpucollectiontest' -CollectionDate '2024-02-29' | Out-Null
Test-Condition (($collectorTestState.GraphDates -join ',') -eq '20240229') 'The existing explicit single-date invocation must remain supported.'

Reset-CollectorTestData
Invoke-ExpectedCollectorFailure -Parameters @{ CollectionEndDate = '2024-03-01' } -ExpectedMessage 'CollectionDate is required'
Invoke-ExpectedCollectorFailure -Parameters @{ CollectionDate = '2024-03-01'; CollectionEndDate = '2024-02-29' } -ExpectedMessage 'on or after'
Invoke-ExpectedCollectorFailure -Parameters @{ CollectionDate = '2024-02-30' } -ExpectedMessage 'ParseExact'
Invoke-ExpectedCollectorFailure -Parameters @{ CollectionDate = '2024-02-28'; CollectionEndDate = '2024-02-30' } -ExpectedMessage 'ParseExact'
Invoke-ExpectedCollectorFailure -Parameters @{ CollectionDate = '2024-2-28' } -ExpectedMessage 'does not match'
Invoke-ExpectedCollectorFailure -Parameters @{
    CollectionDate = [datetime]::UtcNow.Date.AddDays(-2).ToString('yyyy-MM-dd')
    CollectionEndDate = [datetime]::UtcNow.Date.ToString('yyyy-MM-dd')
} -ExpectedMessage 'completed UTC days'
Invoke-ExpectedCollectorFailure -Parameters @{
    CollectionDate = [datetime]::UtcNow.Date.AddDays(1).ToString('yyyy-MM-dd')
} -ExpectedMessage 'completed UTC days'
Test-Condition ($collectorTestState.IdentityConnections -eq 0 -and $collectorTestState.GraphDates.Count -eq 0 -and
    $collectorTestState.States.Count -eq 0) 'The entire range must be validated before authentication or storage changes.'
Write-Output 'Collection date-range tests passed.'
