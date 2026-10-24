#Requires -Version 7.2
<#
.SYNOPSIS
    Exercises analyzer Boolean inputs and Table Storage lock requests without Azure credentials.
.DESCRIPTION
    Runs real analyzer control flow and locking with mocked authentication, data, and HTTP boundaries.
.NOTES
    Run with pwsh -NoProfile -File .\Tests\AnalysisRunbook.Tests.ps1. Pester is not required.
#>

Set-StrictMode -Version Latest
$analyzerPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Runbooks\Repair-PrimaryUserAssignments.ps1'
$analyzerTokens = $null
$analyzerIssues = $null
$analyzerAst = [Management.Automation.Language.Parser]::ParseFile($analyzerPath, [ref]$analyzerTokens, [ref]$analyzerIssues)
if ($analyzerIssues.Count) { throw ($analyzerIssues | Out-String) }
$analyzerSource = $analyzerAst.Extent.Text
$mockedFunctions = @(
    'Initialize-ManagedIdentity', 'Get-TableEntity', 'Set-TableEntity',
    'Get-TableEntitiesByPartition', 'Invoke-GraphGet', 'Invoke-GraphBatch', 'Remove-ExpiredAnalysisHistory'
)
foreach ($mockedFunction in @($analyzerAst.FindAll({
    param($syntaxNode)
    $syntaxNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $syntaxNode.Name -in $mockedFunctions
}, $true) | Sort-Object { $_.Extent.StartOffset } -Descending)) {
    $analyzerSource = $analyzerSource.Remove($mockedFunction.Extent.StartOffset,
        $mockedFunction.Extent.EndOffset - $mockedFunction.Extent.StartOffset)
}
$analyzerSource = $analyzerSource -replace '(?m)^#Requires -Module Az.Accounts\r?\n', ''
$analyzerUnderTest = [scriptblock]::Create($analyzerSource)
$analysisTestState = @{}
$analysisParameters = @{
    StorageAccountName = 'rpuanalysistest'
    AnalysisEndDate = '2024-02-29'
    DaysToAnalyze = 1
}

function Test-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Reset-AnalysisTestData {
    $analysisTestState.ActiveLock = $null
    $analysisTestState.InsertConflict = $false
    $analysisTestState.PostCount = 0
    $analysisTestState.DeleteCount = 0
    $analysisTestState.BatchCount = 0
    $analysisTestState.Audit = $null
    $analysisTestState.Summary = $null
    $analysisTestState.HistoryCleanups = 0
    $analysisTestState.LockHeldDuringCleanup = $true
}

function Remove-ExpiredAnalysisHistory {
    $analysisTestState.HistoryCleanups++
    if ($null -eq $analysisTestState.ActiveLock) { $analysisTestState.LockHeldDuringCleanup = $false }
}

function Initialize-ManagedIdentity {}
function Get-TableEntity {
    param([string]$TableName, [string]$PartitionKey, [string]$RowKey)
    if ($PartitionKey -eq 'Analysis') { return $analysisTestState.ActiveLock }
    return [pscustomobject]@{ Status = 'Complete' }
}
function Set-TableEntity {
    param([string]$TableName, [hashtable]$Entity)
    if ($TableName -eq 'PrimaryUserAudit') { $analysisTestState.Audit = $Entity }
    if ($Entity.PartitionKey -eq 'AnalysisRuns') { $analysisTestState.Summary = $Entity }
}
function Get-TableEntitiesByPartition {
    [pscustomobject]@{
        DeviceId = '11111111-1111-1111-1111-111111111111'
        UserId = '22222222-2222-2222-2222-222222222222'
        SignInCount = 5
        LatestSignIn = '2024-02-29T12:00:00Z'
    }
}
function Invoke-GraphGet {
    [pscustomobject]@{
        value = @([pscustomobject]@{
            id = 'managed-device'
            azureADDeviceId = '11111111-1111-1111-1111-111111111111'
            deviceName = 'Test device'
            userId = '33333333-3333-3333-3333-333333333333'
        })
    }
}
function Invoke-GraphBatch {
    param([object[]]$Requests)
    $analysisTestState.BatchCount++
    foreach ($request in $Requests) {
        [pscustomobject]@{ Request = $request; Status = 204; Error = $null }
    }
}
function Invoke-WebRequest {
    param([string]$Method, [uri]$Uri, [hashtable]$Headers, [byte[]]$Body)
    if ($Method -eq 'Post') {
        Test-Condition (-not $Headers.ContainsKey('If-Match') -and -not $Headers.ContainsKey('If-None-Match')) `
            'Table insert must not send conditional headers.'
        Test-Condition ($Uri.AbsolutePath -eq '/PrimaryUserState') 'Lock insertion must target the state table.'
        $analysisTestState.PostCount++
        if ($analysisTestState.InsertConflict) {
            $response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Conflict)
            throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('EntityAlreadyExists', $response)
        }
        $analysisTestState.ActiveLock = [Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json
    } elseif ($Method -eq 'Delete') {
        Test-Condition ($Headers['If-Match'] -eq '*') 'Lock deletion must retain its required If-Match header.'
        $analysisTestState.DeleteCount++
        $analysisTestState.ActiveLock = $null
    } else {
        throw "Unexpected HTTP method '$Method'."
    }
    return [pscustomobject]@{ StatusCode = 204; Content = '' }
}

Reset-AnalysisTestData
& $analyzerUnderTest @analysisParameters -Preview $true | Out-Null
Test-Condition ($analysisTestState.Audit.Outcome -eq 'Preview' -and $analysisTestState.Audit.Preview -eq $true) `
    'Boolean true must audit recommendations as previews.'
Test-Condition ($analysisTestState.BatchCount -eq 0 -and $analysisTestState.Summary.Updated -eq 0) `
    'Preview must never submit Graph assignment requests.'
Test-Condition ($analysisTestState.PostCount -eq 1 -and $analysisTestState.DeleteCount -eq 1 -and
    $null -eq $analysisTestState.ActiveLock) 'Preview must acquire and release the analysis lock.'
Test-Condition ($analysisTestState.HistoryCleanups -eq 1 -and $analysisTestState.LockHeldDuringCleanup) `
    'Audit retention must run once per analysis while the lock is held, including previews.'

foreach ($applyParameters in @(@{ Preview = $false }, @{})) {
    Reset-AnalysisTestData
    & $analyzerUnderTest @analysisParameters @applyParameters | Out-Null
    Test-Condition ($analysisTestState.BatchCount -eq 1 -and $analysisTestState.Audit.Outcome -eq 'Updated' -and
        $analysisTestState.Summary.Preview -eq $false) 'Boolean false and omitted Preview must preserve apply mode.'
    Test-Condition ($analysisTestState.DeleteCount -eq 1) 'Apply mode must release its lock.'
}

foreach ($lockScenario in @('InsertConflict', 'ActiveLock', 'StaleLock')) {
    Reset-AnalysisTestData
    if ($lockScenario -eq 'InsertConflict') {
        $analysisTestState.InsertConflict = $true
    } else {
        $analysisTestState.ActiveLock = [pscustomobject]@{
            RunId = 'other-run'
            StartedAt = if ($lockScenario -eq 'StaleLock') {
                [datetime]::UtcNow.AddHours(-13).ToString('o')
            } else {
                [datetime]::UtcNow.ToString('o')
            }
        }
    }
    if ($lockScenario -eq 'StaleLock') {
        & $analyzerUnderTest @analysisParameters -Preview $true | Out-Null
        Test-Condition ($analysisTestState.DeleteCount -eq 2 -and $analysisTestState.PostCount -eq 1) `
            'An expired lock must be removed, replaced, and released.'
        continue
    }
    $expectedMessage = if ($lockScenario -eq 'InsertConflict') { 'acquired the lock first' } else { 'has held the lock' }
    $failureObserved = $false
    try {
        & $analyzerUnderTest @analysisParameters -Preview $true | Out-Null
    } catch {
        if ($_.Exception.Message -notlike "*$expectedMessage*") { throw }
        $failureObserved = $true
    }
    Test-Condition $failureObserved 'Competing analyses must fail before evaluating assignments.'
    Test-Condition ($analysisTestState.BatchCount -eq 0 -and $analysisTestState.DeleteCount -eq 0 -and
        $analysisTestState.HistoryCleanups -eq 0) `
        'A failed lock acquisition must not submit updates, clean history, or release another run''s lock.'
}
Write-Output 'Analyzer Boolean input and lock tests passed.'
