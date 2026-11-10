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
    $analysisTestState.Audits = [Collections.Generic.List[hashtable]]::new()
    $analysisTestState.Summary = $null
    $analysisTestState.HistoryCleanups = 0
    $analysisTestState.LockHeldDuringCleanup = $true
    $analysisTestState.Rows = @([pscustomobject]@{
        DeviceId = '11111111-1111-1111-1111-111111111111'
        UserId = '22222222-2222-2222-2222-222222222222'
        SignInCount = 5
        LatestSignIn = '2024-02-29T12:00:00Z'
    })
    $analysisTestState.Devices = @([pscustomobject]@{
        id = 'managed-device'
        azureADDeviceId = '11111111-1111-1111-1111-111111111111'
        deviceName = 'Test device'
        userId = '33333333-3333-3333-3333-333333333333'
    })
}

function New-AggregateRow {
    param([string]$DeviceId, [string]$UserId, [int]$SignInCount, [string]$LatestSignIn, [string]$UserPrincipalName)
    $row = [ordered]@{ DeviceId = $DeviceId; UserId = $UserId; SignInCount = $SignInCount; LatestSignIn = $LatestSignIn }
    if ($UserPrincipalName) { $row.UserPrincipalName = $UserPrincipalName }
    return [pscustomobject]$row
}

# Devices are returned in the order C, A, B, D, E to verify sorting and the example limit.
function Set-PreviewScenario {
    $alice = 'aaaaaaaa-0000-0000-0000-000000000001'
    $bob = 'aaaaaaaa-0000-0000-0000-000000000002'
    $carol = 'aaaaaaaa-0000-0000-0000-000000000003'
    $dave = 'aaaaaaaa-0000-0000-0000-000000000004'
    $analysisTestState.Rows = @(
        New-AggregateRow 'dddddddd-0000-0000-0000-00000000000c' $alice 4 '2024-02-29T09:00:00Z' 'alice@contoso.com'
        New-AggregateRow 'dddddddd-0000-0000-0000-00000000000a' $alice 5 '2024-02-29T11:00:00Z'
        New-AggregateRow 'dddddddd-0000-0000-0000-00000000000a' $bob 2 '2024-02-29T08:00:00Z'
        New-AggregateRow 'dddddddd-0000-0000-0000-00000000000b' $alice 3 '2024-02-29T12:00:00Z'
        New-AggregateRow 'dddddddd-0000-0000-0000-00000000000b' $bob 3 '2024-02-29T10:00:00Z'
        New-AggregateRow 'dddddddd-0000-0000-0000-00000000000d' $alice 6 '2024-02-29T13:00:00Z'
        New-AggregateRow 'dddddddd-0000-0000-0000-00000000000e' $dave 1 '2024-02-29T14:00:00Z'
    )
    $analysisTestState.Devices = @(
        [pscustomobject]@{ id = 'intune-c'; azureADDeviceId = 'DDDDDDDD-0000-0000-0000-00000000000C'; deviceName = 'Device C'; userId = $null; lastSyncDateTime = '0001-01-01T00:00:00Z' }
        [pscustomobject]@{ id = 'intune-a'; azureADDeviceId = 'dddddddd-0000-0000-0000-00000000000a'; deviceName = 'Device A'; userId = $bob; userPrincipalName = 'bob@contoso.com'; lastSyncDateTime = '2024-02-28T08:30:00Z' }
        [pscustomobject]@{ id = 'intune-b'; azureADDeviceId = 'dddddddd-0000-0000-0000-00000000000b'; deviceName = 'Device B'; userId = $bob; lastSyncDateTime = [datetime]::new(2024, 2, 27, 7, 15, 0, [DateTimeKind]::Utc) }
        [pscustomobject]@{ id = 'intune-d'; azureADDeviceId = 'dddddddd-0000-0000-0000-00000000000d'; deviceName = 'Device D'; userId = $alice; userPrincipalName = 'alice@contoso.com' }
        [pscustomobject]@{ id = 'intune-e'; azureADDeviceId = 'dddddddd-0000-0000-0000-00000000000e'; deviceName = 'Device E'; userId = $carol; userPrincipalName = 'carol@contoso.com' }
    )
}

function Get-OutputLineIndex {
    param([object[]]$OutputLines, [string]$Text)
    for ($lineIndex = 0; $lineIndex -lt $OutputLines.Count; $lineIndex++) {
        if ([string]$OutputLines[$lineIndex] -like "*$Text*") { return $lineIndex }
    }
    return -1
}

function Get-OutputLine {
    param([object[]]$OutputLines, [string]$Text)
    $lineIndex = Get-OutputLineIndex -OutputLines $OutputLines -Text $Text
    if ($lineIndex -lt 0) { return '' }
    return [string]$OutputLines[$lineIndex]
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
    if ($TableName -eq 'PrimaryUserAudit') {
        $analysisTestState.Audit = $Entity
        $analysisTestState.Audits.Add($Entity)
    }
    if ($Entity.PartitionKey -eq 'AnalysisRuns') { $analysisTestState.Summary = $Entity }
}
function Get-TableEntitiesByPartition {
    $analysisTestState.Rows
}
function Invoke-GraphGet {
    param([uri]$Uri)
    Test-Condition ([uri]::UnescapeDataString($Uri.Query) -like '*$select=*userPrincipalName,lastSyncDateTime*') `
        'The device query must request the primary user name and last sync time.'
    [pscustomobject]@{ value = @($analysisTestState.Devices) }
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

Reset-AnalysisTestData
Set-PreviewScenario
$previewOutput = @(& $analyzerUnderTest @analysisParameters -Preview $true)
Test-Condition ((Get-OutputLine $previewOutput 'Preview examples:') -like '*4 of 4 devices that would change*') `
    'Preview must report how many of the planned changes are listed.'
$tableHeader = Get-OutputLine $previewOutput 'IntuneDeviceId'
foreach ($columnName in @('DeviceName', 'CurrentPrimaryUser', 'CurrentUserSignIns', 'NewPrimaryUser', 'NewUserSignIns',
    'NewUserShare', 'DeviceUsers', 'NewUserLastSignInUtc', 'LastIntuneSyncUtc', 'Reason')) {
    Test-Condition ($tableHeader -like "*$columnName*") "The preview table must include the $columnName column."
}
$exampleOrder = @('Device A', 'Device B', 'Device C', 'Device E' | ForEach-Object { Get-OutputLineIndex $previewOutput $_ })
Test-Condition ((Get-OutputLineIndex $previewOutput 'Device D') -lt 0 -and $exampleOrder[0] -gt 0 -and
    $exampleOrder[0] -lt $exampleOrder[1] -and $exampleOrder[1] -lt $exampleOrder[2] -and $exampleOrder[2] -lt $exampleOrder[3]) `
    'Preview examples must list only changed devices, sorted by device name.'
$deviceALine = Get-OutputLine $previewOutput 'Device A'
Test-Condition ($deviceALine -match 'intune-a\s+bob@contoso\.com\s+2\s+alice@contoso\.com\s+5\s+71%\s+2\s+2024-02-29 11:00\s+2024-02-28 08:30\s+More sign-ins$') `
    "Device A must show names from Intune and collected sign-ins, counts, share, and times. Line: $deviceALine"
$deviceBLine = Get-OutputLine $previewOutput 'Device B'
Test-Condition ($deviceBLine -match 'bob@contoso\.com.+2024-02-27 07:15\s+Tie, latest sign-in$') `
    "Primary user names seen on other devices and Graph date values must be used. Line: $deviceBLine"
Test-Condition ((Get-OutputLine $previewOutput 'Device C') -match 'intune-c\s+\(none\)\s+0\s+alice@contoso\.com\s+4\s+100%\s+1\s+2024-02-29 09:00\s+No primary user$') `
    'A device without a primary user and without a sync time must be shown clearly.'
Test-Condition ((Get-OutputLine $previewOutput 'Device E') -match 'carol@contoso\.com\s+0\s+aaaaaaaa-0000-0000-0000-000000000004\s+1\s.+Current user has no sign-ins$') `
    'A new user without a known name must be shown by user ID.'
Test-Condition ((Get-OutputLine $previewOutput 'Change reasons:') -eq
    'Change reasons: No primary user: 1; Current user has no sign-ins: 1; More sign-ins: 1; Tie, latest sign-in: 1.') `
    'Every run must report the number of changes per reason.'
$deviceAAudit = @($analysisTestState.Audits | Where-Object { $_.RowKey -eq 'intune-a' })[0]
Test-Condition ($deviceAAudit.Outcome -eq 'Preview' -and $deviceAAudit.ChangeReason -eq 'MoreSignIns' -and
    $deviceAAudit.PreviousUserPrincipalName -eq 'bob@contoso.com' -and $deviceAAudit.RecommendedUserPrincipalName -eq 'alice@contoso.com' -and
    $deviceAAudit.PreviousUserSignInCount -eq 2 -and $deviceAAudit.SignInCount -eq 5 -and $deviceAAudit.DeviceSignInCount -eq 7 -and
    $deviceAAudit.DistinctUserCount -eq 2) 'Audit rows must store the preview details.'
$deviceDAudit = @($analysisTestState.Audits | Where-Object { $_.RowKey -eq 'intune-d' })[0]
Test-Condition ($deviceDAudit.Outcome -eq 'Unchanged' -and -not $deviceDAudit.ContainsKey('ChangeReason')) `
    'Unchanged audit rows must not carry a change reason.'

Reset-AnalysisTestData
Set-PreviewScenario
$limitedOutput = @(& $analyzerUnderTest @analysisParameters -Preview $true -PreviewDeviceCount 2)
Test-Condition ((Get-OutputLine $limitedOutput 'Preview examples:') -like '*2 of 4 devices*' -and
    (Get-OutputLineIndex $limitedOutput 'Device A') -lt (Get-OutputLineIndex $limitedOutput 'Device C') -and
    (Get-OutputLineIndex $limitedOutput 'Device A') -gt 0 -and (Get-OutputLineIndex $limitedOutput 'Device B') -lt 0 -and
    (Get-OutputLineIndex $limitedOutput 'Device E') -lt 0) 'PreviewDeviceCount must limit the listed examples.'
Test-Condition (@($analysisTestState.Audits | Where-Object { $_.Outcome -eq 'Preview' }).Count -eq 4) `
    'The example limit must not limit audited recommendations.'

Reset-AnalysisTestData
Set-PreviewScenario
$disabledOutput = @(& $analyzerUnderTest @analysisParameters -Preview $true -PreviewDeviceCount 0)
Test-Condition ((Get-OutputLineIndex $disabledOutput 'Preview examples:') -lt 0 -and (Get-OutputLineIndex $disabledOutput 'Device A') -lt 0 -and
    (Get-OutputLineIndex $disabledOutput 'Change reasons:') -ge 0) 'PreviewDeviceCount 0 must print only totals.'

Reset-AnalysisTestData
Set-PreviewScenario
$applyOutput = @(& $analyzerUnderTest @analysisParameters)
$updatedAudits = @($analysisTestState.Audits | Where-Object { $_.Outcome -eq 'Updated' })
Test-Condition ((Get-OutputLineIndex $applyOutput 'Preview examples:') -lt 0 -and $analysisTestState.BatchCount -eq 1 -and
    $updatedAudits.Count -eq 4 -and $analysisTestState.Summary.Updated -eq 4 -and
    @($updatedAudits | Where-Object { $_.HttpStatus -eq 204 -and $_.Preview -eq $false -and $_.ChangeReason }).Count -eq 4) `
    'Apply mode must update changed devices and audit their change reasons without preview examples.'

Reset-AnalysisTestData
$analysisTestState.Rows = @(for ($deviceIndex = 1; $deviceIndex -le 21; $deviceIndex++) {
    New-AggregateRow ('eeeeeeee-0000-0000-0000-{0:d12}' -f $deviceIndex) '22222222-2222-2222-2222-222222222222' 3 '2024-02-29T12:00:00Z'
})
$analysisTestState.Devices = @(for ($deviceIndex = 1; $deviceIndex -le 21; $deviceIndex++) {
    [pscustomobject]@{ id = "intune-$deviceIndex"; azureADDeviceId = ('eeeeeeee-0000-0000-0000-{0:d12}' -f $deviceIndex); deviceName = "Device $deviceIndex"; userId = $null }
})
& $analyzerUnderTest @analysisParameters | Out-Null
Test-Condition ($analysisTestState.BatchCount -eq 2 -and $analysisTestState.Summary.Updated -eq 21 -and
    @($analysisTestState.Audits | Where-Object { $_.Outcome -eq 'Updated' }).Count -eq 21) `
    'Apply mode must submit full batches of 20 and the remaining requests.'
Write-Output 'Analyzer Boolean input, lock, and preview example tests passed.'
