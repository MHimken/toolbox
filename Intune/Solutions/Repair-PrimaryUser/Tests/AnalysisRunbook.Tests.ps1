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
    $analysisTestState.CollectionStatus = 'Complete'
    $analysisTestState.ExclusionVariables = @{
        'RepairPrimaryUser-ExcludedGroupIds' = ''
        'RepairPrimaryUser-ExcludedDeviceNamePrefixes' = $null
    }
    $analysisTestState.Groups = @{}
    $analysisTestState.BatchRequests = [Collections.Generic.List[object]]::new()
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

# Group members and devices use mixed case to verify case-insensitive matching.
function Set-ExclusionScenario {
    $alice = 'aaaaaaaa-0000-0000-0000-000000000001'
    $bob = 'aaaaaaaa-0000-0000-0000-000000000002'
    $analysisTestState.ExclusionVariables['RepairPrimaryUser-ExcludedGroupIds'] = '99999999-0000-0000-0000-000000000001;99999999-0000-0000-0000-000000000002'
    $analysisTestState.ExclusionVariables['RepairPrimaryUser-ExcludedDeviceNamePrefixes'] = "kiosk-*`r`nLAB-"
    $analysisTestState.Groups = @{
        '99999999-0000-0000-0000-000000000001' = @{ DisplayName = 'Shared devices'; Members = @(
            [pscustomobject]@{ id = 'object-1'; deviceId = 'FFFFFFFF-0000-0000-0000-000000000001'; displayName = 'SHARED-01' }
            [pscustomobject]@{ id = 'object-2'; deviceId = 'ffffffff-0000-0000-0000-000000000002'; displayName = 'SHARED-02' }
        ) }
        '99999999-0000-0000-0000-000000000002' = @{ DisplayName = 'Kiosk users'; Members = @() }
    }
    $analysisTestState.Rows = @(
        New-AggregateRow 'ffffffff-0000-0000-0000-00000000000a' $alice 5 '2024-02-29T11:00:00Z' 'alice@contoso.com'
        New-AggregateRow 'ffffffff-0000-0000-0000-00000000000b' $alice 3 '2024-02-29T12:00:00Z'
    )
    $analysisTestState.Devices = @(
        [pscustomobject]@{ id = 'intune-kiosk'; azureADDeviceId = 'ffffffff-0000-0000-0000-00000000000a'; deviceName = 'KIOSK-01'; userId = $bob; userPrincipalName = 'bob@contoso.com' }
        [pscustomobject]@{ id = 'intune-normal'; azureADDeviceId = 'ffffffff-0000-0000-0000-00000000000b'; deviceName = 'OFFICE-01'; userId = $null }
        [pscustomobject]@{ id = 'intune-shared-1'; azureADDeviceId = 'ffffffff-0000-0000-0000-000000000001'; deviceName = 'SHARED-01'; userId = $bob; userPrincipalName = 'bob@contoso.com' }
        [pscustomobject]@{ id = 'intune-shared-2'; azureADDeviceId = 'FFFFFFFF-0000-0000-0000-000000000002'; deviceName = 'SHARED-02'; userId = $null }
        [pscustomobject]@{ id = 'intune-other'; azureADDeviceId = 'ffffffff-0000-0000-0000-00000000000c'; deviceName = 'OTHER-01'; userId = $bob; userPrincipalName = 'bob@contoso.com' }
    )
}

function Get-OutputLineIndex {
    param([object[]]$OutputLines, [string]$Text)
    for ($lineIndex = 0; $lineIndex -lt $OutputLines.Count; $lineIndex++) {
        if ([string]$OutputLines[$lineIndex] -clike "*$Text*") { return $lineIndex }
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
    return [pscustomobject]@{ Status = $analysisTestState.CollectionStatus }
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
function Get-AutomationVariable {
    [CmdletBinding()]
    param([string]$Name)
    if (-not $analysisTestState.ExclusionVariables.ContainsKey($Name)) { throw "Variable '$Name' was not found." }
    $analysisTestState.ExclusionVariables[$Name]
}
function Invoke-GraphGet {
    param([uri]$Uri, [hashtable]$Headers = @{})
    if ($Uri.AbsolutePath -eq '/beta/deviceManagement/managedDevices') {
        Test-Condition ([uri]::UnescapeDataString($Uri.Query) -like '*$select=*userPrincipalName,lastSyncDateTime*') `
            'The device query must request the primary user name and last sync time.'
        return [pscustomobject]@{ value = @($analysisTestState.Devices) }
    }
    $groupMatch = [regex]::Match($Uri.AbsolutePath, '^/v1\.0/groups/([^/]+)(/transitiveMembers/microsoft\.graph\.device)?$')
    if (-not $groupMatch.Success) { throw "Unexpected Graph request '$Uri'." }
    $group = $analysisTestState.Groups[$groupMatch.Groups[1].Value]
    if ($null -eq $group) {
        $response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::NotFound)
        throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Request_ResourceNotFound', $response)
    }
    if (-not $groupMatch.Groups[2].Success) { return [pscustomobject]@{ id = $groupMatch.Groups[1].Value; displayName = $group.DisplayName } }
    Test-Condition ($Headers['ConsistencyLevel'] -eq 'eventual' -and [uri]::UnescapeDataString($Uri.Query) -like '*$count=true*') `
        'Device members must be read with an advanced query.'
    return [pscustomobject]@{ value = @($group.Members) }
}
function Invoke-GraphBatch {
    param([object[]]$Requests)
    $analysisTestState.BatchCount++
    foreach ($request in $Requests) {
        $analysisTestState.BatchRequests.Add($request)
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
Test-Condition ((Get-OutputLine $previewOutput 'Device exclusions:') -eq 'Device exclusions: none configured.') `
    'Empty exclusion variables must exclude no devices.'
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

Reset-AnalysisTestData
$analysisTestState.CollectionStatus = 'LowSignInCount'
$incompleteMessage = ''
try { & $analyzerUnderTest @analysisParameters | Out-Null } catch { $incompleteMessage = $_.Exception.Message }
Test-Condition ($incompleteMessage -like '*incomplete for: 2024-02-29 (LowSignInCount).' -and $analysisTestState.BatchCount -eq 0 -and
    $analysisTestState.Audits.Count -eq 0) 'Days that are not complete must stop the analysis and show their collection status.'

Reset-AnalysisTestData
Set-ExclusionScenario
$exclusionOutput = @(& $analyzerUnderTest @analysisParameters -Preview $true 3>&1)
Test-Condition ((Get-OutputLine $exclusionOutput 'Device exclusions:') -eq ('Device exclusions: Prefix kiosk-; Prefix LAB-; ' +
    'Group Shared devices (99999999-0000-0000-0000-000000000001) with 2 devices; Group Kiosk users (99999999-0000-0000-0000-000000000002) with 0 devices.')) `
    "Every run must report the exclusion rules and the devices per group. Line: $(Get-OutputLine $exclusionOutput 'Device exclusions:')"
Test-Condition ((Get-OutputLine $exclusionOutput 'has no device members') -like 'Group Kiosk users (*) has no device members*') `
    'A group without device members must be reported, because it usually contains users instead of devices.'
$kioskLine = Get-OutputLine $exclusionOutput 'KIOSK-01'
Test-Condition ($kioskLine -match 'intune-kiosk\s+bob@contoso\.com\s+0\s+\(none\)\s+1\s+Excluded device: Prefix kiosk-$') `
    "A prefix match must remove the primary user even when another user signs in most. Line: $kioskLine"
$sharedLine = Get-OutputLine $exclusionOutput 'SHARED-01'
Test-Condition ($sharedLine -match 'intune-shared-1\s+bob@contoso\.com\s+0\s+\(none\)\s+0\s+Excluded device: Group Shared devices \(99999999-0000-0000-0000-000000000001\)$') `
    "A group member without collected sign-ins must have its primary user removed. Line: $sharedLine"
Test-Condition ((Get-OutputLine $exclusionOutput 'OFFICE-01') -match 'intune-normal\s+\(none\)\s+0\s+alice@contoso\.com\s+3\s+100%.+No primary user$') `
    'Devices that are not excluded must still be assigned.'
Test-Condition ((Get-OutputLineIndex $exclusionOutput 'SHARED-02') -lt 0 -and (Get-OutputLineIndex $exclusionOutput 'OTHER-01') -lt 0) `
    'Excluded devices without a primary user and devices without sign-ins must not be listed as changes.'
Test-Condition ((Get-OutputLine $exclusionOutput 'Change reasons:') -eq 'Change reasons: No primary user: 1; Excluded device: 2.' -and
    (Get-OutputLine $exclusionOutput 'complete. Evaluated:') -like '*Evaluated: 4; changes: 3; updated: 0; failed: 0; unchanged: 1; excluded: 3.') `
    'Removals must be counted as changes, and every excluded device must be counted.'
$kioskAudit = @($analysisTestState.Audits | Where-Object { $_.RowKey -eq 'intune-kiosk' })[0]
Test-Condition ($kioskAudit.Outcome -eq 'Preview' -and $kioskAudit.ChangeReason -eq 'Excluded' -and $kioskAudit.ExcludedBy -eq 'Prefix kiosk-' -and
    $kioskAudit.RecommendedUserId -eq '' -and $kioskAudit.SignInCount -eq 0 -and $kioskAudit.DeviceSignInCount -eq 5 -and
    -not $kioskAudit.ContainsKey('LatestSignIn')) 'Audit rows must store the rule that excluded a device.'
$sharedAudit = @($analysisTestState.Audits | Where-Object { $_.RowKey -eq 'intune-shared-2' })[0]
Test-Condition ($sharedAudit.Outcome -eq 'Unchanged' -and $sharedAudit.ExcludedBy -like 'Group Shared devices (*' -and
    -not $sharedAudit.ContainsKey('ChangeReason')) 'An excluded device without a primary user must be audited as unchanged.'
Test-Condition ($analysisTestState.Summary.Excluded -eq 3 -and $analysisTestState.Summary.ExcludedDeviceNamePrefixes -eq 'kiosk-, LAB-' -and
    $analysisTestState.Summary.ExcludedGroupIds -eq '99999999-0000-0000-0000-000000000001, 99999999-0000-0000-0000-000000000002' -and
    @($analysisTestState.Audits | Where-Object { $_.RowKey -eq 'intune-other' }).Count -eq 0) `
    'The run summary must store the applied exclusions.'

Reset-AnalysisTestData
Set-ExclusionScenario
& $analyzerUnderTest @analysisParameters 3>$null | Out-Null
$removalRequests = @($analysisTestState.BatchRequests | Where-Object { $_.method -eq 'DELETE' })
Test-Condition ($analysisTestState.BatchRequests.Count -eq 3 -and $removalRequests.Count -eq 2 -and
    @($removalRequests | Where-Object { $_.url -match '^/deviceManagement/managedDevices/intune-(kiosk|shared-1)/users/\$ref$' -and
        $null -eq $_.PSObject.Properties['body'] }).Count -eq 2 -and
    @($analysisTestState.BatchRequests | Where-Object { $_.method -eq 'POST' -and $_.url -like '*/intune-normal/*' }).Count -eq 1 -and
    $analysisTestState.Summary.Updated -eq 3) 'Apply mode must remove the primary user of excluded devices and assign the others.'

$invalidExclusions = @(
    @{ Name = 'MissingVariable'; Expected = "*'RepairPrimaryUser-ExcludedDeviceNamePrefixes' could not be read*" }
    @{ Name = 'GroupName'; Expected = "*contains 'Shared', which is not a group object ID." }
    @{ Name = 'Wildcard'; Expected = "*contains '[*]'. Use device name prefixes*" }
    @{ Name = 'QuotedPrefix'; Expected = '*contains "KIOSK-". Enter the prefixes without quotation marks*' }
    @{ Name = 'UnknownGroup'; Expected = "Excluded group '99999999-0000-0000-0000-000000000003' was not found.*" }
    @{ Name = 'MissingDeviceId'; Expected = '*without a device ID*Device.Read.All.' }
)
foreach ($invalidExclusion in $invalidExclusions) {
    Reset-AnalysisTestData
    Set-ExclusionScenario
    if ($invalidExclusion.Name -eq 'MissingVariable') { $analysisTestState.ExclusionVariables.Remove('RepairPrimaryUser-ExcludedDeviceNamePrefixes') }
    if ($invalidExclusion.Name -eq 'GroupName') { $analysisTestState.ExclusionVariables['RepairPrimaryUser-ExcludedGroupIds'] = 'Shared devices' }
    if ($invalidExclusion.Name -eq 'Wildcard') { $analysisTestState.ExclusionVariables['RepairPrimaryUser-ExcludedDeviceNamePrefixes'] = 'KIOSK-, *' }
    if ($invalidExclusion.Name -eq 'QuotedPrefix') { $analysisTestState.ExclusionVariables['RepairPrimaryUser-ExcludedDeviceNamePrefixes'] = '"KIOSK-","LAB-"' }
    if ($invalidExclusion.Name -eq 'UnknownGroup') { $analysisTestState.ExclusionVariables['RepairPrimaryUser-ExcludedGroupIds'] = '99999999-0000-0000-0000-000000000003' }
    if ($invalidExclusion.Name -eq 'MissingDeviceId') {
        $analysisTestState.Groups['99999999-0000-0000-0000-000000000001'].Members += [pscustomobject]@{ id = 'object-3'; deviceId = $null; displayName = 'SHARED-03' }
    }
    $exclusionMessage = ''
    try { & $analyzerUnderTest @analysisParameters 3>$null | Out-Null } catch { $exclusionMessage = $_.Exception.Message }
    Test-Condition ($exclusionMessage -like $invalidExclusion.Expected -and $analysisTestState.BatchCount -eq 0 -and
        $analysisTestState.Audits.Count -eq 0 -and $analysisTestState.Summary.Status -eq 'Failed') `
        "An invalid exclusion ($($invalidExclusion.Name)) must stop the analysis before any change. Message: $exclusionMessage"
}
Write-Output 'Analyzer Boolean input, lock, preview example, and device exclusion tests passed.'
