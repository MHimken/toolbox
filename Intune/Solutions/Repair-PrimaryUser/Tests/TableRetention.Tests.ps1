#Requires -Version 7.2
<#
.SYNOPSIS
    Exercises batched Table Storage retention deletes without Azure credentials.
.DESCRIPTION
    Loads the real table helper functions from both runbooks and replaces only the HTTP boundary.
.NOTES
    Run with pwsh -NoProfile -File .\Tests\TableRetention.Tests.ps1. Pester is not required.
#>

Set-StrictMode -Version Latest
$runbookFolder = Join-Path (Split-Path $PSScriptRoot -Parent) 'Runbooks'
$sharedHelperNames = @(
    'Get-OptionalProperty', 'Get-HttpStatusCode', 'Test-RetryableError', 'Get-RetryDelaySeconds',
    'Get-StorageHeaders', 'Invoke-RestWithRetry', 'ConvertTo-EntityUri',
    'Remove-TableEntity', 'Invoke-TableBatchDelete', 'Remove-TableEntityByFilter'
)

function Get-RunbookFunctionText {
    param([string]$Path, [string[]]$Names)
    $parseTokens = $null
    $parseIssues = $null
    $runbookAst = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$parseTokens, [ref]$parseIssues)
    if ($parseIssues.Count) { throw ($parseIssues | Out-String) }
    $definitions = @{}
    foreach ($definition in $runbookAst.FindAll({
        param($syntaxNode)
        $syntaxNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $syntaxNode.Name -in $Names
    }, $true)) { $definitions[$definition.Name] = $definition.Extent.Text }
    return $definitions
}

function Test-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

$collectorHelpers = Get-RunbookFunctionText -Path (Join-Path $runbookFolder 'Collect-PrimaryUserSignInData.ps1') -Names $sharedHelperNames
$analyzerHelpers = Get-RunbookFunctionText -Path (Join-Path $runbookFolder 'Repair-PrimaryUserAssignments.ps1') -Names ($sharedHelperNames + 'Remove-ExpiredAnalysisHistory')
foreach ($helperName in @('Remove-TableEntity', 'Invoke-TableBatchDelete', 'Remove-TableEntityByFilter')) {
    Test-Condition ($collectorHelpers[$helperName] -ceq $analyzerHelpers[$helperName]) "Both runbooks must share the same $helperName implementation."
}
foreach ($helperName in $sharedHelperNames) { . ([scriptblock]::Create($collectorHelpers[$helperName])) }

$script:StorageBaseUri = 'https://rputest.table.core.windows.net'
$script:StorageToken = 'test-token'
$MaximumRetryCount = 1
$retentionTestState = @{}

function Reset-RetentionTestData {
    param([hashtable]$PartitionSizes, [int]$PageSize = 120)
    $retentionTestState.Rows = [Collections.Generic.List[object]]::new()
    foreach ($partitionKey in @($PartitionSizes.Keys | Sort-Object)) {
        for ($rowIndex = 0; $rowIndex -lt $PartitionSizes[$partitionKey]; $rowIndex++) {
            $retentionTestState.Rows.Add([pscustomobject]@{ PartitionKey = $partitionKey; RowKey = ('{0:D5}|device' -f $rowIndex) })
        }
    }
    $retentionTestState.PageSize = $PageSize
    $retentionTestState.QueryUris = [Collections.Generic.List[string]]::new()
    $retentionTestState.BatchSizes = [Collections.Generic.List[int]]::new()
    $retentionTestState.SingleDeletes = 0
    $retentionTestState.BatchFailureStatus = 0
}

function Invoke-WebRequest {
    param([string]$Method, [uri]$Uri, [hashtable]$Headers, [byte[]]$Body)
    if ($Method -eq 'Get') {
        $retentionTestState.QueryUris.Add($Uri.OriginalString)
        $startIndex = 0
        $continuation = [regex]::Match($Uri.OriginalString, 'NextRowKey=([^&]+)')
        if ($continuation.Success) { $startIndex = [int][uri]::UnescapeDataString($continuation.Groups[1].Value) }
        $page = @($retentionTestState.Rows | Select-Object -Skip $startIndex -First $retentionTestState.PageSize)
        $responseHeaders = @{}
        if ($startIndex + $page.Count -lt $retentionTestState.Rows.Count) {
            $responseHeaders['x-ms-continuation-NextPartitionKey'] = 'next'
            $responseHeaders['x-ms-continuation-NextRowKey'] = [string]($startIndex + $page.Count)
        }
        return [pscustomobject]@{ Content = (@{ value = $page } | ConvertTo-Json -Depth 4); Headers = $responseHeaders }
    }
    if ($Method -eq 'Post') {
        Test-Condition ($Uri.AbsolutePath -eq '/$batch') 'Batches must target the $batch endpoint.'
        Test-Condition ($Headers['Content-Type'] -like 'multipart/mixed; boundary=batch_*') 'Batches must declare their multipart boundary.'
        $payload = [Text.Encoding]::UTF8.GetString($Body)
        $deleteLines = @([regex]::Matches($payload, "(?m)^DELETE \S+PartitionKey='([^']+)',RowKey='([^']+)'\) HTTP/1\.1\r$"))
        Test-Condition ($deleteLines.Count -ge 1 -and $deleteLines.Count -le 100) 'A batch must contain between 1 and 100 deletes.'
        Test-Condition (@($deleteLines | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique).Count -eq 1) 'A batch must target a single partition.'
        Test-Condition ([regex]::Matches($payload, '(?m)^If-Match: \*\r$').Count -eq $deleteLines.Count) 'Every batched delete needs If-Match.'
        if ($retentionTestState.BatchFailureStatus -ne 0) {
            return [pscustomobject]@{ Content = "--batchresponse_x`r`nHTTP/1.1 $($retentionTestState.BatchFailureStatus) Error`r`n"; Headers = @{} }
        }
        $retentionTestState.BatchSizes.Add($deleteLines.Count)
        $responseText = ($deleteLines | ForEach-Object { "HTTP/1.1 204 No Content`r`n" }) -join "--changesetresponse_x`r`n"
        return [pscustomobject]@{ Content = [Text.Encoding]::UTF8.GetBytes($responseText); Headers = @{} }
    }
    if ($Method -eq 'Delete') {
        $retentionTestState.SingleDeletes++
        return [pscustomobject]@{ Content = ''; Headers = @{} }
    }
    throw "Unexpected HTTP method '$Method'."
}

Reset-RetentionTestData -PartitionSizes @{ '20240101' = 250; '20240102' = 30 }
$removedCount = Remove-TableEntityByFilter -TableName 'PrimaryUserDaily' -Filter "PartitionKey lt '20240103'"
Test-Condition ($removedCount -eq 280) 'Every matching row must be counted as removed.'
Test-Condition (($retentionTestState.BatchSizes -join ',') -eq '100,100,50,30') 'Rows must be grouped into full per-partition batches across page boundaries.'
Test-Condition ($retentionTestState.QueryUris.Count -eq 3) 'All continuation pages must be followed.'
Test-Condition (@($retentionTestState.QueryUris | Where-Object { $_ -notlike '*$select=PartitionKey,RowKey*' }).Count -eq 0) 'Queries must only request the keys.'
Test-Condition ($retentionTestState.SingleDeletes -eq 0) 'Successful batches must not fall back to single deletes.'

Reset-RetentionTestData -PartitionSizes @{}
Test-Condition ((Remove-TableEntityByFilter -TableName 'PrimaryUserDaily' -Filter "PartitionKey lt '20240103'") -eq 0) 'An empty result must not send batches.'
Test-Condition ($retentionTestState.BatchSizes.Count -eq 0) 'An empty result must not send batches.'

Reset-RetentionTestData -PartitionSizes @{ '20240101' = 3 }
$retentionTestState.BatchFailureStatus = 404
Remove-TableEntityByFilter -TableName 'PrimaryUserDaily' -Filter "PartitionKey lt '20240103'" | Out-Null
Test-Condition ($retentionTestState.SingleDeletes -eq 3) 'A rolled-back batch with a missing row must retry the rows individually.'

Reset-RetentionTestData -PartitionSizes @{ '20240101' = 3 }
$retentionTestState.BatchFailureStatus = 403
$failureObserved = $false
try { Remove-TableEntityByFilter -TableName 'PrimaryUserDaily' -Filter "PartitionKey lt '20240103'" | Out-Null }
catch { $failureObserved = $_.Exception.Message -like '*Batch delete failed*' }
Test-Condition ($failureObserved -and $retentionTestState.SingleDeletes -eq 0) 'Other batch failures must stop the cleanup.'

$filterCalls = [Collections.Generic.List[string]]::new()
function Remove-TableEntityByFilter {
    param([string]$TableName, [string]$Filter)
    $filterCalls.Add("$TableName|$Filter")
    return 0
}
. ([scriptblock]::Create($analyzerHelpers['Remove-ExpiredAnalysisHistory']))
$AuditTableName = 'PrimaryUserAudit'
$StateTableName = 'PrimaryUserState'
$AuditRetentionDays = 180
$expectedCutoff = [datetime]::UtcNow.Date.AddDays(-180).ToString('yyyyMMdd')
Remove-ExpiredAnalysisHistory | Out-Null
Test-Condition (($filterCalls -join ';') -eq "PrimaryUserAudit|PartitionKey lt '$expectedCutoff';PrimaryUserState|PartitionKey eq 'AnalysisRuns' and RowKey lt '$expectedCutoff'") `
    'Audit retention must target only expired audit partitions and run summaries.'
Write-Output 'Table retention tests passed.'
