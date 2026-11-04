#Requires -Version 7.2
<#
.SYNOPSIS
    Exercises deployment recovery and runbook discovery with in-memory Azure and Graph responses.
.DESCRIPTION
    Runs without Azure modules, credentials, or Pester. All cloud commands are mocked locally.
.NOTES
    Run with pwsh -NoProfile -File .\Tests\DeploymentResume.Tests.ps1.
#>

Set-StrictMode -Version Latest
$deploymentScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Deployment\Deploy-RepairPrimaryUser.ps1'
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) "RepairPrimaryUser-ResumeTests-$([guid]::NewGuid())"
$checkpointPath = Join-Path $testDirectory 'state.json'
$layoutTestDirectory = Join-Path $testDirectory 'Runbook Layout Test'
$testSubscriptionId = '11111111-1111-1111-1111-111111111111'
$testTenantId = '22222222-2222-2222-2222-222222222222'
$testPrincipalId = '33333333-3333-3333-3333-333333333333'
$testResourceGroupId = "/subscriptions/$testSubscriptionId/resourceGroups/rg-resume-test"
$testStorageId = "$testResourceGroupId/providers/Microsoft.Storage/storageAccounts/rpuresumetest"
$testAutomationId = "$testResourceGroupId/providers/Microsoft.Automation/automationAccounts/aa-rpu-rpuresumetest"
$tableRoleDefinitionId = "/subscriptions/$testSubscriptionId/providers/Microsoft.Authorization/roleDefinitions/0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
$readerRoleDefinitionId = "/subscriptions/$testSubscriptionId/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
$mockDeploymentEnvironment = @{
    Resources = @{}
    Runbooks = @{}
    ImportedRunbookPaths = @{}
    Schedules = @{}
    Links = @{}
    Assignments = @()
    Deployments = 0
    Imports = 0
    ScheduleCreations = 0
    ScheduleRemovals = 0
    GraphPosts = 0
    FailGraph = $true
    FailWeeklyRegistration = $false
    FailBicep = $false
    DenyResourceReads = $false
    ResourceResponseOverride = $null
    ThrowMissingResource = $false
    DenyRoleAssignmentWrite = $false
    RoleAssignmentExists = $false
    ManualRoleAssignments = @()
    ConfirmationAnswer = 'NO'
    ConfirmationRequests = 0
    ResourceGroupExists = $true
}
$initialParameters = @{
    SubscriptionId = $testSubscriptionId
    TenantId = $testTenantId
    ResourceGroupName = 'rg-resume-test'
    Location = 'westeurope'
    StorageAccountName = 'rpuresumetest'
    DeploymentStatePath = $checkpointPath
}
$resumeParameters = @{ Resume = $true; DeploymentStatePath = $checkpointPath }

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Assert-DeploymentFailure {
    param([hashtable]$Parameters, [string]$ExpectedMessage)
    try {
        & $deploymentScript @Parameters | Out-Null
    } catch {
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") { throw }
        return
    }
    throw "Expected deployment failure containing '$ExpectedMessage'."
}

function Read-TestCheckpoint {
    Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json -AsHashtable
}

# These functions shadow cloud commands only within this test script and its child scripts.
function Get-Module { [pscustomobject]@{ Name = 'Mock prerequisite' } }
function Import-Module {}
function Connect-AzAccount {}
function Set-AzContext {}
function Connect-MgGraph {}
function Disconnect-MgGraph {}
function bicep {}
function Read-Host {
    $mockDeploymentEnvironment.ConfirmationRequests++
    return $mockDeploymentEnvironment.ConfirmationAnswer
}
function Get-AzContext {
    [pscustomobject]@{
        Subscription = [pscustomobject]@{ Id = $testSubscriptionId }
        Tenant = [pscustomobject]@{ Id = $testTenantId }
    }
}
function Get-AzResourceGroup {
    if ($mockDeploymentEnvironment.ResourceGroupExists) {
        return [pscustomobject]@{ ResourceGroupName = 'rg-resume-test' }
    }
    $notFoundError = [Management.Automation.ErrorRecord]::new(
        [Exception]::new('The requested resource group does not exist.'), 'ResourceGroupNotFound',
        [Management.Automation.ErrorCategory]::ObjectNotFound, 'rg-resume-test'
    )
    $notFoundError.ErrorDetails = [Management.Automation.ErrorDetails]::new('{"error":{"code":"ResourceGroupNotFound"}}')
    throw $notFoundError
}
function New-AzResourceGroup { $mockDeploymentEnvironment.ResourceGroupExists = $true }
function Get-AzResource {
    param([string]$ResourceId, [string]$ApiVersion)
    if ($ResourceId -like '*/providers/Microsoft.Authorization/roleAssignments/*') {
        if ($ApiVersion -ne '2022-04-01') {
            throw "No registered resource provider found for API version '$ApiVersion' for type 'roleAssignments'."
        }
    } elseif ($ResourceId -like '*/providers/Microsoft.Automation/automationAccounts/*') {
        Assert-Condition ($ApiVersion -eq '2023-11-01') 'Automation lookups must use the template API version.'
    } else {
        Assert-Condition ($ApiVersion -eq '2023-05-01') 'Storage and table lookups must use the template API version.'
    }
    if ($mockDeploymentEnvironment.DenyResourceReads) { throw 'AuthorizationFailed' }
    if ($mockDeploymentEnvironment.Resources.ContainsKey($ResourceId)) {
        return [pscustomobject]@{ ResourceId = $ResourceId }
    }
    throw [Management.Automation.ErrorRecord]::new(
        [Exception]::new('The requested resource does not exist.'), 'ResourceNotFound',
        [Management.Automation.ErrorCategory]::ObjectNotFound, $ResourceId
    )
}
function Invoke-AzRestMethod {
    param([string]$Path, [string]$Method)
    if ($Method -ne 'GET') { throw "Unexpected inventory method '$Method'." }
    if ($Path.Contains('/providers/Microsoft.Authorization/roleAssignments?')) {
        Assert-Condition ($Path -like "*api-version=2022-04-01*principalId%20eq%20%27$testPrincipalId%27*") 'Role assignment lists must filter by managed identity.'
        # Like ARM, return assignments regardless of scope so the deployment script must filter inherited scopes itself.
        $assignments = @($mockDeploymentEnvironment.ManualRoleAssignments | ForEach-Object {
            @{ properties = @{ scope = $_.Scope; roleDefinitionId = $_.RoleDefinitionId; principalId = $testPrincipalId } }
        })
        return [pscustomobject]@{ StatusCode = 200; Content = (@{ value = $assignments } | ConvertTo-Json -Depth 5 -Compress) }
    }
    if ($null -ne $mockDeploymentEnvironment.ResourceResponseOverride) {
        return $mockDeploymentEnvironment.ResourceResponseOverride
    }
    if ($mockDeploymentEnvironment.DenyResourceReads) {
        return [pscustomobject]@{
            StatusCode = 403
            Content = '{"error":{"code":"AuthorizationFailed","message":"Access denied."}}'
        }
    }
    $resourceId, $apiVersion = $Path -split '\?api-version=', 2
    if ($resourceId -like '*/providers/Microsoft.Authorization/roleAssignments/*') {
        if ($apiVersion -ne '2022-04-01') {
            throw "No registered resource provider found for API version '$apiVersion' for type 'roleAssignments'."
        }
    } elseif ($resourceId -like '*/providers/Microsoft.Automation/automationAccounts/*') {
        Assert-Condition ($apiVersion -eq '2023-11-01') 'Automation lookups must use the template API version.'
    } else {
        Assert-Condition ($apiVersion -eq '2023-05-01') 'Storage and table lookups must use the template API version.'
    }
    if (-not $mockDeploymentEnvironment.Resources.ContainsKey($resourceId)) {
        if ($mockDeploymentEnvironment.ThrowMissingResource) {
            $notFoundError = [Management.Automation.ErrorRecord]::new(
                [Exception]::new('The requested resource does not exist.'), 'ResourceNotFound',
                [Management.Automation.ErrorCategory]::ObjectNotFound, $resourceId
            )
            $notFoundError.ErrorDetails = [Management.Automation.ErrorDetails]::new('{"error":{"code":"ResourceNotFound"}}')
            throw $notFoundError
        }
        $missingResourceCode = if (-not $mockDeploymentEnvironment.ResourceGroupExists) {
            'ResourceGroupNotFound'
        } elseif ($resourceId.StartsWith("$testStorageId/", [StringComparison]::OrdinalIgnoreCase) -and
            -not $mockDeploymentEnvironment.Resources.ContainsKey($testStorageId)) {
            'ParentResourceNotFound'
        } else {
            'ResourceNotFound'
        }
        return [pscustomobject]@{
            StatusCode = 404
            Content = (@{ error = @{ code = $missingResourceCode; message = 'Resource does not exist.' } } |
                ConvertTo-Json -Compress)
        }
    }
    [pscustomobject]@{ StatusCode = 200; Content = (@{ id = $resourceId } | ConvertTo-Json -Compress) }
}
function Get-AzAutomationAccount {
    [pscustomobject]@{ Identity = [pscustomobject]@{ PrincipalId = $testPrincipalId } }
}
function New-AzResourceGroupDeployment {
    param([string]$Mode, [hashtable]$TemplateParameterObject)
    Assert-Condition ($Mode -eq 'Incremental') 'Bicep must reconcile resources incrementally.'
    Assert-Condition ($TemplateParameterObject.storageAccountName -eq 'rpuresumetest' -and
        $TemplateParameterObject.automationAccountName -eq 'aa-rpu-rpuresumetest' -and
        $TemplateParameterObject.location -eq 'westeurope') 'Template parameters must come from the deployment configuration.'
    $assignTableRoles = [bool]$TemplateParameterObject.assignTableRoles
    $mockDeploymentEnvironment.Deployments++
    if ($mockDeploymentEnvironment.FailBicep) { throw 'Simulated Bicep failure' }
    if ($assignTableRoles -and $mockDeploymentEnvironment.DenyRoleAssignmentWrite) {
        throw ("InvalidTemplateDeployment - The template deployment failed with error: 'Authorization failed for template " +
            "resource of type 'Microsoft.Authorization/roleAssignments'. The client does not have permission to perform " +
            "action 'Microsoft.Authorization/roleAssignments/write' at scope '$testStorageId'.'")
    }
    $roleIds = @()
    $mockDeploymentEnvironment.Resources[$testStorageId] = $true
    $mockDeploymentEnvironment.Resources[$testAutomationId] = $true
    foreach ($tableName in @('PrimaryUserDaily', 'PrimaryUserState', 'PrimaryUserAudit')) {
        $tableId = "$testStorageId/tableServices/default/tables/$tableName"
        $mockDeploymentEnvironment.Resources[$tableId] = $true
        if (-not $assignTableRoles) { continue }
        if ($mockDeploymentEnvironment.RoleAssignmentExists) {
            throw "The deployment failed. Status Message: The role assignment already exists. (Code:RoleAssignmentExists)"
        }
        $roleId = "$tableId/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000001"
        $mockDeploymentEnvironment.Resources[$roleId] = $true
        $roleIds += $roleId
    }
    [pscustomobject]@{
        ProvisioningState = 'Succeeded'
        Outputs = @{ tableRoleAssignmentIds = @{ Value = $roleIds } }
    }
}
function Invoke-MgGraphRequest {
    param([string]$Method, [string]$Uri, [string]$Body)
    if ($Method -eq 'Post') {
        if ($mockDeploymentEnvironment.FailGraph) { throw 'Simulated Graph failure' }
        $assignment = $Body | ConvertFrom-Json
        $mockDeploymentEnvironment.Assignments += $assignment
        $mockDeploymentEnvironment.GraphPosts++
    } elseif ($Uri -like '*appRoleAssignments*') {
        [pscustomobject]@{ value = @($mockDeploymentEnvironment.Assignments) }
    } elseif ($Uri -like '*appId eq*') {
        [pscustomobject]@{
            value = @([pscustomobject]@{
                id = '44444444-4444-4444-4444-444444444444'
                appRoles = @(
                    [pscustomobject]@{
                        id = '55555555-5555-5555-5555-555555555555'
                        value = 'AuditLog.Read.All'; isEnabled = $true; allowedMemberTypes = @('Application')
                    },
                    [pscustomobject]@{
                        id = '66666666-6666-6666-6666-666666666666'
                        value = 'DeviceManagementManagedDevices.ReadWrite.All'; isEnabled = $true; allowedMemberTypes = @('Application')
                    }
                )
            })
        }
    } else {
        [pscustomobject]@{ id = $testPrincipalId }
    }
}
function Import-AzAutomationRunbook {
    param([string]$Name, [string]$Path)
    $mockDeploymentEnvironment.Imports++
    $mockDeploymentEnvironment.Runbooks[$Name] = [pscustomobject]@{ Name = $Name; State = 'Published' }
    $mockDeploymentEnvironment.ImportedRunbookPaths[$Name] = $Path
}
function Get-AzAutomationRunbook { $mockDeploymentEnvironment.Runbooks.Values }
function Get-AzAutomationSchedule { $mockDeploymentEnvironment.Schedules.Values }
function Get-AzAutomationScheduledRunbook {
    param([string]$RunbookName)
    $mockDeploymentEnvironment.Links.Values | Where-Object { $_.RunbookName -eq $RunbookName }
}
function New-AzAutomationSchedule {
    param([string]$Name)
    $mockDeploymentEnvironment.ScheduleCreations++
    $mockDeploymentEnvironment.Schedules[$Name] = [pscustomobject]@{ Name = $Name }
}
function Remove-AzAutomationSchedule {
    param([string]$Name)
    $mockDeploymentEnvironment.ScheduleRemovals++
    $mockDeploymentEnvironment.Schedules.Remove($Name) | Out-Null
}
function Register-AzAutomationScheduledRunbook {
    param([string]$RunbookName, [string]$ScheduleName)
    if ($mockDeploymentEnvironment.FailWeeklyRegistration -and $ScheduleName -eq 'RepairPrimaryUser-WeeklyAnalysis') {
        throw 'Simulated weekly registration failure'
    }
    $mockDeploymentEnvironment.Links[$ScheduleName] = [pscustomobject]@{
        RunbookName = $RunbookName; ScheduleName = $ScheduleName
    }
}
function Unregister-AzAutomationScheduledRunbook {
    param([string]$ScheduleName)
    $mockDeploymentEnvironment.Links.Remove($ScheduleName) | Out-Null
}

try {
    # Adopt accounts left by an older deployment, then interrupt the Graph stage.
    $mockDeploymentEnvironment.Resources[$testStorageId] = $true
    $mockDeploymentEnvironment.Resources[$testAutomationId] = $true
    Assert-DeploymentFailure -Parameters $initialParameters -ExpectedMessage 'Simulated Graph failure'
    $savedCheckpoint = Read-TestCheckpoint
    Assert-Condition ($savedCheckpoint.completedStages.Contains('AzureResourcesReady')) 'Foundation must be checkpointed before Graph.'
    Assert-Condition (-not $savedCheckpoint.completedStages.Contains('GraphPermissionsGranted')) 'A failed Graph stage must remain incomplete.'
    Assert-Condition ($savedCheckpoint.resources.Count -eq 8) 'Both accounts, three tables, and three role IDs must be recorded.'
    Assert-Condition ($savedCheckpoint.managedIdentityPrincipalId -eq $testPrincipalId) 'The managed identity must be recorded.'

    # Complete Graph and both imports, but interrupt the second schedule after creation.
    $mockDeploymentEnvironment.FailGraph = $false
    $mockDeploymentEnvironment.FailWeeklyRegistration = $true
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'Simulated weekly registration failure'
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq 1) 'Resume must skip verified Bicep resources.'
    Assert-Condition ((Read-TestCheckpoint).completedStages.Contains('RepairPrimaryUser-DailyCollection')) 'The daily schedule must be checkpointed separately.'
    $mockDeploymentEnvironment.FailWeeklyRegistration = $false
    & $deploymentScript @resumeParameters | Out-Null
    Assert-Condition ((Read-TestCheckpoint).deploymentCompleted) 'Resume must finish the installation.'
    Assert-Condition ($mockDeploymentEnvironment.Imports -eq 2) 'Completed runbook imports must be skipped.'
    Assert-Condition ($mockDeploymentEnvironment.ScheduleCreations -eq 3) 'Only the interrupted schedule must be retried.'
    Assert-Condition ($mockDeploymentEnvironment.ScheduleRemovals -eq 1) 'Only the uncheckpointed partial schedule must be replaced.'
    Assert-Condition ($mockDeploymentEnvironment.GraphPosts -eq 2) 'Existing Graph assignments must not be duplicated.'
    Assert-Condition ((Read-TestCheckpoint).automationResourceIds.Count -eq 4) 'Both runbook and schedule resource IDs must be recorded.'

    # Repeated successful resumes preserve existing schedules and runbooks.
    & $deploymentScript @resumeParameters | Out-Null
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq 1 -and $mockDeploymentEnvironment.Imports -eq 2 -and
        $mockDeploymentEnvironment.ScheduleCreations -eq 3) 'A completed resume must avoid redeployment.'
    Assert-DeploymentFailure -Parameters @{ DeploymentStatePath = $checkpointPath } -ExpectedMessage 'Resume was declined'
    Assert-Condition ($mockDeploymentEnvironment.ConfirmationRequests -eq 1) 'Automatic resume must request confirmation.'
    $mockDeploymentEnvironment.ConfirmationAnswer = 'YES'
    & $deploymentScript -DeploymentStatePath $checkpointPath | Out-Null
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq 1) 'A confirmed parameterless resume must reuse saved configuration.'

    # Deleted cloud objects and changed source fingerprints invalidate only their stages.
    $mockDeploymentEnvironment.Runbooks.Remove('Collect-PrimaryUserSignInData')
    $mockDeploymentEnvironment.Links.Remove('RepairPrimaryUser-DailyCollection')
    & $deploymentScript @resumeParameters | Out-Null
    Assert-Condition ($mockDeploymentEnvironment.Imports -eq 3 -and $mockDeploymentEnvironment.ScheduleCreations -eq 4) 'Missing runbooks and links must be repaired.'
    $savedCheckpoint = Read-TestCheckpoint
    $savedCheckpoint.completedStages['Repair-PrimaryUserAssignments'] = 'outdated-source-hash'
    $savedCheckpoint | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $checkpointPath
    & $deploymentScript @resumeParameters | Out-Null
    Assert-Condition ($mockDeploymentEnvironment.Imports -eq 4 -and $mockDeploymentEnvironment.Deployments -eq 1) 'A changed runbook hash must trigger only its import.'
    $mockDeploymentEnvironment.Resources.Remove("$testStorageId/tableServices/default/tables/PrimaryUserAudit")
    $mockDeploymentEnvironment.ThrowMissingResource = $true
    & $deploymentScript @resumeParameters | Out-Null
    $mockDeploymentEnvironment.ThrowMissingResource = $false
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq 2) 'Missing foundation resources must trigger reconciliation.'

    # Read errors and parameter conflicts must fail rather than creating another deployment.
    $mockDeploymentEnvironment.DenyResourceReads = $true
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'HTTP 403'
    $mockDeploymentEnvironment.DenyResourceReads = $false
    $mockDeploymentEnvironment.ResourceResponseOverride = [pscustomobject]@{
        StatusCode = 404
        Content = '{"error":{"code":"SubscriptionNotFound","message":"Subscription does not exist."}}'
    }
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'SubscriptionNotFound'
    $mockDeploymentEnvironment.ResourceResponseOverride = [pscustomobject]@{
        StatusCode = 404
        Content = 'Unknown endpoint'
    }
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'Unknown endpoint'
    $mockDeploymentEnvironment.ResourceResponseOverride = [pscustomobject]@{
        StatusCode = 403
        Content = '{"error":{"code":"ResourceNotFound","message":"Access denied."}}'
    }
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'HTTP 403'
    $mockDeploymentEnvironment.ResourceResponseOverride = [pscustomobject]@{
        StatusCode = 503
        Content = 'Service unavailable'
    }
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'Service unavailable'
    $mockDeploymentEnvironment.ResourceResponseOverride = [pscustomobject]@{
        StatusCode = 200
        Content = '{"name":"missing-id"}'
    }
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'Azure returned an unexpected resource'
    $mockDeploymentEnvironment.ResourceResponseOverride = $null
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq 2) 'Authorization errors must never be treated as missing resources.'
    Assert-DeploymentFailure -Parameters ($resumeParameters + @{ ResourceGroupName = 'rg-conflicting' }) -ExpectedMessage 'differs from the checkpoint'
    $checkpointBeforePreview = Get-Content -LiteralPath $checkpointPath -Raw
    & $deploymentScript @resumeParameters -WhatIf | Out-Null
    Assert-Condition ((Get-Content -LiteralPath $checkpointPath -Raw) -eq $checkpointBeforePreview) 'WhatIf must not update the checkpoint.'

    # ForceRecreate is explicit, and even a failed Bicep call preserves discovered accounts.
    $mockDeploymentEnvironment.FailBicep = $true
    Assert-DeploymentFailure -Parameters ($initialParameters + @{ ForceRecreate = $true }) -ExpectedMessage 'Simulated Bicep failure'
    Assert-Condition ((Read-TestCheckpoint).resources.Contains($testStorageId)) 'Partial resources must survive in the checkpoint after failure.'
    Assert-Condition (-not (Read-TestCheckpoint).completedStages.Contains('AzureResourcesReady')) 'A failed resource deployment must not be checkpointed as complete.'
    $mockDeploymentEnvironment.FailBicep = $false
    & $deploymentScript @resumeParameters | Out-Null
    Assert-Condition ((Read-TestCheckpoint).deploymentCompleted) 'A failed Bicep deployment must be resumable.'
    & $deploymentScript @initialParameters -ForceRecreate -SkipGraphPermissionGrant | Out-Null
    Assert-Condition (-not (Read-TestCheckpoint).completedStages.Contains('GraphPermissionsGranted')) 'Skipped Graph permissions must remain incomplete.'
    & $deploymentScript @resumeParameters | Out-Null
    Assert-Condition ((Read-TestCheckpoint).completedStages.Contains('GraphPermissionsGranted')) 'A later resume must reconcile previously skipped permissions.'
    Set-Content -LiteralPath $checkpointPath -Value '{"version":1}'
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'Invalid deployment checkpoint'
    Set-Content -LiteralPath $checkpointPath -Value '{invalid-json'
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'Cannot read deployment checkpoint'
    Assert-Condition ((Get-Content -LiteralPath $checkpointPath -Raw).Trim() -eq '{invalid-json') 'An unreadable checkpoint must not be overwritten.'
    Remove-Item -LiteralPath $checkpointPath -Force
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'No deployment checkpoint exists'
    Assert-DeploymentFailure -Parameters @{ DeploymentStatePath = $checkpointPath } -ExpectedMessage 'are required when starting without a checkpoint'
    $mockDeploymentEnvironment.Resources.Clear()
    $mockDeploymentEnvironment.ResourceGroupExists = $false
    & $deploymentScript @initialParameters | Out-Null
    Assert-Condition ($mockDeploymentEnvironment.ResourceGroupExists -and (Read-TestCheckpoint).deploymentCompleted) 'A new resource group must still be deployable.'

    # An existing resource group without the storage account reports its tables as ParentResourceNotFound.
    $mockDeploymentEnvironment.Resources.Clear()
    $deploymentsBeforeExistingGroup = $mockDeploymentEnvironment.Deployments
    & $deploymentScript @initialParameters -ForceRecreate | Out-Null
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq $deploymentsBeforeExistingGroup + 1 -and
        (Read-TestCheckpoint).deploymentCompleted) 'An existing resource group without solution resources must be deployable.'

    # A Contributor cannot write role assignments: deploy the rest and print the manual steps, even if a later stage fails.
    $tableIdPrefix = "$testStorageId/tableServices/default/tables"
    $mockDeploymentEnvironment.Resources.Clear()
    $mockDeploymentEnvironment.DenyRoleAssignmentWrite = $true
    $mockDeploymentEnvironment.FailWeeklyRegistration = $true
    $deploymentsBeforeContributor = $mockDeploymentEnvironment.Deployments
    $contributorOutput = [Collections.Generic.List[string]]::new()
    $contributorFailure = $null
    try {
        & $deploymentScript @initialParameters -ForceRecreate 3>&1 | ForEach-Object { $contributorOutput.Add([string]$_) }
    } catch {
        $contributorFailure = $_
    }
    $contributorText = $contributorOutput -join "`n"
    $savedCheckpoint = Read-TestCheckpoint
    Assert-Condition ($null -ne $contributorFailure -and
        $contributorFailure.Exception.Message -like '*Simulated weekly registration failure*') 'A later stage failure must still fail the run.'
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq $deploymentsBeforeContributor + 2) 'Denied role assignments must trigger one deployment without them.'
    Assert-Condition ($savedCheckpoint.tableRoleAssignmentMode -eq 'Manual' -and $savedCheckpoint.roleAssignmentIds.Count -eq 0 -and
        $savedCheckpoint.completedStages.Contains('AzureResourcesReady')) 'The fallback deployment must be checkpointed in manual mode.'
    Assert-Condition ($contributorText.Contains('New-AzRoleAssignment') -and $contributorText.Contains($testPrincipalId) -and
        $contributorText.Contains("'$tableIdPrefix/PrimaryUserAudit'")) 'Manual steps must survive a later stage failure.'

    $mockDeploymentEnvironment.FailWeeklyRegistration = $false
    $contributorText = & $deploymentScript @resumeParameters 3>&1 | Out-String -Width 4096
    $savedCheckpoint = Read-TestCheckpoint
    Assert-Condition ($mockDeploymentEnvironment.Deployments -eq $deploymentsBeforeContributor + 2) 'Manual mode resumes must not redeploy verified resources.'
    Assert-Condition (-not $savedCheckpoint.deploymentCompleted -and
        $savedCheckpoint.completedStages.Contains('RepairPrimaryUser-WeeklyAnalysis')) 'All other stages must finish while role assignments are missing.'
    foreach ($tableName in @('PrimaryUserDaily', 'PrimaryUserState', 'PrimaryUserAudit')) {
        Assert-Condition ($contributorText.Contains("'$tableIdPrefix/$tableName'")) "Manual steps must list table $tableName."
    }
    Assert-Condition ($contributorText.Contains("-Resume -DeploymentStatePath '$checkpointPath'")) 'Manual steps must include the resume command.'

    # Wrong roles, sibling resources, and similar names do not satisfy table assignments.
    $mockDeploymentEnvironment.ManualRoleAssignments = @(
        @{ Scope = "$tableIdPrefix/PrimaryUserDaily"; RoleDefinitionId = $tableRoleDefinitionId }
        @{ Scope = "$tableIdPrefix/PrimaryUserState"; RoleDefinitionId = $readerRoleDefinitionId }
        @{ Scope = "$tableIdPrefix/PrimaryUserAuditArchive"; RoleDefinitionId = $tableRoleDefinitionId }
        @{ Scope = "${testStorageId}archive"; RoleDefinitionId = $tableRoleDefinitionId }
    )
    $contributorText = & $deploymentScript @resumeParameters 3>&1 | Out-String -Width 4096
    Assert-Condition (-not (Read-TestCheckpoint).deploymentCompleted) 'Partial manual role assignments must leave deployment incomplete.'
    Assert-Condition (-not $contributorText.Contains("'$tableIdPrefix/PrimaryUserDaily'") -and
        $contributorText.Contains("'$tableIdPrefix/PrimaryUserState'") -and
        $contributorText.Contains("'$tableIdPrefix/PrimaryUserAudit'")) 'Manual steps must list only uncovered tables.'

    # A storage account scope assignment covers all tables.
    $mockDeploymentEnvironment.ManualRoleAssignments = @(@{ Scope = $testStorageId; RoleDefinitionId = $tableRoleDefinitionId })
    & $deploymentScript @resumeParameters | Out-Null
    Assert-Condition ((Read-TestCheckpoint).deploymentCompleted -and
        $mockDeploymentEnvironment.Deployments -eq $deploymentsBeforeContributor + 2) 'Verified manual role assignments must complete the deployment.'

    # Assignments created manually under other names make template role assignments conflict.
    $mockDeploymentEnvironment.DenyRoleAssignmentWrite = $false
    $mockDeploymentEnvironment.RoleAssignmentExists = $true
    $deploymentsBeforeConflict = $mockDeploymentEnvironment.Deployments
    & $deploymentScript @initialParameters -ForceRecreate 3>$null | Out-Null
    $savedCheckpoint = Read-TestCheckpoint
    Assert-Condition ($savedCheckpoint.deploymentCompleted -and $savedCheckpoint.tableRoleAssignmentMode -eq 'Manual' -and
        $mockDeploymentEnvironment.Deployments -eq $deploymentsBeforeConflict + 2) 'Existing manual role assignments must be adopted.'
    $mockDeploymentEnvironment.RoleAssignmentExists = $false
    $mockDeploymentEnvironment.ManualRoleAssignments = @()

    $layoutDeploymentDirectory = Join-Path $layoutTestDirectory 'Deployment'
    $layoutRunbooksDirectory = Join-Path $layoutTestDirectory 'Runbooks'
    New-Item -Path @($layoutDeploymentDirectory, $layoutRunbooksDirectory) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $deploymentScript -Destination $layoutDeploymentDirectory
    Copy-Item -LiteralPath (Join-Path (Split-Path $deploymentScript -Parent) 'main.bicep') -Destination $layoutDeploymentDirectory
    $sourceSolutionRoot = Split-Path (Split-Path $deploymentScript -Parent) -Parent
    $runbookNames = @('Collect-PrimaryUserSignInData', 'Repair-PrimaryUserAssignments')
    foreach ($runbookName in $runbookNames) {
        $sourceRunbookPath = Join-Path $sourceSolutionRoot "Runbooks\$runbookName.ps1"
        Copy-Item -LiteralPath $sourceRunbookPath -Destination $layoutRunbooksDirectory
        Copy-Item -LiteralPath $sourceRunbookPath -Destination $layoutDeploymentDirectory
    }
    $deploymentScript = Join-Path $layoutDeploymentDirectory 'Deploy-RepairPrimaryUser.ps1'

    & $deploymentScript @initialParameters -ForceRecreate -SkipGraphPermissionGrant | Out-Null
    foreach ($runbookName in $runbookNames) {
        Assert-Condition ($mockDeploymentEnvironment.ImportedRunbookPaths[$runbookName] -eq
            (Join-Path $layoutRunbooksDirectory "$runbookName.ps1")) 'Parent Runbooks must take precedence over adjacent copies.'
    }

    $parentCollectorPath = Join-Path $layoutRunbooksDirectory 'Collect-PrimaryUserSignInData.ps1'
    $adjacentCollectorPath = Join-Path $layoutDeploymentDirectory 'Collect-PrimaryUserSignInData.ps1'
    Remove-Item -LiteralPath $parentCollectorPath -Force
    & $deploymentScript @initialParameters -ForceRecreate -SkipGraphPermissionGrant | Out-Null
    Assert-Condition ($mockDeploymentEnvironment.ImportedRunbookPaths['Collect-PrimaryUserSignInData'] -eq
        $adjacentCollectorPath) 'A missing parent collector must fall back to the adjacent file.'
    Assert-Condition ($mockDeploymentEnvironment.ImportedRunbookPaths['Repair-PrimaryUserAssignments'] -eq
        (Join-Path $layoutRunbooksDirectory 'Repair-PrimaryUserAssignments.ps1')) 'Each runbook must be resolved independently.'

    Remove-Item -LiteralPath (Join-Path $layoutRunbooksDirectory 'Repair-PrimaryUserAssignments.ps1') -Force
    & $deploymentScript @initialParameters -ForceRecreate -SkipGraphPermissionGrant | Out-Null
    foreach ($runbookName in $runbookNames) {
        Assert-Condition ($mockDeploymentEnvironment.ImportedRunbookPaths[$runbookName] -eq
            (Join-Path $layoutDeploymentDirectory "$runbookName.ps1")) 'Both runbooks must support deployment from the same folder.'
    }

    Remove-Item -LiteralPath $adjacentCollectorPath -Force
    $checkpointBeforeMissingRunbook = Get-Content -LiteralPath $checkpointPath -Raw
    $missingRunbookFailure = $null
    try {
        & $deploymentScript @initialParameters -ForceRecreate -SkipGraphPermissionGrant | Out-Null
    } catch {
        $missingRunbookFailure = $_
    }
    Assert-Condition ($null -ne $missingRunbookFailure) 'A runbook missing from both locations must stop deployment.'
    Assert-Condition ($missingRunbookFailure.Exception.Message.Contains($parentCollectorPath) -and
        $missingRunbookFailure.Exception.Message.Contains($adjacentCollectorPath)) 'Missing-runbook errors must identify both checked paths.'
    Assert-Condition ((Get-Content -LiteralPath $checkpointPath -Raw) -eq
        $checkpointBeforeMissingRunbook) 'Missing runbooks must fail before changing the deployment checkpoint.'

    $layoutTemplatePath = Join-Path $layoutDeploymentDirectory 'main.bicep'
    (Get-Content -LiteralPath $layoutTemplatePath -Raw) -replace '(?m)^param assignTableRoles bool = true\r?\n', '' |
        Set-Content -LiteralPath $layoutTemplatePath
    Assert-DeploymentFailure -Parameters $resumeParameters -ExpectedMessage 'is from an older version'
    Write-Output 'Deployment recovery tests passed.'
} finally {
    if (Test-Path -LiteralPath $checkpointPath) { Remove-Item -LiteralPath $checkpointPath -Force }
    if (Test-Path -LiteralPath $layoutTestDirectory) { Remove-Item -LiteralPath $layoutTestDirectory -Recurse -Force }
    if (Test-Path -LiteralPath $testDirectory) { Remove-Item -LiteralPath $testDirectory -Force }
}
