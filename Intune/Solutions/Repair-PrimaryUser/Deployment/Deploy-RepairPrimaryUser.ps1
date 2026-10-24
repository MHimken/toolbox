#Requires -Version 7.2
<#
.SYNOPSIS
    Deploys and schedules the Repair Primary User Azure Automation solution.
.DESCRIPTION
    Deploys the Azure foundation from Bicep, imports both PowerShell 7.2 runbooks, creates daily and
    weekly UTC schedules, and optionally grants the required Microsoft Graph application permissions
    to the Automation Account system-assigned managed identity. Saves configuration, resource IDs,
    and completed stages to a local JSON checkpoint so interrupted deployments can continue.
.PARAMETER DeploymentStatePath
    Checkpoint file path. Defaults to .repair-primary-user-deployment-state.json beside this script.
.PARAMETER Resume
    Approves continuing a saved deployment without the confirmation prompt. Saved configuration is
    restored; explicitly supplied configuration must match it.
.PARAMETER ForceRecreate
    Replaces the checkpoint using the supplied configuration and reconciles all deployment stages.
    Does not delete Azure resources. Supply all required initial-deployment parameters.
.PARAMETER InstallTemporaryBicep
    Approves downloading a temporary Microsoft-signed Bicep executable on Windows when Bicep is not
    available on PATH. Without this switch, the script asks before downloading it.
.NOTES
    Run this deployment script from PowerShell 7.2 or later on an administration workstation or Azure Cloud Shell.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [guid]$SubscriptionId,

    [guid]$TenantId,

    [ValidatePattern('^[a-zA-Z0-9._()-]{1,90}$')]
    [string]$ResourceGroupName,

    [string]$Location,

    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [ValidateLength(6, 50)]
    [string]$AutomationAccountName,

    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$CollectorStartTimeUtc = '03:00',

    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$AnalyzerStartTimeUtc = '05:00',

    [ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')]
    [string]$AnalyzerDayOfWeek = 'Sunday',

    [ValidateRange(1, 90)]
    [int]$DaysToAnalyze = 28,

    [ValidateRange(29, 365)]
    [int]$RetentionDays = 35,

    [switch]$InstallMissingModules,

    [switch]$InstallTemporaryBicep,

    [switch]$SkipGraphPermissionGrant,

    [string]$DeploymentStatePath = (Join-Path -Path $PSScriptRoot -ChildPath '.repair-primary-user-deployment-state.json'),

    [switch]$Resume,

    [switch]$ForceRecreate
)

Set-StrictMode -Version Latest
$script:OriginalErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
$script:OriginalPath = $env:PATH
$script:TemporaryBicepDirectory = $null

function Confirm-Action {
    param([Parameter(Mandatory = $true)][string]$Message)
    return (Read-Host "$Message Type YES to continue") -ceq 'YES'
}

function Initialize-DeploymentState {
    param([System.Collections.IDictionary]$DeploymentArguments)

    if ($Resume -and $ForceRecreate) { throw '-Resume and -ForceRecreate cannot be combined.' }
    $script:DeploymentState = $null
    if (-not $ForceRecreate -and (Test-Path -LiteralPath $DeploymentStatePath)) {
        try {
            $script:DeploymentState = Get-Content -LiteralPath $DeploymentStatePath -Raw -ErrorAction Stop |
                ConvertFrom-Json -AsHashtable -ErrorAction Stop
        } catch {
            throw "Cannot read deployment checkpoint '$DeploymentStatePath': $($_.Exception.Message)"
        }
        $savedState = $script:DeploymentState
        if ($savedState -isnot [System.Collections.IDictionary] -or
            -not $savedState.Contains('version') -or $savedState.version -ne 1 -or
            -not $savedState.Contains('configuration') -or
            $savedState.configuration -isnot [System.Collections.IDictionary] -or
            -not $savedState.Contains('completedStages') -or
            $savedState.completedStages -isnot [System.Collections.IDictionary] -or
            -not $savedState.Contains('resources') -or
            $savedState.resources -isnot [System.Collections.IDictionary] -or
            -not $savedState.Contains('automationResourceIds') -or
            $savedState.automationResourceIds -isnot [System.Collections.IDictionary] -or
            -not $savedState.Contains('roleAssignmentIds') -or
            -not $savedState.Contains('managedIdentityPrincipalId')) {
            throw "Invalid deployment checkpoint '$DeploymentStatePath'. Review it or use -ForceRecreate with complete parameters."
        }
    } elseif ($Resume) {
        throw "No deployment checkpoint exists at '$DeploymentStatePath'. Supply initial-deployment parameters."
    }

    $configurationNames = @(
        'SubscriptionId', 'TenantId', 'ResourceGroupName', 'Location', 'StorageAccountName',
        'AutomationAccountName', 'CollectorStartTimeUtc', 'AnalyzerStartTimeUtc',
        'AnalyzerDayOfWeek', 'DaysToAnalyze', 'RetentionDays'
    )
    if ($null -ne $script:DeploymentState) {
        foreach ($configurationName in $configurationNames) {
            if (-not $script:DeploymentState.configuration.Contains($configurationName)) {
                throw "The deployment checkpoint is missing configuration '$configurationName'."
            }
            $savedValue = $script:DeploymentState.configuration[$configurationName]
            if ($DeploymentArguments.ContainsKey($configurationName) -and
                [string]$DeploymentArguments[$configurationName] -ne [string]$savedValue) {
                throw "Parameter '$configurationName' differs from the checkpoint. Omit it to resume, or use -ForceRecreate with complete parameters to reconfigure."
            }
            Set-Variable -Name $configurationName -Value $savedValue -Scope Script -WhatIf:$false -Confirm:$false
        }
        if (-not $Resume -and -not $WhatIfPreference -and
            -not (Confirm-Action -Message "Continue the saved deployment for resource group '$ResourceGroupName'?")) {
            throw 'Resume was declined. No deployment changes were made.'
        }
        Write-Output "Loaded deployment checkpoint '$DeploymentStatePath'."
    }

    if ($SubscriptionId -eq [guid]::Empty -or [string]::IsNullOrWhiteSpace($ResourceGroupName) -or
        [string]::IsNullOrWhiteSpace($Location) -or [string]::IsNullOrWhiteSpace($StorageAccountName)) {
        throw 'SubscriptionId, ResourceGroupName, Location, and StorageAccountName are required when starting without a checkpoint.'
    }
    if ([string]::IsNullOrWhiteSpace($AutomationAccountName)) {
        $script:AutomationAccountName = "aa-rpu-$StorageAccountName"
    }
    $script:ResolvedAutomationAccountName = $AutomationAccountName
    if ($script:ResolvedAutomationAccountName.Length -gt 50) { throw 'The derived Automation Account name exceeds 50 characters.' }

    if ($null -eq $script:DeploymentState) {
        $configuration = @{}
        foreach ($configurationName in $configurationNames) {
            $configurationValue = Get-Variable -Name $configurationName -ValueOnly -Scope Script
            $configuration[$configurationName] = if ($configurationName -in @('DaysToAnalyze', 'RetentionDays')) {
                [int]$configurationValue
            } else {
                [string]$configurationValue
            }
        }
        $script:DeploymentState = @{
            version = 1
            configuration = $configuration
            completedStages = @{}
            resources = @{}
            automationResourceIds = @{}
            roleAssignmentIds = @()
            managedIdentityPrincipalId = ''
            deploymentCompleted = $false
        }
    }
}

function Write-DeploymentState {
    param([string]$Stage, [string]$Fingerprint = '1')

    if (-not [string]::IsNullOrWhiteSpace($Stage)) {
        $script:DeploymentState.completedStages[$Stage] = $Fingerprint
    }
    $script:DeploymentState.updatedAtUtc = [datetime]::UtcNow.ToString('o')
    $stateDirectory = Split-Path -Path $DeploymentStatePath -Parent
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        New-Item -Path $stateDirectory -ItemType Directory -ErrorAction Stop | Out-Null
    }
    $temporaryStatePath = "$DeploymentStatePath.$([guid]::NewGuid()).tmp"
    try {
        $script:DeploymentState | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $temporaryStatePath -Encoding utf8 -ErrorAction Stop
        [IO.File]::Move($temporaryStatePath, $DeploymentStatePath, $true)
    } finally {
        if (Test-Path -LiteralPath $temporaryStatePath) {
            Remove-Item -LiteralPath $temporaryStatePath -Force -ErrorAction Stop
        }
    }
}

function Test-DeploymentStageCompleted {
    param([string]$Stage, [string]$Fingerprint = '1')

    return $script:DeploymentState.completedStages.Contains($Stage) -and
        $script:DeploymentState.completedStages[$Stage] -eq $Fingerprint
}

function Start-DeploymentStage {
    param([string]$Stage)

    $script:DeploymentState.currentStage = $Stage
    $script:DeploymentState.deploymentCompleted = $false
    $script:DeploymentState.completedStages.Remove($Stage) | Out-Null
    Write-DeploymentState
}

function Test-AzureResourceNotFound {
    param([System.Management.Automation.ErrorRecord]$OperationError)

    $azureErrorCode = ''
    if ($null -ne $OperationError.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($OperationError.ErrorDetails.Message)) {
        try {
            $azureError = $OperationError.ErrorDetails.Message | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            if ($azureError -is [System.Collections.IDictionary] -and $azureError.Contains('error')) {
                $azureErrorCode = [string]$azureError.error.code
            }
        } catch {
            Write-Verbose 'The Azure error response did not contain a JSON error code.'
        }
    }
    return $azureErrorCode -in @('ResourceNotFound', 'ResourceGroupNotFound') -or
        $OperationError.FullyQualifiedErrorId -like '*ResourceNotFound*' -or
        $OperationError.FullyQualifiedErrorId -like '*ResourceGroupNotFound*'
}

function Get-DeploymentResource {
    param([string]$ResourceId)

    # Extension resources use the API version of their own provider, not the parent Storage provider.
    $resourceApiVersion = switch -Wildcard ($ResourceId) {
        '*/providers/Microsoft.Authorization/roleAssignments/*' { '2022-04-01'; break }
        '*/providers/Microsoft.Automation/automationAccounts/*' { '2023-11-01'; break }
        '*/providers/Microsoft.Storage/storageAccounts/*' { '2023-05-01'; break }
        default { throw "No deployment inventory API version is defined for resource '$ResourceId'." }
    }
    try {
        $response = Invoke-AzRestMethod -Path "$ResourceId`?api-version=$resourceApiVersion" -Method GET -ErrorAction Stop
        $resource = $response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        if ($resource -isnot [System.Collections.IDictionary] -or
            [string]$resource.id -ine $ResourceId) {
            throw "Azure returned an unexpected resource for '$ResourceId'."
        }
        return [pscustomobject]@{ ResourceId = [string]$resource.id }
    } catch {
        if (Test-AzureResourceNotFound -OperationError $_) { return $null }
        throw
    }
}

function Update-DeploymentResourceInventory {
    $resourceGroupId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
    $storageId = "$resourceGroupId/providers/Microsoft.Storage/storageAccounts/$StorageAccountName"
    $automationId = "$resourceGroupId/providers/Microsoft.Automation/automationAccounts/$script:ResolvedAutomationAccountName"
    $expectedIds = @($storageId, $automationId) + @(
        'PrimaryUserDaily', 'PrimaryUserState', 'PrimaryUserAudit' | ForEach-Object {
            "$storageId/tableServices/default/tables/$_"
        }
    )
    $allResourcesPresent = $true
    $resourceInventory = @{}
    foreach ($resourceId in ($expectedIds + @($script:DeploymentState.roleAssignmentIds))) {
        $azureResource = Get-DeploymentResource -ResourceId $resourceId
        if ($null -eq $azureResource) {
            $allResourcesPresent = $false
        } else {
            $resourceInventory[$resourceId] = [string]$azureResource.ResourceId
        }
    }
    $script:DeploymentState.resources = $resourceInventory
    $script:DeploymentState.resourceGroupId = $resourceGroupId
    if ($resourceInventory.Contains($automationId)) {
        $automationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
            -Name $script:ResolvedAutomationAccountName -ErrorAction Stop
        $currentPrincipalId = [string]$automationAccount.Identity.PrincipalId
        if ($currentPrincipalId -ne [string]$script:DeploymentState.managedIdentityPrincipalId) {
            $script:DeploymentState.completedStages.Remove('GraphPermissionsGranted') | Out-Null
            $script:DeploymentState.completedStages.Remove('AzureResourcesReady') | Out-Null
        }
        $script:DeploymentState.managedIdentityPrincipalId = $currentPrincipalId
        if ([string]::IsNullOrWhiteSpace($currentPrincipalId)) { $allResourcesPresent = $false }
    } else {
        $script:DeploymentState.managedIdentityPrincipalId = ''
    }
    return $allResourcesPresent -and @($script:DeploymentState.roleAssignmentIds).Count -eq 3
}

function Initialize-Bicep {
    if (Get-Command bicep -ErrorAction SilentlyContinue) {
        Write-Output 'Using the Bicep executable available on PATH.'
        return
    }
    if (-not $IsWindows) {
        throw 'Bicep is not available on PATH. Temporary Bicep installation is currently supported only on Windows.'
    }

    Write-Warning 'Bicep is required to deploy the Azure resource template.'
    Write-Warning 'The temporary installation is stored under the current user TEMP directory and does not normally require administrator rights.'
    if (-not $InstallTemporaryBicep -and -not (Confirm-Action -Message 'Download Microsoft Bicep temporarily for this deployment?')) {
        throw 'Bicep is required and the temporary download was declined.'
    }

    $script:TemporaryBicepDirectory = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "RepairPrimaryUser-Bicep-$([guid]::NewGuid())"
    $bicepPath = Join-Path -Path $script:TemporaryBicepDirectory -ChildPath 'bicep.exe'
    $downloadUri = 'https://github.com/Azure/bicep/releases/latest/download/bicep-win-x64.exe'
    Write-Output 'Downloading a temporary Bicep executable from the official Azure Bicep release.'
    New-Item -Path $script:TemporaryBicepDirectory -ItemType Directory -ErrorAction Stop | Out-Null
    Invoke-WebRequest -Uri $downloadUri -OutFile $bicepPath -ErrorAction Stop

    $signature = Get-AuthenticodeSignature -FilePath $bicepPath -ErrorAction Stop
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        [string]$signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
        throw 'The downloaded Bicep executable does not have a valid Microsoft Authenticode signature.'
    }

    $env:PATH = "$($script:TemporaryBicepDirectory)$([IO.Path]::PathSeparator)$env:PATH"
    $versionOutput = & $bicepPath --version
    if ($LASTEXITCODE -ne 0) {
        throw 'The temporary Bicep executable could not be started.'
    }
    Write-Output "Temporary $versionOutput is ready for this deployment."
}

function Remove-TemporaryBicep {
    if ([string]::IsNullOrWhiteSpace($script:TemporaryBicepDirectory)) { return }
    $env:PATH = $script:OriginalPath
    if (Test-Path -LiteralPath $script:TemporaryBicepDirectory) {
        try {
            Remove-Item -LiteralPath $script:TemporaryBicepDirectory -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Warning "Could not remove temporary Bicep directory '$script:TemporaryBicepDirectory': $($_.Exception.Message)"
        }
    }
}

function Import-DeploymentModules {
    $requiredModules = @('Az.Accounts', 'Az.Automation', 'Az.Resources', 'Microsoft.Graph.Authentication')
    $missing = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
    if ($missing.Count -gt 0) {
        if (-not $InstallMissingModules -and -not (Confirm-Action -Message "Install missing modules for the current user ($($missing -join ', '))?")) {
            throw "Missing modules: $($missing -join ', ')."
        }
        foreach ($moduleName in $missing) {
            Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        }
    }
    foreach ($moduleName in $requiredModules) { Import-Module -Name $moduleName -ErrorAction Stop }
}

function Connect-DeploymentAccounts {
    $parameters = @{ Subscription = $SubscriptionId; ErrorAction = 'Stop' }
    if ($TenantId -ne [guid]::Empty) { $parameters.Tenant = $TenantId }
    Connect-AzAccount @parameters | Out-Null
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    if (-not $SkipGraphPermissionGrant) {
        $graphParameters = @{
            Scopes = @('Application.Read.All', 'AppRoleAssignment.ReadWrite.All')
            NoWelcome = $true
            TenantId = [string](Get-AzContext -ErrorAction Stop).Tenant.Id
        }
        Connect-MgGraph @graphParameters | Out-Null
    }
}

function Get-NextUtcStartTime {
    param(
        [Parameter(Mandatory = $true)][string]$Time,
        [string]$DayOfWeek
    )

    $parts = $Time.Split(':')
    $candidate = [datetime]::UtcNow.Date.AddHours([int]$parts[0]).AddMinutes([int]$parts[1])
    if ([string]::IsNullOrWhiteSpace($DayOfWeek)) {
        if ($candidate -le [datetime]::UtcNow.AddMinutes(10)) { $candidate = $candidate.AddDays(1) }
    } else {
        while ([string]$candidate.DayOfWeek -ne $DayOfWeek -or $candidate -le [datetime]::UtcNow.AddMinutes(10)) {
            $candidate = $candidate.AddDays(1)
        }
    }
    return [datetimeoffset]::new($candidate, [timespan]::Zero)
}

function Grant-ManagedIdentityGraphPermissions {
    param([Parameter(Mandatory = $true)][guid]$ManagedIdentityPrincipalId)

    if ($SkipGraphPermissionGrant) { return }
    $graphApplicationId = '00000003-0000-0000-c000-000000000000'
    $response = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$graphApplicationId'&`$select=id,appRoles" -OutputType PSObject
    $graphServicePrincipal = @($response.value)[0]
    if ($null -eq $graphServicePrincipal) { throw 'The Microsoft Graph service principal could not be found.' }

    $identityAvailable = $false
    for ($attempt = 1; $attempt -le 6 -and -not $identityAvailable; $attempt++) {
        try {
            Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${ManagedIdentityPrincipalId}?`$select=id" -OutputType PSObject | Out-Null
            $identityAvailable = $true
        } catch {
            if ($attempt -eq 6) { throw }
            Start-Sleep -Seconds (5 * $attempt)
        }
    }

    $assignments = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityPrincipalId/appRoleAssignments?`$select=appRoleId,resourceId" -OutputType PSObject
    foreach ($permissionValue in @('AuditLog.Read.All', 'DeviceManagementManagedDevices.ReadWrite.All')) {
        $appRole = @($graphServicePrincipal.appRoles | Where-Object {
            $_.value -eq $permissionValue -and $_.isEnabled -and $_.allowedMemberTypes -contains 'Application'
        })[0]
        if ($null -eq $appRole) { throw "Microsoft Graph application permission '$permissionValue' could not be found." }

        $exists = @($assignments.value | Where-Object {
            [string]$_.appRoleId -eq [string]$appRole.id -and [string]$_.resourceId -eq [string]$graphServicePrincipal.id
        }).Count -gt 0
        if ($exists) {
            Write-Output "Microsoft Graph permission $permissionValue is already assigned."
            continue
        }

        $body = @{
            principalId = [string]$ManagedIdentityPrincipalId
            resourceId  = [string]$graphServicePrincipal.id
            appRoleId   = [string]$appRole.id
        } | ConvertTo-Json -Compress
        Invoke-MgGraphRequest -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityPrincipalId/appRoleAssignments" -Body $body -ContentType 'application/json' | Out-Null
        Write-Output "Granted Microsoft Graph permission $permissionValue."
    }
}

function Import-SolutionRunbook {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $script:ResolvedAutomationAccountName `
        -Name $Name -Path $Path -Type PowerShell72 -Published -Force -ErrorAction Stop | Out-Null
    Write-Output "Imported and published runbook $Name."
}

function Test-SolutionRunbookReady {
    param([string]$Name, [string]$Fingerprint)

    if (-not (Test-DeploymentStageCompleted -Stage $Name -Fingerprint $Fingerprint)) { return $false }
    $runbooks = @(Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName -ErrorAction Stop)
    return @($runbooks | Where-Object { $_.Name -eq $Name -and $_.State -eq 'Published' }).Count -eq 1
}

function Test-SolutionScheduleReady {
    param([string]$RunbookName, [string]$ScheduleName)

    if (-not (Test-DeploymentStageCompleted -Stage $ScheduleName)) { return $false }
    $schedules = @(Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName -ErrorAction Stop)
    $links = @(Get-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName -RunbookName $RunbookName -ErrorAction Stop)
    return @($schedules | Where-Object { $_.Name -eq $ScheduleName }).Count -eq 1 -and
        @($links | Where-Object { $_.ScheduleName -eq $ScheduleName }).Count -eq 1
}

function Set-RunbookSchedule {
    param(
        [Parameter(Mandatory = $true)][string]$RunbookName,
        [Parameter(Mandatory = $true)][string]$ScheduleName,
        [Parameter(Mandatory = $true)][datetimeoffset]$StartTime,
        [Parameter(Mandatory = $true)][ValidateSet('Daily', 'Weekly')][string]$Frequency,
        [hashtable]$Parameters,
        [string]$DayOfWeek
    )

    $existingLinks = @(Get-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName -RunbookName $RunbookName -ErrorAction Stop)
    foreach ($link in @($existingLinks | Where-Object { $_.ScheduleName -eq $ScheduleName })) {
        Unregister-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $script:ResolvedAutomationAccountName `
            -RunbookName $RunbookName -ScheduleName $ScheduleName -Force -ErrorAction Stop
    }

    $existingSchedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName -ErrorAction Stop |
        Where-Object { $_.Name -eq $ScheduleName }
    if ($null -ne $existingSchedule) {
        Remove-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $script:ResolvedAutomationAccountName `
            -Name $ScheduleName -Force -ErrorAction Stop
    }

    if ($Frequency -eq 'Daily') {
        New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $script:ResolvedAutomationAccountName `
            -Name $ScheduleName -StartTime $StartTime -DayInterval 1 -TimeZone 'Etc/UTC' -ErrorAction Stop | Out-Null
    } else {
        New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $script:ResolvedAutomationAccountName `
            -Name $ScheduleName -StartTime $StartTime -WeekInterval 1 -DaysOfWeek $DayOfWeek -TimeZone 'Etc/UTC' -ErrorAction Stop | Out-Null
    }

    Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $script:ResolvedAutomationAccountName `
        -RunbookName $RunbookName -ScheduleName $ScheduleName -Parameters $Parameters -ErrorAction Stop | Out-Null
    Write-Output "Configured $Frequency schedule $ScheduleName at $($StartTime.ToString('u'))."
}

try {
    $script:DeploymentStarted = $false
    $script:DeploymentStatePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DeploymentStatePath)
    Initialize-DeploymentState -DeploymentArguments $PSBoundParameters
    $script:SolutionRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:TemplatePath = Join-Path -Path $PSScriptRoot -ChildPath 'main.bicep'
    $collectorPath = Join-Path -Path $script:SolutionRoot -ChildPath 'Runbooks\Collect-PrimaryUserSignInData.ps1'
    $analyzerPath = Join-Path -Path $script:SolutionRoot -ChildPath 'Runbooks\Repair-PrimaryUserAssignments.ps1'
    foreach ($path in @($script:TemplatePath, $collectorPath, $analyzerPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required deployment file was not found: $path" }
    }
    $collectorTime = [timespan]::ParseExact($CollectorStartTimeUtc, 'hh\:mm', [Globalization.CultureInfo]::InvariantCulture)
    $analyzerTime = [timespan]::ParseExact($AnalyzerStartTimeUtc, 'hh\:mm', [Globalization.CultureInfo]::InvariantCulture)
    if ($analyzerTime -lt $collectorTime.Add([timespan]::FromHours(1))) {
        throw 'AnalyzerStartTimeUtc must be at least one hour after CollectorStartTimeUtc on the same UTC day.'
    }

    try {
        Import-DeploymentModules
        Connect-DeploymentAccounts
        if (-not $PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy Repair Primary User resources and schedules')) { return }
        $azureContext = Get-AzContext -ErrorAction Stop
        if ([string]$azureContext.Subscription.Id -ne [string]$SubscriptionId -or
            ($TenantId -ne [guid]::Empty -and [string]$azureContext.Tenant.Id -ne [string]$TenantId)) {
            throw 'The Azure context does not match the deployment subscription and tenant.'
        }
        $script:TenantId = [guid]$azureContext.Tenant.Id
        $script:DeploymentState.configuration.TenantId = [string]$TenantId
        $script:DeploymentState.deploymentCompleted = $false
        $script:DeploymentStarted = $true
        Write-DeploymentState

        $templateFingerprint = (Get-FileHash -LiteralPath $script:TemplatePath -Algorithm SHA256).Hash
        $resourcesReady = Update-DeploymentResourceInventory
        Write-DeploymentState
        if (-not $resourcesReady -or -not (Test-DeploymentStageCompleted -Stage 'AzureResourcesReady' -Fingerprint $templateFingerprint)) {
            Start-DeploymentStage -Stage 'AzureResourcesReady'
            Initialize-Bicep
            try {
                $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
            } catch {
                if (-not (Test-AzureResourceNotFound -OperationError $_)) { throw }
                $resourceGroup = $null
            }
            if ($null -eq $resourceGroup) {
                New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop | Out-Null
            }
            $deployment = New-AzResourceGroupDeployment -Name "RepairPrimaryUser-$([datetime]::UtcNow.ToString('yyyyMMddHHmmss'))" `
                -ResourceGroupName $ResourceGroupName -TemplateFile $script:TemplatePath -location $Location -Mode Incremental `
                -storageAccountName $StorageAccountName -automationAccountName $script:ResolvedAutomationAccountName -ErrorAction Stop
            if ($deployment.ProvisioningState -ne 'Succeeded') { throw "Azure deployment completed with state '$($deployment.ProvisioningState)'." }
            $script:DeploymentState.roleAssignmentIds = @($deployment.Outputs.tableRoleAssignmentIds.Value)
            if (-not (Update-DeploymentResourceInventory)) { throw 'Azure deployment completed, but the expected resources could not all be verified.' }
            Write-DeploymentState -Stage 'AzureResourcesReady' -Fingerprint $templateFingerprint
        } else {
            Write-Output 'Verified Azure resources; skipping Bicep deployment.'
        }

        $principalId = [guid]$script:DeploymentState.managedIdentityPrincipalId
        if (-not $SkipGraphPermissionGrant) {
            if (-not $PSCmdlet.ShouldProcess([string]$principalId, 'Grant required Microsoft Graph application permissions')) {
                throw 'Graph permission reconciliation was declined. Resume to finish, or use -SkipGraphPermissionGrant when granting permissions separately.'
            }
            Start-DeploymentStage -Stage 'GraphPermissionsGranted'
            Grant-ManagedIdentityGraphPermissions -ManagedIdentityPrincipalId $principalId
            Write-DeploymentState -Stage 'GraphPermissionsGranted'
        }
        $script:DeploymentState.graphPermissionGrantSkipped = [bool]$SkipGraphPermissionGrant
        $automationResourceId = "$($script:DeploymentState.resourceGroupId)/providers/Microsoft.Automation/automationAccounts/$script:ResolvedAutomationAccountName"

        foreach ($runbookDefinition in @(
            @{ Name = 'Collect-PrimaryUserSignInData'; Path = $collectorPath },
            @{ Name = 'Repair-PrimaryUserAssignments'; Path = $analyzerPath }
        )) {
            $runbookFingerprint = (Get-FileHash -LiteralPath $runbookDefinition.Path -Algorithm SHA256).Hash
            if (-not (Test-SolutionRunbookReady -Name $runbookDefinition.Name -Fingerprint $runbookFingerprint)) {
                Start-DeploymentStage -Stage $runbookDefinition.Name
                Import-SolutionRunbook -Name $runbookDefinition.Name -Path $runbookDefinition.Path
                $script:DeploymentState.automationResourceIds[$runbookDefinition.Name] = "$automationResourceId/runbooks/$($runbookDefinition.Name)"
                Write-DeploymentState -Stage $runbookDefinition.Name -Fingerprint $runbookFingerprint
            } else {
                Write-Output "Verified published runbook $($runbookDefinition.Name); skipping import."
            }
        }

        if (-not (Test-SolutionScheduleReady -RunbookName 'Collect-PrimaryUserSignInData' -ScheduleName 'RepairPrimaryUser-DailyCollection')) {
            Start-DeploymentStage -Stage 'RepairPrimaryUser-DailyCollection'
            Set-RunbookSchedule -RunbookName 'Collect-PrimaryUserSignInData' -ScheduleName 'RepairPrimaryUser-DailyCollection' `
                -StartTime (Get-NextUtcStartTime -Time $CollectorStartTimeUtc) -Frequency Daily `
                -Parameters @{ StorageAccountName = $StorageAccountName; RetentionDays = $RetentionDays }
            $script:DeploymentState.automationResourceIds['RepairPrimaryUser-DailyCollection'] = "$automationResourceId/schedules/RepairPrimaryUser-DailyCollection"
            Write-DeploymentState -Stage 'RepairPrimaryUser-DailyCollection'
        }
        if (-not (Test-SolutionScheduleReady -RunbookName 'Repair-PrimaryUserAssignments' -ScheduleName 'RepairPrimaryUser-WeeklyAnalysis')) {
            Start-DeploymentStage -Stage 'RepairPrimaryUser-WeeklyAnalysis'
            Set-RunbookSchedule -RunbookName 'Repair-PrimaryUserAssignments' -ScheduleName 'RepairPrimaryUser-WeeklyAnalysis' `
                -StartTime (Get-NextUtcStartTime -Time $AnalyzerStartTimeUtc -DayOfWeek $AnalyzerDayOfWeek) -Frequency Weekly `
                -DayOfWeek $AnalyzerDayOfWeek -Parameters @{ StorageAccountName = $StorageAccountName; DaysToAnalyze = $DaysToAnalyze }
            $script:DeploymentState.automationResourceIds['RepairPrimaryUser-WeeklyAnalysis'] = "$automationResourceId/schedules/RepairPrimaryUser-WeeklyAnalysis"
            Write-DeploymentState -Stage 'RepairPrimaryUser-WeeklyAnalysis'
        }

        $script:DeploymentState.currentStage = ''
        $script:DeploymentState.deploymentCompleted = $true
        Write-DeploymentState
        Write-Output "Deployment complete. Daily collection: $CollectorStartTimeUtc UTC. Weekly analysis: $AnalyzerDayOfWeek $AnalyzerStartTimeUtc UTC."
    } catch {
        if ($script:DeploymentStarted) {
            try {
                $script:DeploymentState.deploymentCompleted = $false
                Update-DeploymentResourceInventory | Out-Null
                Write-DeploymentState
            } catch {
                Write-Warning "Could not refresh the deployment checkpoint after failure: $($_.Exception.Message)"
            }
        }
        throw
    } finally {
        Remove-TemporaryBicep
        if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
} finally {
    $ErrorActionPreference = $script:OriginalErrorActionPreference
}