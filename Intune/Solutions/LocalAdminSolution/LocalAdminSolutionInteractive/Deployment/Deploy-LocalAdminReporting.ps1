<#
.SYNOPSIS
    Deploys the Azure resources used by the local administrator reporting solution.
.DESCRIPTION
    Deploys the Storage account, Azure Tables, Automation account, managed identity, and table-level
    role assignments from Bicep. The script imports and schedules the reconciliation runbook, grants
    Microsoft Graph application permissions to the managed identity, and creates separate endpoint
    and reporting account SAS tokens. Token values are never written to the deployment log. The user
    chooses the reporting frontend and whether tokens are saved to a protected text file, displayed
    once, or withheld. When Bicep is unavailable, the script can download a temporary Microsoft-signed
    executable for the current process and remove it when deployment finishes.
.PARAMETER SubscriptionId
    Azure subscription that receives the deployment.
.PARAMETER TenantId
    Optional Microsoft Entra tenant ID used for Azure and Microsoft Graph sign-in.
.PARAMETER ResourceGroupName
    Resource group that contains the solution resources.
.PARAMETER Location
    Azure region used when the resource group and resources are created.
.PARAMETER StorageAccountName
    Globally unique Storage account name. Use 3 to 24 lowercase letters and numbers.
.PARAMETER GovernanceStorageAccountName
    Globally unique Storage account name dedicated to allow rules, user settings, and review actions.
    When omitted, a name ending in gov is derived from StorageAccountName.
.PARAMETER AutomationAccountName
    Azure Automation account name. When omitted, a name is derived from the Storage account name.
.PARAMETER ReportingFrontend
    Reporting frontend to configure. LiveHtml is the default and enables Table CORS. GeneratedHtml
    and Excel disable Table CORS because they do not query Azure Storage from a browser.
.PARAMETER AllowedCorsOrigins
    Origins permitted to access Azure Table Storage when ReportingFrontend is LiveHtml. Defaults to
    * for directly opened HTML files. Specify the exact hosting origin whenever possible.
.PARAMETER GenerateConfigJson
    Writes a public, non-secret LiveHTML config.json. LiveHtml deployments generate it by default;
    this switch also permits explicit generation for another selected frontend.
.PARAMETER SkipConfigJson
    Prevents automatic config.json generation for LiveHtml.
.PARAMETER ConfigJsonPath
    Optional output path for the public config.json. Defaults to HTML\config.json.
.PARAMETER BffBaseUrl
    Existing HTTPS BFF URL or same-origin reverse-proxy path written to config.json when BackendMode is Existing.
.PARAMETER BackendMode
    None deploys no backend, Existing records BffBaseUrl, and AzureFunctions creates and publishes the BFF.
.PARAMETER FunctionAppName
    Globally unique Azure Function App name used when BackendMode is AzureFunctions.
.PARAMETER FunctionStorageAccountName
    Globally unique Storage account used internally by Azure Functions.
.PARAMETER AppRegistrationMode
    Create creates or reconciles dedicated API and SPA app registrations. Existing uses supplied IDs and scope.
.PARAMETER ApiClientId
    Existing API app registration client ID used as the BFF token audience.
.PARAMETER ConfigureApiAppRoles
    Explicit opt-in that adds or updates the four Admin-mode app roles (LocalAdmin.Governance.Read,
    LocalAdmin.Governance.Approve, LocalAdmin.Governance.SelfApprove, LocalAdmin.Actions.Operate) on the
    API app registration. Works with Create and Existing app registrations; unrelated roles are preserved.
.PARAMETER AdminAuthContextId
    Conditional Access authentication context ID (c1 to c99) the BFF requires for Admin mode. Defaults to c1.
.PARAMETER AdminSessionMaxMinutes
    Maximum Admin-mode lifetime after the step-up sign-in, from 5 to 240 minutes. Defaults to 30.
.PARAMETER SpaRedirectUri
    Exact HTTPS LiveHTML URL registered as the SPA redirect URI.
.PARAMETER ApiAppDisplayName
    Optional API app-registration display name. A name is derived from FunctionAppName when omitted.
.PARAMETER SpaAppDisplayName
    Optional SPA app-registration display name. A name is derived from FunctionAppName when omitted.
.PARAMETER BffAllowedOrigins
    Exact HTTPS origins allowed by the BFF. Defaults to the origin of SpaRedirectUri.
.PARAMETER SpaTenantId
    Optional Entra tenant ID used by the future SPA/BFF browser integration.
.PARAMETER SpaClientId
    Optional SPA application client ID written to config.json.
.PARAMETER BffApiScope
    Optional delegated BFF API scope written to config.json.
.PARAMETER LockHostConfig
    Locks host-configured Storage account name fields in the browser. Credentials remain user supplied.
.PARAMETER ScheduleIntervalHours
    Number of hours between reconciliation runbook executions. Defaults to four hours.
.PARAMETER EndpointSasValidityDays
    Validity period for the endpoint SAS with Table Object Read, Add, and Update permissions.
.PARAMETER ReportSasValidityDays
    Validity period for the reporting SAS with Table Object Read permission.
.PARAMETER TokenOutputMode
    Controls token delivery. Prompt asks interactively, File saves a protected text file, Console
    displays tokens after confirmation, and None creates no SAS tokens.
.PARAMETER TokenOutputPath
    Optional destination for File mode. When omitted, the user is prompted and offered a default.
.PARAMETER InstallMissingModules
    Installs missing required modules from PowerShell Gallery for the current user after confirmation.
.PARAMETER InstallTemporaryBicep
    Approves downloading Bicep temporarily when it is not available. Without this switch, the script
    requests confirmation. The temporary installation does not normally require administrator rights.
.PARAMETER SkipGraphPermissionGrant
    Skips granting the required user, group, Entra device, and Intune managed-device permissions to
    the Automation managed identity.
.PARAMETER UseExistingAzureContext
    Uses the current Az context when it is valid. Otherwise, the normal interactive Azure sign-in is started.
.PARAMETER ForceRecreate
    Ignores and replaces the persisted deployment checkpoint. Use this only when intentionally starting
    a fresh deployment or changing the recorded deployment configuration.
.PARAMETER RemoveDeployment
    Removes the Azure resources recorded in the persisted deployment checkpoint instead of deploying.
    Existing or previously reused app registrations are preserved. App registrations are removed only
    when the checkpoint explicitly records that this script created them.
.PARAMETER RemoveResourceGroup
    Removes the deployment resource group after tracked resources and deployment records are deleted.
    Azure may create the Application Insights Smart Detection action group automatically. When found,
    the script explains the resource and asks separately before removing it. The operation stops if
    any other untracked Azure resources remain in the resource group.
.PARAMETER ForceTokenOutput
    Confirms noninteractively that a protected plaintext SAS token file may be created.
.PARAMETER LogPath
    Directory in which the deployment log is created. Defaults to the current folder.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.NOTES
Version: 0.7
Author: Martin Himken
Original script name: Deploy-LocalAdminReporting.ps1
Initial creation date: 2026-09-06
Last change: 2026-10-09
Changes: ..\changelog.md
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

    [string]$GovernanceStorageAccountName,

    [string]$AutomationAccountName,

    [ValidateSet('LiveHtml', 'GeneratedHtml', 'Excel')]
    [string]$ReportingFrontend = 'LiveHtml',

    [string[]]$AllowedCorsOrigins = @(),

    [switch]$GenerateConfigJson,

    [switch]$SkipConfigJson,

    [string]$ConfigJsonPath,

    [ValidateSet('None', 'Existing', 'AzureFunctions')]
    [string]$BackendMode = 'None',

    [string]$BffBaseUrl,

    [string]$FunctionAppName,

    [string]$FunctionStorageAccountName,

    [ValidateSet('Create', 'Existing')]
    [string]$AppRegistrationMode = 'Create',

    [string]$ApiClientId,

    [string]$SpaTenantId,

    [string]$SpaClientId,

    [string]$BffApiScope,

    [string]$SpaRedirectUri,

    [string]$ApiAppDisplayName,

    [string]$SpaAppDisplayName,

    [string[]]$BffAllowedOrigins = @(),

    [switch]$ConfigureApiAppRoles,

    [ValidatePattern('^c([1-9]|[1-9][0-9])$')]
    [string]$AdminAuthContextId = 'c1',

    [ValidateRange(5, 240)]
    [int]$AdminSessionMaxMinutes = 30,

    [switch]$LockHostConfig,

    [ValidateRange(1, 168)]
    [int]$ScheduleIntervalHours = 4,

    [ValidateRange(1, 365)]
    [int]$EndpointSasValidityDays = 180,

    [ValidateRange(1, 365)]
    [int]$ReportSasValidityDays = 30,

    [ValidateSet('Prompt', 'File', 'Console', 'None')]
    [string]$TokenOutputMode = 'Prompt',

    [string]$TokenOutputPath,

    [switch]$InstallMissingModules,

    [switch]$InstallTemporaryBicep,

    [switch]$SkipGraphPermissionGrant,

    [switch]$UseExistingAzureContext,

    [switch]$ForceRecreate,

    [switch]$RemoveDeployment,

    [switch]$RemoveResourceGroup,

    [switch]$ForceTokenOutput,

    [string]$LogPath = (Get-Location).Path,

    [string]$LogFile = $null
)

$Pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $Pwsh7Path) {
    Write-Error 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error 'This script must run in PowerShell 7. Start the script with pwsh.exe.'
    exit 1
}

function Write-Log {
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')]
        [int]$Type
    )
    if ($Script:LogFile) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($Script:ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"" + $Time + "`" date=`"" + $Date + "`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            [IO.File]::AppendAllText($Script:LogFile, "$LogMessage$([Environment]::NewLine)", [Text.UTF8Encoding]::new($false))
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

function Test-OptionalGuid {
    param(
        [AllowEmptyString()]
        [string]$Value,
        [string]$ParameterName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $parsedGuid = [guid]::Empty
    if (-not [guid]::TryParse($Value, [ref] $parsedGuid)) {
        throw "$ParameterName must be a valid GUID when supplied."
    }

    return $parsedGuid
}

function Initialize-Script {
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'Deploy-LocalAdminReporting'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
    if (-not($LogFile)) {
        $script:ResolvedLogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    } else {
        $script:ResolvedLogFile = $LogFile
    }

    if (-not (Test-Path -LiteralPath $LogPath -PathType Container)) {
        [IO.Directory]::CreateDirectory($LogPath) | Out-Null
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $script:ResolvedLogFile
    $Script:ToConsole = $false
    $script:OriginalPath = $env:PATH
    $script:TemporaryBicepDirectory = $null
    $script:ConnectedGraphInThisRun = $false
    $script:ResumeFromState = $false
    $script:DeploymentState = $null
    $script:ApiAppRegistrationOwned = $false
    $script:SpaAppRegistrationOwned = $false
    $script:RemovalPerformed = $false

    $deploymentState = Get-DeploymentState
    if ($RemoveDeployment -and $ForceRecreate) {
        throw 'RemoveDeployment and ForceRecreate cannot be used together.'
    }
    if ($RemoveResourceGroup -and -not $RemoveDeployment) {
        throw 'RemoveResourceGroup requires RemoveDeployment.'
    }
    if ($RemoveDeployment -and $null -eq $deploymentState) {
        throw "RemoveDeployment requires the persisted deployment checkpoint at '$(Get-DeploymentStatePath)'."
    }
    if (($RemoveDeployment -or -not $ForceRecreate) -and $null -ne $deploymentState) {
        $script:DeploymentState = $deploymentState
        Use-DeploymentStateConfiguration -State $deploymentState
    }

    if ($SubscriptionId -eq [guid]::Empty) {
        throw 'SubscriptionId is required when no reusable deployment state exists.'
    }
    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        throw 'ResourceGroupName is required when no reusable deployment state exists.'
    }
    if ([string]::IsNullOrWhiteSpace($Location)) {
        throw 'Location is required when no reusable deployment state exists.'
    }
    if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
        throw 'StorageAccountName is required when no reusable deployment state exists.'
    }

    if ([string]::IsNullOrWhiteSpace($AutomationAccountName)) {
        $script:ResolvedAutomationAccountName = "AA-LAS-$StorageAccountName"
    } else {
        if ($AutomationAccountName.Length -lt 6 -or $AutomationAccountName.Length -gt 50) {
            throw 'AutomationAccountName must be 6 to 50 characters when supplied.'
        }
        $script:ResolvedAutomationAccountName = $AutomationAccountName
    }
    if ($script:ResolvedAutomationAccountName.Length -gt 50) {
        throw 'The derived Automation account name exceeds 50 characters. Pass AutomationAccountName explicitly.'
    }
    if ([string]::IsNullOrWhiteSpace($GovernanceStorageAccountName)) {
        $baseNameLength = [math]::Min(21, $StorageAccountName.Length)
        $script:ResolvedGovernanceStorageAccountName = '{0}gov' -f $StorageAccountName.Substring(0, $baseNameLength)
    } else {
        if ($GovernanceStorageAccountName -notmatch '^[a-z0-9]{3,24}$') {
            throw 'GovernanceStorageAccountName must be 3 to 24 lowercase letters and numbers when supplied.'
        }
        $script:ResolvedGovernanceStorageAccountName = $GovernanceStorageAccountName
    }
    if ($script:ResolvedGovernanceStorageAccountName -eq $StorageAccountName) {
        throw 'GovernanceStorageAccountName must differ from StorageAccountName.'
    }

    $script:ResolvedSpaTenantId = Test-OptionalGuid -Value $SpaTenantId -ParameterName 'SpaTenantId'
    $script:ResolvedSpaClientId = Test-OptionalGuid -Value $SpaClientId -ParameterName 'SpaClientId'
    $script:ResolvedApiClientId = Test-OptionalGuid -Value $ApiClientId -ParameterName 'ApiClientId'
    $script:ResolvedBffBaseUrl = [string]$BffBaseUrl
    $script:ResolvedBffApiScope = [string]$BffApiScope

    $script:SolutionRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:TemplatePath = Join-Path -Path $PSScriptRoot -ChildPath 'main.bicep'
    $script:RunbookPath = Join-Path -Path $script:SolutionRoot -ChildPath 'Runbooks\Resolve-LocalAdminLookupNames.ps1'
    $script:BackendPath = Join-Path -Path $script:SolutionRoot -ChildPath 'Backend'
    $script:RunbookName = 'rb-Resolve-LocalAdminLookupNames'
    $script:ScheduleName = 'rb-Resolve-LocalAdminLookupNames-Schedule'
    $script:ConfigJsonPath = if ([string]::IsNullOrWhiteSpace($ConfigJsonPath)) {
        Join-Path -Path (Join-Path -Path $script:SolutionRoot -ChildPath 'HTML') -ChildPath 'config.json'
    } else {
        $ConfigJsonPath
    }
    if (-not [string]::IsNullOrWhiteSpace($script:ResolvedBffBaseUrl) -and
        $script:ResolvedBffBaseUrl -notmatch '^https://[^/]+(?:/.*)?$' -and
        $script:ResolvedBffBaseUrl -notmatch '^/[A-Za-z0-9._~!$&''()*+,;=:@%/-]*$') {
        throw 'BffBaseUrl must be an HTTPS URL or a same-origin path beginning with /.'
    }
    if (-not [string]::IsNullOrWhiteSpace($script:ResolvedBffApiScope) -and $script:ResolvedBffApiScope -notmatch '^api://[^/\s]+/[A-Za-z0-9._-]+$') {
        throw 'BffApiScope must use the form api://<application-id-or-uri>/<scope-name>.'
    }
    if ($BackendMode -eq 'Existing' -and [string]::IsNullOrWhiteSpace($script:ResolvedBffBaseUrl)) {
        throw 'BffBaseUrl is required when BackendMode is Existing.'
    }
    if ($BackendMode -eq 'AzureFunctions') {
        if ($FunctionAppName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,58}[A-Za-z0-9]$') {
            throw 'FunctionAppName must contain 2 to 60 letters, numbers, or hyphens and cannot start or end with a hyphen.'
        }
        if ($FunctionStorageAccountName -notmatch '^[a-z0-9]{3,24}$') {
            throw 'FunctionStorageAccountName must contain 3 to 24 lowercase letters or numbers.'
        }
        if ($TenantId -eq [guid]::Empty) {
            throw 'TenantId is required when BackendMode is AzureFunctions.'
        }
        $redirect = $null
        if (-not [uri]::TryCreate($SpaRedirectUri, [UriKind]::Absolute, [ref]$redirect) -or $redirect.Scheme -ne 'https') {
            throw 'SpaRedirectUri must be an absolute HTTPS URL when BackendMode is AzureFunctions.'
        }
        $script:ResolvedSpaRedirectUri = $redirect.AbsoluteUri
        $script:ResolvedBffAllowedOrigins = if ($BffAllowedOrigins.Count -gt 0) {
            @($BffAllowedOrigins)
        } else {
            @($redirect.GetLeftPart([UriPartial]::Authority))
        }
        foreach ($origin in $script:ResolvedBffAllowedOrigins) {
            if ($origin -ne '*' -and $origin -notmatch '^https://[^/]+(?::\d+)?$') {
                throw "BffAllowedOrigins contains invalid origin '$origin'. Use exact HTTPS origins without paths, or an explicit *."
            }
        }
        $script:ResolvedApiAppDisplayName = if ([string]::IsNullOrWhiteSpace($ApiAppDisplayName)) { "$FunctionAppName API" } else { $ApiAppDisplayName }
        $script:ResolvedSpaAppDisplayName = if ([string]::IsNullOrWhiteSpace($SpaAppDisplayName)) { "$FunctionAppName SPA" } else { $SpaAppDisplayName }
        if ($AppRegistrationMode -eq 'Existing') {
            if (-not $script:ResolvedApiClientId -or -not $script:ResolvedSpaClientId -or [string]::IsNullOrWhiteSpace($script:ResolvedBffApiScope)) {
                throw 'ApiClientId, SpaClientId, and BffApiScope are required when AppRegistrationMode is Existing.'
            }
        }
    } else {
        $script:ResolvedSpaRedirectUri = ''
        $script:ResolvedBffAllowedOrigins = @()
    }
    if ($ReportingFrontend -eq 'LiveHtml') {
        $script:ResolvedAllowedCorsOrigins = if ($AllowedCorsOrigins.Count -eq 0) { @('*') } else { @($AllowedCorsOrigins) }
    } else {
        $script:ResolvedAllowedCorsOrigins = @()
    }

    if (-not $RemoveDeployment) {
        $requiredPaths = @($script:TemplatePath, $script:RunbookPath)
        if ($BackendMode -eq 'AzureFunctions') {
            $requiredPaths += @(
                (Join-Path -Path $script:BackendPath -ChildPath 'package.json'),
                (Join-Path -Path $script:BackendPath -ChildPath 'package-lock.json'),
                (Join-Path -Path $script:BackendPath -ChildPath 'host.json')
            )
        }
        foreach ($requiredPath in $requiredPaths) {
            if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
                throw "Required deployment file was not found: $requiredPath"
            }
        }
    }
}

function Confirm-Action {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    return (Read-Host "$Message Type YES to continue") -ceq 'YES'
}

function Get-DeploymentStatePath {
    return Join-Path -Path $PSScriptRoot -ChildPath '.localadmin-deployment-state.json'
}

function Get-DeploymentState {
    $statePath = Get-DeploymentStatePath
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        return $null
    }

    try {
        $state = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 10 -AsHashtable
        if ($null -ne $state -and $state.version -in @(1, 2, 3)) {
            if ($state.version -eq 1 -and -not $state.completedStages) {
                $state.completedStages = @([string]$state.lastSuccessfulStage)
            }
            return $state
        }
    } catch {
        Write-Log -Message "Ignoring an unreadable deployment state file at '$statePath'." -Component 'State' -Type 2
    }

    return $null
}

function Use-DeploymentStateConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State
    )

    $script:SubscriptionId = [guid]$State.subscriptionId
    $script:TenantId = if ([string]::IsNullOrWhiteSpace([string]$State.tenantId)) { [guid]::Empty } else { [guid]$State.tenantId }
    $script:ResourceGroupName = [string]$State.resourceGroupName
    $script:Location = [string]$State.location
    $script:StorageAccountName = [string]$State.storageAccountName
    $script:GovernanceStorageAccountName = [string]$State.governanceStorageAccountName
    $script:AutomationAccountName = [string]$State.automationAccountName
    $script:ReportingFrontend = if ($State.reportingFrontend) { [string]$State.reportingFrontend } else { 'LiveHtml' }
    $script:AllowedCorsOrigins = @($State.allowedCorsOrigins)
    $script:GenerateConfigJson = [bool]$State.generateConfigJson
    $script:SkipConfigJson = [bool]$State.skipConfigJson
    $script:BackendMode = if ($State.backendMode) { [string]$State.backendMode } else { 'None' }
    $script:BffBaseUrl = [string]$State.bffBaseUrl
    $script:FunctionAppName = [string]$State.functionAppName
    $script:FunctionStorageAccountName = [string]$State.functionStorageAccountName
    $script:AppRegistrationMode = if ($State.appRegistrationMode) { [string]$State.appRegistrationMode } else { 'Existing' }
    $script:ApiClientId = [string]$State.apiClientId
    $script:SpaTenantId = [string]$State.spaTenantId
    $script:SpaClientId = [string]$State.spaClientId
    $script:BffApiScope = [string]$State.bffApiScope
    $script:SpaRedirectUri = [string]$State.spaRedirectUri
    $script:ApiAppDisplayName = [string]$State.apiAppDisplayName
    $script:SpaAppDisplayName = [string]$State.spaAppDisplayName
    $script:BffAllowedOrigins = @($State.bffAllowedOrigins)
    $script:LockHostConfig = [bool]$State.lockHostConfig
    $script:ScheduleIntervalHours = if ($State.scheduleIntervalHours) { [int]$State.scheduleIntervalHours } else { 4 }
    $script:EndpointSasValidityDays = if ($State.endpointSasValidityDays) { [int]$State.endpointSasValidityDays } else { 180 }
    $script:ReportSasValidityDays = if ($State.reportSasValidityDays) { [int]$State.reportSasValidityDays } else { 30 }
    $script:TokenOutputMode = if ($State.tokenOutputMode) { [string]$State.tokenOutputMode } else { 'Prompt' }
    $script:TokenOutputPath = [string]$State.tokenOutputPath
    $script:SkipGraphPermissionGrant = [bool]$State.skipGraphPermissionGrant
    $script:ApiAppRegistrationOwned = [bool]$State.apiAppRegistrationOwned
    $script:SpaAppRegistrationOwned = [bool]$State.spaAppRegistrationOwned
    if (-not [string]::IsNullOrWhiteSpace([string]$State.configJsonPath)) {
        $script:ConfigJsonPath = [string]$State.configJsonPath
    }
}

function Test-DeploymentStageCompleted {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage
    )

    return $script:ResumeFromState -and
        $null -ne $script:DeploymentState -and
        @($script:DeploymentState.completedStages) -contains $Stage
}

function Test-DeploymentStateValidity {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State
    )

    if ($null -eq $State -or
        [string]::IsNullOrWhiteSpace([string]$State.subscriptionId) -or
        [string]::IsNullOrWhiteSpace([string]$State.resourceGroupName)) {
        return $false
    }

    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $currentContext -or [string]$currentContext.Subscription.Id -ne [string]$State.subscriptionId) {
        return $false
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$State.tenantId) -and
        [string]$currentContext.Tenant.Id -ne [string]$State.tenantId) {
        return $false
    }

    try {
        $resourceGroup = Get-AzResourceGroup -Name $State.resourceGroupName -ErrorAction Stop
        if ($null -eq $resourceGroup) {
            return $false
        }
    } catch {
        return $false
    }

    try {
        Get-AzStorageAccount -ResourceGroupName $State.resourceGroupName -Name $State.storageAccountName -ErrorAction Stop | Out-Null
        Get-AzStorageAccount -ResourceGroupName $State.resourceGroupName -Name $State.governanceStorageAccountName -ErrorAction Stop | Out-Null
        Get-AzAutomationAccount -ResourceGroupName $State.resourceGroupName -Name $State.automationAccountName -ErrorAction Stop | Out-Null
        if ([string]$State.backendMode -eq 'AzureFunctions') {
            Get-AzStorageAccount -ResourceGroupName $State.resourceGroupName -Name $State.functionStorageAccountName -ErrorAction Stop | Out-Null
            $functionApp = Get-AzWebApp -ResourceGroupName $State.resourceGroupName -Name $State.functionAppName -ErrorAction Stop
            if ([string]$functionApp.State -ne 'Running') {
                return $false
            }
        }
    } catch {
        return $false
    }

    return $true
}

function Write-DeploymentState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage
    )

    $completedStages = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $script:DeploymentState) {
        foreach ($completedStage in @($script:DeploymentState.completedStages)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$completedStage) -and -not $completedStages.Contains([string]$completedStage)) {
                $completedStages.Add([string]$completedStage)
            }
        }
    }
    if (-not $completedStages.Contains($Stage)) {
        $completedStages.Add($Stage)
    }

    $state = [ordered]@{
        version = 3
        updatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        subscriptionId = [string]$SubscriptionId
        tenantId = if ($TenantId -ne [guid]::Empty) { [string]$TenantId } else { '' }
        resourceGroupName = [string]$ResourceGroupName
        location = [string]$Location
        storageAccountName = [string]$StorageAccountName
        governanceStorageAccountName = [string]$script:ResolvedGovernanceStorageAccountName
        automationAccountName = [string]$script:ResolvedAutomationAccountName
        reportingFrontend = [string]$ReportingFrontend
        allowedCorsOrigins = @($script:ResolvedAllowedCorsOrigins)
        generateConfigJson = [bool]$GenerateConfigJson
        skipConfigJson = [bool]$SkipConfigJson
        backendMode = [string]$BackendMode
        functionAppName = if ($BackendMode -eq 'AzureFunctions') { [string]$FunctionAppName } else { '' }
        functionStorageAccountName = if ($BackendMode -eq 'AzureFunctions') { [string]$FunctionStorageAccountName } else { '' }
        appRegistrationMode = [string]$AppRegistrationMode
        apiAppDisplayName = if ($BackendMode -eq 'AzureFunctions') { [string]$script:ResolvedApiAppDisplayName } else { '' }
        spaAppDisplayName = if ($BackendMode -eq 'AzureFunctions') { [string]$script:ResolvedSpaAppDisplayName } else { '' }
        apiAppRegistrationOwned = [bool]$script:ApiAppRegistrationOwned
        spaAppRegistrationOwned = [bool]$script:SpaAppRegistrationOwned
        apiClientId = if ($script:ResolvedApiClientId) { $script:ResolvedApiClientId.ToString() } else { '' }
        spaTenantId = if ($script:ResolvedSpaTenantId) { $script:ResolvedSpaTenantId.ToString() } elseif ($TenantId -ne [guid]::Empty) { [string]$TenantId } else { '' }
        spaClientId = if ($script:ResolvedSpaClientId) { $script:ResolvedSpaClientId.ToString() } else { '' }
        bffApiScope = if ($script:ResolvedBffApiScope) { [string]$script:ResolvedBffApiScope } else { '' }
        bffBaseUrl = if ($script:ResolvedBffBaseUrl) { [string]$script:ResolvedBffBaseUrl } else { '' }
        spaRedirectUri = [string]$script:ResolvedSpaRedirectUri
        bffAllowedOrigins = @($script:ResolvedBffAllowedOrigins)
        lockHostConfig = [bool]$LockHostConfig
        scheduleIntervalHours = [int]$ScheduleIntervalHours
        endpointSasValidityDays = [int]$EndpointSasValidityDays
        reportSasValidityDays = [int]$ReportSasValidityDays
        tokenOutputMode = [string]$TokenOutputMode
        tokenOutputPath = [string]$TokenOutputPath
        skipGraphPermissionGrant = [bool]$SkipGraphPermissionGrant
        configJsonPath = [string]$script:ConfigJsonPath
        completedStages = @($completedStages)
        lastSuccessfulStage = $Stage
        deploymentCompleted = ($Stage -eq 'DeploymentComplete')
    }

    $path = Get-DeploymentStatePath
    $state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8 -Force -ErrorAction Stop
    $script:DeploymentState = $state
}

function Initialize-Bicep {
    if (Get-Command bicep -ErrorAction SilentlyContinue) {
        Write-Log -Message 'Using the Bicep executable available on PATH.' -Component 'Prerequisites' -Type 1
        return
    }

    if (-not $IsWindows) {
        throw 'Bicep is not available on PATH. Temporary Bicep installation is currently supported only on Windows.'
    }

    Write-Warning 'Bicep is required to deploy the Azure resource template.'
    Write-Warning 'The temporary installation is stored under the current user TEMP directory and does not normally require administrator rights.'
    $approved = $InstallTemporaryBicep -or (Confirm-Action -Message 'Download Microsoft Bicep temporarily for this deployment?')
    if (-not $approved) {
        throw 'Bicep is required and the temporary download was declined.'
    }

    $script:TemporaryBicepDirectory = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "LocalAdminReporting-Bicep-$([guid]::NewGuid())"
    $bicepPath = Join-Path -Path $script:TemporaryBicepDirectory -ChildPath 'bicep.exe'
    $downloadUri = 'https://github.com/Azure/bicep/releases/latest/download/bicep-win-x64.exe'

    Write-Log -Message 'Downloading a temporary Bicep executable from the official Azure Bicep release.' -Component 'Prerequisites' -Type 1
    $null = New-Item -Path $script:TemporaryBicepDirectory -ItemType Directory -Force
    Invoke-WebRequest -Uri $downloadUri -OutFile $bicepPath -UseBasicParsing -ErrorAction Stop

    $signature = Get-AuthenticodeSignature -FilePath $bicepPath
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        [string]$signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
        throw 'The downloaded Bicep executable does not have a valid Microsoft Authenticode signature.'
    }

    $env:PATH = "$($script:TemporaryBicepDirectory)$([IO.Path]::PathSeparator)$env:PATH"
    $bicepCommand = Get-Command bicep -ErrorAction Stop
    $versionOutput = & $bicepCommand.Source --version
    if ($LASTEXITCODE -ne 0) {
        throw 'The temporary Bicep executable could not be started.'
    }
    Write-Log -Message "Temporary $versionOutput is ready for this deployment." -Component 'Prerequisites' -Type 1
}

function Remove-TemporaryBicep {
    if ($null -ne (Get-Variable -Name OriginalPath -Scope Script -ErrorAction SilentlyContinue)) {
        $env:PATH = $script:OriginalPath
    }
    if ($null -ne (Get-Variable -Name TemporaryBicepDirectory -Scope Script -ErrorAction SilentlyContinue) -and
        -not [string]::IsNullOrWhiteSpace($script:TemporaryBicepDirectory) -and
        (Test-Path -LiteralPath $script:TemporaryBicepDirectory)) {
        Remove-Item -LiteralPath $script:TemporaryBicepDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Import-RequiredModules {
    $requiredModules = @(
        'Az.Accounts'
        'Az.Automation'
        'Az.Resources'
        'Az.Storage'
        'Microsoft.Graph.Authentication'
    )
    if ($BackendMode -eq 'AzureFunctions') {
        $requiredModules += 'Az.Websites'
    }

    $missingModules = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
    if ($missingModules.Count -gt 0) {
        Write-Log -Message ('Missing modules: {0}.' -f ($missingModules -join ', ')) -Component 'Prerequisites' -Type 2
        $approved = $InstallMissingModules -or (Confirm-Action -Message 'Install the missing modules from PowerShell Gallery for the current user?')
        if (-not $approved) {
            throw 'Required PowerShell modules are missing.'
        }
        foreach ($moduleName in $missingModules) {
            Write-Log -Message "Installing module $moduleName for the current user." -Component 'Prerequisites' -Type 1
            Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        }
    }

    foreach ($moduleName in $requiredModules) {
        Import-Module -Name $moduleName -ErrorAction Stop
    }
}

function Connect-DeploymentAccounts {
    $azureContextValid = $false
    if ($UseExistingAzureContext) {
        $currentContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($null -ne $currentContext) {
            if ([string]$currentContext.Subscription.Id -ne [string]$SubscriptionId) {
                Write-Log -Message 'The current Az context does not match SubscriptionId. Starting a fresh Azure sign-in.' -Component 'Authentication' -Type 2
            } elseif ($TenantId -ne [guid]::Empty -and [string]$currentContext.Tenant.Id -ne [string]$TenantId) {
                Write-Log -Message 'The current Az context does not match TenantId. Starting a fresh Azure sign-in.' -Component 'Authentication' -Type 2
            } else {
                try {
                    Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop | Out-Null
                    $azureContextValid = $true
                    Write-Log -Message 'Using the existing validated Azure context.' -Component 'Authentication' -Type 1
                } catch {
                    Write-Log -Message "The existing Azure context is no longer valid: $($_.Exception.Message). Starting a fresh Azure sign-in." -Component 'Authentication' -Type 2
                }
            }
        }
    }

    if (-not $azureContextValid) {
        $azureParameters = @{
            Subscription = $SubscriptionId
            ErrorAction  = 'Stop'
        }
        if ($TenantId -ne [guid]::Empty) {
            $azureParameters.Tenant = $TenantId
        }

        Write-Log -Message 'Starting interactive Azure sign-in.' -Component 'Authentication' -Type 1
        Connect-AzAccount @azureParameters | Out-Null
    }
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    $recordedStages = if ($null -ne $script:DeploymentState) { @($script:DeploymentState.completedStages) } else { @() }
    $requiresGraphRemoval = $RemoveDeployment -and
        ($script:ApiAppRegistrationOwned -or $script:SpaAppRegistrationOwned)
    $requiresGraph = $requiresGraphRemoval -or
        (-not $SkipGraphPermissionGrant -and $recordedStages -notcontains 'GraphPermissionsGranted') -or
        ($BackendMode -eq 'AzureFunctions' -and $ConfigureApiAppRoles) -or
        ($BackendMode -eq 'AzureFunctions' -and
            $AppRegistrationMode -eq 'Create' -and
            $recordedStages -notcontains 'AppRegistrationsReady')
    if ($requiresGraph) {
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -ne $graphContext) {
            $requiredScopes = @('Application.Read.All', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
            $missingScopes = @($requiredScopes | Where-Object { -not ($graphContext.Scopes -contains $_) })
            if ($missingScopes.Count -eq 0) {
                Write-Log -Message 'Using the existing Microsoft Graph context for managed identity permission assignment.' -Component 'Authentication' -Type 1
            } else {
                Write-Log -Message "The existing Graph context is missing scopes: $($missingScopes -join ', '). Starting interactive authentication." -Component 'Authentication' -Type 2
                $graphParameters = @{
                    Scopes       = $requiredScopes
                    NoWelcome    = $true
                    ContextScope = 'Process'
                }
                if ($TenantId -ne [guid]::Empty) {
                    $graphParameters.TenantId = [string]$TenantId
                }
                Connect-MgGraph @graphParameters | Out-Null
                $script:ConnectedGraphInThisRun = $true
            }
        } else {
            $graphParameters = @{
                Scopes       = @('Application.Read.All', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
                NoWelcome    = $true
                ContextScope = 'Process'
            }
            if ($TenantId -ne [guid]::Empty) {
                $graphParameters.TenantId = [string]$TenantId
            }
            Write-Log -Message 'Starting interactive Microsoft Graph sign-in for app registration and managed identity permission assignment.' -Component 'Authentication' -Type 1
            Connect-MgGraph @graphParameters | Out-Null
            $script:ConnectedGraphInThisRun = $true
        }
    }
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [string]$Body,
        [int]$MaximumAttempts = 6
    )

    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        try {
            $parameters = @{
                Method     = $Method
                Uri        = $Uri
                OutputType = 'PSObject'
                ErrorAction = 'Stop'
            }
            if (-not [string]::IsNullOrWhiteSpace($Body)) {
                $parameters.Body = $Body
                $parameters.ContentType = 'application/json'
            }
            return Invoke-MgGraphRequest @parameters
        } catch {
            if ($attempt -eq $MaximumAttempts) {
                throw
            }
            Start-Sleep -Seconds (3 * $attempt)
        }
    }
}

function Get-GraphErrorMessage {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $messages = @($ErrorRecord.Exception.Message)
    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        $messages += $ErrorRecord.ErrorDetails.Message
    }

    $response = $ErrorRecord.Exception.Response
    if ($null -ne $response -and $null -ne $response.Content) {
        try {
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                $messages += $responseBody
            }
        } catch {
            # Preserve the original Graph error when the response body is unavailable.
        }
    }

    return (@($messages | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique) -join ' ')
}

function Get-OrCreateApplicationRegistration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $escapedDisplayName = $DisplayName.Replace("'", "''")
    $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$escapedDisplayName'&`$select=id,appId,displayName,api,spa,requiredResourceAccess,identifierUris" -OutputType PSObject
    $applications = @($response.value)
    if ($applications.Count -gt 1) {
        throw "More than one app registration named '$DisplayName' exists. Use unique display names or clean up the duplicates."
    }
    if ($applications.Count -eq 1) {
        Write-Log -Message "Reusing app registration '$DisplayName'." -Component 'Entra' -Type 1
        return [pscustomobject]@{
            Application = $applications[0]
            Created = $false
        }
    }

    $body = @{
        displayName    = $DisplayName
        signInAudience = 'AzureADMyOrg'
    } | ConvertTo-Json -Depth 5 -Compress
    $created = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body $body -ContentType 'application/json' -OutputType PSObject
    Write-Log -Message "Created app registration '$DisplayName'." -Component 'Entra' -Type 1
    return [pscustomobject]@{
        Application = $created
        Created = $true
    }
}

function Ensure-ServicePrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ApplicationId
    )

    $response = Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$ApplicationId'&`$select=id,appId"
    if (@($response.value).Count -gt 0) {
        return
    }
    $body = @{ appId = $ApplicationId.ToString() } | ConvertTo-Json -Compress
    Invoke-GraphRequestWithRetry -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body $body | Out-Null
}

function Get-LocalAdminApiAppRoleDefinitions {
    @(
        @{ id = 'f305884c-354d-40af-9af6-6db7e366b98c'; value = 'LocalAdmin.Governance.Read'; displayName = 'Local admin governance reader'; description = 'Read organization governance rules and all review actions, and propose governance rules.' }
        @{ id = '723d4fca-2239-472f-a0ec-bb71067321ed'; value = 'LocalAdmin.Governance.Approve'; displayName = 'Local admin governance approver'; description = 'Approve, reject, and revoke governance rules in Admin mode. Own proposals require another approver.' }
        @{ id = '3d2751ed-c2c7-45de-87e6-8c7eaf000549'; value = 'LocalAdmin.Governance.SelfApprove'; displayName = 'Local admin governance self-approver'; description = 'Explicitly permits an approver to approve their own governance proposals. Intended for small tenants; every self-approval is audited.' }
        @{ id = 'ecf29a7f-d789-4931-a2e5-e2aabb4c3dfc'; value = 'LocalAdmin.Actions.Operate'; displayName = 'Local admin action operator'; description = 'Cancel review actions owned by other users in Admin mode.' }
    )
}

function Set-BffApiAppRoles {
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ApiClientId
    )

    $response = Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ApiClientId'&`$select=id,appId,appRoles"
    $application = @($response.value)[0]
    if ($null -eq $application) {
        throw "The API app registration '$ApiClientId' was not found or is not readable with the current Graph permissions."
    }
    $definitions = Get-LocalAdminApiAppRoleDefinitions
    $managedValues = @($definitions | ForEach-Object { $_.value })
    $existingRoles = @($application.appRoles)
    $preservedRoles = @($existingRoles | Where-Object { $managedValues -notcontains [string]$_.value })
    $managedRoles = foreach ($definition in $definitions) {
        $existing = @($existingRoles | Where-Object { [string]$_.value -eq $definition.value })[0]
        @{
            id                 = if ($null -ne $existing) { [string]$existing.id } else { $definition.id }
            value              = $definition.value
            displayName        = $definition.displayName
            description        = $definition.description
            allowedMemberTypes = @('User')
            isEnabled          = $true
        }
    }
    $body = @{ appRoles = @($preservedRoles) + @($managedRoles) } | ConvertTo-Json -Depth 10 -Compress
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($application.id)" -Body $body -ContentType 'application/json' | Out-Null
    } catch {
        throw "The Admin-mode app roles could not be configured on the API app registration. $(Get-GraphErrorMessage -ErrorRecord $_)"
    }
    Write-Log -Message "Configured Admin-mode app roles on API app registration '$ApiClientId': $($managedValues -join ', '). Assign them under Enterprise applications > Users and groups." -Component 'Entra' -Type 1
}

function Initialize-BffAppRegistrations {
    $spaApplicationResult = Get-OrCreateApplicationRegistration -DisplayName $script:ResolvedSpaAppDisplayName
    $apiApplicationResult = Get-OrCreateApplicationRegistration -DisplayName $script:ResolvedApiAppDisplayName
    $spaApplication = $spaApplicationResult.Application
    $apiApplication = $apiApplicationResult.Application
    $script:SpaAppRegistrationOwned = [bool]$spaApplicationResult.Created
    $script:ApiAppRegistrationOwned = [bool]$apiApplicationResult.Created
    $spaApplicationId = [guid]$spaApplication.appId
    $apiApplicationId = [guid]$apiApplication.appId

    $existingScopes = @($apiApplication.api.oauth2PermissionScopes)
    $profileScope = @($existingScopes | Where-Object { $_.value -eq 'access_as_user' })[0]
    $scopeId = if ($null -ne $profileScope) { [guid]$profileScope.id } else { [guid]::NewGuid() }
    $scope = @{
        id                      = $scopeId.ToString()
        adminConsentDescription = 'Allow the application to access the Local Administrator governance API on behalf of the signed-in user.'
        adminConsentDisplayName = 'Access Local Administrator governance API'
        isEnabled               = $true
        type                    = 'User'
        userConsentDescription = 'Allow this application to access your Local Administrator profile.'
        userConsentDisplayName = 'Access your Local Administrator profile'
        value                   = 'access_as_user'
    }
    $otherScopes = @($existingScopes | Where-Object { $_.value -ne 'access_as_user' })
    $existingPreauthorized = @($apiApplication.api.preAuthorizedApplications | Where-Object { [string]$_.appId -ne $spaApplicationId.ToString() })

    $scopeBody = @{
        identifierUris = @("api://$apiApplicationId")
        api = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes = @($otherScopes) + @($scope)
        }
    } | ConvertTo-Json -Depth 10 -Compress
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($apiApplication.id)" -Body $scopeBody -ContentType 'application/json' | Out-Null
    } catch {
        throw "The API app registration scope could not be configured. $(Get-GraphErrorMessage -ErrorRecord $_)"
    }
    Write-Log -Message 'Configured the API identifier URI and delegated access_as_user scope.' -Component 'Entra' -Type 1

    Ensure-ServicePrincipal -ApplicationId $apiApplicationId
    Ensure-ServicePrincipal -ApplicationId $spaApplicationId

    $preauthorizationBody = @{
        api = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes = @($otherScopes) + @($scope)
            preAuthorizedApplications = @($existingPreauthorized) + @(
                @{
                    appId = $spaApplicationId.ToString()
                    delegatedPermissionIds = @($scopeId.ToString())
                }
            )
        }
    } | ConvertTo-Json -Depth 10 -Compress
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($apiApplication.id)" -Body $preauthorizationBody -ContentType 'application/json' | Out-Null
    } catch {
        throw "The SPA could not be pre-authorized for the API scope. $(Get-GraphErrorMessage -ErrorRecord $_)"
    }
    Write-Log -Message 'Pre-authorized the SPA for the delegated API scope.' -Component 'Entra' -Type 1

    $existingRequiredAccess = @($spaApplication.requiredResourceAccess | Where-Object { [string]$_.resourceAppId -ne $apiApplicationId.ToString() })
    $existingRedirectUris = @($spaApplication.spa.redirectUris)
    $spaBody = @{
        spa = @{
            redirectUris = @($existingRedirectUris + $script:ResolvedSpaRedirectUri | Select-Object -Unique)
        }
        requiredResourceAccess = @($existingRequiredAccess) + @(
            @{
                resourceAppId = $apiApplicationId.ToString()
                resourceAccess = @(
                    @{
                        id = $scopeId.ToString()
                        type = 'Scope'
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 10 -Compress
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($spaApplication.id)" -Body $spaBody -ContentType 'application/json' | Out-Null
    } catch {
        throw "The SPA redirect URI or required API access could not be configured. $(Get-GraphErrorMessage -ErrorRecord $_)"
    }

    $script:ResolvedApiClientId = $apiApplicationId
    $script:ResolvedSpaClientId = $spaApplicationId
    $script:ResolvedSpaTenantId = $TenantId
    $script:ResolvedBffApiScope = "api://$apiApplicationId/access_as_user"
    Write-Log -Message 'Configured the API and SPA app registrations without client secrets.' -Component 'Entra' -Type 1
}

function Remove-OwnedApplicationRegistration {
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ApplicationId,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $servicePrincipalResponse = Invoke-MgGraphRequest `
        -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$ApplicationId'&`$select=id" `
        -OutputType PSObject
    foreach ($servicePrincipal in @($servicePrincipalResponse.value)) {
        Invoke-GraphRequestWithRetry `
            -Method DELETE `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)" | Out-Null
    }

    $applicationResponse = Invoke-MgGraphRequest `
        -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ApplicationId'&`$select=id,displayName" `
        -OutputType PSObject
    foreach ($application in @($applicationResponse.value)) {
        Invoke-GraphRequestWithRetry `
            -Method DELETE `
            -Uri "https://graph.microsoft.com/v1.0/applications/$($application.id)" | Out-Null
    }
    Write-Log -Message "Removed script-owned $Description app registration '$ApplicationId' and its service principal." -Component 'Removal' -Type 1
}

function Remove-TrackedAzureResource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$ResourceType
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return
    }
    $resource = Get-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -Name $Name `
        -ResourceType $ResourceType `
        -ErrorAction SilentlyContinue
    if ($null -eq $resource) {
        Write-Log -Message "Tracked resource '$Name' of type '$ResourceType' is already absent." -Component 'Removal' -Type 2
        return
    }
    Remove-AzResource -ResourceId $resource.ResourceId -Force -ErrorAction Stop | Out-Null
    Write-Log -Message "Removed tracked resource '$Name' of type '$ResourceType'." -Component 'Removal' -Type 1
}

function Get-DeploymentRemovalPlan {
    $plan = [System.Collections.Generic.List[string]]::new()
    $plan.Add("Azure resource group: $ResourceGroupName (retain unless -RemoveResourceGroup is specified)")
    $plan.Add("Azure Storage account: $StorageAccountName (including inventory tables and data)")
    $plan.Add("Azure Storage account: $($script:ResolvedGovernanceStorageAccountName) (including governance tables and data)")
    $plan.Add("Azure Automation account: $($script:ResolvedAutomationAccountName) (including runbook, schedule, jobs, and managed identity)")

    if ($BackendMode -eq 'AzureFunctions') {
        $plan.Add("Azure Function App: $FunctionAppName (including its managed identity)")
        $plan.Add("Azure Function plan: $FunctionAppName-plan")
        $plan.Add("Application Insights: $FunctionAppName-ai")
        $plan.Add("Function host Storage account: $FunctionStorageAccountName (including package container and packages)")
    }

    if ($script:ApiAppRegistrationOwned -and $script:ResolvedApiClientId) {
        $plan.Add("Microsoft Entra API app registration and service principal: $($script:ResolvedApiClientId)")
    } elseif ($script:ResolvedApiClientId) {
        $plan.Add("Preserve Microsoft Entra API app registration: $($script:ResolvedApiClientId)")
    }
    if ($script:SpaAppRegistrationOwned -and $script:ResolvedSpaClientId) {
        $plan.Add("Microsoft Entra SPA app registration and service principal: $($script:ResolvedSpaClientId)")
    } elseif ($script:ResolvedSpaClientId) {
        $plan.Add("Preserve Microsoft Entra SPA app registration: $($script:ResolvedSpaClientId)")
    }

    $plan.Add('Resource-group deployment records named LocalAdminReporting-*')
    if ($RemoveResourceGroup) {
        if ($BackendMode -eq 'AzureFunctions') {
            $plan.Add('Azure-created Application Insights Smart Detection action group, if present (separate confirmation required)')
        }
        $plan.Add("Azure resource group deletion: $ResourceGroupName (only if no other untracked resources remain)")
    }
    if (-not [string]::IsNullOrWhiteSpace($script:ConfigJsonPath)) {
        $plan.Add("Local generated configuration: $($script:ConfigJsonPath)")
    }
    $plan.Add("Local deployment checkpoint: $(Get-DeploymentStatePath)")
    return @($plan)
}

function Remove-SolutionDeployment {
    $summary = "resource group '$ResourceGroupName' in subscription '$SubscriptionId'"
    $plan = @(Get-DeploymentRemovalPlan)
    Write-Output 'Removal plan:'
    Write-Log -Message "Removal plan for $summary." -Component 'RemovalPlan' -Type 1
    foreach ($item in $plan) {
        Write-Output " - $item"
        Write-Log -Message $item -Component 'RemovalPlan' -Type 1
    }
    Write-Output ''
    Write-Log -Message 'Storage account removal permanently deletes the contained tables and data.' -Component 'RemovalPlan' -Type 2

    if (-not $WhatIfPreference -and
        -not (Confirm-Action -Message "Permanently remove the tracked local administrator reporting resources from $summary?")) {
        throw 'Deployment removal was declined.'
    }
    if (-not $PSCmdlet.ShouldProcess($summary, 'Permanently remove the tracked local administrator reporting deployment')) {
        Write-Log -Message 'Deployment removal was not performed.' -Component 'Removal' -Type 2
        return
    }

    if ($script:SpaAppRegistrationOwned -and $script:ResolvedSpaClientId) {
        Remove-OwnedApplicationRegistration -ApplicationId $script:ResolvedSpaClientId -Description 'SPA'
    } elseif ($script:ResolvedSpaClientId) {
        Write-Log -Message "Preserving SPA app registration '$($script:ResolvedSpaClientId)' because the checkpoint does not record script ownership." -Component 'Removal' -Type 1
    }
    if ($script:ApiAppRegistrationOwned -and $script:ResolvedApiClientId) {
        Remove-OwnedApplicationRegistration -ApplicationId $script:ResolvedApiClientId -Description 'API'
    } elseif ($script:ResolvedApiClientId) {
        Write-Log -Message "Preserving API app registration '$($script:ResolvedApiClientId)' because the checkpoint does not record script ownership." -Component 'Removal' -Type 1
    }

    if ($BackendMode -eq 'AzureFunctions') {
        Remove-TrackedAzureResource -Name $FunctionAppName -ResourceType 'Microsoft.Web/sites'
        Remove-TrackedAzureResource -Name "$FunctionAppName-plan" -ResourceType 'Microsoft.Web/serverfarms'
        Remove-TrackedAzureResource -Name "$FunctionAppName-ai" -ResourceType 'Microsoft.Insights/components'
        Remove-TrackedAzureResource -Name $FunctionStorageAccountName -ResourceType 'Microsoft.Storage/storageAccounts'
    }
    Remove-TrackedAzureResource -Name $script:ResolvedAutomationAccountName -ResourceType 'Microsoft.Automation/automationAccounts'
    Remove-TrackedAzureResource -Name $script:ResolvedGovernanceStorageAccountName -ResourceType 'Microsoft.Storage/storageAccounts'
    Remove-TrackedAzureResource -Name $StorageAccountName -ResourceType 'Microsoft.Storage/storageAccounts'

    $deployments = @(Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue |
        Where-Object { $_.DeploymentName -like 'LocalAdminReporting-*' })
    foreach ($deployment in $deployments) {
        Remove-AzResourceGroupDeployment `
            -ResourceGroupName $ResourceGroupName `
            -Name $deployment.DeploymentName `
            -ErrorAction Stop | Out-Null
        Write-Log -Message "Removed deployment record '$($deployment.DeploymentName)'." -Component 'Removal' -Type 1
    }

    if ($RemoveResourceGroup) {
        $remainingResources = @(Get-AzResource -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
        $smartDetectionActionGroups = @($remainingResources | Where-Object {
                $_.ResourceType -ieq 'microsoft.insights/actiongroups' -and
                $_.Name -ieq 'Application Insights Smart Detection'
            })
        foreach ($actionGroup in $smartDetectionActionGroups) {
            $actionGroupMessage = "Azure automatically creates the action group '$($actionGroup.Name)' with Application Insights. It is not tracked by the deployment template and may be shared. Removing it is required before the resource group can be deleted."
            Write-Output $actionGroupMessage
            Write-Log -Message $actionGroupMessage -Component 'Removal' -Type 2
            if (-not (Confirm-Action -Message "Remove Azure-created action group '$($actionGroup.Name)' from resource group '$ResourceGroupName'?")) {
                throw "The resource group was not removed because deletion of Azure-created action group '$($actionGroup.Name)' was declined."
            }
            Remove-AzResource -ResourceId $actionGroup.ResourceId -Force -ErrorAction Stop | Out-Null
            Write-Log -Message "Removed Azure-created Application Insights action group '$($actionGroup.Name)'." -Component 'Removal' -Type 1
        }

        $remainingResources = @(Get-AzResource -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
        if ($remainingResources.Count -gt 0) {
            $remainingSummary = @($remainingResources | ForEach-Object { "$($_.ResourceType)/$($_.Name)" }) -join ', '
            throw "The resource group was not removed because untracked resources remain: $remainingSummary"
        }
        Remove-AzResourceGroup -Name $ResourceGroupName -Force -ErrorAction Stop | Out-Null
        Write-Log -Message "Removed empty resource group '$ResourceGroupName'." -Component 'Removal' -Type 1
    }

    if (-not [string]::IsNullOrWhiteSpace($script:ConfigJsonPath) -and
        (Test-Path -LiteralPath $script:ConfigJsonPath -PathType Leaf)) {
        Remove-Item -LiteralPath $script:ConfigJsonPath -Force -ErrorAction Stop
        Write-Log -Message "Removed generated host configuration '$($script:ConfigJsonPath)'." -Component 'Removal' -Type 1
    }
    Remove-Item -LiteralPath (Get-DeploymentStatePath) -Force -ErrorAction Stop
    Write-Log -Message 'Removed the local deployment checkpoint after successful teardown.' -Component 'Removal' -Type 1
    $script:RemovalPerformed = $true
}

function Invoke-SolutionResourceDeployment {
    $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if ($null -eq $resourceGroup) {
        Write-Log -Message "Creating resource group $ResourceGroupName in $Location." -Component 'Azure' -Type 1
        $resourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
    }

    if ($ReportingFrontend -eq 'LiveHtml') {
        Write-Log -Message "Configuring Table CORS for the Live HTML frontend with origins: $($script:ResolvedAllowedCorsOrigins -join ', ')." -Component 'Azure' -Type 1
    } else {
        Write-Log -Message "Disabling Table CORS for the $ReportingFrontend frontend." -Component 'Azure' -Type 1
    }
    Write-Log -Message 'Deploying the Bicep resource foundation.' -Component 'Azure' -Type 1
    $deployBff = $BackendMode -eq 'AzureFunctions'
    $deployment = New-AzResourceGroupDeployment `
        -Name "LocalAdminReporting-$($script:DateTime)" `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile $script:TemplatePath `
        -location $Location `
        -storageAccountName $StorageAccountName `
        -governanceStorageAccountName $script:ResolvedGovernanceStorageAccountName `
        -automationAccountName $script:ResolvedAutomationAccountName `
        -allowedCorsOrigins $script:ResolvedAllowedCorsOrigins `
        -deployBff $deployBff `
        -functionAppName $(if ($deployBff) { $FunctionAppName } else { '' }) `
        -functionStorageAccountName $(if ($deployBff) { $FunctionStorageAccountName } else { '' }) `
        -tenantId $(if ($deployBff) { $TenantId.ToString() } else { '' }) `
        -apiClientId $(if ($deployBff) { $script:ResolvedApiClientId.ToString() } else { '' }) `
        -bffAllowedOrigins $(if ($deployBff) { $script:ResolvedBffAllowedOrigins } else { @() }) `
        -adminAuthContextId $AdminAuthContextId `
        -adminSessionMaxMinutes $AdminSessionMaxMinutes `
        -ErrorAction Stop

    if ($deployment.ProvisioningState -ne 'Succeeded') {
        throw "Azure deployment completed with state '$($deployment.ProvisioningState)'."
    }
    Write-Log -Message 'Azure resource deployment completed successfully.' -Component 'Azure' -Type 1
    if ($deployBff) {
        $script:ResolvedBffBaseUrl = [string]$deployment.Outputs.bffBaseUrl.Value
    }
    return $deployment
}

function Invoke-ManagedIdentityGraphPermissionGrant {
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ManagedIdentityPrincipalId
    )

    if ($SkipGraphPermissionGrant) {
        Write-Log -Message 'Microsoft Graph permission assignment was skipped by parameter.' -Component 'Graph' -Type 2
        return
    }

    $graphApplicationId = '00000003-0000-0000-c000-000000000000'
    $graphResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$graphApplicationId'&`$select=id,appRoles" -OutputType PSObject
    $graphServicePrincipal = @($graphResponse.value)[0]
    if ($null -eq $graphServicePrincipal) {
        throw 'The Microsoft Graph service principal could not be found.'
    }

    $identityAvailable = $false
    for ($attempt = 1; $attempt -le 6 -and -not $identityAvailable; $attempt++) {
        try {
            Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${ManagedIdentityPrincipalId}?`$select=id" -OutputType PSObject | Out-Null
            $identityAvailable = $true
        } catch {
            if ($attempt -eq 6) {
                throw
            }
            Start-Sleep -Seconds (5 * $attempt)
        }
    }

    $assignmentResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityPrincipalId/appRoleAssignments?`$select=appRoleId,resourceId" -OutputType PSObject
    $existingAssignments = @($assignmentResponse.value)

    foreach ($permissionValue in @('User.Read.All', 'Group.Read.All', 'Device.Read.All', 'DeviceManagementManagedDevices.Read.All')) {
        $appRole = @($graphServicePrincipal.appRoles | Where-Object {
            $_.value -eq $permissionValue -and $_.isEnabled -and $_.allowedMemberTypes -contains 'Application'
        })[0]
        if ($null -eq $appRole) {
            throw "Microsoft Graph application permission '$permissionValue' could not be found."
        }

        $alreadyAssigned = @($existingAssignments | Where-Object {
            [string]$_.appRoleId -eq [string]$appRole.id -and [string]$_.resourceId -eq [string]$graphServicePrincipal.id
        }).Count -gt 0
        if ($alreadyAssigned) {
            Write-Log -Message "Microsoft Graph permission $permissionValue is already assigned." -Component 'Graph' -Type 1
            continue
        }

        $body = @{
            principalId = [string]$ManagedIdentityPrincipalId
            resourceId  = [string]$graphServicePrincipal.id
            appRoleId   = [string]$appRole.id
        } | ConvertTo-Json -Compress
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityPrincipalId/appRoleAssignments" -Body $body -ContentType 'application/json' | Out-Null
        Write-Log -Message "Granted Microsoft Graph permission $permissionValue." -Component 'Graph' -Type 1
    }
}

function Get-AutomationManagedIdentityPrincipalId {
    $automationAccount = Get-AzAutomationAccount `
        -ResourceGroupName $ResourceGroupName `
        -Name $script:ResolvedAutomationAccountName `
        -ErrorAction Stop
    $principalId = [string]$automationAccount.Identity.PrincipalId
    if ([string]::IsNullOrWhiteSpace($principalId)) {
        throw "Automation account '$($script:ResolvedAutomationAccountName)' does not expose a system-assigned managed identity."
    }
    return [guid]$principalId
}

function Import-ReconciliationRunbook {
    Write-Log -Message 'Importing and publishing the reconciliation runbook.' -Component 'Automation' -Type 1
    Import-AzAutomationRunbook `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName `
        -Name $script:RunbookName `
        -Path $script:RunbookPath `
        -Type PowerShell72 `
        -Published `
        -Force `
        -ErrorAction Stop | Out-Null

    $schedule = Get-AzAutomationSchedule `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName `
        -Name $script:ScheduleName `
        -ErrorAction SilentlyContinue
    if ($null -eq $schedule) {
        $schedule = New-AzAutomationSchedule `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $script:ResolvedAutomationAccountName `
            -Name $script:ScheduleName `
            -StartTime ([datetime]::Now.AddMinutes(10)) `
            -HourInterval $ScheduleIntervalHours `
            -ErrorAction Stop
        Write-Log -Message "Created an Automation schedule with a $ScheduleIntervalHours hour interval." -Component 'Automation' -Type 1
    } elseif ([int]$schedule.Interval -ne $ScheduleIntervalHours -or [string]$schedule.Frequency -ne 'Hour') {
        throw "Schedule '$($script:ScheduleName)' exists with a different frequency. Remove it or select its configured interval before redeployment."
    }

    $scheduledRunbooks = @(Get-AzAutomationScheduledRunbook `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName `
        -RunbookName $script:RunbookName `
        -ErrorAction SilentlyContinue)
    $isRegistered = @($scheduledRunbooks | Where-Object { $_.ScheduleName -eq $script:ScheduleName }).Count -gt 0
    if ($isRegistered) {
        Unregister-AzAutomationScheduledRunbook `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $script:ResolvedAutomationAccountName `
            -RunbookName $script:RunbookName `
            -ScheduleName $script:ScheduleName `
            -Force `
            -ErrorAction Stop
    }
    Register-AzAutomationScheduledRunbook `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName `
        -RunbookName $script:RunbookName `
        -ScheduleName $script:ScheduleName `
        -Parameters @{ StorageAccountName = $StorageAccountName } `
        -ErrorAction Stop | Out-Null
    Write-Log -Message 'Linked the reconciliation runbook to its schedule with current parameters.' -Component 'Automation' -Type 1
}

function Publish-BffFunctionApp {
    $stagingPath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "LocalAdminBff-$([guid]::NewGuid())"
    $archivePath = "$stagingPath.zip"
    try {
        Write-Log -Message 'Building the Azure Functions BFF package.' -Component 'BFF' -Type 1
        Push-Location $script:BackendPath
        try {
            & npm ci --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) {
                throw 'npm ci failed for the BFF source.'
            }
            & npm run build
            if ($LASTEXITCODE -ne 0) {
                throw 'The BFF TypeScript build failed.'
            }
        } finally {
            Pop-Location
        }

        $null = New-Item -Path $stagingPath -ItemType Directory -Force
        Copy-Item -LiteralPath (Join-Path $script:BackendPath 'dist') -Destination (Join-Path $stagingPath 'dist') -Recurse -Force
        Copy-Item -LiteralPath (Join-Path $script:BackendPath 'host.json') -Destination $stagingPath -Force
        Copy-Item -LiteralPath (Join-Path $script:BackendPath 'package.json') -Destination $stagingPath -Force
        Copy-Item -LiteralPath (Join-Path $script:BackendPath 'package-lock.json') -Destination $stagingPath -Force

        Push-Location $stagingPath
        try {
            & npm ci --omit=dev --ignore-scripts --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) {
                throw 'Production dependency restore failed for the BFF deployment package.'
            }
        } finally {
            Pop-Location
        }

        Compress-Archive -Path (Join-Path $stagingPath '*') -DestinationPath $archivePath -CompressionLevel Optimal -Force
        $packageContainerName = 'function-packages'
        $packageBlobName = "localadmin-bff-$($script:DateTime).zip"
        Write-Log -Message "Uploading the BFF package to the private Function package container." -Component 'BFF' -Type 1
        $functionStorageKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $FunctionStorageAccountName -ErrorAction Stop)[0].Value
        try {
            $functionStorageContext = New-AzStorageContext -StorageAccountName $FunctionStorageAccountName -StorageAccountKey $functionStorageKey
            Set-AzStorageBlobContent `
                -Context $functionStorageContext `
                -Container $packageContainerName `
                -File $archivePath `
                -Blob $packageBlobName `
                -Force `
                -ErrorAction Stop | Out-Null
        } finally {
            $functionStorageKey = $null
        }

        $packageUri = "https://$FunctionStorageAccountName.blob.core.windows.net/$packageContainerName/$packageBlobName"
        $siteResourcePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$FunctionAppName"
        $appSettingsPath = "$siteResourcePath/config/appsettings?api-version=2023-12-01"
        $existingSettingsResponse = Invoke-AzRestMethod -Method POST -Path "$siteResourcePath/config/appsettings/list?api-version=2023-12-01" -ErrorAction Stop
        $existingSettings = ($existingSettingsResponse.Content | ConvertFrom-Json -AsHashtable).properties
        $existingSettings['WEBSITE_RUN_FROM_PACKAGE'] = $packageUri
        $existingSettings['WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID'] = 'SystemAssigned'
        $settingsBody = @{ properties = $existingSettings } | ConvertTo-Json -Depth 10 -Compress
        Invoke-AzRestMethod -Method PUT -Path $appSettingsPath -Payload $settingsBody -ErrorAction Stop | Out-Null
        Write-Log -Message "Configured Function App '$FunctionAppName' to run from the private package using its managed identity." -Component 'BFF' -Type 1

        Restart-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ErrorAction Stop | Out-Null
        $syncPath = "$siteResourcePath/host/default/sync?api-version=2023-12-01"
        $syncComplete = $false
        for ($attempt = 1; $attempt -le 12 -and -not $syncComplete; $attempt++) {
            Start-Sleep -Seconds 10
            try {
                $syncResponse = Invoke-AzRestMethod -Method POST -Path $syncPath -ErrorAction Stop
                $syncComplete = [int]$syncResponse.StatusCode -eq 200
            } catch {
                if ($attempt -eq 12) {
                    throw "The BFF package was configured, but Function trigger synchronization failed. $($_.Exception.Message)"
                }
            }
        }

        $healthUri = "$($script:ResolvedBffBaseUrl)/profile"
        $ready = $false
        for ($attempt = 1; $attempt -le 30 -and -not $ready; $attempt++) {
            Start-Sleep -Seconds 10
            try {
                $response = Invoke-WebRequest -Uri $healthUri -Method Get -SkipHttpErrorCheck -TimeoutSec 30
                if ([int]$response.StatusCode -eq 401) {
                    $ready = $true
                } elseif ([int]$response.StatusCode -ge 500) {
                    Write-Log -Message "BFF readiness attempt $attempt returned HTTP $([int]$response.StatusCode)." -Component 'BFF' -Type 2
                } else {
                    throw "The BFF readiness endpoint returned unexpected HTTP $([int]$response.StatusCode)."
                }
            } catch {
                if ($attempt -eq 30) {
                    throw "The BFF package was published but did not become ready. $($_.Exception.Message)"
                }
            }
        }
        Write-Log -Message 'The BFF endpoint is online and rejects unauthenticated requests as expected.' -Component 'BFF' -Type 1
    } finally {
        if (Test-Path -LiteralPath $archivePath) {
            Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $stagingPath) {
            Remove-Item -LiteralPath $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-SolutionSasTokens {
    Write-Log -Message 'Generating endpoint, reporting, and governance reporting SAS tokens.' -Component 'Tokens' -Type 1
    $accountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop)[0].Value
    $governanceAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $script:ResolvedGovernanceStorageAccountName -ErrorAction Stop)[0].Value
    try {
        $context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $accountKey
        $governanceContext = New-AzStorageContext -StorageAccountName $script:ResolvedGovernanceStorageAccountName -StorageAccountKey $governanceAccountKey
        $startTime = [datetime]::UtcNow.AddMinutes(-5)
        $endpointExpiry = [datetime]::UtcNow.AddDays($EndpointSasValidityDays)
        $reportExpiry = [datetime]::UtcNow.AddDays($ReportSasValidityDays)
        $endpointToken = New-AzStorageAccountSASToken -Context $context -Service Table -ResourceType Object -Permission rau -Protocol HttpsOnly -StartTime $startTime -ExpiryTime $endpointExpiry
        $reportToken = New-AzStorageAccountSASToken -Context $context -Service Table -ResourceType Object -Permission r -Protocol HttpsOnly -StartTime $startTime -ExpiryTime $reportExpiry
        $governanceReportToken = New-AzStorageAccountSASToken -Context $governanceContext -Service Table -ResourceType Object -Permission r -Protocol HttpsOnly -StartTime $startTime -ExpiryTime $reportExpiry
        return [pscustomobject]@{
            EndpointToken         = $endpointToken
            EndpointExpiry        = $endpointExpiry
            ReportToken           = $reportToken
            GovernanceReportToken = $governanceReportToken
            ReportExpiry          = $reportExpiry
        }
    } finally {
        $accountKey = $null
        $governanceAccountKey = $null
    }
}

function Export-HostConfigJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = $Path
    $outputDirectory = Split-Path -Path $resolvedPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
        $null = New-Item -Path $outputDirectory -ItemType Directory -Force
    }

    $config = [ordered]@{
        version = 1
        defaults = [ordered]@{
            storageAccountName = [string]$StorageAccountName
            governanceStorageAccountName = [string]$script:ResolvedGovernanceStorageAccountName
            bffBaseUrl = [string]$script:ResolvedBffBaseUrl
            entraTenantId = if ($script:ResolvedSpaTenantId) { $script:ResolvedSpaTenantId.ToString() } elseif ($TenantId -ne [guid]::Empty) { $TenantId.ToString() } else { '' }
            spaClientId = if ($script:ResolvedSpaClientId) { $script:ResolvedSpaClientId.ToString() } else { '' }
            apiScope = [string]$script:ResolvedBffApiScope
            redirectUri = [string]$script:ResolvedSpaRedirectUri
            defaultView = 'summary'
            lockStorageAccountName = [bool]$LockHostConfig
            lockGovernanceStorageAccountName = [bool]$LockHostConfig
        }
    }

    $json = $config | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $resolvedPath -Value $json -Encoding UTF8 -NoNewline -Force
    Write-Log -Message "Wrote a non-secret host config to '$resolvedPath'." -Component 'Config' -Type 1
}

function Protect-TokenFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($IsWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $accessRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule($accessRule)
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $acl)
    } else {
        & chmod 600 -- $Path
        if ($LASTEXITCODE -ne 0) {
            throw "chmod could not restrict access to '$Path'."
        }
    }
}

function Export-SolutionSasTokens {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Tokens,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Prompt', 'File', 'Console')]
        [string]$Mode
    )

    $resolvedMode = $Mode
    if ($resolvedMode -eq 'Prompt') {
        Write-Host ''
        Write-Host 'Choose how the generated SAS tokens are delivered:'
        Write-Host '  1. Save to a protected text file (recommended)'
        Write-Host '  2. Display once in this console'
        Write-Host '  3. Do not expose the tokens'
        $selection = Read-Host 'Selection [1]'
        $resolvedMode = switch ($selection) {
            '2' { 'Console' }
            '3' { 'None' }
            default { 'File' }
        }
    }

    if ($resolvedMode -eq 'None') {
        Write-Log -Message 'SAS tokens were generated but were not displayed or saved.' -Component 'Tokens' -Type 2
        return
    }

    if ($resolvedMode -eq 'Console') {
        Write-Warning 'SAS tokens may remain visible in terminal history, screen recordings, support logs, or shared sessions.'
        if (-not (Confirm-Action -Message 'Display all generated SAS tokens in this console?')) {
            Write-Log -Message 'Console token display was declined.' -Component 'Tokens' -Type 2
            return
        }
        Write-Host ''
        Write-Host "Endpoint SAS, Table Object Read/Add/Update, expires $($Tokens.EndpointExpiry.ToString('u')):"
        Write-Host $Tokens.EndpointToken
        Write-Host ''
        Write-Host "Inventory reporting SAS, Table Object Read, expires $($Tokens.ReportExpiry.ToString('u')):"
        Write-Host $Tokens.ReportToken
        Write-Host ''
        Write-Host "Governance reporting SAS, Table Object Read, expires $($Tokens.ReportExpiry.ToString('u')):"
        Write-Host $Tokens.GovernanceReportToken
        Write-Warning 'Move these values to their final systems and clear the terminal when practical.'
        return
    }

    Write-Warning 'The selected output file will contain plaintext Azure Storage credentials.'
    Write-Warning 'Anyone with a token can perform its listed operations until expiry. Account SAS tokens cannot be revoked individually.'
    if (-not $ForceTokenOutput -and -not (Confirm-Action -Message 'Write the SAS tokens to a protected text file?')) {
        Write-Log -Message 'Token file creation was declined.' -Component 'Tokens' -Type 2
        return
    }

    $selectedPath = $TokenOutputPath
    if ([string]::IsNullOrWhiteSpace($selectedPath)) {
        $defaultPath = Join-Path -Path $PSScriptRoot -ChildPath "LocalAdminReporting-Secrets_$($script:DateTime).txt"
        $enteredPath = Read-Host "Destination path (press Enter to use '$defaultPath')"
        $selectedPath = if ([string]::IsNullOrWhiteSpace($enteredPath)) { $defaultPath } else { $enteredPath }
    }
    try {
        $selectedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($selectedPath)
    } catch {
        throw "TokenOutputPath '$selectedPath' is not a valid file-system path. $($_.Exception.Message)"
    }
    $parentPath = Split-Path -Path $selectedPath -Parent
    if (-not (Test-Path -LiteralPath $parentPath)) {
        $null = New-Item -Path $parentPath -ItemType Directory -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $selectedPath) {
        if (-not (Confirm-Action -Message "Overwrite existing file '$selectedPath'?")) {
            Write-Log -Message 'Token file overwrite was declined.' -Component 'Tokens' -Type 2
            return
        }
    }

    $content = @"
SECURITY WARNING
This file contains plaintext Azure Storage credentials.
Anyone possessing a token can perform its listed operations until expiry.
Account SAS tokens cannot be revoked individually. Rotate a Storage account key to invalidate them before expiry.
Move the values to their final systems and securely delete this file after use.

Storage account
Name: $StorageAccountName
Table endpoint: https://$StorageAccountName.table.core.windows.net

Governance storage account
Name: $($script:ResolvedGovernanceStorageAccountName)
Table endpoint: https://$($script:ResolvedGovernanceStorageAccountName).table.core.windows.net

Endpoint token
Purpose: Device inventory remediation through Intune, ConfigMgr, RMM, scheduled task, or equivalent tooling.
Permissions: Table service, Object resource type, Read, Add, Update.
Expiry UTC: $($Tokens.EndpointExpiry.ToString('o'))
Token: $($Tokens.EndpointToken)

Reporting token
Purpose: Inventory tables used by the Live HTML report, HTML exporter, and Excel Power Query.
Permissions: Table service, Object resource type, Read.
Expiry UTC: $($Tokens.ReportExpiry.ToString('o'))
Token: $($Tokens.ReportToken)

Governance reporting token
Purpose: Allow rules and review action history used by the interactive report.
Permissions: Table service, Object resource type, Read.
Expiry UTC: $($Tokens.ReportExpiry.ToString('o'))
Token: $($Tokens.GovernanceReportToken)
"@

    $temporaryFileName = ".{0}.{1}.tmp" -f ([IO.Path]::GetFileName($selectedPath)), ([guid]::NewGuid().ToString('N'))
    $temporaryPath = Join-Path -Path $parentPath -ChildPath $temporaryFileName
    try {
        [IO.File]::WriteAllText($temporaryPath, [string]::Empty, [Text.UTF8Encoding]::new($false))
        Protect-TokenFile -Path $temporaryPath
        Set-Content -LiteralPath $temporaryPath -Value $content -Encoding UTF8 -NoNewline -Force -ErrorAction Stop
        [IO.File]::Move($temporaryPath, $selectedPath, $true)
    } catch {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        throw "The protected token file could not be created. $($_.Exception.Message)"
    }

    Write-Warning "SAS tokens were saved to '$selectedPath'."
    Write-Warning 'Move the tokens into their final systems, then securely delete the plaintext file.'
    Write-Log -Message "Created a protected token file at '$selectedPath'. Token values were excluded from the log." -Component 'Tokens' -Type 2
}

# Main
try {
    Initialize-Script
    Write-Host 'Prerequisites may be installed for the current user or downloaded temporarily with your approval.'
    Write-Host 'These prerequisite actions do not normally require administrator rights. The Azure deployment still requires appropriate Azure and Microsoft Graph permissions.'
    Write-Log -Message 'Starting local administrator reporting deployment.' -Component 'Initialize' -Type 1
    $requestedWhatIf = $WhatIfPreference
    try {
        # Module loading and context selection are prerequisites, not deployment mutations.
        # Allow them and the audit log to run so -WhatIf can produce a useful removal preview.
        $WhatIfPreference = $false
        Import-RequiredModules
        Connect-DeploymentAccounts
    } finally {
        $WhatIfPreference = $requestedWhatIf
    }

    if ($RemoveDeployment) {
        Remove-SolutionDeployment
        if ($script:RemovalPerformed) {
            Write-Output "SUCCESS: Deployment removal completed. Review the log at $($script:LogFile)."
        } else {
            Write-Output "PREVIEW: Deployment removal was not performed. Review the WhatIf output and log at $($script:LogFile)."
        }
        exit 0
    }

    if ($null -ne $script:DeploymentState) {
        if (-not (Test-DeploymentStateValidity -State $script:DeploymentState)) {
            throw "The persisted deployment state at '$(Get-DeploymentStatePath)' no longer matches valid Azure resources. Review or remove it, or rerun with -ForceRecreate and complete parameters."
        }

        $completedStageText = @($script:DeploymentState.completedStages) -join ', '
        $resumeSummary = "resource group '$($script:DeploymentState.resourceGroupName)' with completed stages: $completedStageText"
        if (-not (Confirm-Action -Message "A previous valid deployment state was found for $resumeSummary. Continue with it and ignore supplied deployment parameters?")) {
            throw 'Resume was declined. Rerun with -ForceRecreate to replace the recorded deployment state.'
        }
        $script:ResumeFromState = $true
        Write-Log -Message "Continuing the verified deployment state for $resumeSummary." -Component 'State' -Type 1
    }

    if (-not (Test-DeploymentStageCompleted -Stage 'AzureResourcesReady')) {
        Initialize-Bicep
    } else {
        Write-Log -Message 'Skipping Bicep initialization because AzureResourcesReady is recorded and verified.' -Component 'State' -Type 1
    }

    if (-not $PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy the local administrator reporting solution')) {
        Write-Log -Message 'Deployment was not performed.' -Component 'Summary' -Type 2
        exit 0
    }

    if ($BackendMode -eq 'AzureFunctions' -and
        $AppRegistrationMode -eq 'Create' -and
        -not (Test-DeploymentStageCompleted -Stage 'AppRegistrationsReady')) {
        if (-not $PSCmdlet.ShouldProcess($script:ResolvedApiAppDisplayName, 'Create or reconcile the BFF API and SPA app registrations')) {
            throw 'Azure Functions deployment requires the requested app registrations.'
        }
        Initialize-BffAppRegistrations
        Write-DeploymentState -Stage 'AppRegistrationsReady'
    } elseif ($BackendMode -eq 'AzureFunctions' -and (Test-DeploymentStageCompleted -Stage 'AppRegistrationsReady')) {
        Write-Log -Message 'Skipping app-registration reconciliation because AppRegistrationsReady is recorded.' -Component 'State' -Type 1
    }

    if ($BackendMode -eq 'AzureFunctions' -and $ConfigureApiAppRoles) {
        if ($PSCmdlet.ShouldProcess([string]$script:ResolvedApiClientId, 'Add or update the Admin-mode app roles on the API app registration')) {
            Set-BffApiAppRoles -ApiClientId $script:ResolvedApiClientId
        }
    } elseif ($BackendMode -eq 'AzureFunctions') {
        Write-Log -Message 'API app roles were not changed. Use -ConfigureApiAppRoles to add the Admin-mode roles to the API app registration.' -Component 'Entra' -Type 1
    }

    $deployment = $null
    if (-not (Test-DeploymentStageCompleted -Stage 'AzureResourcesReady')) {
        $deployment = Invoke-SolutionResourceDeployment
        Write-DeploymentState -Stage 'AzureResourcesReady'
    } else {
        Write-Log -Message 'Skipping the Bicep resource deployment because AzureResourcesReady is recorded and verified.' -Component 'State' -Type 1
    }

    if (-not $SkipGraphPermissionGrant -and -not (Test-DeploymentStageCompleted -Stage 'GraphPermissionsGranted')) {
        $managedIdentityPrincipalId = if ($null -ne $deployment) {
            [guid]$deployment.Outputs.automationManagedIdentityPrincipalId.Value
        } else {
            Get-AutomationManagedIdentityPrincipalId
        }
        if ($PSCmdlet.ShouldProcess([string]$managedIdentityPrincipalId, 'Grant Microsoft Graph application permissions')) {
            Invoke-ManagedIdentityGraphPermissionGrant -ManagedIdentityPrincipalId $managedIdentityPrincipalId
            Write-DeploymentState -Stage 'GraphPermissionsGranted'
        }
    } elseif (Test-DeploymentStageCompleted -Stage 'GraphPermissionsGranted') {
        Write-Log -Message 'Skipping managed-identity Graph permission grants because GraphPermissionsGranted is recorded.' -Component 'State' -Type 1
    } elseif ($SkipGraphPermissionGrant) {
        Write-Log -Message 'Microsoft Graph permission assignment was skipped by parameter.' -Component 'Graph' -Type 2
    }

    if (-not (Test-DeploymentStageCompleted -Stage 'RunbookReady') -and
        $PSCmdlet.ShouldProcess($script:ResolvedAutomationAccountName, 'Import, publish, and schedule the reconciliation runbook')) {
        Import-ReconciliationRunbook
        Write-DeploymentState -Stage 'RunbookReady'
    } elseif (Test-DeploymentStageCompleted -Stage 'RunbookReady') {
        Write-Log -Message 'Skipping runbook publication because RunbookReady is recorded.' -Component 'State' -Type 1
    }

    if ($BackendMode -eq 'AzureFunctions' -and
        -not (Test-DeploymentStageCompleted -Stage 'BffPublished') -and
        $PSCmdlet.ShouldProcess($FunctionAppName, 'Build and publish the Azure Functions BFF')) {
        Publish-BffFunctionApp
        Write-DeploymentState -Stage 'BffPublished'
    } elseif ($BackendMode -eq 'AzureFunctions' -and (Test-DeploymentStageCompleted -Stage 'BffPublished')) {
        Write-Log -Message 'Skipping BFF publication because BffPublished is recorded.' -Component 'State' -Type 1
    }

    if ($TokenOutputMode -ne 'None' -and -not (Test-DeploymentStageCompleted -Stage 'SasTokensReady')) {
        $tokens = New-SolutionSasTokens
        Export-SolutionSasTokens -Tokens $tokens -Mode $TokenOutputMode
        $tokens = $null
        Write-DeploymentState -Stage 'SasTokensReady'
    } elseif (Test-DeploymentStageCompleted -Stage 'SasTokensReady') {
        Write-Log -Message 'Skipping SAS token generation because SasTokensReady is recorded.' -Component 'State' -Type 1
    } else {
        Write-Log -Message 'SAS token generation was skipped by parameter.' -Component 'Tokens' -Type 1
    }

    $writeConfigJson = -not $SkipConfigJson -and (
        $ReportingFrontend -eq 'LiveHtml' -or
        $GenerateConfigJson -or
        $PSBoundParameters.ContainsKey('ConfigJsonPath') -or
        $BackendMode -ne 'None' -or
        $PSBoundParameters.ContainsKey('SpaClientId') -or
        $PSBoundParameters.ContainsKey('BffApiScope') -or
        $PSBoundParameters.ContainsKey('LockHostConfig')
    )
    if ($writeConfigJson -and -not (Test-DeploymentStageCompleted -Stage 'ConfigReady')) {
        Export-HostConfigJson -Path $script:ConfigJsonPath
        Write-Output "Public LiveHTML configuration: $($script:ConfigJsonPath)"
        Write-DeploymentState -Stage 'ConfigReady'
    } elseif (Test-DeploymentStageCompleted -Stage 'ConfigReady') {
        Write-Log -Message 'Skipping config.json generation because ConfigReady is recorded.' -Component 'State' -Type 1
    }

    if (-not (Test-DeploymentStageCompleted -Stage 'DeploymentComplete')) {
        Write-DeploymentState -Stage 'DeploymentComplete'
    }

    Write-Log -Message "Deployment completed. Inventory storage account: $StorageAccountName. Governance storage account: $($script:ResolvedGovernanceStorageAccountName). Automation account: $($script:ResolvedAutomationAccountName)." -Component 'Summary' -Type 1
    Write-Output "SUCCESS: Deployment completed. Review the log at $($script:LogFile)."
    exit 0
} catch {
    if ($script:LogFile) {
        Write-Log -Message $_.Exception.Message -Component 'Error' -Type 3
    }
    Write-Error "Deployment failed. $($_.Exception.Message)"
    exit 1
} finally {
    Remove-TemporaryBicep
    if ($script:ConnectedGraphInThisRun -and (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
        $requestedWhatIf = $WhatIfPreference
        try {
            $WhatIfPreference = $false
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        } finally {
            $WhatIfPreference = $requestedWhatIf
        }
    }
}
