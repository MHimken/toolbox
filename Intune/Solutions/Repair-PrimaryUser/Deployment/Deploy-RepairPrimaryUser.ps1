#Requires -Version 7.2
<#
.SYNOPSIS
    Deploys and schedules the Repair Primary User Azure Automation solution.
.DESCRIPTION
    Deploys the Azure foundation from Bicep, imports both PowerShell 7.2 runbooks, creates daily and
    weekly UTC schedules, and optionally grants the required Microsoft Graph application permissions
    to the Automation Account system-assigned managed identity.
.NOTES
    Run this deployment script from PowerShell 7.2 on an administration workstation or Azure Cloud Shell.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [guid]$SubscriptionId,

    [guid]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9._()-]{1,90}$')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Location,

    [Parameter(Mandatory = $true)]
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

    [switch]$SkipGraphPermissionGrant
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Confirm-Action {
    param([Parameter(Mandatory = $true)][string]$Message)
    return (Read-Host "$Message Type YES to continue") -ceq 'YES'
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
        $graphParameters = @{ Scopes = @('Application.Read.All', 'AppRoleAssignment.ReadWrite.All'); NoWelcome = $true }
        if ($TenantId -ne [guid]::Empty) { $graphParameters.TenantId = [string]$TenantId }
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
            Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityPrincipalId?`$select=id" -OutputType PSObject | Out-Null
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
        -AutomationAccountName $script:ResolvedAutomationAccountName -RunbookName $RunbookName -ErrorAction SilentlyContinue)
    foreach ($link in @($existingLinks | Where-Object { $_.ScheduleName -eq $ScheduleName })) {
        Unregister-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $script:ResolvedAutomationAccountName `
            -RunbookName $RunbookName -ScheduleName $ScheduleName -Force -ErrorAction Stop
    }

    $existingSchedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $script:ResolvedAutomationAccountName -Name $ScheduleName -ErrorAction SilentlyContinue
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

$script:SolutionRoot = Split-Path -Path $PSScriptRoot -Parent
$script:TemplatePath = Join-Path -Path $PSScriptRoot -ChildPath 'main.bicep'
$collectorPath = Join-Path -Path $script:SolutionRoot -ChildPath 'Runbooks\Collect-PrimaryUserSignInData.ps1'
$analyzerPath = Join-Path -Path $script:SolutionRoot -ChildPath 'Runbooks\Repair-PrimaryUserAssignments.ps1'
$script:ResolvedAutomationAccountName = if ([string]::IsNullOrWhiteSpace($AutomationAccountName)) { "aa-rpu-$StorageAccountName" } else { $AutomationAccountName }
if ($script:ResolvedAutomationAccountName.Length -gt 50) { throw 'The derived Automation Account name exceeds 50 characters.' }

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

    if ($null -eq (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop | Out-Null
    }
    $deployment = New-AzResourceGroupDeployment -Name "RepairPrimaryUser-$([datetime]::UtcNow.ToString('yyyyMMddHHmmss'))" `
        -ResourceGroupName $ResourceGroupName -TemplateFile $script:TemplatePath -location $Location `
        -storageAccountName $StorageAccountName -automationAccountName $script:ResolvedAutomationAccountName -ErrorAction Stop
    if ($deployment.ProvisioningState -ne 'Succeeded') { throw "Azure deployment completed with state '$($deployment.ProvisioningState)'." }

    $principalId = [guid]$deployment.Outputs.automationManagedIdentityPrincipalId.Value
    if (-not $SkipGraphPermissionGrant -and $PSCmdlet.ShouldProcess([string]$principalId, 'Grant required Microsoft Graph application permissions')) {
        Grant-ManagedIdentityGraphPermissions -ManagedIdentityPrincipalId $principalId
    }

    Import-SolutionRunbook -Name 'Collect-PrimaryUserSignInData' -Path $collectorPath
    Import-SolutionRunbook -Name 'Repair-PrimaryUserAssignments' -Path $analyzerPath

    $collectorStart = Get-NextUtcStartTime -Time $CollectorStartTimeUtc
    $analyzerStart = Get-NextUtcStartTime -Time $AnalyzerStartTimeUtc -DayOfWeek $AnalyzerDayOfWeek
    Set-RunbookSchedule -RunbookName 'Collect-PrimaryUserSignInData' -ScheduleName 'RepairPrimaryUser-DailyCollection' `
        -StartTime $collectorStart -Frequency Daily -Parameters @{ StorageAccountName = $StorageAccountName; RetentionDays = $RetentionDays }
    Set-RunbookSchedule -RunbookName 'Repair-PrimaryUserAssignments' -ScheduleName 'RepairPrimaryUser-WeeklyAnalysis' `
        -StartTime $analyzerStart -Frequency Weekly -DayOfWeek $AnalyzerDayOfWeek `
        -Parameters @{ StorageAccountName = $StorageAccountName; DaysToAnalyze = $DaysToAnalyze }

    Write-Output "Deployment complete. Daily collection: $CollectorStartTimeUtc UTC. Weekly analysis: $AnalyzerDayOfWeek $AnalyzerStartTimeUtc UTC."
} finally {
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}