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
.PARAMETER AutomationAccountName
    Azure Automation account name. When omitted, a name is derived from the Storage account name.
.PARAMETER ReportingFrontend
    Reporting frontend to configure. LiveHtml is the default and enables Table CORS. GeneratedHtml
    and Excel disable Table CORS because they do not query Azure Storage from a browser.
.PARAMETER AllowedCorsOrigins
    Origins permitted to access Azure Table Storage when ReportingFrontend is LiveHtml. Defaults to
    * for directly opened HTML files. Specify the exact hosting origin whenever possible.
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
    Skips granting User.Read.All and Group.Read.All to the Automation managed identity.
.PARAMETER LogPath
    Directory in which the deployment log is created. Defaults to the current folder.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.NOTES
Version: 0.1
Author: Martin Himken
Original script name: Deploy-LocalAdminReporting.ps1
Initial creation date: 2026-09-06
Last change: 2026-09-06
Changes: ..\changelog.md
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

    [ValidateSet('LiveHtml', 'GeneratedHtml', 'Excel')]
    [string]$ReportingFrontend = 'LiveHtml',

    [string[]]$AllowedCorsOrigins = @(),

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
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'Deploy-LocalAdminReporting'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
    if (-not($LogFile)) {
        $script:ResolvedLogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    } else {
        $script:ResolvedLogFile = $LogFile
    }

    if (-not (Test-Path -LiteralPath $LogPath)) {
        $null = New-Item -Path $LogPath -ItemType Directory -Force
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $script:ResolvedLogFile
    $Script:ToConsole = $false
    $script:OriginalPath = $env:PATH
    $script:TemporaryBicepDirectory = $null

    if ([string]::IsNullOrWhiteSpace($AutomationAccountName)) {
        $script:ResolvedAutomationAccountName = "aa-las-$StorageAccountName"
    } else {
        $script:ResolvedAutomationAccountName = $AutomationAccountName
    }
    if ($script:ResolvedAutomationAccountName.Length -gt 50) {
        throw 'The derived Automation account name exceeds 50 characters. Pass AutomationAccountName explicitly.'
    }

    $script:SolutionRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:TemplatePath = Join-Path -Path $PSScriptRoot -ChildPath 'main.bicep'
    $script:RunbookPath = Join-Path -Path $script:SolutionRoot -ChildPath 'Runbooks\Resolve-LocalAdminLookupNames.ps1'
    $script:RunbookName = 'Resolve-LocalAdminLookupNames'
    $script:ScheduleName = 'Resolve-LocalAdminLookupNames-Schedule'
    if ($ReportingFrontend -eq 'LiveHtml') {
        $script:ResolvedAllowedCorsOrigins = if ($AllowedCorsOrigins.Count -eq 0) { @('*') } else { @($AllowedCorsOrigins) }
    } else {
        $script:ResolvedAllowedCorsOrigins = @()
    }

    foreach ($requiredPath in @($script:TemplatePath, $script:RunbookPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required deployment file was not found: $requiredPath"
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
    $azureParameters = @{
        Subscription = $SubscriptionId
        ErrorAction  = 'Stop'
    }
    if ($TenantId -ne [guid]::Empty) {
        $azureParameters.Tenant = $TenantId
    }

    Write-Log -Message 'Starting interactive Azure sign-in.' -Component 'Authentication' -Type 1
    Connect-AzAccount @azureParameters | Out-Null
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    if (-not $SkipGraphPermissionGrant) {
        $graphParameters = @{
            Scopes    = @('Application.Read.All', 'AppRoleAssignment.ReadWrite.All')
            NoWelcome = $true
        }
        if ($TenantId -ne [guid]::Empty) {
            $graphParameters.TenantId = [string]$TenantId
        }
        Write-Log -Message 'Starting interactive Microsoft Graph sign-in for managed identity permission assignment.' -Component 'Authentication' -Type 1
        Connect-MgGraph @graphParameters | Out-Null
    }
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
    $deployment = New-AzResourceGroupDeployment `
        -Name "LocalAdminReporting-$($script:DateTime)" `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile $script:TemplatePath `
        -location $Location `
        -storageAccountName $StorageAccountName `
        -automationAccountName $script:ResolvedAutomationAccountName `
        -allowedCorsOrigins $script:ResolvedAllowedCorsOrigins `
        -ErrorAction Stop

    if ($deployment.ProvisioningState -ne 'Succeeded') {
        throw "Azure deployment completed with state '$($deployment.ProvisioningState)'."
    }
    Write-Log -Message 'Azure resource deployment completed successfully.' -Component 'Azure' -Type 1
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

    foreach ($permissionValue in @('User.Read.All', 'Group.Read.All')) {
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

function New-SolutionSasTokens {
    Write-Log -Message 'Generating separate endpoint and reporting SAS tokens.' -Component 'Tokens' -Type 1
    $accountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop)[0].Value
    try {
        $context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $accountKey
        $startTime = [datetime]::UtcNow.AddMinutes(-5)
        $endpointExpiry = [datetime]::UtcNow.AddDays($EndpointSasValidityDays)
        $reportExpiry = [datetime]::UtcNow.AddDays($ReportSasValidityDays)
        $endpointToken = New-AzStorageAccountSASToken -Context $context -Service Table -ResourceType Object -Permission rau -Protocol HttpsOnly -StartTime $startTime -ExpiryTime $endpointExpiry
        $reportToken = New-AzStorageAccountSASToken -Context $context -Service Table -ResourceType Object -Permission r -Protocol HttpsOnly -StartTime $startTime -ExpiryTime $reportExpiry
        return [pscustomobject]@{
            EndpointToken  = $endpointToken
            EndpointExpiry = $endpointExpiry
            ReportToken    = $reportToken
            ReportExpiry   = $reportExpiry
        }
    } finally {
        $accountKey = $null
    }
}

function Protect-TokenFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($IsWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $accessRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($existingRule in @($acl.Access)) {
            $acl.RemoveAccessRuleSpecific($existingRule)
        }
        $acl.SetAccessRule($accessRule)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
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
        if (-not (Confirm-Action -Message 'Display both SAS tokens in this console?')) {
            Write-Log -Message 'Console token display was declined.' -Component 'Tokens' -Type 2
            return
        }
        Write-Host ''
        Write-Host "Endpoint SAS, Table Object Read/Add/Update, expires $($Tokens.EndpointExpiry.ToString('u')):"
        Write-Host $Tokens.EndpointToken
        Write-Host ''
        Write-Host "Reporting SAS, Table Object Read, expires $($Tokens.ReportExpiry.ToString('u')):"
        Write-Host $Tokens.ReportToken
        Write-Warning 'Move these values to their final systems and clear the terminal when practical.'
        return
    }

    Write-Warning 'The selected output file will contain plaintext Azure Storage credentials.'
    Write-Warning 'Anyone with a token can perform its listed operations until expiry. Account SAS tokens cannot be revoked individually.'
    if (-not (Confirm-Action -Message 'Write the SAS tokens to a protected text file?')) {
        Write-Log -Message 'Token file creation was declined.' -Component 'Tokens' -Type 2
        return
    }

    $selectedPath = $TokenOutputPath
    if ([string]::IsNullOrWhiteSpace($selectedPath)) {
        $defaultPath = Join-Path -Path $PSScriptRoot -ChildPath "LocalAdminReporting-Secrets_$($script:DateTime).txt"
        $enteredPath = Read-Host "Destination path [$defaultPath]"
        $selectedPath = if ([string]::IsNullOrWhiteSpace($enteredPath)) { $defaultPath } else { $enteredPath }
    }
    $selectedPath = [IO.Path]::GetFullPath($selectedPath)
    $parentPath = Split-Path -Path $selectedPath -Parent
    if (-not (Test-Path -LiteralPath $parentPath)) {
        $null = New-Item -Path $parentPath -ItemType Directory -Force
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

Endpoint token
Purpose: Device inventory remediation through Intune, ConfigMgr, RMM, scheduled task, or equivalent tooling.
Permissions: Table service, Object resource type, Read, Add, Update.
Expiry UTC: $($Tokens.EndpointExpiry.ToString('o'))
Token: $($Tokens.EndpointToken)

Reporting token
Purpose: Live HTML report, HTML exporter, and Excel Power Query.
Permissions: Table service, Object resource type, Read.
Expiry UTC: $($Tokens.ReportExpiry.ToString('o'))
Token: $($Tokens.ReportToken)
"@

    try {
        Set-Content -LiteralPath $selectedPath -Value $content -Encoding UTF8 -NoNewline -Force
        Protect-TokenFile -Path $selectedPath
    } catch {
        Remove-Item -LiteralPath $selectedPath -Force -ErrorAction SilentlyContinue
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
    Import-RequiredModules
    Initialize-Bicep
    Connect-DeploymentAccounts
    if (-not $PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy the local administrator reporting solution')) {
        Write-Log -Message 'Deployment was not performed.' -Component 'Summary' -Type 2
        exit 0
    }
    $deployment = Invoke-SolutionResourceDeployment

    $managedIdentityPrincipalId = [guid]$deployment.Outputs.automationManagedIdentityPrincipalId.Value
    if (-not $SkipGraphPermissionGrant -and $PSCmdlet.ShouldProcess([string]$managedIdentityPrincipalId, 'Grant Microsoft Graph application permissions')) {
        Invoke-ManagedIdentityGraphPermissionGrant -ManagedIdentityPrincipalId $managedIdentityPrincipalId
    }
    if ($PSCmdlet.ShouldProcess($script:ResolvedAutomationAccountName, 'Import, publish, and schedule the reconciliation runbook')) {
        Import-ReconciliationRunbook
    }

    if ($TokenOutputMode -ne 'None') {
        $tokens = New-SolutionSasTokens
        Export-SolutionSasTokens -Tokens $tokens -Mode $TokenOutputMode
        $tokens = $null
    } else {
        Write-Log -Message 'SAS token generation was skipped by parameter.' -Component 'Tokens' -Type 1
    }

    Write-Log -Message "Deployment completed. Storage account: $StorageAccountName. Automation account: $($script:ResolvedAutomationAccountName)." -Component 'Summary' -Type 1
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
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
