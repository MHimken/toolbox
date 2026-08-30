<#
THIS DOESN'T WORK AS ENTRA CUSTOM ROLES DO NOT SUPPORT THE INTUNE PERMISSION microsoft.intune/allEntities/allTasks.
I HAVE LEFT THE SCRIPT HERE FOR REFERENCE PURPOSES, BUT IT WILL FAIL WHEN RUN.
.SYNOPSIS
Creates a custom Microsoft Entra role definition for Intune permissions using Microsoft Graph.

.DESCRIPTION
This script connects to Microsoft Graph with application certificate authentication and creates a custom
Microsoft Entra role definition that includes the microsoft.intune/allEntities/allTasks permission.
The script uses Invoke-MgGraphRequest for Graph API operations and writes execution details to a log file.

.PARAMETER LogPath
Folder path where the log file is written. Defaults to the current folder.

.PARAMETER LogFile
Log file name. When omitted, the script generates a file name using the script name and a timestamp.

.PARAMETER RoleDisplayName
Display name for the custom role definition.

.PARAMETER RoleDescription
Description for the custom role definition.

.PARAMETER TemplateId
Optional template identifier for the role definition. When omitted, a new GUID is generated.

.PARAMETER ClientId
Application (client) ID used for Connect-MgGraph certificate authentication.

.PARAMETER TenantId
Tenant ID used for Connect-MgGraph certificate authentication.

.PARAMETER CertificateThumbprint
Certificate thumbprint used for Connect-MgGraph certificate authentication.

.NOTES
Version: 0.1
Author: Martin Himken
Original script name: Create-CustomIntuneRoleUsingGraph.ps1
Initial creation date: 2026-07-23
Last change: 2026-07-23
Changes: Initial version
#>

[CmdletBinding()]
param(
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null,
    [string]$RoleDisplayName = 'Intune Custom Role - All Intune Entities All Tasks',
    [string]$RoleDescription = 'Custom role with microsoft.intune/allEntities/allTasks permission.',
    [string]$TemplateId = '',
    [string]$ClientId = 'a6c5bdbc-490d-422b-8f44-94abf02418b0',
    [string]$TenantId = 'd5b7cd63-8572-46e8-bace-dc62d1be4252',
    [string]$CertificateThumbprint = 'eedb77352ee48d0cbff058fe503452d816784081'
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
			$LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
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
    # Set a default log file name using ISO 8601 date-time with 24-hour timestamp.
    # Use a file-system-safe variant for Windows file names.
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'Create-CustomIntuneRoleUsingGraph'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
    if (-not($LogFile)) {
        $LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
    $Script:RoleDefinitionsEndpoint = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'
    $Script:ToConsole = $false
}

function Connect-GraphApplication {
    try {
        $context = Get-MgContext
        if ($context) {
            Write-Log -Message 'An existing Microsoft Graph context is present.' -Component 'Connect-GraphApplication' -Type 1
            return
        }

        Write-Log -Message 'Connecting to Microsoft Graph with certificate-based application authentication.' -Component 'Connect-GraphApplication' -Type 1
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
        Write-Log -Message 'Connected to Microsoft Graph successfully.' -Component 'Connect-GraphApplication' -Type 1
    }
    catch {
        Write-Log -Message "Graph connection failed: $($_.Exception.Message)" -Component 'Connect-GraphApplication' -Type 3
        throw
    }
}

function Get-CustomRoleDefinitionByName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    try {
        $encodedFilter = [System.Uri]::EscapeDataString("displayName eq '$DisplayName'")
        $uri = "$($Script:RoleDefinitionsEndpoint)?`$filter=$encodedFilter"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        if ($response.value -and $response.value.Count -gt 0) {
            return $response.value[0]
        }
        return $null
    }
    catch {
        Write-Log -Message "Failed to query existing role definitions: $($_.Exception.Message)" -Component 'Get-CustomRoleDefinitionByName' -Type 3
        throw
    }
}

function New-CustomEntraRoleDefinition {
    [OutputType([pscustomobject])]
    param()

    try {
        $effectiveTemplateId = $TemplateId
        if ([string]::IsNullOrWhiteSpace($effectiveTemplateId)) {
            $effectiveTemplateId = (New-Guid).Guid
        }

        $existingRole = Get-CustomRoleDefinitionByName -DisplayName $RoleDisplayName
        if ($existingRole) {
            $message = "A role definition with display name '$RoleDisplayName' already exists (Id: $($existingRole.id))."
            Write-Log -Message $message -Component 'New-CustomEntraRoleDefinition' -Type 2
            return [pscustomobject]@{
                Status           = 'Exists'
                RoleDefinitionId = $existingRole.id
                DisplayName      = $existingRole.displayName
                TemplateId       = $existingRole.templateId
            }
        }

        $payload = @{
            description     = $RoleDescription
            displayName     = $RoleDisplayName
            isEnabled       = $true
            templateId      = $effectiveTemplateId
            rolePermissions = @(
                @{
                    allowedResourceActions = @(
                        'microsoft.intune/allEntities/allTasks'
                    )
                }
            )
        }

        $body = $payload | ConvertTo-Json -Depth 10
        Write-Log -Message "Creating custom role definition '$RoleDisplayName'." -Component 'New-CustomEntraRoleDefinition' -Type 1
        $response = Invoke-MgGraphRequest -Method POST -Uri $Script:RoleDefinitionsEndpoint -Body $body -ErrorAction Stop

        Write-Log -Message "Custom role definition created successfully with Id: $($response.id)." -Component 'New-CustomEntraRoleDefinition' -Type 1
        return [pscustomobject]@{
            Status           = 'Created'
            RoleDefinitionId = $response.id
            DisplayName      = $response.displayName
            TemplateId       = $response.templateId
        }
    }
    catch {
        $apiErrorMessage = $_.ErrorDetails.Message
        if ($apiErrorMessage -and $apiErrorMessage -match 'is not supported for Custom Role creation') {
            $unsupportedMessage = "Graph rejected '$RoleDisplayName' because action 'microsoft.intune/allEntities/allTasks' is currently not supported for Microsoft Entra custom role creation in this API surface. Use an Entra built-in role for Intune administration, or create a custom Intune RBAC role in Intune instead."
            Write-Log -Message $unsupportedMessage -Component 'New-CustomEntraRoleDefinition' -Type 3
            throw $unsupportedMessage
        }

        Write-Log -Message "Failed to create custom role definition: $($_.Exception.Message)" -Component 'New-CustomEntraRoleDefinition' -Type 3
        throw
    }
}

# Main
try {
    Initialize-Script
    Write-Log -Message 'Script started.' -Component 'Main' -Type 1

    Connect-GraphApplication

    $result = New-CustomEntraRoleDefinition

    Write-Log -Message "Script completed with status: $($result.Status)." -Component 'Main' -Type 1
    $result
}
catch {
    Write-Log -Message "Script terminated with error: $($_.Exception.Message)" -Component 'Main' -Type 3
    throw
}
