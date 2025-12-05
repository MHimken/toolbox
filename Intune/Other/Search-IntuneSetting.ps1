<#
THIS IS NOT DONE!

.SYNOPSIS
    This script searches for a setting within Intune. Will accept a search string and return matching settings and their policies.
.DESCRIPTION
    This script connects to the Microsoft Graph API and retrieves all Intune settings catalog based policies as JSON. 
    It will then filter the results based on the search string provided by the user.
.PARAMETER SearchString
    The search string to filter Intune settings. This can be a partial or full name of the setting you are looking for.
.PARAMETER WorkingFolder
    The folder path to save the output files if any.
.PARAMETER SettingType
    The type of setting to filter by. This can be 'DeviceConfiguration', 'CompliancePolicy', or 'AppConfigPolicy'.
#>
[CmdletBinding()]
param (
    [string]$SearchString,
    [string]$WorkingFolder,
    [string]$SettingType,
    [string]$LogPrefix = 'SIS',
    [switch]$NoLog,
    [string]$CertificateThumbprint,
    [string]$ClientID,
    [string]$TenantId
)
if (-not(Get-MgContext)) {
    Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientID -TenantId $TenantId 
    if (-not(Get-MgContext)) {
        exit
    }
}
function Get-ScriptPath {
    <#
    .SYNOPSIS
    Get the current script path.
    #>
    if ($PSScriptRoot) { 
        # Console or VS Code debug/run button/F5 temp console
        $ScriptRoot = $PSScriptRoot 
    } else {
        if ($psISE) { 
            Split-Path -Path $psISE.CurrentFile.FullPath
        } else {
            if ($profile -match 'VScode') { 
                # VS Code "Run Code Selection" button/F8 in integrated console
                $ScriptRoot = Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
            } else { 
                Write-Output 'unknown directory to set path variable. exiting script.'
                exit
            } 
        } 
    }
    $Script:PathToScript = $ScriptRoot
}
function Initialize-Script {
    <#
    .SYNOPSIS
    Will initialize most of the required variables throughout this script.
    #>
    $Script:DateTime = Get-Date -Format yyyyMMdd_HHmmss
    if (-not($Script:CurrentLocation)) {
        $Script:CurrentLocation = Get-Location
    }
    if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null } 
    if ((Get-Location).path -ne $WorkingDirectory) {
        Set-Location $WorkingDirectory
    }
    Get-ScriptPath
    if (-not($Script:LogFile)) {
        if (-not($LogPrefix)) {
            $Script:LogPrefix = 'SIS'#Search Intune Settings
        } else {
            $Script:LogPrefix = $LogPrefix
        }
        $Script:LogFile = Join-Path -Path $Script:LogDirectory -ChildPath ('{0}_{1}.log' -f $Script:LogPrefix, $Script:DateTime)
        if (-not(Test-Path $Script:LogDirectory)) { New-Item $Script:LogDirectory -ItemType Directory -Force | Out-Null }
    }
}
