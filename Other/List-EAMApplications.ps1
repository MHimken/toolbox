<#
.SYNOPSIS
This script will provide the current list of all EAM applications
.DESCRIPTION
Will return the list in an Out-Gridview. This script requires the Graph module to be installed.
.EXAMPLE
.\List-EAMApplications.ps1 -TenantAPIToUse /beta
This example is all you need - it will request an interactive auth and get the applications.
NOTE THAT THIS REQUIRES A USER WITH AN ACTIVE EAM LICENSE AND INTERACTIVE AUTHENTICATION. A custom application will _not_ work!
.NOTES
    Version: 1.0
    Versionname: Initial
    Intial creation date: 07.03.2025
    Last change date: 08.03.2025
    Latest changes: https://github.com/MHimken/toolbox/tree/main/Autopilot/MEMNetworkRequirements/changelog.md
#>
param(
    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$WorkingDirectory = "$env:SystemDrive\EAMApps\",

    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$LogDirectory = "$WorkingDirectory\Logs\",

    [Parameter(Mandatory = $false)]
    [ValidateSet('/beta', '/v1.0')]
    [String]$TenantAPIToUse = '/beta',

    [Parameter(Mandatory = $True, ParameterSetName = 'CertificateAuth')]
    [String]$CertificateThumbprint,

    [Parameter(Mandatory = $True, ParameterSetName = 'CertificateAuth')]
    [Parameter(Mandatory = $True, ParameterSetName = 'SignInAuthCustom')]
    [String]$ClientID,

    [Parameter(Mandatory = $True, ParameterSetName = 'CertificateAuth')]
    [Parameter(Mandatory = $False, ParameterSetName = 'SignInAuth')]
    [Parameter(Mandatory = $True, ParameterSetName = 'SignInAuthCustom')]
    [String]$TenantID,

    [Parameter(Mandatory = $true, ParameterSetName = 'AccessTokenAuth')]
    [Securestring]$AccessToken
)

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
        $LogPrefix = 'EAML' #Enterprise App Management List
        $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
        if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
    }
}
function Write-Log {
    <#
    .DESCRIPTION
        This is a modified version of the script by Ryan Ephgrave.
        .LINK
        https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')][int]$Type
    )
    if (-not($NoLog)) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
        } elseif ($ToConsole) {
            switch ($type) {
                1 { Write-Host "T:$Type C:$Component M:$Message" }
                2 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Yellow -ForegroundColor Black }
                3 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Red -ForegroundColor White }
                default { Write-Host "T:$Type C:$Component M:$Message" }
            }
        }
    }
}
function Connect-ToGraph {
    param(
        [string]$AuthMethod
    )    
    switch -Exact ($AuthMethod) {
        'SignInAuth' {
            $Splat = @{}
            if (-not([string]::IsNullOrEmpty($TenantID))) {
                $Splat['TenantId'] = $TenantID
            }
            $Splat['Scopes'] = $RequiredGraphScopes
        }
        'SignInAuthCustom' {
            $Splat = @{
                'TenantId' = $TenantID
                'ClientId' = $ClientID
            }
        }
        'CertificateAuth' {
            $Splat = @{
                'TenantId'              = $TenantID
                'ClientId'              = $ClientID
                'CertificateThumbPrint' = $CertificateThumbprint
            }
        }
        'AccessTokenAuth' {
            $Splat = @{
                'AccessToken' = $AccessToken
            }
        }
    }
    Connect-MgGraph @Splat
    $Splat = $Null
    $MgContext = Get-MgContext
    if ($null -eq $($MgContext)) {
        Write-Log -Message 'The connection could not be established, please verify you can connect by using Connect-MgGraph' -Component 'GFDConnectToGraph' -Type 3
        Return $false
    }
    if ($Null -ne ($RequiredGraphScopes | Where-Object { $_ -notin $MgContext.Scopes })) {
        Write-Log -Message 'The required Microsoft Graph scopes are not present in the authentication context. Please use Disconnect-MgGraph and try again' -Component 'GFDConnectToGraph' -Type 3        
        Return $false
    }
    
    Return $true
}
function Get-nextLinkData {
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $nextLink = ''
        $nextLink = $Request.'@odata.nextLink'
    }
    return $Results
}

#Start Coding!
Initialize-Script

$MgContext = Get-MgContext
if ($null -eq $($MgContext)) {
    if (Connect-ToGraph -AuthMethod $PSCmdlet.ParameterSetName) {
        Write-Log -Message 'Connection failed - please consult the logs' -Component 'GFDCore' -Type 2
    }
} else {
    if ($Null -ne ($RequiredGraphScopes | Where-Object { $_ -notin $MgContext.Scopes })) {
        #throw [System.Security.Authentication.AuthenticationException]::New('The required Microsoft Graph scopes are not present in the authentication context. Please use Disconnect-MgGraph and try again')
        Write-Log -Message 'The required Microsoft Graph scopes are not present in the authentication context. Please use Disconnect-MgGraph and try again' -Component 'GFDCore' -Type 3
    }
}
$EAMAppsQuery = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppCatalogPackages"
$AllEAEMApps = Get-nextLinkData -OriginalObject $EAMAppsQuery
$ResultList = [System.Collections.ArrayList]::new()
$Counter = 0
foreach ($EAMApp in $AllEAEMApps.value) {
    $EAMAppObject = [PSCustomObject]@{
        Counter       = $Counter
        DisplayName = $EAMApp.productDisplayName
        BranchDisplayName = $EAMApp.branchDisplayName
        Version     = $EAMApp.versionDisplayName
        SelfUpdate = $EAMApp.packageAutoUpdateCapable
    }
    $ResultList.add($EAMAppObject) | Out-Null
    $Counter++
}
$ResultList | Out-GridView
Disconnect-MgGraph
Set-Location $Script:CurrentLocation