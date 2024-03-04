<#
.SYNOPSIS
Will assign a given set of configuration profiles to a given group.
.DESCRIPTION
Needs works by looking for a prefix in the name of configuration profiles and will assign that to a given group.
.NOTES
Version: 0.1
#>
[CmdletBinding()]
param(
    [string]$ConfigProfilePrefix = 'CIS',
    [string]$GroupName,
    [string[]]$RequiredGraphScopes,
    [string]$CertificateThumbprint,
    [string]$ClientID,
    [string]$TenantID,
    [Parameter(Mandatory = $false)]
    [ValidateSet('/beta', '/v1.0')]
    [String]$TenantAPIToUse = '/beta',
    [switch]$ToConsole
)
function Write-Log {
    <#
    .DESCRIPTION
        This is a modified version of Ryan Ephgrave's script
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
    $Time = Get-Date -Format 'HH:mm:ss.ffffff'
    $Date = Get-Date -Format 'MM-dd-yyyy'
    if (-not($Component)) { $Component = 'Runner' }
    if (-not($Type)) { $Type = 1 }
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
function Get-ConfigurationProfiles {

}
#Start Coding!
$MgContext = Get-MgContext
if ($null -eq $($MgContext)) {
    if (Connect-ToGraph -AuthMethod CertificateAuth) {
        Write-Log -Message 'Connection failed - please consult the logs' -Component 'CisToGroupCore' -Type 2
    }
} else {
    if ($Null -ne ($RequiredGraphScopes | Where-Object { $_ -notin $MgContext.Scopes })) {
        Write-Log -Message 'The required Microsoft Graph scopes are not present in the authentication context. Please use Disconnect-MgGraph and try again' -Component 'CisToGroupCore' -Type 3
        exit 6
    }
}
$AllSettingsCatalogProfiles = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/configurationPolicies/?`$select=id&`$filter=startsWith(name, '$ConfigProfilePrefix')"
$AllSettingsCatalogProfiles = Get-nextLinkData -OriginalObject $AllSettingsCatalogProfiles
$GroupID = (Get-MgGroup -Search "displayname:$GroupName" -ConsistencyLevel eventual).id
foreach ($Configuration in $AllSettingsCatalogProfiles.value) {
    $RequestURI = "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/configurationPolicies('$($Configuration.id)')/assign"
    $JSONPayload = ConvertTo-Json -Depth 4 @{
        "assignments" = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $GroupID
                }
            }
        )
    }
    Invoke-MgRestMethod -Method POST -Uri $RequestURI -Body $JSONPayload
}
Disconnect-MgGraph