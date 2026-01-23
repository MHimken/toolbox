<#
.SYNOPSIS
    This script creates a new "on-premises" application in Entra ID. It is a replacement for the cmdlet New-AzureADApplicationProxyApplication
.DESCRIPTION
    This script uses Microsoft Graph to create a new "on-premises" application in Entra ID based on the "On-premises application" template.
    The only reason I made this is because the new cmdlet is still in Beta, see link below.
.NOTES
    Version: 1.0
    Versionname: New-AzureADApplicationProxyApplicationCommunity
    Initial creation date: 19.01.2026
    Last change date: 19.01.2026
    Latest changes: Initial Version
    Sources: https://learn.microsoft.com/en-us/powershell/module/microsoft.entra.beta.applications/new-entrabetaapplicationproxyapplication?
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string]$DisplayName = "",
    [ValidateSet("Global", "USGov", "China")]
    [string]$Region = "Global",
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string]$InternalURL = "",
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string]$ExternalURL = "",
    [ValidateSet("Default", "Long")] # Only these two are supported by App Proxy
    [string]$applicationServerTimeout = "Default",
    [ValidateSet( "Passthru", "AadPreAuthentication")] # Only these two are supported by App Proxy
    [string]$externalAuthenticationType = "AadPreAuthentication",
    [bool]$isHttpOnlyCookieEnabled = $false,
    [bool]$isPersistentCookieEnabled = $false,
    [bool]$isBackendCertificateValidationEnabled = $true,
    [bool]$isTranslateHostHeaderEnabled = $true,
    [bool]$isTranslateLinksInBodyEnabled = $false,
    [bool]$useAlternateUrlForTranslationAndRedirect = $false,
    [string]$ConnectorGroupId = ""
)
$RequiredScopes = @(
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All" # This one can only be used with Delegated Permissions as of 19.01.2026
)
function Initialize-Script {
    switch ($Region) {
        "Global" {
            $Script:EntraEnvironment = "Global"
            $Script:AppTemplateId = "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"
        }
        "USGov" {
            $Script:EntraEnvironment = "USGov"
            $Script:AppTemplateId = "4602d0b4-76bb-404b-bca9-2652e1a39c6d"
        }
        "China" {
            $Script:EntraEnvironment = "China"
            $Script:AppTemplateId = "5a532e38-1581-4918-9658-008dc27c1d68"
        }
    }
    # Validate that URLs must end on a slash and are well formed
    # We check well formed by looking if they start with http or https first
    if (-not($ExternalURL.StartsWith("http://") -or $ExternalURL.StartsWith("https://"))) {
        Write-Error "External URL must start with http:// or https://"
        Exit 1
    }
    if (-not($InternalURL.StartsWith("http://") -or $InternalURL.StartsWith("https://"))) {
        Write-Error "Internal URL must start with http:// or https://"
        Exit 1
    }
    # We also check for at least one dot in the URL to ensure its a FQDN for the external URL
    $ExternalURLHost = ([uri]$ExternalURL).Host
    if (-not($ExternalURLHost.Contains("."))) {
        Write-Error "External URL must be a fully qualified domain name (FQDN)"
        Exit 1
    }
    # Ensure both URLs end with a slash
    if ($ExternalURL[-1] -ne "/") {
        $ExternalURL = "$ExternalURL/"
    }
    if ($InternalURL[-1] -ne "/") {
        $InternalURL = "$InternalURL/"
    }
}
function New-EntraAppWithTemplate {
    $GraphEndpointRequestApp = "beta/applicationTemplates/$($Script:AppTemplateId)/instantiate"
    $Method = "POST"
    $body = @{
        displayName = $DisplayName
    } | ConvertTo-Json
    $RequestID = Invoke-MgGraphRequest -Method $Method -Uri $GraphEndpointRequestApp -Body $body
    $ObjectID = $RequestID.application.objectId
    $GraphEndpointGetApp = "beta/applications/$ObjectID"
    $GetAppID = Invoke-MgGraphRequest -Method "GET" -Uri $GraphEndpointGetApp | Select-Object -ExpandProperty appId
    return @{
        AppId    = $GetAppID
        ObjectID = $ObjectID
    }
}
function Get-ConnectorGroupIds {
    $GraphEndpointConnectorGroups = "beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups"
    $Method = "GET"
    $ConnectorGroups = Invoke-MgGraphRequest -Method $Method -Uri $GraphEndpointConnectorGroups
    $Script:ConnectorGroupIds = [System.Collections.ArrayList]::new()
    foreach ($cg in $ConnectorGroups.value) {
        $Script:ConnectorGroupIds.add(@{ Name = $cg.Name; Id = $cg.Id })
    }
}
function Get-ConnectorGroupFromUser {
    if (-not($Script:ConnectorGroupIds)) {
        Get-ConnectorGroupIds
    }
    if ($Script:ConnectorGroupIds.count -eq 1) {
        return ($Script:ConnectorGroupIds["Default"]) # Only one Connector Group found, return it
    } else {
        Write-Host "Multiple Connector Groups found. Select 'Default' when unsure. Please select one:"
        $i = 1
        $Script:ConnectorGroupIds | ForEach-Object {
            Write-Host "$i. $($_.Name) (ID: $($_.Id))"
            $i++
        }
        $selection = Read-Host "Enter the number of the Connector Group to use"
        if ($selection -match '^\d+$' -and $selection -ge 1 -and $selection -le $Script:ConnectorGroupIds.Count) {
            return $Script:ConnectorGroupIds[$selection - 1].id
        }
        Write-Error "Invalid selection."
        Exit 1
    }
    return $null
}
function New-EntraAppSettings {
    param(
        [string]$AppId
    )
    $GraphEndpointAppProxy = "beta/applications/$AppId"
    $Method = "PATCH"
    $body = @{
        api            = @{
            requestedAccessTokenVersion = 2
        }
        identifierUris = @($ExternalURL)
        web            = @{
            homePageUrl           = "$ExternalURL"
            implicitGrantSettings = @{
                enableAccessTokenIssuance = $false
                enableIdTokenIssuance     = $true
            }
            logoutUrl             = "$ExternalURL/?appproxy=logout"
            redirectUris          = @("$ExternalURL/")
        }
    } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method $Method -Uri $GraphEndpointAppProxy -Body $body | Out-Null
}
function New-EntraAppProxySettings {
    param(
        [string]$AppId
    )
    $body = @{
        externalUrl                              = "$ExternalURL/"
        internalUrl                              = $InternalURL
        applicationServerTimeout                 = "Default"
        externalAuthenticationType               = $externalAuthenticationType
        isBackendCertificateValidationEnabled    = $isBackendCertificateValidationEnabled
        isHttpOnlyCookieEnabled                  = $isHttpOnlyCookieEnabled
        isOnPremPublishingEnabled                = $true #This is what makes it an App Proxy app so its not configurable in this script
        isPersistentCookieEnabled                = $isPersistentCookieEnabled
        isTranslateHostHeaderEnabled             = $isTranslateHostHeaderEnabled
        isTranslateLinksInBodyEnabled            = $isTranslateLinksInBodyEnabled
        useAlternateUrlForTranslationAndRedirect = $useAlternateUrlForTranslationAndRedirect
    } | ConvertTo-Json -Depth 10
    $GraphEndpointAppProxy = "beta/applications/$AppId/onPremisesPublishing"
    $Method = "PATCH"
    Invoke-MgGraphRequest -Method $Method -Uri $GraphEndpointAppProxy -Body $body | Out-Null
}
function Add-AppToConnectorGroup {
    param(
        [string]$AppId,
        [string]$ConnectorGroupId
    )
    $GraphEndpointAppProxy = "/applications/$AppId/connectorGroup/$ref"
    $Method = "PUT"
    $body = @{
        connectorGroup = @{
            "@odata.id" = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId"
        }
    } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method $Method -Uri $GraphEndpointAppProxy -Body $body | Out-Null
}
# Start coding!
Initialize-Script
if (-not(Get-MGContext)) {
    Connect-MgGraph -Scopes $RequiredScopes -Environment $Script:EntraEnvironment
}
if (-not((Get-MGContext).authtype -eq "Delegated")) {
    Write-Error "This script requires Delegated Permissions. Please connect with Connect-MgGraph using Delegated Permissions."
    Exit 1
}
if (-not($ConnectorGroupId)) {
    $ConnectorGroupId = Get-ConnectorGroupFromUser
    if (-not($ConnectorGroupId)) {
        Write-Error "No Connector Group ID provided or selected. Exiting."
        Exit 1
    }
}
Write-Host "Creating new Entra ID Application with template..."
$AppId = New-EntraAppWithTemplate
Write-Host "Created new Entra ID Application with ID: $AppId"
Write-Host "Pre-Configuring the Application"
New-EntraAppSettings -AppId $AppId.AppId
Write-Host "Pre-configured Application settings for Application ID: $($AppId.AppId)"
Write-Host "Configuring Application Proxy settings as follows..."
Write-Host "  External URL: $ExternalURL"
Write-Host "  Internal URL: $InternalURL"
New-EntraAppProxySettings -AppId $AppId.AppId
Write-Host "Configured Application Proxy settings for Application ID: $($AppId.AppId)"
Write-Host "Finally, put the Application into the specified Connector Group..."
Add-AppToConnectorGroup -AppId $AppId.AppId -ConnectorGroupId $ConnectorGroupId