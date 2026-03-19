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
.NOTES
    Search Filters:
    * Add risk level from the settings
    * Assigned + unassigned
    To do:
    * Fix search
    * Fix settings being added multiple times to $Script:ConfigurationPolicies 
    * Add settings window
#>
[CmdletBinding()]
param (
    [string]$SearchString,
    [ValidateSet('en', 'cs', 'de', 'es', 'fr', 'hu', 'id', 'it', 'ja', 'ko', 'nl', 'pl', 'pt-BR', 'pt-PT', 'ru', 'sv', 'tr', 'zh-hans', 'zh-hant')]
    [string]$Language = 'de',
    [string]$APIVersion = 'beta',
    [System.IO.DirectoryInfo]$WorkingFolder,
    [string]$SettingType,
    [string]$LogPrefix = 'SIS',
    [switch]$NoLog,
    [string]$CertificateThumbprint,
    [string]$ClientID,
    [string]$TenantId
)
$RequiredScopes = @("DeviceManagementConfiguration.Read.All")
function Connect-SISGraph {
    param(
        [string]$ClientID,
        [string]$CertificateThumbprint,
        [boolean]$ModuleInstallationAllowed,
        [string]$TenantId,
        [ValidateSet('Global', 'USGov', 'China', 'Germany')]
        [string]$Environment = 'Global',
        [PSCredential]$AppSecretCredential
    )
    <#
    .SYNOPSIS
    Connects to Microsoft Graph using the provided credentials.
    #>
    try {
        Get-MgContext -ErrorAction Stop | Out-Null
        $RequiredScopes.ForEach({ if (-not((Get-MgContext).Scopes -contains $_)) { throw } })
        Write-Verbose "Already connected to Microsoft Graph with required scopes."
        return $true
    } catch {
        Write-Verbose "Not connected to Microsoft Graph or required scopes are missing. Attempting to (re-)connect..."
    }
    if (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable -ErrorAction SilentlyContinue) {
        Write-Verbose "Microsoft.Graph.Authentication module is already imported."
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            Write-Verbose "Microsoft.Graph.Authentication module imported successfully."
        } catch {
            $ErrorMessage = "Microsoft.Graph.Authentication could not be imported. Please ensure the module is installed and try again. Error details: $_"
            Write-Error $_.ErrorDetails.error.message
            return $ErrorMessage
        }
    } elseif ($ModuleInstallationAllowed) {
        try {
            Install-Module Microsoft.Graph.Authentication -Force -Scope CurrentUser
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        } catch {
            $ErrorMessage = "Failed to install or import Microsoft.Graph.Authentication module: $_. Please ensure you have the necessary permissions and try again."
            Write-Error $ErrorMessage
            return $ErrorMessage
        }
    } else {
        $ErrorMessage = "Microsoft.Graph.Authentication module is not available. Please install it using 'Install-Module Microsoft.Graph.Authentication' and try again."
        Write-Error $ErrorMessage
        return $ErrorMessage
    }
    try {
        if (($CertificateThumbprint -or $AppSecret) -and $ClientID -and $TenantId) {
            $ConnectionParams = @{
                Environment = $Environment
                TenantId    = $TenantId
            }
            if ($CertificateThumbprint) {
                $ConnectionParams.ClientId = $ClientID
                $ConnectionParams.CertificateThumbprint = $CertificateThumbprint
            } elseif ($AppSecretCredential) {
                $ConnectionParams.ClientSecretCredential = $AppSecretCredential
            }
            Connect-MgGraph @ConnectionParams -NoWelcome
        } else {
            Connect-MgGraph -Environment $Environment -NoWelcome -Scopes $RequiredScopes
        }
    } catch {
        $ErrorMessage = "Failed to connect to Microsoft Graph: $_"
        Write-Error $ErrorMessage
        return $ErrorMessage
    }
    $AvailableScopes = (Get-MgContext).Scopes
    if (-not($AvailableScopes -contains "DeviceManagementConfiguration.Read.All") -and -not($AvailableScopes -contains "DeviceManagementConfiguration.ReadWrite.All")) {
        $ErrorMessage = "Connected to Microsoft Graph, but the required scope 'DeviceManagementConfiguration.Read.All' is not available. Please ensure you have the necessary permissions."
        Write-Error $ErrorMessage
        return $ErrorMessage
    }
    return $true
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
    if ($WorkingFolder) {
        if (-not(Test-Path $WorkingFolder )) { New-Item $WorkingFolder -ItemType Directory -Force | Out-Null } 
        if ((Get-Location).path -ne $WorkingFolder) {
            Set-Location $WorkingFolder
        }
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
    Get-ScriptPath
    $Script:PolicyTypesFromGraph = @()
    $Script:PlatformsFromGraph = @()
    $Script:QueryLanguageMap = @{
        'English'                = 'en'
        'Czech'                  = 'cs'
        'German'                 = 'de'
        'Spanish'                = 'es'
        'French'                 = 'fr'
        'Hungarian'              = 'hu'
        'Indonesian'             = 'id'
        'Italian'                = 'it'
        'Japanese'               = 'ja'
        'Korean'                 = 'ko'
        'Dutch'                  = 'nl'
        'Polish'                 = 'pl'
        'Portuguese (Brazil)'    = 'pt-BR'
        'Portuguese (Portugal)'  = 'pt-PT'
        'Russian'                = 'ru'
        'Swedish'                = 'sv'
        'Turkish'                = 'tr'
        'Chinese Simplified'     = 'zh-hans'
        'Chinese Traditional'    = 'zh-hant'
    }
    $Script:QueryLanguagesHumanReadable = @($Script:QueryLanguageMap.Keys | Sort-Object)

    # Build Invoke-MGGRaphRequest URI base
    $Script:GraphApiBaseUri = "https://graph.microsoft.com/$APIVersion/"
    
    # Map policy types to their corresponding Graph API endpoints and make them human readable
    $Script:PolicyTypeToURIMap = @{
        'App Config Policy'          = 'deviceAppManagement/mobileAppConfigurations' # Is this relevant?
        'Compliance Policy'          = 'deviceManagement/deviceCompliancePolicies'
        'Configuration Policy'       = 'deviceManagement/configurationPolicies'
        'Device Configuration'       = 'deviceManagement/deviceConfigurations' # ToDo create odata type map for this # OLD policies - basically everything that is created through "Templates" in the Intune portal
        'Group Policy Configuration' = 'deviceManagement/groupPolicyConfigurations' # ToDo create odata type map for this
        'Hardware Configuration'     = 'deviceManagement/hardwareConfigurations'
        'Resource Access Profile'    = 'deviceManagement/resourceAccessProfiles' # ToDo create odata type map for this
        'Inventory Policy'           = 'deviceManagement/inventoryPolicies' # ToDo create odata type map for this
    }
    $Script:PolicyTypeMapToHumanReadable = @{
        "#microsoft.graph.deviceManagementConfigurationSimpleSettingDefinition"           = 'Simple Setting'
        "#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition"           = 'Choice Setting'
        "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionDefinition" = 'Simple Setting Collection'
        "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionDefinition" = 'Choice Setting Collection'
        "#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition"  = 'Setting Group Collection'
    }
    # Map OS platforms to human readable names
    $Script:PlatformMap = @{
        'all'                                      = 'All'
        'android'                                  = 'Android device administrator'
        'androidAOSP'                              = 'Android (AOSP)'
        'androidEnterprise'                        = 'Android Enterprise'
        'androidForWork'                           = 'Android Enterprise'
        'androidWorkProfile'                       = 'Android enterprise'
        'common'                                   = 'Common'
        'iOS'                                      = 'iOS/iPadOS'
        'iOSAndWindowsPlatformLabel'               = 'Windows and iOS'
        'iOSiPadOS'                                = 'iOS/iPadOS'
        'iosAndAndroidPlatformLabel'               = 'iOS and Android'
        'iosCommaAndroidPlatformLabel'             = 'iOS, Android'
        'linux'                                    = 'Linux'
        'macOS'                                    = 'macOS'
        'unknown'                                  = 'Unknown'
        'unsupported'                              = 'Unsupported'
        'windows'                                  = 'Windows'
        'windows10'                                = 'Windows 10 and later'
        'windows10Holo'                            = 'Windows 10 Holographic'
        'windows10Mobile'                          = 'Windows 10 Mobile'
        'windows10Team'                            = 'Windows 10 Team'
        'windows10X'                               = 'Windows 10X'
        'windows8'                                 = 'Windows 8.1 and later'
        'windows8And10'                            = 'Windows 8 and 10'
        'windowsAndAndroidPlatformLabel'           = 'Windows and Android'
        'windowsCommaIOSCommaAndroidPlatformLabel' = 'Windows, iOS, and Android'
        'windowsPhone'                             = 'Windows Phone 8.1'
    }
    <#
        Taken from a json file in /intunedevicesettings/Content/Dynamic
        Platform: {
        all: "All",
        android: "Android device administrator",
        androidAOSP: "Android (AOSP)",
        androidEnterprise: "Android Enterprise",
        androidForWork: "Android Enterprise",
        androidWorkProfile: "Android enterprise",
        common: "Common",
        iOS: "iOS/iPadOS",
        iOSAndWindowsPlatformLabel: "Windows and iOS",
        iOSiPadOS: "iOS/iPadOS",
        iosAndAndroidPlatformLabel: "iOS and Android",
        iosCommaAndroidPlatformLabel: "iOS, Android",
        linux: "Linux",
        macOS: "macOS",
        unknown: "Unknown",
        unsupported: "Unsupported",
        windows: "Windows",
        windows10: "Windows 10 and later",
        windows10Holo: "Windows 10 Holographic",
        windows10Mobile: "Windows 10 Mobile",
        windows10Team: "Windows 10 Team",
        windows10X: "Windows 10X",
        windows8: "Windows 8.1 and later",
        windows8And10: "Windows 8 and 10",
        windowsAndAndroidPlatformLabel: "Windows and Android",
        windowsCommaIOSCommaAndroidPlatformLabel: "Windows, iOS, and Android",
        windowsPhone: "Windows Phone 8.1"

        original from me
            $Script:PlatformMap = @{
        'aosp'              = 'Android Open Source Project'
        'androidEnterprise' = 'Android Enterprise'
        'iOS'               = 'iOS'
        'linux'             = 'Linux'
        'macOS'             = 'macOS'
        'tvOS'              = 'tvOS'
        'visionOS'          = 'visionOS'
        'windows10'         = 'Windows 10/11'
    }
    }#>
    # Map policy type by odata type to human readable names
    $Script:PolicyTypeODataMapAppConfigPolicy = @{
        # APP policies
        "#microsoft.graph.managedDeviceMobileAppConfiguration" = 'Managed Device Mobile App Configuration'
    }
    $Script:PolicyTypeODataMapCompliancePolicy = @{
        # Android
        "#microsoft.graph.androidCompliancePolicy"            = 'Android Compliance Policy'
        # Android Device Owner
        "#microsoft.graph.androidDeviceOwnerCompliancePolicy" = 'Android Device Owner Compliance Policy'
        # Android for Work
        "#microsoft.graph.androidForWorkCompliancePolicy"     = 'Android for Work Compliance Policy'
        # Android Work
        "#microsoft.graph.androidWorkProfileCompliancePolicy" = 'Android Work Profile Compliance Policy'
        # Android Open Source Project (AOSP)
        "#microsoft.graph.aospDeviceOwnerCompliancePolicy"    = 'Android Open Source Project (AOSP) Device Owner Compliance Policy'
    }
    $Script:PolicyTypeODataMapHardwareConfiguration = @{
        # BIOS/UEFI Configuration
        "#microsoft.graph.hardwareConfiguration" = 'BIOS/UEFI Configuration'
    }
    $Script:PolicyTypeToOSMap = @{
        # Android
        'android'            = @{
            "#microsoft.graph.androidCertificateProfileBase"        = 'Android Certificate Profile Base'
            "#microsoft.graph.androidCustomConfiguration"           = 'Android Custom Configuration'
            "#microsoft.graph.androidEasEmailProfileConfiguration"  = 'Android EAS Email Profile Configuration'
            "#microsoft.graph.androidGeneralDeviceConfiguration"    = 'Android General Device Configuration'
            "#microsoft.graph.androidImportedPFXCertificateProfile" = 'Android Imported PFX Certificate Profile'
            "#microsoft.graph.androidOmaCpConfiguration"            = 'Android OMA-CP Configuration'
            "#microsoft.graph.androidPkcsCertificateProfile"        = 'Android PKCS Certificate Profile'
            "#microsoft.graph.androidScepCertificateProfile"        = 'Android SCEP Certificate Profile'
            "#microsoft.graph.androidTrustedRootCertificate"        = 'Android Trusted Root Certificate'
            "#microsoft.graph.androidVpnConfiguration"              = 'Android VPN Configuration'
            "#microsoft.graph.androidWiFiConfiguration"             = 'Android Wi-Fi Configuration'
        }
        # Android Enterprise
        'androidEnterprise'  = @{
            "#microsoft.graph.androidEnterpriseWiFiConfiguration" = 'Android Enterprise Wi-Fi Configuration'
        }
        # Android Device Owner
        'androidDeviceOwner' = @{
            "#microsoft.graph.androidDeviceOwnerDerivedCredentialAuthenticationConfiguration" = 'Android Device Owner Derived Credential Authentication Configuration'
            "#microsoft.graph.androidDeviceOwnerEnterpriseWiFiConfiguration"                  = 'Android Device Owner Enterprise Wi-Fi Configuration'
            "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration"                   = 'Android Device Owner General Configuration'
            "#microsoft.graph.androidDeviceOwnerImportedPFXCertificateProfile"                = 'Android Device Owner Imported PFX Certificate Profile'
            "#microsoft.graph.androidDeviceOwnerPkcsCertificateProfile"                       = 'Android Device Owner PKCS Certificate Profile'
            "#microsoft.graph.androidDeviceOwnerScepCertificateProfile"                       = 'Android Device Owner SCEP Certificate Profile'
            "#microsoft.graph.androidDeviceOwnerTrustedRootCertificate"                       = 'Android Device Owner Trusted Root Certificate'
            "#microsoft.graph.androidDeviceOwnerVpnConfiguration"                             = 'Android Device Owner VPN Configuration'
            "#microsoft.graph.androidDeviceOwnerWiFiConfiguration"                            = 'Android Device Owner Wi-Fi Configuration'
        }
        # Android for work
        'androidForWork'     = @{
            "#microsoft.graph.androidForWorkCertificateProfileBase"        = 'Android for Work Certificate Profile Base'
            "#microsoft.graph.androidForWorkCustomConfiguration"           = 'Android for Work Custom Configuration'
            "#microsoft.graph.androidForWorkEasEmailProfileBase"           = 'Android for Work EAS Email Profile Base'
            "#microsoft.graph.androidForWorkEnterpriseWiFiConfiguration"   = 'Android for Work Enterprise Wi-Fi Configuration'
            "#microsoft.graph.androidForWorkGeneralDeviceConfiguration"    = 'Android for Work General Configuration'
            "#microsoft.graph.androidForWorkGmailEasConfiguration"         = 'Android for Work Gmail EAS Configuration'
            "#microsoft.graph.androidForWorkImportedPFXCertificateProfile" = 'Android for Work Imported PFX Certificate Profile'
            "#microsoft.graph.androidForWorkNineWorkEasConfiguration"      = 'Android for Work Nine Work EAS Configuration'
            "#microsoft.graph.androidForWorkPkcsCertificateProfile"        = 'Android for Work PKCS Certificate Profile'
            "#microsoft.graph.androidForWorkScepCertificateProfile"        = 'Android for Work SCEP Certificate Profile'
            "#microsoft.graph.androidForWorkTrustedRootCertificate"        = 'Android for Work Trusted Root Certificate'
            "#microsoft.graph.androidForWorkVpnConfiguration"              = 'Android for Work VPN Configuration'
            "#microsoft.graph.androidForWorkWiFiConfiguration"             = 'Android for Work Wi-Fi Configuration'
        }
        # Android Work
        'androidWorkProfile' = @{
            "#microsoft.graph.androidWorkProfileCertificateProfileBase"      = 'Android Work Profile Certificate Profile Base'
            "#microsoft.graph.androidWorkProfileCustomConfiguration"         = 'Android Work Profile Custom Configuration'
            "#microsoft.graph.androidWorkProfileEasEmailProfileBase"         = 'Android Work Profile EAS Email Profile Base'
            "#microsoft.graph.androidWorkProfileEnterpriseWiFiConfiguration" = 'Android Work Profile Enterprise Wi-Fi Configuration'
            "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration"  = 'Android Work Profile General Configuration'
            "#microsoft.graph.androidWorkProfileGmailEasConfiguration"       = 'Android Work Profile Gmail EAS Configuration'
            "#microsoft.graph.androidWorkProfileNineWorkEasConfiguration"    = 'Android Work Profile Nine Work EAS Configuration'
            "#microsoft.graph.androidWorkProfilePkcsCertificateProfile"      = 'Android Work Profile PKCS Certificate Profile'
            "#microsoft.graph.androidWorkProfileScepCertificateProfile"      = 'Android Work Profile SCEP Certificate Profile'
            "#microsoft.graph.androidWorkProfileTrustedRootCertificate"      = 'Android Work Profile Trusted Root Certificate'
            "#microsoft.graph.androidWorkProfileVpnConfiguration"            = 'Android Work Profile VPN Configuration'
            "#microsoft.graph.androidWorkProfileWiFiConfiguration"           = 'Android Work Profile Wi-Fi Configuration'
        }
        # Android Open Source Project (AOSP)
        'aosp'               = @{
            "#microsoft.graph.aospDeviceOwnerCertificateProfileBase"      = 'Android Open Source Project (AOSP) Device Owner Certificate Profile Base'
            "#microsoft.graph.aospDeviceOwnerDeviceConfiguration"         = 'Android Open Source Project (AOSP) Device Owner Device Configuration'
            "#microsoft.graph.aospDeviceOwnerEnterpriseWiFiConfiguration" = 'Android Open Source Project (AOSP) Device Owner Enterprise Wi-Fi Configuration'
            "#microsoft.graph.aospDeviceOwnerPkcsCertificateProfile"      = 'Android Open Source Project (AOSP) Device Owner PKCS Certificate Profile'
            "#microsoft.graph.aospDeviceOwnerScepCertificateProfile"      = 'Android Open Source Project (AOSP) Device Owner SCEP Certificate Profile'
            "#microsoft.graph.aospDeviceOwnerTrustedRootCertificate"      = 'Android Open Source Project (AOSP) Device Owner Trusted Root Certificate'
            "#microsoft.graph.aospDeviceOwnerWiFiConfiguration"           = 'Android Open Source Project (AOSP) Device Owner Wi-Fi Configuration'
        }
        # Apple
        'apple'              = @{
            "#microsoft.graph.appleDeviceFeaturesConfigurationBase"   = 'Apple Device Features Configuration Base'
            "#microsoft.graph.appleExpeditedCheckinConfigurationBase" = 'Apple Expedited Check-in Configuration Base'
            "#microsoft.graph.appleVpnConfiguration"                  = 'Apple VPN Configuration'
        }
        # iOS
        'iOS'                = @{
            "#microsoft.graph.iosDeviceFeaturesConfiguration"  = 'iOS Device Features Configuration'
            "#microsoft.graph.iosEasEmailProfileConfiguration" = 'iOS EAS Email Profile Configuration'
            "#microsoft.graph.iosGeneralDeviceConfiguration"   = 'iOS General Device Configuration'
            "#microsoft.graph.iosTrustedRootCertificate"       = 'iOS Trusted Root Certificate'
            "#microsoft.graph.iosUpdateConfiguration"          = 'iOS Update Configuration'
            "#microsoft.graph.iosVpnConfiguration"             = 'iOS VPN Configuration'
            "#microsoft.graph.iosWiFiConfiguration"            = 'iOS Wi-Fi Configuration'
        }
        # macOS
        'macOS'              = @{
            "#microsoft.graph.macOSCustomAppConfiguration"      = 'macOS Custom App Configuration'
            "#microsoft.graph.macOSCustomConfiguration"         = 'macOS Custom Configuration'
            "#microsoft.graph.macOSDeviceFeaturesConfiguration" = 'macOS Device Features Configuration'
            "#microsoft.graph.macOSExtensionsConfiguration"     = 'macOS Extensions Configuration'
            "#microsoft.graph.macOSSoftwareUpdateConfiguration" = 'macOS Software Update Configuration'
            "#microsoft.graph.macOSTrustedRootCertificate"      = 'macOS Trusted Root Certificate'
        }
        # Windows
        'windows'            = @{
            "#microsoft.graph.editionUpgradeConfiguration"            = 'Edition Upgrade Configuration'
            "#microsoft.graph.groupPolicyConfiguration"               = 'Group Policy Configuration'
            "#microsoft.graph.sharedPCConfiguration"                  = 'Shared PC Configuration'
            "#microsoft.graph.windows10CustomConfiguration"           = 'Windows 10/11 Custom Configuration'
            "#microsoft.graph.windows10GeneralConfiguration"          = 'Windows 10/11 General Configuration'
            "#microsoft.graph.windows10PkcsCertificateProfile"        = 'Windows 10/11 PKCS Certificate Profile'
            "#microsoft.graph.windows81SCEPCertificateProfile"        = 'Windows 8.1 SCEP Certificate Profile'
            "#microsoft.graph.windows81TrustedRootCertificate"        = 'Windows 8.1 Trusted Root Certificate'
            "#microsoft.graph.windowsDomainJoinConfiguration"         = 'Windows Domain Join Configuration'
            "#microsoft.graph.windowsHealthMonitoringConfiguration"   = 'Windows Health Monitoring Configuration'
            "#microsoft.graph.windowsIdentityProtectionConfiguration" = 'Windows Identity Protection Configuration'
            "#microsoft.graph.windowsKioskConfiguration"              = 'Windows Kiosk Configuration'
            "#microsoft.graph.windowsUpdateForBusinessConfiguration"  = 'Windows Update for Business Configuration'
            "#microsoft.graph.windowsWifiConfiguration"               = 'Windows Wi-Fi Configuration'
            "#microsoft.graph.windowsWifiEnterpriseEAPConfiguration"  = 'Windows Wi-Fi Enterprise EAP Configuration'
        }
    }
    $Script:PlatformSearchStrings = $script:PolicyTypeToOSMap.Keys | Sort-Object 
    <#$Script:PolicyTypeODataMapDeviceConfiguration = @{
        # Android
        "#microsoft.graph.androidCertificateProfileBase"                                  = 'Android Certificate Profile Base'
        "#microsoft.graph.androidCustomConfiguration"                                     = 'Android Custom Configuration'
        "#microsoft.graph.androidEasEmailProfileConfiguration"                            = 'Android EAS Email Profile Configuration'
        "#microsoft.graph.androidGeneralDeviceConfiguration"                              = 'Android General Device Configuration'
        "#microsoft.graph.androidImportedPFXCertificateProfile"                           = 'Android Imported PFX Certificate Profile'
        "#microsoft.graph.androidOmaCpConfiguration"                                      = 'Android OMA-CP Configuration'
        "#microsoft.graph.androidPkcsCertificateProfile"                                  = 'Android PKCS Certificate Profile'
        "#microsoft.graph.androidScepCertificateProfile"                                  = 'Android SCEP Certificate Profile'
        "#microsoft.graph.androidTrustedRootCertificate"                                  = 'Android Trusted Root Certificate'
        "#microsoft.graph.androidVpnConfiguration"                                        = 'Android VPN Configuration'
        "#microsoft.graph.androidWiFiConfiguration"                                       = 'Android Wi-Fi Configuration'
        # Android Enterprise
        "#microsoft.graph.androidEnterpriseWiFiConfiguration"                             = 'Android Enterprise Wi-Fi Configuration'
        # Android Device Owner
        "#microsoft.graph.androidDeviceOwnerDerivedCredentialAuthenticationConfiguration" = 'Android Device Owner Derived Credential Authentication Configuration'
        "#microsoft.graph.androidDeviceOwnerEnterpriseWiFiConfiguration"                  = 'Android Device Owner Enterprise Wi-Fi Configuration'
        "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration"                   = 'Android Device Owner General Configuration'
        "#microsoft.graph.androidDeviceOwnerImportedPFXCertificateProfile"                = 'Android Device Owner Imported PFX Certificate Profile'
        "#microsoft.graph.androidDeviceOwnerPkcsCertificateProfile"                       = 'Android Device Owner PKCS Certificate Profile'
        "#microsoft.graph.androidDeviceOwnerScepCertificateProfile"                       = 'Android Device Owner SCEP Certificate Profile'
        "#microsoft.graph.androidDeviceOwnerTrustedRootCertificate"                       = 'Android Device Owner Trusted Root Certificate'
        "#microsoft.graph.androidDeviceOwnerVpnConfiguration"                             = 'Android Device Owner VPN Configuration'
        "#microsoft.graph.androidDeviceOwnerWiFiConfiguration"                            = 'Android Device Owner Wi-Fi Configuration'
        # Android for work
        "#microsoft.graph.androidForWorkCertificateProfileBase"                           = 'Android for Work Certificate Profile Base'
        
        "#microsoft.graph.androidForWorkCustomConfiguration"                              = 'Android for Work Custom Configuration'
        "#microsoft.graph.androidForWorkEasEmailProfileBase"                              = 'Android for Work EAS Email Profile Base'
        "#microsoft.graph.androidForWorkEnterpriseWiFiConfiguration"                      = 'Android for Work Enterprise Wi-Fi Configuration'
        "#microsoft.graph.androidForWorkGeneralDeviceConfiguration"                       = 'Android for Work General Configuration'
        "#microsoft.graph.androidForWorkGmailEasConfiguration"                            = 'Android for Work Gmail EAS Configuration'
        "#microsoft.graph.androidForWorkImportedPFXCertificateProfile"                    = 'Android for Work Imported PFX Certificate Profile'
        "#microsoft.graph.androidForWorkNineWorkEasConfiguration"                         = 'Android for Work Nine Work EAS Configuration'
        "#microsoft.graph.androidForWorkPkcsCertificateProfile"                           = 'Android for Work PKCS Certificate Profile'
        "#microsoft.graph.androidForWorkScepCertificateProfile"                           = 'Android for Work SCEP Certificate Profile'
        "#microsoft.graph.androidForWorkTrustedRootCertificate"                           = 'Android for Work Trusted Root Certificate'
        "#microsoft.graph.androidForWorkVpnConfiguration"                                 = 'Android for Work VPN Configuration'
        "#microsoft.graph.androidForWorkWiFiConfiguration"                                = 'Android for Work Wi-Fi Configuration'
        # Android Work
        "#microsoft.graph.androidWorkProfileCertificateProfileBase"                       = 'Android Work Profile Certificate Profile Base'
        
        "#microsoft.graph.androidWorkProfileCustomConfiguration"                          = 'Android Work Profile Custom Configuration'
        "#microsoft.graph.androidWorkProfileEasEmailProfileBase"                          = 'Android Work Profile EAS Email Profile Base'
        "#microsoft.graph.androidWorkProfileEnterpriseWiFiConfiguration"                  = 'Android Work Profile Enterprise Wi-Fi Configuration'
        "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration"                   = 'Android Work Profile General Configuration'
        "#microsoft.graph.androidWorkProfileGmailEasConfiguration"                        = 'Android Work Profile Gmail EAS Configuration'
        "#microsoft.graph.androidWorkProfileNineWorkEasConfiguration"                     = 'Android Work Profile Nine Work EAS Configuration'
        "#microsoft.graph.androidWorkProfilePkcsCertificateProfile"                       = 'Android Work Profile PKCS Certificate Profile'
        "#microsoft.graph.androidWorkProfileScepCertificateProfile"                       = 'Android Work Profile SCEP Certificate Profile'
        "#microsoft.graph.androidWorkProfileTrustedRootCertificate"                       = 'Android Work Profile Trusted Root Certificate'
        "#microsoft.graph.androidWorkProfileVpnConfiguration"                             = 'Android Work Profile VPN Configuration'
        "#microsoft.graph.androidWorkProfileWiFiConfiguration"                            = 'Android Work Profile Wi-Fi Configuration'
        # Android Open Source Project (AOSP)
        "#microsoft.graph.aospDeviceOwnerCertificateProfileBase"                          = 'Android Open Source Project (AOSP) Device Owner Certificate Profile Base'
        "#microsoft.graph.aospDeviceOwnerDeviceConfiguration"                             = 'Android Open Source Project (AOSP) Device Owner Device Configuration'
        "#microsoft.graph.aospDeviceOwnerEnterpriseWiFiConfiguration"                     = 'Android Open Source Project (AOSP) Device Owner Enterprise Wi-Fi Configuration'
        "#microsoft.graph.aospDeviceOwnerPkcsCertificateProfile"                          = 'Android Open Source Project (AOSP) Device Owner PKCS Certificate Profile'
        "#microsoft.graph.aospDeviceOwnerScepCertificateProfile"                          = 'Android Open Source Project (AOSP) Device Owner SCEP Certificate Profile'
        "#microsoft.graph.aospDeviceOwnerTrustedRootCertificate"                          = 'Android Open Source Project (AOSP) Device Owner Trusted Root Certificate'
        "#microsoft.graph.aospDeviceOwnerWiFiConfiguration"                               = 'Android Open Source Project (AOSP) Device Owner Wi-Fi Configuration'
        # Apple
        "#microsoft.graph.appleDeviceFeaturesConfigurationBase"                           = 'Apple Device Features Configuration Base'
        "#microsoft.graph.appleExpeditedCheckinConfigurationBase"                         = 'Apple Expedited Check-in Configuration Base'
        "#microsoft.graph.appleVpnConfiguration"                                          = 'Apple VPN Configuration'
        # iOS
        # ToDo: add missing types for this entry
        "#microsoft.graph.iosDeviceFeaturesConfiguration"                                 = 'iOS Device Features Configuration'
        "#microsoft.graph.iosEasEmailProfileConfiguration"                                = 'iOS EAS Email Profile Configuration'
        "#microsoft.graph.iosGeneralDeviceConfiguration"                                  = 'iOS General Device Configuration'
        "#microsoft.graph.iosTrustedRootCertificate"                                      = 'iOS Trusted Root Certificate'
        "#microsoft.graph.iosUpdateConfiguration"                                         = 'iOS Update Configuration'
        "#microsoft.graph.iosVpnConfiguration"                                            = 'iOS VPN Configuration'
        "#microsoft.graph.iosWiFiConfiguration"                                           = 'iOS Wi-Fi Configuration'
        # macOS
        # ToDo: add missing types for this entry
        "#microsoft.graph.macOSCustomAppConfiguration"                                    = 'macOS Custom App Configuration'
        "#microsoft.graph.macOSCustomConfiguration"                                       = 'macOS Custom Configuration'
        "#microsoft.graph.macOSDeviceFeaturesConfiguration"                               = 'macOS Device Features Configuration'
        "#microsoft.graph.macOSExtensionsConfiguration"                                   = 'macOS Extensions Configuration'
        "#microsoft.graph.macOSSoftwareUpdateConfiguration"                               = 'macOS Software Update Configuration'
        "#microsoft.graph.macOSTrustedRootCertificate"                                    = 'macOS Trusted Root Certificate'
        # Windows
        # ToDo: add missing types for this entry
        "#microsoft.graph.editionUpgradeConfiguration"                                    = 'Edition Upgrade Configuration'
        "#microsoft.graph.groupPolicyConfiguration"                                       = 'Group Policy Configuration'
        "#microsoft.graph.sharedPCConfiguration"                                          = 'Shared PC Configuration'
        "#microsoft.graph.windows10CustomConfiguration"                                   = 'Windows 10/11 Custom Configuration'
        "#microsoft.graph.windows10GeneralConfiguration"                                  = 'Windows 10/11 General Configuration'
        "#microsoft.graph.windows10PkcsCertificateProfile"                                = 'Windows 10/11 PKCS Certificate Profile'
        "#microsoft.graph.windows81SCEPCertificateProfile"                                = 'Windows 8.1 SCEP Certificate Profile'
        "#microsoft.graph.windows81TrustedRootCertificate"                                = 'Windows 8.1 Trusted Root Certificate'
        "#microsoft.graph.windowsDomainJoinConfiguration"                                 = 'Windows Domain Join Configuration'
        "#microsoft.graph.windowsHealthMonitoringConfiguration"                           = 'Windows Health Monitoring Configuration'
        "#microsoft.graph.windowsIdentityProtectionConfiguration"                         = 'Windows Identity Protection Configuration'
        "#microsoft.graph.windowsKioskConfiguration"                                      = 'Windows Kiosk Configuration'
        "#microsoft.graph.windowsUpdateForBusinessConfiguration"                          = 'Windows Update for Business Configuration'
        "#microsoft.graph.windowsWifiConfiguration"                                       = 'Windows Wi-Fi Configuration'
        "#microsoft.graph.windowsWifiEnterpriseEAPConfiguration"                          = 'Windows Wi-Fi Enterprise EAP Configuration'
    }#>
    $Script:Policies = [System.Collections.ArrayList]::new()
}
function Get-nextLinkData {
    <#
    .SYNOPSIS
    This function retrieves all pages of data from a Microsoft Graph API request that supports pagination.
    .DESCRIPTION
    The function takes an original object that contains a '@odata.nextLink' property and retrieves all pages of data until there are no more pages left.
    #>
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $Results.'@odata.count' += $Request.'@odata.count'
        $nextLink = $Request.'@odata.nextLink'
    }
    $Results.'@odata.nextLink' = $null
    return $Results
}
function Get-DeviceConfigurationPlatform {
    param(
        [string]$PolicyType
    )
    foreach ($Platform in $Script:PolicyTypeToOSMap.GetEnumerator()) {
        if ($Platform.Value.ContainsKey($PolicyType)) {
            return $Platform.Key
        }
    }
}
function Get-DeviceConfigurationPolicies {
    #Might have to abandon this as these descriptions and displaynames are not actually stored in the policy object but in a java script object in the Intune portal, which means we can't retrieve them via Graph API
    $URI = $Script:GraphApiBaseUri + $Script:PolicyTypeToURIMap['Device Configuration']
    $Method = 'GET'
    $Response = Invoke-MgGraphRequest -Method $Method -Uri $URI -ErrorAction Stop
    $Script:AllConfigurationPolicies = Get-nextLinkData -OriginalObject $Response
    # create a custom object
    foreach ($Policy in $Script:AllConfigurationPolicies.value) {
        $CustomObject = [PSCustomObject]@{ 
            Id          = $Policy.id
            DisplayName = $Policy.displayName
            Description = $Policy.description
            Platform    = $Script:PlatformMap[$Policy.'@odata.type']#Get-DeviceConfigurationPlatform -PolicyType $Policy.'@odata.type'
            PolicyType  = $Policy.'@odata.type'
            RawData     = $Policy
        }
        $Script:Policies.Add($CustomObject) | Out-Null
    }
}
function ConvertTo-HumanReadablePolicyType {
    param(
        [string]$PolicyType
    )
    if ($Script:PolicyTypeMapToHumanReadable.ContainsKey($PolicyType)) {
        return $Script:PolicyTypeMapToHumanReadable[$PolicyType]
    } else {
        return $PolicyType
    }
}
function Get-ConfigurationPolicies {
    if (-not($Script:ConfigurationPolicies)) {
        $Script:ConfigurationPolicies = [System.Collections.ArrayList]::new()
    }
    if ($Script:AllConfigurationPolicies) {
        Clear-Variable -Name AllConfigurationPolicies -Force
    }
    if (-not($Language)) {
        $Language = "en"
    }
    $LanguageHeaders = @{
        "Accept-Language" = $Language
        "content-type"    = "application/json"
    }
    $URI = $Script:GraphApiBaseUri + $Script:PolicyTypeToURIMap['Configuration Policy'] + "/?`$expand=assignments"
    $Method = 'GET'
    $Response = Invoke-MgGraphRequest -Method $Method -Uri $URI -Headers $LanguageHeaders -ErrorAction Stop
    $Script:AllConfigurationPolicies = Get-nextLinkData -OriginalObject $Response
    $Script:PlatformsFromGraph = $Script:AllConfigurationPolicies.value.platforms | Sort-Object -Unique
    # First, get the single settings in each policy - hopefully none are ever more than 1000, otherwise we'll need to implement pagination here as well
    # Example https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('bf1ce4d5-f4c4-4745-879e-6643fc881590')/settings?`$expand=settingDefinitions&top=1000"
    # From the response we can deduct a description and display name for each setting, and then we can filter by the search string and setting type
    foreach ($Policy in $Script:AllConfigurationPolicies.value) {
        $CustomPolicyObject = [PSCustomObject]@{ 
            Id            = $Policy.id
            DisplayName   = $Policy.name
            Description   = $Policy.description
            Platform      = $Policy.platforms
            PolicyType    = "SettingsCatalog"
            Assignments   = $Policy.assignments.Count
            SettingsCount = $Policy.settingCount
            Settings      = @()
        }
        $SettingsURIBase = $Script:GraphApiBaseUri + $Script:PolicyTypeToURIMap['Configuration Policy'] + "('$($Policy.id)')/settings?`$expand=settingDefinitions&`$top=1000"
        $Settings = Invoke-MgGraphRequest -Method $Method -Uri $SettingsURIBase -Headers $LanguageHeaders -ErrorAction Stop
        foreach ($Setting in $Settings.value) {
            # create a custom object
            $CustomSettingObject = [PSCustomObject]@{ 
                SettingId          = $Setting.id # Setting within the policy, this is not a unique identifier across policies, only within the same policy, and also not the same as the setting definition id, which is in the settingDefinitions property.
                SettingDefinitions = $Setting.settingDefinitions
            }
            $CustomPolicyObject.Settings += $CustomSettingObject
            $CustomSettingObject.SettingDefinitions.'@odata.type' | Select-Object -Unique | ForEach-Object {
                $HumanReadablePolicyType = ConvertTo-HumanReadablePolicyType -PolicyType $_
                if (-not($Script:PolicyTypesFromGraph) -or -not($Script:PolicyTypesFromGraph.Contains($HumanReadablePolicyType))) {
                    $Script:PolicyTypesFromGraph += $HumanReadablePolicyType
                }
            }
            $Script:ConfigurationPolicies.Add($CustomPolicyObject) | Out-Null
        }
    }
    return $true
}
function Search-IntuneSettings {
    param (   
        [Parameter(Mandatory = $true)]
        [string]$SearchString,
        [string]$SettingType,
        [string]$Platform
    )
    if (-not($Script:ConfigurationPolicies)) {
        Get-ConfigurationPolicies
    }
    if ($SettingType) {
        $PreFilteredSettingsType = $Script:ConfigurationPolicies | Where-Object { $_.Settings | Where-Object { $_.SettingType -eq $SettingType } }
    }
    if ($Platform -and -not($PreFilteredSettingsType)) {
        $PreFilteredSettingsPlatform = $Script:ConfigurationPolicies | Where-Object { $_.Platform -like "*$Platform*" }
    } elseif ($Platform -and $PreFilteredSettingsType) {
        $PreFilteredSettingsPlatform = $PreFilteredSettingsType | Where-Object { $_.Platform -like "*$Platform*" }
    }
    if ($PreFilteredSettingsPlatform -or $PreFilteredSettingsType) {
        $Results = $PreFilteredSettingsPlatform ? $PreFilteredSettingsPlatform : $PreFilteredSettingsType
        $Results = $Results | Where-Object { 
            ($_.DisplayName -like "*$SearchString*") -or 
            ($_.Description -like "*$SearchString*") -or 
            ($_.Settings | Where-Object {
                ($_.Name -like "*$SearchString*") -or
                ($_.DisplayName -like "*$SearchString*") -or 
                ($_.Description -like "*$SearchString*") -or 
                ($_.Keywords -like "*$SearchString*")
            })
        }
    } else {
        $Results = $Script:ConfigurationPolicies | Where-Object { 
            ($_.DisplayName -like "*$SearchString*") -or 
            ($_.Description -like "*$SearchString*") -or 
            ($_.Settings | Where-Object {
                ($_.SettingName -like "*$SearchString*") -or
                ($_.SettingDisplayName -like "*$SearchString*") -or 
                ($_.SettingDescription -like "*$SearchString*") -or 
                ($_.Keywords -like "*$SearchString*")
            })
        }
        return $Results
    }
}
# Get all settings catalog policies and filter by the search string and setting type
function Get-IntuneSettings {
    param (
        [string]$SearchString,
        [string]$SettingType,
        [string]$Platform
    )
}

# Start Coding!
Initialize-Script
#Get-DeviceConfigurationPolicies


# Create a GUI to search through the settings catalog
# Settings Window

# Show the buttons but have them not clickable until the user has connected to graph.
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Intune Settings Search"
$Form.Size = New-Object System.Drawing.Size(800, 600)
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "FixedDialog"

# Search Area
$GroupBoxSearchFilters = New-Object System.Windows.Forms.GroupBox
$GroupBoxSearchFilters.Text = "Search Filters"
$GroupBoxSearchFilters.Location = New-Object System.Drawing.Point(5, 5)
$GroupBoxSearchFilters.Size = New-Object System.Drawing.Size(350, 320)
$Form.Controls.Add($GroupBoxSearchFilters)

$LabelSearch = New-Object System.Windows.Forms.Label
$LabelSearch.Text = "Search String:"
$LabelSearch.Location = New-Object System.Drawing.Point(10, 25)
$GroupBoxSearchFilters.Controls.Add($LabelSearch)

$TextBoxSearch = New-Object System.Windows.Forms.TextBox
$TextBoxSearch.Location = New-Object System.Drawing.Point(120, 25)
$TextBoxSearch.Size = New-Object System.Drawing.Size(200, 20)
$TextBoxSearch.Enabled = $false
$GroupBoxSearchFilters.Controls.Add($TextBoxSearch)
$LabelSettingType = New-Object System.Windows.Forms.Label
$LabelSettingType.Text = "Setting Type:"
$LabelSettingType.Location = New-Object System.Drawing.Point(10, 60)
$GroupBoxSearchFilters.Controls.Add($LabelSettingType)
$ComboBoxSettingType = New-Object System.Windows.Forms.ComboBox
$ComboBoxSettingType.Location = New-Object System.Drawing.Point(120, 60)
$ComboBoxSettingType.Size = New-Object System.Drawing.Size(200, 20)
$ComboBoxSettingType.Items.AddRange($Script:PolicyTypesFromGraph)
$ComboBoxSettingType.Enabled = $false
$GroupBoxSearchFilters.Controls.Add($ComboBoxSettingType)

$ComboBoxPlatform = New-Object System.Windows.Forms.ComboBox
$ComboBoxPlatform.Location = New-Object System.Drawing.Point(120, 95)
$ComboBoxPlatform.Size = New-Object System.Drawing.Size(200, 20)
$ComboBoxPlatform.Items.AddRange($Script:PlatformSearchStrings)
$ComboBoxPlatform.Enabled = $false
$GroupBoxSearchFilters.Controls.Add($ComboBoxPlatform)

$LabelPlatform = New-Object System.Windows.Forms.Label
$LabelPlatform.Text = "Platform:"
$LabelPlatform.Location = New-Object System.Drawing.Point(10, 95)
$GroupBoxSearchFilters.Controls.Add($LabelPlatform)

$ComboBoxRiskLevel = New-Object System.Windows.Forms.ComboBox
$ComboBoxRiskLevel.Location = New-Object System.Drawing.Point(120, 130)
$ComboBoxRiskLevel.Size = New-Object System.Drawing.Size(200, 20)
$ComboBoxRiskLevel.Enabled = $false
$GroupBoxSearchFilters.Controls.Add($ComboBoxRiskLevel)

$LabelRiskLevel = New-Object System.Windows.Forms.Label
$LabelRiskLevel.Text = "Risk Level:"
$LabelRiskLevel.Location = New-Object System.Drawing.Point(10, 130)
$GroupBoxSearchFilters.Controls.Add($LabelRiskLevel)

$CheckBoxAssigned = New-Object System.Windows.Forms.CheckBox
$CheckBoxAssigned.Text = "Show only assigned policies"
$CheckBoxAssigned.Location = New-Object System.Drawing.Point(10, 165)
$CheckBoxAssigned.Size = New-Object System.Drawing.Size(310, 20)
$CheckBoxAssigned.Enabled = $false
$GroupBoxSearchFilters.Controls.Add($CheckBoxAssigned)

# Load Data Area
$GroupBoxLoadData.Controls.Add($ButtonLoadData)
$GroupBoxLoadData = New-Object System.Windows.Forms.GroupBox
$GroupBoxLoadData.Text = "Load Data from Graph API"
$GroupBoxLoadData.Location = New-Object System.Drawing.Point(370, 5)
$GroupBoxLoadData.Size = New-Object System.Drawing.Size(410, 260)
$Form.Controls.Add($GroupBoxLoadData)
$ComboBoxLanguage = New-Object System.Windows.Forms.ComboBox
$ComboBoxLanguage.Location = New-Object System.Drawing.Point(120, 80)
$ComboBoxLanguage.Size = New-Object System.Drawing.Size(200, 20)
$ComboBoxLanguage.Items.AddRange($Script:QueryLanguagesHumanReadable)
$ComboBoxLanguage.Enabled = $false
$GroupBoxLoadData.Controls.Add($ComboBoxLanguage)
$LabelLanguage = New-Object System.Windows.Forms.Label
$LabelLanguage.Text = "Language:"
$LabelLanguage.Location = New-Object System.Drawing.Point(10, 80)
$GroupBoxLoadData.Controls.Add($LabelLanguage)

$ConnectionStatusIcon = New-Object System.Windows.Forms.PictureBox
$ConnectionStatusIcon.Location = New-Object System.Drawing.Point(115, 25)
$ConnectionStatusIcon.Size = New-Object System.Drawing.Size(32, 32)
$ConnectionStatusIcon.ImageLocation = "$($Script:PathToScript)\Disconnected.png"
$ConnectionStatusIcon.SizeMode = "StretchImage"
$GroupBoxLoadData.Controls.Add($ConnectionStatusIcon)

$ButtonConnect = New-Object System.Windows.Forms.Button
$ButtonConnect.Text = "Connect to Graph"
$GroupBoxLoadData.Controls.Add($ButtonConnect)
$ButtonConnect.Location = New-Object System.Drawing.Point(150, 25)
$ButtonConnect.Size = New-Object System.Drawing.Size(140, 32)
$ButtonConnect.Add_Click({
        $ConnectionMethodForm = New-Object System.Windows.Forms.Form
        $ConnectionMethodForm.Text = "Select Connection Method"
        $ConnectionMethodForm.Size = New-Object System.Drawing.Size(400, 210)
        $ConnectionMethodForm.StartPosition = "CenterScreen"
        $ConnectionMethodForm.FormBorderStyle = "FixedDialog"
        $ConnectionMethodForm.TopMost = $true

        # We need a checkbox for ModuleInstallationAllowed that is checked by default
        $ModuleInstallationAllowedCheckbox = New-Object System.Windows.Forms.CheckBox
        $ModuleInstallationAllowedCheckbox.Text = "Allow Module Installation"
        $ModuleInstallationAllowedCheckbox.Location = New-Object System.Drawing.Point(10, 100)
        $ModuleInstallationAllowedCheckbox.Size = New-Object System.Drawing.Size(200, 20)
        $ModuleInstallationAllowedCheckbox.Checked = $true
        $ConnectionMethodForm.Controls.Add($ModuleInstallationAllowedCheckbox)

        # Add a checked box to allow users to save their connection details in a local file
        $SaveConnectionDetailsCheckbox = New-Object System.Windows.Forms.CheckBox
        $SaveConnectionDetailsCheckbox.Text = "Save Connection Details"
        $ToolTip = New-Object System.Windows.Forms.ToolTip
        $ToolTip.SetToolTip($SaveConnectionDetailsCheckbox, "WILL NOT SAVE SECRETS! If checked, your connection details will be saved in a local file for future use.")
        $SaveConnectionDetailsCheckbox.Enabled = $false
        $SaveConnectionDetailsCheckbox.Location = New-Object System.Drawing.Point(230, 100)
        $SaveConnectionDetailsCheckbox.Size = New-Object System.Drawing.Size(200, 20)
        $SaveConnectionDetailsCheckbox.Checked = $false
        $ConnectionMethodForm.Controls.Add($SaveConnectionDetailsCheckbox)

        $LabelMethod = New-Object System.Windows.Forms.Label
        $LabelMethod.Text = "Connection Method:"
        $LabelMethod.Location = New-Object System.Drawing.Point(10, 60)
        $LabelMethod.AutoSize = $true
        $ConnectionMethodForm.Controls.Add($LabelMethod)

        # If the user selects certificate, show text boxes for certificate thumbprint, client id and tenant id
        # Labels show only be visible when certificate method is selected, and the text boxes should only be visible when certificate method is selected
        $LabelCertificateThumbprint = New-Object System.Windows.Forms.Label
        $LabelCertificateThumbprint.Text = "Certificate Thumbprint:"
        $LabelCertificateThumbprint.Location = New-Object System.Drawing.Point(10, 100)
        $LabelCertificateThumbprint.AutoSize = $true
        $LabelCertificateThumbprint.Visible = $false
        $ConnectionMethodForm.Controls.Add($LabelCertificateThumbprint)
        $TextBoxCertificateThumbprint = New-Object System.Windows.Forms.TextBox
        $TextBoxCertificateThumbprint.Location = New-Object System.Drawing.Point(150, 100)
        $TextBoxCertificateThumbprint.Size = New-Object System.Drawing.Size(220, 20)
        $TextBoxCertificateThumbprint.Visible = $false
        $ConnectionMethodForm.Controls.Add($TextBoxCertificateThumbprint)

        $LabelClientID = New-Object System.Windows.Forms.Label
        $LabelClientID.Text = "Client ID:"
        $LabelClientID.Location = New-Object System.Drawing.Point(10, 130)
        $LabelClientID.AutoSize = $true
        $LabelClientID.Visible = $false
        $ConnectionMethodForm.Controls.Add($LabelClientID)
        $TextBoxClientID = New-Object System.Windows.Forms.TextBox
        $TextBoxClientID.Location = New-Object System.Drawing.Point(150, 130)
        $TextBoxClientID.Size = New-Object System.Drawing.Size(220, 20)
        $TextBoxClientID.Visible = $false
        $ConnectionMethodForm.Controls.Add($TextBoxClientID)

        $LabelTenantID = New-Object System.Windows.Forms.Label
        $LabelTenantID.Text = "Tenant ID:"
        $LabelTenantID.Location = New-Object System.Drawing.Point(10, 160)
        $LabelTenantID.AutoSize = $true
        $LabelTenantID.Visible = $false
        $ConnectionMethodForm.Controls.Add($LabelTenantID)
        $TextBoxTenantID = New-Object System.Windows.Forms.TextBox
        $TextBoxTenantID.Location = New-Object System.Drawing.Point(150, 160)
        $TextBoxTenantID.Size = New-Object System.Drawing.Size(220, 20)
        $TextBoxTenantID.Visible = $false
        $ConnectionMethodForm.Controls.Add($TextBoxTenantID)

        $ConnectionMethodComboBox = New-Object System.Windows.Forms.ComboBox
        $ConnectionMethodComboBox.Location = New-Object System.Drawing.Point(150, 60)
        $ConnectionMethodComboBox.Size = New-Object System.Drawing.Size(220, 20)
        $ConnectionMethodComboBox.Items.AddRange(@('Interactive', 'Certificate', 'AppSecret'))
        $ConnectionMethodComboBox.SelectedIndex = 0
        $ConnectionMethodForm.Controls.Add($ConnectionMethodComboBox)
        $ConnectionMethodComboBox.Add_SelectedIndexChanged({
                if ($ConnectionMethodComboBox.SelectedItem -eq 'Certificate') {
                    $SaveConnectionDetailsCheckbox.Enabled = $true
                    $SaveConnectionDetailsCheckbox.Checked = $true
                    # Load existing connection settings from file if they exist and pre-populate the connection form with those settings
                    if (Test-Path "$($Script:PathToScript)\ConnectionDetails.xml") {
                        $ConnectionDetails = Import-Clixml -Path "$($Script:PathToScript)\ConnectionDetails.xml"
        
                    } else {
                        $ConnectionDetails = @{
                            ConnectionMethod          = "Interactive"
                            ModuleInstallationAllowed = $true
                            SaveConnectionDetails     = $true
                            CertificateThumbprint     = ""
                            ClientID                  = ""
                            TenantID                  = ""
                        }
                    }
                    $TextBoxCertificateThumbprint.Text = $ConnectionDetails.CertificateThumbprint
                    $TextBoxClientID.Text = $ConnectionDetails.ClientID
                    $TextBoxTenantID.Text = $ConnectionDetails.TenantID
                    $LabelCertificateThumbprint.Visible = $true
                    $TextBoxCertificateThumbprint.Visible = $true
                    $LabelClientID.Visible = $true
                    $TextBoxClientID.Visible = $true
                    $LabelTenantID.Visible = $true
                    $TextBoxTenantID.Visible = $true
                    $ConnectionMethodForm.Size = New-Object System.Drawing.Size(400, 300)
                    $ButtonConnect.Location = New-Object System.Drawing.Point(90, 220)
                    $ButtonCancel.Location = New-Object System.Drawing.Point(210, 220)
                    $ModuleInstallationAllowedCheckbox.Location = New-Object System.Drawing.Point(15, 200)
                    $SaveConnectionDetailsCheckbox.Location = New-Object System.Drawing.Point(230, 200)
                } else {
                    $SaveConnectionDetailsCheckbox.Enabled = $false
                    $SaveConnectionDetailsCheckbox.Checked = $false
                    $LabelCertificateThumbprint.Visible = $false
                    $TextBoxCertificateThumbprint.Visible = $false
                    $LabelClientID.Visible = $false
                    $TextBoxClientID.Visible = $false
                    $LabelTenantID.Visible = $false
                    $TextBoxTenantID.Visible = $false
                    $ConnectionMethodForm.Size = New-Object System.Drawing.Size(400, 200)
                    $ButtonConnect.Location = New-Object System.Drawing.Point(90, 120)
                    $ButtonCancel.Location = New-Object System.Drawing.Point(210, 120)
                    $ModuleInstallationAllowedCheckbox.Location = New-Object System.Drawing.Point(10, 100)
                    $SaveConnectionDetailsCheckbox.Location = New-Object System.Drawing.Point(230, 100)
                }
            })

        $LabelEnvironment = New-Object System.Windows.Forms.Label
        $LabelEnvironment.Text = "Environment:"
        $LabelEnvironment.Location = New-Object System.Drawing.Point(10, 20)
        $LabelEnvironment.AutoSize = $true
        $ConnectionMethodForm.Controls.Add($LabelEnvironment)

        $ComboBoxEnvironment = New-Object System.Windows.Forms.ComboBox
        $ComboBoxEnvironment.Location = New-Object System.Drawing.Point(150, 20)
        $ComboBoxEnvironment.Size = New-Object System.Drawing.Size(220, 20)
        $ComboBoxEnvironment.Items.AddRange(@('Global', 'USGov', 'China', 'Germany'))
        $ComboBoxEnvironment.SelectedIndex = 0
        $ConnectionMethodForm.Controls.Add($ComboBoxEnvironment)

        $ButtonConnect = New-Object System.Windows.Forms.Button
        $ButtonConnect.Text = "Connect"
        $ButtonConnect.Location = New-Object System.Drawing.Point(90, 130)
        $ButtonConnect.Size = New-Object System.Drawing.Size(100, 30)
        $ButtonConnect.Add_Click({
                $method = $ConnectionMethodComboBox.SelectedItem
                $env = $ComboBoxEnvironment.SelectedItem
                $connectParams = @{
                    Environment               = $env
                    ModuleInstallationAllowed = $true
                }
                
                if ($method -eq 'Certificate' -and $TextBoxCertificateThumbprint.Text -and $TextBoxClientID.Text -and $TextBoxTenantID.Text) {
                    $connectParams['CertificateThumbprint'] = $TextBoxCertificateThumbprint.Text
                    if ([System.Guid]::TryParse($TextBoxClientID.Text, [System.Management.Automation.PSReference]$([System.Guid]::empty))) {
                        $connectParams['ClientID'] = $TextBoxClientID.Text
                    } else {
                        [System.Windows.Forms.MessageBox]::Show("Invalid ClientID. Please enter a valid GUID.", "Error")
                        return
                    }
                    if ([System.Guid]::TryParse($TextBoxTenantID.Text, [System.Management.Automation.PSReference]$([System.Guid]::empty))) {
                        $connectParams['TenantId'] = $TextBoxTenantID.Text
                    } else {
                        [System.Windows.Forms.MessageBox]::Show("Invalid TenantID. Please enter a valid GUID.", "Error")
                        return
                    }
                    if ($SaveConnectionDetailsCheckbox.Checked) {
                        $ConnectionDetails = @{
                            Method                = $method
                            Environment           = $env
                            CertificateThumbprint = $TextBoxCertificateThumbprint.Text
                            ClientID              = $TextBoxClientID.Text
                            TenantID              = $TextBoxTenantID.Text
                        }
                        $ConnectionDetails | Export-Clixml -Path "$($Script:PathToScript)\ConnectionDetails.xml" -Force
                    }
                }
                $result = Connect-SISGraph @connectParams
                if ($result -eq $true) {
                    [System.Windows.Forms.MessageBox]::Show("Connected successfully!", "Success")
                    $ConnectionStatusIcon.ImageLocation = "$($Script:PathToScript)\Connected.png"
                    $ComboBoxLanguage.Enabled = $true
                    $ConnectionMethodForm.Close()
                }
            })
        $ConnectionMethodForm.Controls.Add($ButtonConnect)

        $ButtonCancel = New-Object System.Windows.Forms.Button
        $ButtonCancel.Text = "Cancel"
        $ButtonCancel.Location = New-Object System.Drawing.Point(210, 130)
        $ButtonCancel.Size = New-Object System.Drawing.Size(100, 30)
        $ButtonCancel.Add_Click({ $ConnectionMethodForm.Close() })
        $ConnectionMethodForm.Controls.Add($ButtonCancel)
        $ConnectionMethodForm.ShowDialog()
    })

$ButtonLoadData = New-Object System.Windows.Forms.Button
$ButtonLoadData.Text = "Load Data"
# Center the Load Data button within the GroupBoxLoadData
$ButtonLoadData.Location = New-Object System.Drawing.Point(10, 120)
$ButtonLoadData.Size = New-Object System.Drawing.Size(310, 30)
# Add event handler for the load data button
$ButtonLoadData.Add_Click({
        # Load data in the selected language and store it in the script variable
        $Script:Language = $Script:QueryLanguageMap[$ComboBoxLanguage.SelectedItem]
        $ConfigurationPoliciesSuccessfullyRequested = Get-ConfigurationPolicies
        # Re-populate the setting type and platform combo boxes based on the loaded data
        if ($ConfigurationPoliciesSuccessfullyRequested) {
            if ($Script:PolicyTypesFromGraph) {
                $Script:PolicyTypesFromGraph = $Script:PolicyTypesFromGraph | Sort-Object -Unique
                $ComboBoxSettingType.Items.Clear()
                $ComboBoxSettingType.Items.AddRange($Script:PolicyTypesFromGraph)
                $ComboBoxSettingType.Enabled = $true
            }
            if ($Script:PlatformsFromGraph) {
                $Script:PlatformsFromGraph = $Script:PlatformsFromGraph | Sort-Object -Unique
                $ComboBoxPlatform.Items.Clear()
                $ComboBoxPlatform.Items.AddRange($Script:PlatformsFromGraph)
                $ComboBoxPlatform.Enabled = $true
            }
            if ($Script:RiskLevels) {
                $Script:RiskLevels = $Script:RiskLevels | Sort-Object -Unique
                $ComboBoxRiskLevel.Items.Clear()
                $ComboBoxRiskLevel.Items.AddRange($Script:RiskLevels)
                $ComboBoxRiskLevel.Enabled = $true
            }
            $TextBoxSearch.Enabled = $true
            $CheckBoxAssigned.Enabled = $true
            $ButtonSearch.Enabled = $true
            [System.Windows.Forms.MessageBox]::Show("Data loaded successfully!", "Success")
        }
    })
$GroupBoxLoadData.Controls.Add($ButtonLoadData)

# Add event handler for the search button
$ButtonSearch = New-Object System.Windows.Forms.Button
$ButtonSearch.Text = "Search"
$ButtonSearch.Location = New-Object System.Drawing.Point(10, 200)
$ButtonSearch.Size = New-Object System.Drawing.Size(310, 30)
$ButtonSearch.Enabled = $false
$ButtonSearch.Add_Click({
        if (-not($TextBoxSearch.Text)) { 
            $SearchString = "*"
        }
        $Results = Search-IntuneSettings -SearchString $SearchString -SettingType $ComboBoxSettingType.SelectedItem -Platform $ComboBoxPlatform.SelectedItem
        # Display results in a new form with a list box
        if ($Results) {
            $ResultsForm = New-Object System.Windows.Forms.Form
            $ResultsForm.Text = "Search Results $($Results.Count) - `"$($TextBoxSearch.Text)`""
            $ResultsForm.Size = New-Object System.Drawing.Size(800, 600)
            $ResultsForm.StartPosition = "CenterScreen"
            $ListBoxResults = New-Object System.Windows.Forms.ListBox
            $ListBoxResults.Location = New-Object System.Drawing.Point(10, 10)
            $ListBoxResults.Size = New-Object System.Drawing.Size(760, 540)
            foreach ($Result in $Results) {
                $ListBoxResults.Items.Add($Result.DisplayName)
            }
            $ResultsForm.Controls.Add($ListBoxResults)
            $ResultsForm.ShowDialog() 
        } else {
            [System.Windows.Forms.MessageBox]::Show("No results found for `"$($TextBoxSearch.Text)`". Please try a different search string or adjust your filters.", "No Results")
        }

    })
$GroupBoxSearchFilters.Controls.Add($ButtonSearch)
$Form.ShowDialog()
Write-output "Script finished"
if (Get-MgContext) {
    Disconnect-MgGraph
}