#Requires -Version 7.0 -RunAsAdministrator
<#
.SYNOPSIS
This script will test network connections to various Intune services using PowerShell 7
.DESCRIPTION
Welcome to the first release of INR - Intune Network Requirements. This script will allow you to test several different service areas 
related to Intune. The main way this script is intended to run is not once, but at least **twice**.
**Requirements
* PowerShell 7
* RTFM https://manima.de/2024/08/intune-network-requirements-everything-i-learned/
* Admin rights (if you want to test your currently set NTP server)

Instructions:
1. Run the script on an unmanaged network, but ideally close to you or on the same provider.
2. Run the script using the same parameters on your managed network where you're experiencing issues
3. Run the script again (if necessary) to compare the two results and get a difference between the results.

This is the only way to reliably verify results. It is not possible to deterministically test the endpoints because there is no
documentation of which endpoint has which responses.
.PARAMETER TestAllServiceAreas
Specifies whether to test all target services.
.PARAMETER UseMSJSON
Specifies whether to use MSJSON for network requests.
.PARAMETER UseMS365JSON
Specifies whether to use MS365JSON for network requests. 
.PARAMETER CustomURLFile
Recommended. Put this file next to the script. Specifies the path to the CSV file containing the URLs, ports, and protocols to test. The default value is "INRCustomList.csv".
.PARAMETER AllowBestEffort
Recommended. Specifies whether to allow best effort testing (will try to resolve wildcard URLs) for URLs that don't have an exact match. 
.PARAMETER CheckCertRevocation
Recommended. Will verify if certificates that are presented by URLs are verified.
.PARAMETER GCC
Will test the GCC specific URLs - this related to RemoteHelp and Device Health currently.
.PARAMETER Intune
Specifies whether to test all of the Intune service area (this merges a lot of different areas).
.PARAMETER Autopilot
Specifies whether to test all of the Autopilot service area (this merges a lot of different areas).
.PARAMETER WindowsActivation
Specifies whether to test the Windows Activation service area.
.PARAMETER EntraID
Specifies whether to test the EntraID service area.
.PARAMETER WindowsUpdate
Specifies whether to test the Windows Update service area.
.PARAMETER DeliveryOptimization
Specifies whether to test the Delivery Optimization service area.
.PARAMETER NTP
Specifies whether to test the NTP service area.
.PARAMETER DNS
Warning: This is not put into the result CSV. It will be available in the log. Specifies whether to test the DNS service area.
.PARAMETER DiagnosticsData
Specifies whether to test the Diagnostics Data service area.
.PARAMETER DiagnosticsDataUpload
Specifies whether to test the Diagnostics Data Upload service area.
.PARAMETER NCSI
Specifies whether to test the NCSI service area.
.PARAMETER WindowsNotificationService
Specifies whether to test the WindowsNotificationService service area.
.PARAMETER WindowsStore
Specifies whether to test the Windows Store service area.
.PARAMETER M365
Warning: This is a _lot_ of URLs and will run for a couple minutes. Specifies whether to test the M365 service area.
.PARAMETER CRLs
Specifies whether to test the CRLs service area. These are the well known CRLs by Microsoft, plus my own if you import the CSV.
.PARAMETER SelfDeploying
Specifies whether to test the self-deploying service area.
.PARAMETER RemoteHelp
Specifies whether to test the Remote Help service area.
.PARAMETER TPMAttestation
Specifies whether to test the TPM attestation service area.
.PARAMETER DeviceHealth
Specifies whether to test the device health service area.
.PARAMETER Apple
Specifies whether to test the Apple (iOS/iPadOS) service area.
.PARAMETER Android
Specifies whether to test the Android (Google) service area.
.PARAMETER EndpointAnalytics
Specifies whether to test the Endpoint Analytics service area.
.PARAMETER AppInstaller
Specifies whether to test the app installer (winget) service area.
.PARAMETER UniversalPrint
Specifies whether to test the universal print service area.
.PARAMETER AuthenticatedProxyOnly
Will test if there is an authenticated proxy in use - does not test other service areas.
.PARAMETER TestSSLInspectionOnly
Will test if there is any sort of SSL inspection - does not test other service areas.
.PARAMETER Legacy
This is not implemented yet. Specifies whether to test legacy service.
.PARAMETER TenantName
This must be specified if you want some of the M365 URLS to be populated automatically. This is the first part of your first <tenantname>.onmicrosoft.com
.PARAMETER MaxDelayInMS
Default: 300ms. This is my recommended value because some addresses tend to respond slowly.
.PARAMETER BurstMode
Will use the MaxDelayInMs, divide it into 50ms chunks and then do a quick test. Use this to find out response times.
.PARAMETER BrienMode
This mode allows you to run the script multiple times in succession and automatically merge the results. This can be used to 
change network settings in between running the script with the same parameters. The last two results will be compared. Recommended
value: 2
.PARAMETER MergeResults
Will trigger the result merge path. If two CSV files are in the working directory, it will merge those. Otherwise use -MergeCSVs.
.PARAMETER MergeShowAllResults
Will merge _all_ results not just differences.
.PARAMETER MergeCSVs
This will accept two CSV filesnames as strings. The files must be placed into the working directory.
.PARAMETER NoLog
Specifies whether to disable logging. This is a switch parameter.
.PARAMETER TestMethods
This is not implemented yet. This allows you to chose the test methods that the script will go through.
.PARAMETER OutputCSV
Output the results to a CSV file. This is not enabled by default. This is a recommended default switch.
.PARAMETER ShowResults
Shows the results in an Out-Gridview.
.PARAMETER ToConsole
Specifies whether to output log messages to the console. Enabling this won't create a log.
.PARAMETER WorkingDirectory
Specifies the working directory where the script will be executed. The default value is "C:\INR\".
.PARAMETER LogDirectory
Specifies the directory where log files will be stored. The default value is "C:\INR\".
.EXAMPLE
This example will use the MS-JSON for MEM, ingest the custom CSV if it exists in the same folder, allow wildcard 
handling in URLS, check the CRLs of each certificate provided for the ASA TPM Attestation. The script will run twice, 
asking you to change the network environment in between (e.g. from home to VPN), and then display all the results 
of each pass and the merged results of the last two results.
.\Get-IntuneNetworkRequirements.ps1 -UseMSJSON -AllowBestEffort -CheckCertRevocation -ShowResults -TPMAttestation -BrienMode 2
.EXAMPLE
This example will use the MS-JSON for MEM, my custom CSV, allow for wildcard handling in URLS, check 
the CRLs of each certificate provided for the ASA TPMAttestation and then display the results in a grid, 
while displaying potential issues in the console for the service area TPMAttestation. 
.\Get-IntuneNetworkRequirements.ps1 -UseMSJSON -CustomURLFile '.\INRCustomList.csv' -AllowBestEffort -CheckCertRevocation -TPMAttestation -ShowResults -ToConsole
.EXAMPLE
This will ingest 2 files from the working directory and compare them. The comparison is written to another CSV file while also showing the results in a grid view. 
.\Get-IntuneNetworkRequirements.ps1 -MergeResults -MergeCSVs ResultList_29072024_110030_SADAME-PC.csv,ResultList_30072024_084101_3T0M4W3.csv -ShowResults
.NOTES
    Version: 1.2
    Versionname: Brien 
    Intial creation date: 19.02.2024
    Last change date: 01.10.2024
    Latest changes: https://github.com/MHimken/toolbox/tree/main/Autopilot/MEMNetworkRequirements/changelog.md
    Shoutouts: 
    * WinAdmins Community - especially Chris for helping me figure out some of the features.
    * badssl.com and httpstat.us are awesome! 
#>
[CmdletBinding(DefaultParameterSetName = 'TestMSJSON')]
param(
    [Parameter(ParameterSetName = 'AllAreas', Position = 0)]
    [switch]$TestAllServiceAreas,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON', Position = 0)]
    [switch]$UseMSJSON,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMS365JSON', Position = 0)]
    [switch]$UseMS365JSON,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom', Position = 0)]
    [string]$CustomURLFile,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON', Position = 1)]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$AllowBestEffort,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON', Position = 2)]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$CheckCertRevocation,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$GCC,
    #Service Areas
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$Intune,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$Autopilot,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$WindowsActivation,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$EntraID,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$WindowsUpdate,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$DeliveryOptimization,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$NTP,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$DNS,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$DiagnosticsData,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$DiagnosticsDataUpload,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$NCSI,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$WindowsNotificationService,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$WindowsStore,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$M365,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$CRLs,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$SelfDeploying,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$RemoteHelp,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$TPMAttestation,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$DeviceHealth,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$Apple,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$Android,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$EndpointAnalytics,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$AppInstaller,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$UniversalPrint, 

    #Not Service area specific
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$AuthenticatedProxyOnly,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$TestSSLInspectionOnly,
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$Legacy,
    
    #Special Methods
    [Parameter(ParameterSetName = 'AllAreas', Mandatory)]
    [Parameter(ParameterSetName = 'TestMS365JSON', Mandatory)]
    [string]$TenantName,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [int]$MaxDelayInMS = 300, #300 is recommended due to some Microsoft services being heavy load (like MS Update)
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$BurstMode, #Divide the delay by 50 and try different speeds. Give warning when more than 10 URLs are tested
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [int]$BrienMode,

    #Merge options
    [Parameter(ParameterSetName = 'Merge', Position = 0)]
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$MergeResults,
    [Parameter(ParameterSetName = 'Merge')]
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [switch]$MergeShowAllResults,
    [Parameter(ParameterSetName = 'Merge')]
    [string[]]$MergeCSVs,

    #Output options
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [Parameter(ParameterSetName = 'Merge')]
    [switch]$OutputCSV,
    [Parameter(ParameterSetName = 'AllAreas')]
    [Parameter(ParameterSetName = 'TestMSJSON')]
    [Parameter(ParameterSetName = 'TestMS365JSON')]
    [Parameter(ParameterSetName = 'TestCustom')]
    [Parameter(ParameterSetName = 'Merge')]
    [switch]$ShowResults,
    #Common parameters
    [switch]$NoLog,
    [switch]$ToConsole,
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\INR\",
    [System.IO.DirectoryInfo]$LogDirectory = "C:\INR\"
)

#Preparation
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
        $LogPrefix = 'INR'
        $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
        if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
    }
    if ($PSVersionTable.psversion.major -lt 7) {
        Write-Log -Message 'Please follow the manual - PowerShell 7 is currently required to run this script.' -Component 'InitializeScript' -Type 3
        Exit 1
    }
    $Script:GUID = (New-Guid).Guid
    $Script:M365ServiceURLs = [System.Collections.ArrayList]::new()
    $Script:WildCardURLs = [System.Collections.ArrayList]::new()
    $Script:CRLURLsToCheck = [System.Collections.ArrayList]::new()
    $Script:URLsToVerify = [System.Collections.ArrayList]::new()
    $Script:DNSCache = [System.Collections.ArrayList]::new()
    $Script:TCPCache = [System.Collections.ArrayList]::new()
    if ($Script:FinalResultList) {
        Get-Variable FinalResultList | Clear-Variable 
    }
    $Script:FinalResultList = [System.Collections.ArrayList]::new()
    $Script:ExternalIP = (ConvertFrom-Json (Invoke-WebRequest "https://geo-prod.do.dsp.mp.microsoft.com/geo")).ExternalIpAddress
    Write-Log -Message "External IP: $($Script:ExternalIP)" -Component 'InitializeScript'
    Import-CustomURLFile
    if ($UseMSJSON) {
        Get-M365Service -MEM
    }
    if ($UseMS365JSON) {
        Get-M365Service -M365
    }
    if (-not($Script:M365ServiceURLs) -and -not($Script:ManualURLs)) {
        Write-Log 'No domains have been imported, please specify -UseMSJSON, -UseMS365JSON or -CustomURLFile' -Component 'InitializeScript' -Type 3
        exit 5
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
function Write-SettingsToLog {
    if (-not($MergeResults)) {
        Write-Log "Settings used to run the script:
        General settings
        TestAllServiceAreas: $TestAllServiceAreas
        UseMSJSON: $UseMSJSON
        UseMS365JSON: $UseMS365JSON
        CustomURLFile: $CustomURLFile
        AllowBestEffort: $AllowBestEffort
        CheckCertRevocation: $CheckCertRevocation
        GCC: $GCC
    
        ASAs
        Intune: $Intune
        Autopilot: $Autopilot
        WindowsActivation: $WindowsActivation
        EntraID: $EntraID
        WindowsUpdate: $WindowsUpdate
        DeliveryOptimization: $DeliveryOptimization
        NTP: $NTP
        DNS: $DNS
        DiagnosticsData: $DiagnosticsData
        DiagnosticsDataUpload: $DiagnosticsDataUpload
        NCSI: $NCSI
        WindowsNotificationService: $WindowsNotificationService
        WindowsStore: $WindowsStore
        M365: $M365
        CRLs: $CRLs
        SelfDeploying: $SelfDeploying
        RemoteHelp: $RemoteHelp
        TPMAttestation: $TPMAttestation
        DeviceHealth: $DeviceHealth
        Apple: $Apple
        Android: $Android
        EndpointAnalytics: $EndpointAnalytics
        AppInstaller: $AppInstaller
    
        Other tests
        AuthenticatedProxyOnly: $AuthenticatedProxyOnly
        TestSSLInspectionOnly: $TestSSLInspectionOnly
        Legacy: $Legacy
    
        Additional Settings
        TenantName: $TenantName
        MaxDelayInMS: $MaxDelayInMS
        BurstMode: $BurstMode" -Component 'InitialzeScript'
    } else {
        Write-Log "Settings used to run the script:
        Merge options
        MergeResults: $MergeResults
        MergeShowAllResults: $MergeShowAllResults
        MergeCSVs: $MergeCSVs" -Component 'InitialzeScript'
    }
    Write-Log "Output options
        OutputCSV: $OutputCSV
        ShowResults: $ShowResults
    
        Common parameters
        NoLog: $NoLog
        ToConsole: $ToConsole
        WorkingDirectory: $WorkingDirectory
        LogDirectory: $LogDirectory" -Component 'InitialzeScript'
}
function Import-CustomURLFile {
    <#
    .SYNOPSIS
        Imports URLs from a custom CSV file. Automatically uses 'INRCustomList.csv' if no filename is specified.
    #>
    if (-not($CustomURLFile)) {
        Write-Log 'No CSV provided - trying autodetect for filename ' -Component 'ImportCustomURLFile'
        $DefaultCSVName = "INRCustomList.csv"
        $JoinedDefaultCSVPath = Join-Path $Script:PathToScript -ChildPath $DefaultCSVName
        if (Test-Path $JoinedDefaultCSVPath) {
            Write-Log "CSV found in $($Script:PathToScript)" -Component 'ImportCustomURLFile'
            $CustomURLFile = $DefaultCSVName
        } else {
            Write-Log 'Autodetection did not find a custom CSV file' -Component 'ImportCustomURLFile'
            return
        }
    }
    Write-Log 'Adding custom URLs to the pool' -Component 'ImportCustomURLFile'
    $Header = 'URL', 'Port', 'Protocol', 'ID'
    $Script:ManualURLs = [System.Collections.ArrayList]::new()
    $TempObjects = Import-Csv -Path (Join-Path -Path $Script:PathToScript -ChildPath $CustomURLFile) -Delimiter ',' -Header $Header
    foreach ($Object in $TempObjects) {
        $URLObject = [PSCustomObject]@{
            id       = $Object.ID
            #serviceArea            = $Object.serviceArea
            #serviceAreaDisplayName = $Object.serviceAreaDisplayName
            url      = $Object.url.replace('*.', '')
            Port     = $Object.port
            Protocol = $Object.protocol
            #expressRoute           = $Object.expressRoute
            #category               = $Object.category
            required = 'true'
            #notes                  = $Object.notes
        }
        $Script:ManualURLs.add($URLObject) | Out-Null
    }
}
function Get-URLsFromID {
    <#
    .SYNOPSIS
    Will put the URLs for different service areas into one big arraylist.
    #>
    param(  
        [int[]]$IDs,
        [int[]]$FilterPort
    )
    if ($Script:URLsToVerify) {
        Get-Variable URLsToVerify | Clear-Variable
        $Script:URLsToVerify = [System.Collections.ArrayList]::new()
    }
    foreach ($ID in $IDs) {
        if ($Script:ManualURLs) {
            $Script:ManualURLs | Where-Object { $_.id -eq $ID -and $_.port -notin $FilterPort } | ForEach-Object { $Script:URLsToVerify.Add($_) | Out-Null }
        }
        if ($Script:M365ServiceURLs) {
            $Script:M365ServiceURLs | Where-Object { $_.id -eq $ID -and $_.port -notin $FilterPort } | ForEach-Object { $Script:URLsToVerify.Add($_) | Out-Null }
        }
        if (-not($Script:URLsToVerify)) {
            return $false
        }
        $DuplicateURLsToVerify = [System.Collections.ArrayList]::new()
        foreach ($IDsFound in $Script:URLsToVerify) {
            $RemoveMe = $Script:URLsToVerify | Where-Object { $_.id -eq $IDsFound.id -and $_.url -eq $IDsFound.url -and $_.port -eq $IDsFound.port -and $_.protocol -eq $IDsFound.protocol }
            if ($RemoveMe.count -gt 1) {
                $counter = 0
                foreach ($RemoveObject in $RemoveMe) {
                    if ($counter -gt 0) {
                        $DuplicateURLsToVerify.add($RemoveObject) | Out-Null
                    }
                    $counter++
                }
            }
        }
        $DuplicateURLsToVerify | ForEach-Object { $Script:URLsToVerify.Remove($_) }    
    }
    return $true
}

#Import M365 Service-URLs
function Find-WildcardURL {
    <#
    .SYNOPSIS
    Will resolve wildcards to actual URLs. If AllowBestEffort is set might also remove the wildcards from URLs if they can't be matched otherwise
    #>
    Write-Log -Message 'Now searching for nearest match for Wildcards' -Component 'FindWildcardURL'
    foreach ($Object in $Script:WildCardURLs) {
        Write-Log -Message "Searching for $($Object.url)" -Component 'FindWildcardURL'
        if ($($Script:M365ServiceURLs | Where-Object { $_.url -like "*$($Object.url.replace('*.',''))*" })) {
            continue
        }
        $ReplaceElement = $Object.url.split('.')[0] 
        if ($ReplaceElement -ne '*') {
            $WildcardReplacement = $ReplaceElement.replace('*', 'INR')
            $NewURL = $Object.url.replace($ReplaceElement, $WildcardReplacement)
        } else {
            $NewURL = $Object.url.replace('*.', '')
        }

        Write-Log -Message 'We did not find a matching URL using best effort (no wildcard)' -Component 'FindWildcardURL'
        $URLObject = [PSCustomObject]@{
            id       = $Object.ID
            #serviceArea            = $Object.serviceArea
            #serviceAreaDisplayName = $Object.serviceAreaDisplayName
            url      = $NewURL
            Port     = $Object.port
            Protocol = $Object.protocol
            #expressRoute           = $Object.expressRoute
            #category               = $Object.category
            required = $Object.required
            #notes                  = $Object.notes
        }
        
        $Script:M365ServiceURLs.Add($URLObject) | Out-Null
    }
}
function Get-M365Service {
    <#
    .SYNOPSIS
    Will grab M365 and MEM JSONs from Microsoft using a random GUID
    #>
    param(
        [switch]$M365,
        [switch]$MEM
    )
    $EndpointURL = "https://endpoints.office.com"
    #if (Test-HTTP -URL $EndpointURL) {
    if ($M365) {
        Write-Log 'Adding Microsoft URLs to the pool from service area M365' -Component 'GetM365URLs'
        if ($Tenantname) { $URLs = Invoke-RestMethod -Uri ("$EndpointURL/endpoints/WorldWide?clientrequestid=$Script:GUID&TenantName=$Tenantname") }
        else { $URLs = Invoke-RestMethod -Uri ("$EndpointURL/endpoints/WorldWide?clientrequestid=$Script:GUID") }
    }
    if ($MEM) {
        Write-Log 'Adding Microsoft URLs to the pool from service area MEM' -Component 'GetM365URLs'
        $URLs = Invoke-RestMethod -Uri ("$EndpointURL/endpoints/WorldWide?ServiceAreas=MEM`&`clientrequestid=$Script:GUID")
    }
    foreach ($Object in $URLs) {
        $Ports = [array](($(if ($Object.tcpPorts) { $Object.tcpPorts }elseif ($Object.udpPorts) { $Object.udpPorts }else { '443' })).split(",").trim())
        $Protocol = $(if ($Object.tcpPorts) { 'TCP' } elseif ($Object.udpPorts) { 'UDP' } else { 'TCP' })
        foreach ($URL in $Object.urls) {
            foreach ($Port in $Ports) {
                $URLObject = [PSCustomObject]@{
                    id       = $Object.id
                    #serviceArea            = $Object.serviceArea
                    #serviceAreaDisplayName = $Object.serviceAreaDisplayName
                    url      = $URL
                    Port     = $Port
                    Protocol = $Protocol
                    #expressRoute           = $Object.expressroute
                    #category               = $Object.category
                    required = $Object.required
                    #notes                  = $Object.notes
                }
                if ($URL -match '\*') {
                    Write-Log -Message "The URI $URL contains a wildcard - trying to find nearest match later" -Component 'GetM365Service'
                    if ($URL -in $Script:WildCardURLs.url) {
                        continue
                    }
                    $Script:WildCardURLs.add($URLObject) | Out-Null
                    continue
                }
                $Script:M365ServiceURLs.Add($URLObject) | Out-Null
            }
        }
    }
    if ($AllowBestEffort) {
        Write-Log -Message 'Best effort URLs are enabled - this will turn wildcards into regular URLs using a best effort method' -Component 'IntuneNetworkCheckMain'
        Find-WildcardURL
    }
}

#Test Functions
function Test-SSLInspectionByKnownCRLs {
    <#
    .SYNOPSIS
    Verify CRL against known good - this is an indicator for SSLInspection
    #>
    param(
        [string]$CRLURL,
        [string]$VerifyAgainstKnownGood
    )
    $KnownCRL = $false
    if (-not($Script:CRLURLsToCheck)) {
        if ($Script:ManualURLs) {
            $Script:ManualURLs | Where-Object { $_.id -in "125", "84", "9993" } | ForEach-Object { $Script:CRLURLsToCheck.add($_) | Out-Null }
        }
        if ($Script:M365ServiceURLs) {
            $Script:M365ServiceURLs | Where-Object { $_.id -in "125", "84", "9993" } | ForEach-Object { $Script:CRLURLsToCheck.add($_) | Out-Null }
        }
    }
    foreach ($URL in $Script:CRLURLsToCheck.url) {
        if ($CRLURL -like $("*" + $URL + "*") -or $VerifyAgainstKnownGood -eq $URL) {
            $KnownCRL = $true
        }
    }
    return $KnownCRL
}
function Test-SSL {
    <#
    .SYNOPSIS
    Opens a TCP connection to a URL and attempts to secure it using the strongest encryption method available.
    .NOTES
    Initial idea: https://learn.microsoft.com/en-us/troubleshoot/azure/azure-monitor/log-analytics/windows-agents/ssl-connectivity-mma-windows-powershell
    #>
    param(
        $SSLTarget, 
        $SSLPort = 443
    )
    $TCPSocket = New-Object Net.Sockets.TcpClient($SSLTarget, $SSLPort)
    $SSLStream = New-Object -TypeName Net.Security.SslStream($TCPSocket.GetStream(), $false)
    try {
        $SSLStream.AuthenticateAsClient(
            $SSLTarget, #targetHost
            $null, #clientCertificates (Collection)
            $true #checkCertificateRevocation
        )
    } catch [System.Security.Authentication.AuthenticationException] {
        #THIS ONLY WORKS IN PS7!!
        if ($PSVersionTable.psversion.major -ge 7) {
            switch -Wildcard ($Error[0].Exception.InnerException.Message) {
                "Cannot determine the frame size or a corrupted frame was received." { $AuthException = "FrameSizeOrCorrupted" }
                "*TLS alert: 'HandshakeFailure'." { $AuthException = "HandshakeFailure" }
                "*validation procedure: RemoteCertificateNameMismatch" { $AuthException = "RemoteCertificateNameMismatch" }
                default { $AuthException = $Error[0].Exception.InnerException.Message.Split(':')[1].Trim() }
            } 
        } else {
            Write-Log -Message 'Cannot determine exact certificate failure, defaults to "failed"' -Component 'TestSSL' -Type 2
            $AuthException = "Failed"
        }
    } catch [System.Management.Automation.MethodInvocationException] {
        Write-Log -Message 'The TCP socket closed unexpectedly. This could be random, repeat this test.' -Type 2 -Component 'TestSSL'
    }
    if ($SSLStream.IsAuthenticated) {
        $SSLTest = $true
        $CertInfo = New-Object -TypeName Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
        if ($CertInfo.Thumbprint -and $CheckCertRevocation) {
            Write-Log -Message "Grabbing CRL for $SSLTarget and verify against known-good" -Component 'TestSSL'
            $CRLURIarray = $CertInfo.Extensions |  Where-Object -FilterScript { $_.Oid.Value -eq '2.5.29.31' } | ForEach-Object -Process { $_.Oid.FriendlyName; $_.Format($true) }
            $SSLInspectionResult = $false
            $KnownCRL = $false
            if (-not($CRLURIarray)) {
                Write-Log "No CRL detected - SSL inspection is likely. Testing if tested URL $SSLTarget is a known address CRL itself" -Component 'TestSSL' -Type 2
                $VerifyAgainstKnownGoodResult = Test-SSLInspectionByKnownCRLs -VerifyAgainstKnownGood $SSLTarget
                if ($VerifyAgainstKnownGoodResult) {
                    Write-Log "$SSLTarget is a known good CRL address" -Component 'TestSSL' -Type 2
                    $KnownCRL = $true
                }
                if (-not($VerifyAgainstKnownGoodResult)) {
                    Write-Log "SSL Inspection very likely. $SSLTarget is not a known CRL address" -Component 'TestSSL' -Type 2
                    $SSLInspectionResult = $true
                }
            } elseif ($CRLURIarray[1].split('[').count -ge 2) {
                if ($CRLURIarray[1].split('[').count -eq 2) {
                    $CRLURI = $CRLURIarray[1].Split('http://')[1].split('/')[0]
                    $KnownCRL = Test-SSLInspectionByKnownCRLs -CRLURL $CRLURI
                } elseif ($CRLURIarray[1].split('[').count -gt 2) {
                    $TestMultipleCRLs = $CRLURIarray[1].split('=').split('[').trim() | Where-Object { $_.startswith("http://") } | ForEach-Object { Test-SSLInspectionByKnownCRLs -CRLURL $_.Split('http://')[1].split('/')[0] } | Where-Object { $_ -contains $true }
                    if ($TestMultipleCRLs) { $KnownCRL = $true }
                }
                if (-not($KnownCRL)) {
                    Write-Log "Unknown CRL. $SSLTarget's certificate didn't provide any known CRL address" -Component 'TestSSL' -Type 2
                    $SSLInspectionResult = $true
                }
            }
        }
    }
    $TCPSocket.Close()
    $TCPSocket.Dispose()
    if ($null -eq $SSLTest) {
        $SSLTest = $false
    }
    $Result = [PSCustomObject]@{
        SSLTest         = $SSLTest
        SSLProtocol     = $SSLStream.SslProtocol
        Issuer          = $CertInfo.Issuer
        AuthException   = $AuthException
        KnownCRL        = $KnownCRL
        SSLInterception = $SSLInspectionResult
    }
    return $Result
}
function Test-HTTP {
    <#
    .SYNOPSIS
    Checks for HTTP(s) return codes. 403 and 401 can be indicators of (authenticated) proxy interruption.
    #>
    param(
        [string]$HTTPURL,
        [int]$HTTPPort
    )
    switch ($HTTPPort) {
        "80" { $URIStart = "http://" }
        "443" { $URIStart = "https://" }
        default { $URIStart = "https://" }
    }
    try {
        #MARKED FOR CLEANUP. Reason: PS5 only code.
        #We could use -SkipHttpErrorCheck in PS7...
        if ($PSVersionTable.psversion.major -ge 7) {
            $HTTPiwr = Invoke-WebRequest -Uri $($URIStart + $HTTPURL) -ConnectionTimeoutSeconds $(($MaxDelayInMS / 100)) -Method Get -SkipHttpErrorCheck
        } else {
            $HTTPiwr = Invoke-WebRequest -Uri $($URIStart + $HTTPURL) -ConnectionTimeoutSeconds $(($MaxDelayInMS / 100)) -Method Get 
        }
        return $HTTPiwr.StatusCode
    } catch {
        #This is only reached if PS5 is used
        $Statuscode = $error[0].Exception.Response.StatusCode.value__
        if ($Statuscode) {
            return $Statuscode
        }
        return $false
    }
}
function Test-DNS {
    <#
    .SYNOPSIS
    Verifies that DNS is working for a given URL and that the IP does not resolve a sinkhole (0.0.0.0 or 127.0.0.1 or ::).
    #>
    param(
        [string]$DNSTarget
    )
    $DNSresult = $true
    if ($DNSTarget -in $Script:DNSCache.CachedURL) {
        $CachedResult = $Script:DNSCache | Where-Object { $_.CachedURL -eq $DNSTarget } | Select-Object -Property result
        return $CachedResult.result
    }
    $ResolvedDNSRecords = Resolve-DnsName -Name $DNSTarget -ErrorAction SilentlyContinue
    if ($ResolvedDNSRecords.count) {
        foreach ($DNSARecord in $ResolvedDNSRecords.IP4Address) {
            if ($DNSARecord.IP4Address) {
                if ($DNSARecord -eq '0.0.0.0' -or $DNSARecord -eq '127.0.0.1') {
                    Write-Log -Message "DNS sinkhole detected: Address $DNSTarget resolved to an invalid address" -Component 'TestDNS' -Type 2
                    $DNSresult = $false
                    break
                }
            }
        }
        foreach ($DNSAAAARecord in $ResolvedDNSRecords.IP6Address) {
            if ($DNSAAAARecord -eq '::') {
                Write-Log -Message "DNS sinkhole detected: Address $DNSTarget resolved to an invalid address" -Component 'TestDNS' -Type 2
                $DNSresult = $false
                break
            }
        }
    } else {
        Write-Log -Message "No DNS record found for $DNSTarget" -Component 'TestDNS' -Type 3
        $DNSresult = $false
    }
    $DNSObject = [PSCustomObject]@{
        CachedURL = $DNSTarget
        Result    = $DNSresult
    }
    $Script:DNSCache.add($DNSObject) | Out-Null
    return $DNSresult
}
function Test-TCPPort {
    <#
    .SYNOPSIS
    Opens a TCP connection to a given URL.
    #>
    param(
        [string]$TCPTarget,
        [int]$TCPPort,
        [int]$MaxWaitTime
    )
    if (-not($MaxWaitTime)) {
        $MaxWaitTime = $MaxDelayInMS
    }
    if ($TCPTarget -in $Script:DNSCache.CachedURL) {
        $DNSCachedResult = $Script:DNSCache | Where-Object { $_.CachedURL -eq $TCPTarget } | Select-Object -Property result -First 1
        if (-not($DNSCachedResult.result)) {
            return $false
        }
    }
    if (-not($BurstMode)) {
        if ($TCPTarget -in $Script:TCPCache.CachedURL -and $TCPPort -in ($Script:TCPCache.Port | Where-Object { $_.CachedURL -eq $TCPTarget })) {
            $TCPCachedResult = $Script:TCPCache | Where-Object { $_.CachedURL -eq $TCPTarget } | Select-Object -Property result -First 1
            if (-not($TCPCachedResult.result)) {
                return $false
            }
        }
    }
    $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
    $RunningClient = $TCPClient.ConnectAsync($TCPTarget, $TCPPort)
    Start-Sleep -Milliseconds $MaxWaitTime
    $success = $false 
    if ($RunningClient.IsCompleted) {
        if ($RunningClient.Status -ne 'RanToCompletion') {
            Write-Log "TCP Port test failed with $($RunningClient.Status)" -Component 'TestTCPPort' -Type 2
            if ($RunningClient.Exception.InnerException) {
                Write-Log "$($RunningClient.Exception.InnerException.Message)" -Component 'TestTCPPort'
            }
        } else {
            $success = $true
        }
    } else {
        Write-Log 'TCP Port did not respond in a timely fashion' -Component 'TestTCPPort' -Type 2
    }
    $TCPClient.Close()
    $TCPClient.Dispose()
    if (-not($BurstMode)) {
        $TCPObject = [PSCustomObject]@{
            CachedURL = $TCPTarget
            Port      = $TCPPort
            Result    = $result
        }
        $Script:TCPCache.add($TCPObject) | Out-Null
    }
    return $success
}
function Test-NTPviaUDP {
    <#
    .SYNOPSIS
    Will test an NTP server using UDP. This is the only UDP test available currently. If more endpoints are found (like DO) those might get added too
    .DESCRIPTION
    The only service that will ever answer to a UDP request, because it has to, is a NTP server. There are other ways to test that though see the Test-NTP function
    HUGE thanks to https://github.com/proxb/PowerShell_Scripts/blob/master/Test-Port.ps1 and
    Jannik Reinhard for the idea to use NTP to test UDP https://github.com/JayRHa/Intune-Scripts/blob/main/Check-AutopilotPrerequisites/Check-AutopilotPrerequisites.ps1#L145
    #>
    param(
        [string]$Target,
        [int]$Port
    )
    Write-Log "Test $Target via direct UDP request" -Component 'TestNTPviaUDP'
    $NTPData = New-Object byte[] 48
    $NTPData[0] = 27
    $udpobject = New-Object Net.Sockets.Udpclient([System.Net.Sockets.AddressFamily]::InterNetwork) 
    $udpobject.Client.Blocking = $False
    $udpobject.AllowNatTraversal($true)
    $Error.Clear()
    $udpobject.Connect($Target, $Port) | Out-Null
    
    if ($udpobject.client.Connected) {
        Write-Log -Message 'Sending UDP test message' -Component 'TestUDPPort'
        [void]$udpobject.Send($NTPData, $NTPData.Length)
        $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
        Start-Sleep -Milliseconds 100 #We have to wait slightly to send the data back
        $TestData = $udpobject.Receive([ref]$remoteendpoint)
    } else {
        Write-Log -Message 'No UDP "connection" established' -Component 'TestUDPPort'
        Write-Log -Message "$($Error[0].Exception.InnerException.Message)" -Component 'TestUDPPort' -Type 2
        return $false
    }
    $udpobject.Close()
    $udpobject.Dispose()
    if ($TestData) {
        $Seconds = [BitConverter]::ToUInt32( $TestData[43..40], 0 )
        ( [datetime]'1/1/1900' ).AddSeconds( $Seconds ).ToLocalTime()
    } else {
        Write-Log -Message 'Did not receive a response' -Component 'TestUDPPort' -Type 2
        return $false
    }
    return $true
}
function Test-TCPBurstMode {
    <#
    .SYNOPSIS
    Will test a given URL in 50ms chunks (50,100,150...) until $MaxDelayInMS is reached.
    #>
    param(
        $WorkObject
    )
    $MinimumWaitTime = 50
    $AmountofTimes = [math]::floor([decimal]($MaxDelayInMS / $MinimumWaitTime))
    for ($i = 1; $i -lt $AmountofTimes + 1; $i++) {
        $MaxWaitTime = $($MinimumWaitTime * $i)
        $TCPResult = Test-TCPPort -Target $WorkObject.url -Port $WorkObject.port -MaxWaitTime $MaxWaitTime
        $WorkObject | Add-Member -MemberType NoteProperty -Name "TCP$MaxWaitTime" -Value $TCPResult
    }
}
function Test-Network {
    <#
    .SYNOPSIS
    This is the core function of this script. It combines every possible test (DNS, CRL, TCP, TLS...) into one function.
    .NOTES
    ToDo: Make each check based upon a switch that is default = on
    #>
    
    param(
        [PSCustomObject]$TestObject
    )
    Write-Log "Testing $($TestObject.url) on port $($TestObject.port)" -Component 'TestNetwork'
    if ($TestObject -in $Script:FinalResultList) {
        Write-Log 'This URL/Port was already tested' -Component 'TestNetwork'
        return $true
    }
    $TestObject | Add-Member -Name 'DNSResult' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'TCPResult' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'HTTPStatusCode' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'SSLTest' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'SSLProtocol' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'Issuer' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'AuthException' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'KnownCRL' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'SSLInterception' -MemberType NoteProperty -Value ""
    $DNS = Test-DNS -DNSTarget $TestObject.url
    $TestObject.DNSResult = $DNS
    if ($DNS) {
        if ($BurstMode) {
            Test-TCPBurstMode -TCPTarget $TestObject.url
        } else {
            if ($TestObject.protocol -ne 'TCP') {
                Write-Log 'This script can not test UDP ports - only NTP (see log for those results)' -Component 'TestNetwork' -Type 2
            } else {
                $TCP = Test-TCPPort -TCPTarget $TestObject.url -TCPPort $TestObject.port
                $TestObject.TCPResult = $TCP
            }
            if ($TCP) {
                #Test HTTP(s) Connections
                $HTTPStatuscode = Test-HTTP -HTTPURL $TestObject.url -HTTPPort $TestObject.port
                if ($null -ne $HTTPStatuscode) {
                    $TestObject.HTTPStatusCode = $HTTPStatuscode
                } else { 
                    $TestObject.HTTPStatusCode = $false 
                }
                #Test TLS and verify everything around the cert including traffic interception
                $SSLTest = Test-SSL -SSLTarget $TestObject.url -SSLPort $TestObject.port
                $TestObject.SSlTest = $SSLTest.SSLTest

                if ($SSLTest.SSLTest) {
                    $TestObject.SSLProtocol = $SSLTest.SSLProtocol
                    $TestObject.Issuer = $SSLTest.Issuer
                    if ($SSLTest.AuthException) {
                        $TestObject.AuthException = $SSLTest.AuthException
                    }
                    if ($null -ne $SSLTest.KnownCRL) {
                        $TestObject.KnownCRL = $SSLTest.KnownCRL
                    }      
                    if ($null -ne $SSLTest.SSLInterception) {
                        $TestObject.SSLInterception = $SSLTest.SSLInterception
                    }
                }
            }
        }
    }
    $Script:FinalResultList.add($TestObject) | Out-Null
}

#Service Areas
function Test-DNSServers {
    <#
    .SYNOPSIS
    This will test a mixture of public DNS servers.
    .NOTES
    ServiceIDs 999
    #>
    $ServiceIDs = 999
    $ServiceArea = "DNSServer"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log 'Testing DNSservers will ignore the local "HOSTS" file.' -Component "Test$ServiceArea"
    $DNSServer = Get-URLsFromID -IDs $ServiceIDs
    if (-not($DNSServer)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        Write-Log -Message 'Please use the CSV provided with this script and specify -CustomURLFile' -Component "Test$ServiceArea"
        return $false
    }
    foreach ($DNSTarget in $Script:URLsToVerify) {
        $UDPDNSTest = Resolve-DnsName "microsoft.com" -DnsOnly -Type A -Server $DNSTarget.url -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue
        if (-not($UDPDNSTest)) {
            Write-Log "UDP DNS test failed for DNS server $($DNSTarget.url) - trying TCP fallback" -Component $ServiceArea -Type 2
            $TCPDNSTest = Resolve-DnsName "microsoft.com" -DnsOnly -Type A -Server $DNSTarget.url -NoHostsFile -TcpOnly -QuickTimeout -ErrorAction SilentlyContinue
            if (-not($TCPDNSTest)) {
                Write-Log "TCP DNS test failed for DNS server $($DNSTarget.url) - trying TCP fallback" -Component $ServiceArea -Type 2
            }
            Write-Log "TCP DNS test successful for DNS server $($DNSTarget.url)" -Component $ServiceArea
        }
        Write-Log "UDP DNS test successful for DNS server $($DNSTarget.url)" -Component $ServiceArea
    }
    return $true
}
function Test-RemoteHelp {
    <#
    .SYNOPSIS
    This will test all URLs required for RemoteHelp.
    .NOTES
    ServiceIDs 181,187,189
    ServiceIDs GCC 188
    Remote Help - Default + Required https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#remote-help
    #>
    $ServiceIDs = 181, 187, 189
    if ($GCC) {
        $ServiceIDs = 181, 187, 188, 189
    }
    $ServiceArea = "RemoteHelp"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $RH = Get-URLsFromID -IDs $ServiceIDs
    if (-not($RH)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($RHTarget in $Script:URLsToVerify) {
        Test-Network $RHTarget
    }
    return $true
}
function Test-TPMAttestation {
    <#
    .SYNOPSIS
    This will test all URLs required for TPM attestation.
    .NOTES
    ServiceIDs 173,9998
    https://learn.microsoft.com/en-us/autopilot/requirements?tabs=networking#autopilot-self-deploying-mode-and-autopilot-pre-provisioning
    #>

    $ServiceIDs = 173, 9998
    $ServiceArea = "TPMAtt"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $TPMAtt = Get-URLsFromID -IDs $ServiceIDs
    if (-not($TPMAtt)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($TPMTarget in $Script:URLsToVerify) {
        Test-Network $TPMTarget
    }
    return $true
}
function Test-WNS {
    <#
    .SYNOPSIS
    This will test all URLs required for the windows push notification service (WNS).
    .NOTES
    ServiceIDs 169,171
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#windows-push-notification-serviceswns-dependencies
    #>
    $ServiceIDs = 169, 171
    $ServiceArea = "WNS"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $WNS = Get-URLsFromID -IDs $ServiceIDs
    if (-not($WNS)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($WNSTarget in $Script:URLsToVerify) {
        Test-Network $WNSTarget
    }
    return $true
}
function Test-DeviceHealth {
    <#
    .SYNOPSIS
    This will test all URLs required for Microsoft Azure Attestation (formerly Device Health).
    .NOTES
    ServiceIDs 186
    GCC 9995
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#migrating-device-health-attestation-compliance-policies-to-microsoft-azure-attestation
    https://learn.microsoft.com/en-us/windows/client-management/mdm/healthattestation-csp
    #>
    $ServiceIDs = 186
    if ($GCC) {
        $ServiceIDs = 186, 9995
    }
    $ServiceArea = "DeviceHealth"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $DH = Get-URLsFromID -IDs $ServiceIDs
    if (-not($DH)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($DHTarget in $Script:URLsToVerify) {
        Test-Network $DHTarget
    }
    return $true
}
function Test-DeliveryOptimization {
    <#
    .SYNOPSIS
    This will test all URLs required for delivery optimization.
    .NOTES
    ServiceIDs 172,164,9994
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#delivery-optimization-dependencies
    https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-faq#what-hostnames-should-i-allow-through-my-firewall-to-support-delivery-optimization
    #>
    $ServiceIDs = 172, 164, 9994
    $ServiceArea = "DO"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log 'Filtered Port TCP 7680: Documentation will specify port 7680 TCP. This is used to listen to other clients requests (from the host)' -Component 'TestDO'
    Write-Log 'Filtered Port UDP 3544: Documentation will specify port 3544 UDP in/outbound as required - this is required for P2P connections' -Component 'TestDO'
    Write-Log 'Verify TCP Port 7680 is being listened on' -Component 'TestDO'
    $Listening = Get-NetTCPConnection -LocalPort 7680 -ErrorAction SilentlyContinue
    if (-not($Listening)) {
        Write-Log 'TCP Port 7680 not being listed as listening checking service' -Component 'TestDO'
        if (-not(Get-Service -Name DoSvc)) {
            Write-Log 'DoSvc is not running! Delivery optimization not possible' -Component 'TestDO' -Type 3
            return $false
        }
    }
    $DeliveryOptimization = Get-URLsFromID -IDs $ServiceIDs -FilterPort 7680, 3544
    if (-not($DeliveryOptimization)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($DOTarget in $Script:URLsToVerify) {
        Test-Network $DOTarget
    }
    return $true
}
function Test-Apple {
    <#
    .SYNOPSIS
    This will test all URLs required for managing Apple devices.
    .NOTES
    ServiceIDs 178
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?#apple-dependencies
    #>
    Write-Log -Message 'Port 5223 is only used as a fallback for push notifications and only valid for push.apple.com addresses' -Component 'TestApple'
    Write-Log -Message 'Warning: Other URLs might be required, please also consult https://support.apple.com/de-de/101555' -Component 'TestApple' -Type 2
    $ServiceIDs = 178
    $ServiceArea = "Apple"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $AAPL = Get-URLsFromID -IDs $ServiceIDs
    if (-not($AAPL)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($AAPLTarget in $Script:URLsToVerify) {
        Test-Network $AAPLTarget
    }
    return $true
}
function Test-Android {
    <#
    .SYNOPSIS
    This will test all URLs required for managing Android devices
    .NOTES
    ServiceIDs 179,9992
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#android-aosp-dependencies
    #>
    Write-Log -Message 'Warning: Other URLs might be required, please also consult https://static.googleusercontent.com/media/www.android.com/en//static/2016/pdfs/enterprise/Android-Enterprise-Migration-Bluebook_2019.pdf' -Component 'TestAndroid' -Type 2
    $ServiceIDs = 179, 9992
    $ServiceArea = "Android"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"

    Write-Log 'Testing Android connectivity check' -Component "Test$ServiceArea"
    $AndroidConnectivity = Invoke-WebRequest -Uri https://www.google.com/generate_204
    if ($AndroidConnectivity.StatusCode -ne 204) {
        Write-Log 'Android connectivity check failed - not testing any other addresses' -Component "Test$ServiceArea"
        return $false
    }
    $Googl = Get-URLsFromID -IDs $ServiceIDs
    if (-not($Googl)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($GoogleTarget in $Script:URLsToVerify) {
        Test-Network $GoogleTarget
    }
    return $true
}
function Test-CRL {
    <#
    .SYNOPSIS
    This will test all well-known CRLs by checking the availability of their respective URLs - _not_ the actual CRL.
    .NOTES
    ServiceIDs 84,125,9993
    Source: Martin Himken - this isn't well documented. From the MSJSON we can assume these are correct
    #>
    $ServiceIDs = 84, 125, 9993
    $ServiceArea = "CRL"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log "CRLs should only ever be available through Port 80, however the MS-JSOn specifies 443 as well. Expect errors going forward" -Component "Test$ServiceArea"
    $CertRevocation = Get-URLsFromID -IDs $ServiceIDs
    if (-not($CertRevocation)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($CRLTarget in $Script:URLsToVerify) {
        Test-Network $CRLTarget
    }
    return $true
}
function Test-WindowsActivation {
    <#
    .SYNOPSIS
    This will test all URLs required for windows activation.
    .NOTES
    ServiceIDs 9991
    https://support.microsoft.com/en-us/topic/windows-activation-or-validation-fails-with-error-code-0x8004fe33-a9afe65e-230b-c1ed-3414-39acd7fddf52
    #>
    $ServiceIDs = 9991
    $ServiceArea = "WinAct"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log 'These following URLs are best effort - there is very little documentation about this' -Component "Test$ServiceArea"
    $WinAct = Get-URLsFromID -IDs $ServiceIDs
    if (-not($WinAct)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($WinActTarget in $Script:URLsToVerify) {
        Test-Network $WinActTarget
    }
    return $true
}
function Test-EntraID {
    <#
    .SYNOPSIS
    This will test all URLs required for Entra ID.
    .NOTES
    ServiceIDs 9990,125,84,9993
    https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-connectivity#connectivity-issues-in-the-installation-wizard
    "Of these URLs, the URLs listed in the following table are the absolute bare minimum to be able to connect to Microsoft Entra ID at all"
    As this list contains a lot of CRLs IDs 125,84 and 9993 (Test-CRL) also apply here - this is more than the bare minimum but CRLs should always be reachable.
    #>
    $ServiceIDs = 9990
    $ServiceArea = "EID"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log 'The following URLs are the bare minimum for EntraID to work - depending on the situation there might be more' -Component "Test$ServiceArea"
    $EID = Get-URLsFromID -IDs $ServiceIDs
    if (-not($EID)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($EIDTarget in $Script:URLsToVerify) {
        Test-Network $EIDTarget
    }
    if (-not($TestAllServiceAreas)) {
        $TestCRLs = Test-CRL
        if (-not($TestCRLs)) {
            Write-Log "Testing CRLs for $ServiceArea failed" -Component "Test$ServiceArea" -Type 2
        }
    } else {
        Write-Log 'TestAllServiceAreas detected - not re-running sub-tests for this service area' -Component "Test$ServiceArea"
    }
    return $true
}
function Test-WindowsUpdate {
    <#
    .SYNOPSIS
    This will test all URLs required for Windows Update, this does not include delivery optimization.
    .NOTES
    ServiceIDs 164,9984
    https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/windows-update-issues-troubleshooting#device-cant-access-update-files
    #>
    $ServiceIDs = 164, 9984
    $ServiceArea = "WU"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $WindowsUpdate = Get-URLsFromID -IDs $ServiceIDs
    if (-not($WindowsUpdate)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($WUTarget in $Script:URLsToVerify) {
        Test-Network $WUTarget
    }
    return $true
}
function Test-NTP {
    <#
    .SYNOPSIS
    This will test NTP through multiple methods, including sending an actual NTP request to Microsoft.
    .NOTES
    ServiceIDs 165
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?#autopilot-dependencies
    Would throw 0x800705B4 if the URL exists but isn't an NTP or 0x80072AF9 for not resolved
    #>

    $ServiceIDs = 165
    $ServiceArea = "NTPServers"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log 'Microsofts JSON claims more URLs for Port 123, where in reality its only time.windows.com' -Component "Test$ServiceArea"
    Write-Log 'There are more URLs related to NCSI in the Service ID 165, which will also be tested.' -Component "Test$ServiceArea" 
    $NTPServerNotDefault = $true
    $CurrentTimeServer = (w32tm /query /source).trim()
    switch ($CurrentTimeServer) {
        *80070005* { Write-Log 'You need to run this script as admin to view the currently configured NTP server' -Component "Test$ServiceArea" -Type 2 }
        *80070426* { Write-Log 'The service has not been started' -Component "Test$ServiceArea" -Type 2 }
        *time.windows.com* { $NTPServerNotDefault = $false; Write-Log 'time.windows.com is the default timeserver - skipping custom server test' -Component "Test$ServiceArea" }
    }
    if ($NTPServerNotDefault) {
        if ($Autopilot) {
            Write-Log 'time.windows.com is currently not the timeserver - this is a requirement for Autopilot' -Component "Test$ServiceArea" -Type 2
        }
        $CurrentTimeServer = $CurrentTimeServer.Split(',')[0]
        $CustomTimeServerTestResult = Test-NTPviaUDP $CurrentTimeServer -Port 123
    }
    Write-Log 'Testing default NTP server' -Component "Test$ServiceArea" 
    $DefaultTimeServerTestResult = w32tm /stripchart /computer:time.windows.com /dataonly /samples:3
    if ($DefaultTimeServerTestResult -like "*80072AF9*" -or $DefaultTimeServerTestResult[3 - ($DefaultTimeServerTestResult.count)] -like "*800705B4*") {
        Write-Log 'Testing with w32tm failed - switching to UDP test for NTP' -Component "Test$ServiceArea" -Type 2
        $DefaultTimeServerTestResult = Test-NTPviaUDP 'time.windows.com' -Port 123
    }
    if ($CustomTimeServerTestResult -or $DefaultTimeServerTestResult) {
        Write-Log "Custom NTP Server Test: $CustomTimeServerTestResult" -Component "Test$ServiceArea"
        Write-Log "Default NTP Server Test: $($null -ne $DefaultTimeServerTestResult)" -Component "Test$ServiceArea"
        $NTPServers = Get-URLsFromID -IDs $ServiceIDs -FilterPort 80, 443
        if (-not($NTPServers)) {
            Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
            return $false
        }
        foreach ($NTPServersTarget in $Script:URLsToVerify) {
            Test-Network $NTPServersTarget
        }
        return $true
    }
    Write-Log 'Both, custom and default, NTP servers tested did not answer as expected' -Component "Test$ServiceArea" -Type 3
    return $false
}
function Test-DiagnosticsData {
    <#
    .SYNOPSIS
    This tests all URLs required to send diagnostic data to Microsoft endpoints.
    .NOTES
    ServiceIDs 69,9983
    https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints
    #>
    $ServiceIDs = 69, 9983
    $ServiceArea = "Diagnostics"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $Diagnostics = Get-URLsFromID -IDs $ServiceIDs
    if (-not($Diagnostics)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($DiagnosticsTarget in $Script:URLsToVerify) {
        Test-Network $DiagnosticsTarget
    }
    return $true
}
function Test-DiagnosticsDataUpload {
    <#
    .SYNOPSIS
    This tests all URLs required to send collected diagnostics data to Intune (yes, the .zip file).
    .NOTES
    ServiceIDs 182,9989
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?#autopilot-dependencies
    https://learn.microsoft.com/en-us/mem/intune/remote-actions/collect-diagnostics#requirements-for-windows-devices
    Also called "Autopilot automatic device diagnostics collection"
    #>
    $ServiceIDs = 182, 9989
    $ServiceArea = "DiagnosticsUpload"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $DiagUpload = Get-URLsFromID -IDs $ServiceIDs
    if (-not($DiagUpload)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($DiagUploadTarget in $Script:URLsToVerify) {
        Test-Network $DiagUploadTarget
    }
    return $true
}
function Test-EndpointAnalytics {
    <#
    .SYNOPSIS
    This will test all URLs required for endpoint analytics to receive data.
    .NOTES
    ServiceIDs 69,163,9988
    https://learn.microsoft.com/en-us/mem/analytics/troubleshoot#bkmk_endpoints
    #>
    $ServiceIDs = 69, 163, 9988
    $ServiceArea = "EndpAnalytics"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $EndpAnalytics = Get-URLsFromID -IDs $ServiceIDs
    if (-not($EndpAnalytics)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($EndpAnalyticsTarget in $Script:URLsToVerify) {
        Test-Network $EndpAnalyticsTarget
    }
    return $true
}
function Test-NCSI {
    <#
    .SYNOPSIS
    This tests all the URLs required for the network connection status indicator to work.
    .NOTES
    ServiceIDs 165,9987
    https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints
    https://learn.microsoft.com/en-us/windows/privacy/manage-windows-21h2-endpoints
    #>
    $ServiceIDs = 165, 9987
    $ServiceArea = "NetworkIndicator"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log "Service ID 165 is mixed up with NTP, hence Service ID 9987 is required to only test the correct URLs and ports" -Component "Test$ServiceArea" -Type 2
    try {
        $NCSIActive = (Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator -Name NoActiveProbe -ErrorAction Stop | Out-Null) -eq 0
    } catch {
        $NCSIActive = $true
    }
    if (-not($NCSIActive)) {
        Write-Log 'The NCSI has been detected as disabled - continuing with network tests regardless' -Component "Test$ServiceArea" -Type 2
    }
    $NetworkIndicator = Get-URLsFromID -IDs $ServiceIDs -FilterPort 123
    if (-not($NetworkIndicator)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($NetworkIndicatorTarget in $Script:URLsToVerify) {
        Test-Network $NetworkIndicatorTarget
    }
    return $true
}
function Test-MicrosoftStore {
    <#
    .SYNOPSIS
    This tests all the URLs that are required for the Microsoft Store to work. This includes Store updates.
    .NOTES
    ServiceIDs 9996
    https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints 
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?#microsoft-store
    #>
    $ServiceIDs = 9996
    $ServiceArea = "MS"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $MicrosoftStore = Get-URLsFromID -IDs $ServiceIDs
    if (-not($MicrosoftStore)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($MSTarget in $Script:URLsToVerify) {
        Test-Network $MSTarget
    }
    if (-not($TestAllServiceAreas)) {
        $WNSTest = Test-WNS
        $DOTest = Test-DeliveryOptimization
        if (-not($WNSTest -and $DOTest)) {
            return $false
        }
    } else {
        Write-Log 'TestAllServiceAreas detected - not re-running sub-tests for this service area' -Component "Test$ServiceArea"
    }
    return $true
}
function Test-AppInstaller {
    <#
    .SYNOPSIS
    This tests all the URLs that are required for the AppInstaller to work. This includes winget.
    .NOTES
    ServiceIDs 9996
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#microsoft-store
    #>
    $ServiceArea = "AppInstall"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log "Testing $ServiceArea is the same requirement as for the Microsoft store, this doesn't include downloads from vendor setup files (which depend on each package)" -Component "Test$ServiceArea" -Type 2
    if ($TestAllServiceAreas) {
        Write-Log 'TestAllServiceAreas detected - not re-running sub-tests for this service area' -Component "Test$ServiceArea"
        return $true
    }
    $TestMSStore = Test-MicrosoftStore
    if (-not($TestMSStore)) {
        Write-Log 'Testing the Microsoft store failed' -Component "Test$ServiceArea"
    }
    return $true
}
function Test-SelfDeploying {
    <#
    .SYNOPSIS
    This will test all the URLs that are required for the Autopilot self-deployment mode to work.
    .NOTES
    ServiceID 173, 9998
    https://learn.microsoft.com/en-us/autopilot/requirements?tabs=networking#autopilot-self-deploying-mode-and-autopilot-pre-provisioning
    #>
    $ServiceIDs = 173, 9998
    $ServiceArea = "SelfDepl"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $SelfDepl = Get-URLsFromID -IDs $ServiceIDs
    if (-not($SelfDepl)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($SelfDeplTarget in $Script:URLsToVerify) {
        Test-Network $SelfDeplTarget
    }
    return $true
}
function Test-Legacy {
    <#
    .NOTES
    Test-Hybrid Join? This might prove hard, as this is hardly documented (sure, it needs Entra-ID, but AD connectivity?)
    ToDo
    #>
}
function Test-UniversalPrint {
    <#
    .SYNOPSIS
    This will test all the URLs that are required for Universal Print
    .NOTES
    ServiceID 9982,9981,9980
    https://learn.microsoft.com/en-us/universal-print/fundamentals/universal-print-faqs
    As this is a script that tests client connections, the connector URLs are _not tested_. 
    Applicationinsight addresses are not documented. You can look at these by running "az account list-locations -o table"
    #>
    $ServiceIDs = 9982, 9980
    if ($GCC) {
        $ServiceIDs = 9981, 9980
    }
    $ServiceArea = "UniP"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $UniP = Get-URLsFromID -IDs $ServiceIDs
    if (-not($UniP)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($UniPTarget in $Script:URLsToVerify) {
        Test-Network $UniPTarget
    }
    return $true
}
#Special tests, not service area specific
function Test-AuthenticatedProxy {
    <#
    .SYNOPSIS
    This will attempt to test if an authenticated proxy is being used for URLs marked as incompatible with such a system.
    .NOTES
    ServiceIDs 9986
    These URLs don't allow authenticated proxies according to https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#access-for-managed-devices 
    This will use something.azureedge.com as an example for *.azureedge.com - yes, that is not a documented address.
    #>
    $ServiceIDs = 9986
    $ServiceArea = "AuthenProxy"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $AuthenProxy = Get-URLsFromID -IDs $ServiceIDs
    if (-not($AuthenProxy)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($AuthenProxyTarget in $Script:URLsToVerify) {
        Test-Network $AuthenProxyTarget
        if ($($Script:FinalResultList | Where-Object { ($_.url -eq $AuthenProxyTarget.url -and $_.port -eq $AuthenProxyTarget.port) -and ($_.HTTPStatusCode -in 407, 403, 401 ) })) {
            Write-Log -Message "The URL $($AuthenProxyTarget.url) requested authentication - this is not supported!" -Component "Test$ServiceArea" -Type 3
        }
    }
    return $true
}
function Test-SSLInspection {
    <#
    .SYNOPSIS
    This will attempt to test if an TLS/SSL inspection is being used for URLs marked as incompatible with such a system.
    .NOTES
    ServiceIDs 9985
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#access-for-managed-devices
    This uses checkin.dm.microsoft.com as a standin for *.dm.microsoft.com - could use discovery.dm.microsoft.com as fallback
    #>
    $ServiceIDs = 9985
    $ServiceArea = "TLSInspec"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $TLSInspec = Get-URLsFromID -IDs $ServiceIDs
    if (-not($TLSInspec)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($TLSInspecTarget in $Script:URLsToVerify) {
        Test-Network $TLSInspecTarget
    }
    if (-not($TestAllServiceAreas)) {
        $DeviceHealthTest = Test-DeviceHealth
        if (-not($DeviceHealthTest)) {
            return $false
        }
    } else {
        Write-Log 'TestAllServiceAreas detected - not re-running sub-tests for this service area' -Component "Test$ServiceArea"
    }
    foreach ($TLSInspectObject in $Script:FinalResultList) {
        if ($($Script:FinalResultList | Where-Object { $_.url -eq $TLSInspectObject.url -and $_.port -eq $TLSInspectObject.port -and $_.SSLInspection -eq 'True' })) {
            Write-Log -Message "The traffic to $($TLSInspectObject.url) is probably inspected - this is not supported!" -Component "Test$ServiceArea" -Type 3
        }
    }
    return $true
}
function Test-M365 {
    <#
    .SYNOPSIS
    Yes, this will test _every_ M365 Common URL regardless if it's required or not. Prepare for 15 minutes of runtime minimum.
    .NOTES
    ServiceIDs yes
    https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?
    #>
    $ServiceIDs = 41, 43, 44, 45, 46, 47, 49, 50, 51, 53, 56, 59, 64, 66, 67, 68, 69, 70, 71, 73, 75, 78, 79, 83, 84, 86, 89, 91, 92, 93, 95, 96, 97, 105, 114, 116, 117, 118, 121, 122, 124, 125, 126, 147, 152, 153, 156, 158, 159, 160, 184
    $ServiceArea = "MS365"
    if (-not($UseMS365JSON)) {
        Write-Log 'UseMS365JSON was not specified. This test can not be performed, because most IDs are not available' -Component "Test$ServiceArea" -Type 3
        return $false
    }
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $M365FullTest = Get-URLsFromID -IDs $ServiceIDs
    if (-not($M365FullTest)) {
        Write-Log -Message 'No matching ID found for service area: Windows Update' -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($M365Target in $Script:URLsToVerify) {
        Test-Network $M365Target
    }
    return $true
}
function Test-MDE {
    <#
    .SYNOPSIS
    Test all URLs required to use Microsoft Defender for Endpoint.
    .NOTES
    ServiceIDs
    https://download.microsoft.com/download/6/b/f/6bfff670-47c3-4e45-b01b-64a2610eaefa/mde-urls-commercial.xlsx
    ToDo - sorry Felix, it's coming don't worry.
    #>
    
}
function Test-Autopilot {
    <#
    .SYNOPSIS
    Test all URLs required to use Autopilot. This also includes a lot of other service areas.
    .NOTES
    ServiceIDs 164,165,169,173,182,9999
    9999 = Autopilot
    https://learn.microsoft.com/en-us/autopilot/requirements?tabs=networking#windows-autopilot-deployment-service
    Autopilot dependencies according to https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?#autopilot-dependencies
    #>
    $ServiceIDs = '9999'
    $ServiceArea = 'AP'
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $AP = Get-URLsFromID -IDs $ServiceIDs
    if (-not($AP)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($APTarget in $Script:URLsToVerify) {
        Test-Network $APTarget
    }
    <#
    Test-NTP #165
    Test-WNS #169
    Test-TPMAttestation #173
    Test-DeliveryOptimization #164
    Test-DiagnosticsDataUpload #182
    #>
    $resultlist = @{
        TestWindowsActivation = Test-WindowsActivation
        EntraIDTest           = Test-EntraID
        DiagnosticsDataUTest  = Test-DiagnosticsDataUpload 
        WUTest                = Test-WindowsUpdate
        DOTest                = Test-DeliveryOptimization
        NTPTest               = Test-NTP
        DNSTest               = Test-DNSServers #Log only output!
        DiagnosticsDataTest   = Test-DiagnosticsData
        NCSITest              = Test-NCSI
        WNSTest               = Test-WNS
        StoreTest             = Test-MicrosoftStore
        CRLTest               = Test-CRL
        LegacyTest            = Test-Legacy
        SelfDeployingTest     = Test-SelfDeploying
        TPMAttTest            = Test-TPMAttestation
    }
    if ($resultlist.values -contains $false) {
        Write-Log -Message "$resultlist" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    return $true
}
function Test-Intune {
    <#
    .SYNOPSIS
    Test all URLs required to use Intuine. This also includes a lot of other service areas.
    .NOTES
    ServiceIDs 163,172,170,97,190,189 + Authentiation 56,150,59
    9997 = Defender
    https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints
    #>
    $ServiceIDs = 56, 150, 59, 163, 172, 170, 97, 190, 189, 9998, 9985
    $ServiceArea = "Int"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $Int = Get-URLsFromID -IDs $ServiceIDs
    if (-not($Int)) {
        Write-Log -Message "No matching ID found for service area: $ServiceArea" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($IntTarget in $Script:URLsToVerify) {
        Test-Network $IntTarget
    }
    $resultlist = @{
        TestAutoPilot       = Test-Autopilot
        EntraIDTest         = Test-RemoteHelp
        WNSTest             = Test-WNS
        DOTest              = Test-DeliveryOptimization
        AppleTest           = Test-Apple
        AndroidTest         = Test-Android
        StoreTest           = Test-MicrosoftStore
        DeviceHealth        = Test-DeviceHealth
        WUTest              = Test-WindowsUpdate
        EndpAnalytics       = Test-EndpointAnalytics
        #MDE = Test-MDE #Not done!
        DiagnosticsDataTest = Test-DiagnosticsData
        NTPTest             = Test-NTP
    }
    if ($resultlist.values -contains $false) {
        Write-Log -Message "$resultlist" -Component "Test$ServiceArea" -Type 3
        return $false
    }
    return $true
}

#Data Functions
function Build-OutputCSV {
    <#
    .SYNOPSIS
    Creates either a URL result list or a merged CSV file.
    #>
    param(
        [string[]]$InputCSVs
    )
    if (-not($InputCSVs)) {
        $OutpathFilePath = $(Join-Path $WorkingDirectory -ChildPath "ResultList$("_"+$Script:DateTime + "_"+ $Env:COMPUTERNAME).csv")
        $Script:FinalResultList | Export-Csv -Path $OutpathFilePath -Encoding utf8
    } elseif ($InputCSVs.Count -eq 2) {
        $MergedCSVTargetFolder = $(Join-Path $WorkingDirectory -ChildPath '/MergedResults')
        if (-not(Test-Path $MergedCSVTargetFolder)) { New-Item -Path $MergedCSVTargetFolder -ItemType Directory | Out-Null }
        $OutpathFilePath = $(Join-Path $MergedCSVTargetFolder -ChildPath "/MergedResults$("_"+$Script:DateTime + "_"+ $Script:MergeCSVComputername1 + "_" + $Script:MergeCSVComputername2).csv")
        $Script:ComparedResults | Export-Csv -Path $OutpathFilePath -Encoding utf8 -Force
    }
}
function Merge-ResultFiles {
    <#
    .SYNOPSIS
    Merges two given CSV files.
    #>
    param(
        [PSCustomObject[]]$CSVInput
    )
    if ($CSVInput) {
        if ($CSVInput.count -ne 2) {
            Write-Log 'Currently, this script can only handle two file comparisons. Please provide only 2 CSVs' -Component 'MergeResultFiles' -Type 3
        }
    } else {
        Write-Log 'No input CSV given - triggering auto detection' -Component 'MergeResultFiles'
        $TempCSVInput = Get-ChildItem -Filter "*.csv" | Where-Object { $_.Name -ne $CustomURLFile -and $_.Name -ne 'INRCustomList.csv' }
        if (-not($TempCSVInput)) {
            $TempCSVInput = Get-ChildItem -Path $WorkingDirectory -Filter "*.csv" | Where-Object { $_.Name -ne $CustomURLFile -and $_.Name -ne 'INRCustomList.csv' }
        }
        if ($TempCSVInput.count -ne 2) {
            Write-Log "Auto detection found more or less than 2 CSV files in $WorkingDirectory" -Component 'MergeResultFiles' -Type 3
            return $false
        }         
        $CSVInput = $TempCSVInput.FullName
    }

    $Script:ComparedResults = [System.Collections.ArrayList]::new()
    for ($i = 0; $i -lt $CSVInput.Count; $i++) {
        if (Test-Path $CSVInput[$i]) {
            [System.IO.DirectoryInfo]$CSVPath = $CSVInput[$i]
        } else {
            [System.IO.DirectoryInfo]$CSVPath = Join-Path -Path $WorkingDirectory -ChildPath $CSVInput[$i]
        }
        if (-not(Test-Path $CSVPath)) {
            Write-Log "File $($CSVPath) not found" -Component 'MergeResultFiles' -Type 3
            return $false
        }
        $culture = [Globalization.CultureInfo]::CreateSpecificCulture('de-DE')
        $TimeStamp = Get-Date([DateTime]::ParseExact("$($CSVPath.name.Replace('ResultList_','').substring(0,15))", 'yyyyMMdd_HHmmss', $culture)) -Format "dd.MM.yyyy HH:mm:ss"
        $CSVComputername = $($CSVPath.name.Split('_')[3].split('.')[0])
        if ($i -ge 1) {
            if ($CSVComputername -eq $Script:MergeCSVComputername1) {
                $CSVComputername = $CSVComputername + "_older"
            }
        }
        New-Variable "MergeCSVComputername$($i+1)" -Value $CSVComputername -Scope Script
        New-Variable "MergeCSVTimestamp$($i+1)" -Value $TimeStamp -Scope Script
        New-Variable "ImportedCSV$($i+1)" -Value $(Import-Csv -Path $CSVPath)
    }
    Write-Log 'CSV imported - checking and merging' -Component 'MergeResultFiles'
    if ($ImportedCSV1.count -ne $ImportedCSV2.count) {
        Write-Log 'These CSV files have different lengths - please valide that you used the same tests' -Component 'MergeResultFiles' -Type 3
        Write-Log 'This happens especially when the M365 JSON or a new version of my URL list was selected as that might change at any time' -Component 'MergeResultFiles'
        return $false
    }
    $counter = 0
    if ($MergeShowAllResults) { Write-Log 'MergeShowAllResults is selected. All results will be merge into one result output instead of showing only differences' -Component 'MergeResultFiles' }
    foreach ($CSVLeftObject in $ImportedCSV1) {
        $Result = Compare-Object -ReferenceObject $CSVLeftObject -DifferenceObject $ImportedCSV2[$counter] -Property ID, URL, Port, DNSResult, TCPResult, HTTPStatusCode, SSLTest, SSLProtocol, Issuer, AuthException, SSLInterception
        $CSVLeftObject | Add-Member -Name 'ComputerName' -MemberType NoteProperty -Value "$($Script:MergeCSVComputername1)"
        $CSVLeftObject | Add-Member -Name 'TimeStamp' -MemberType NoteProperty -Value "$($Script:MergeCSVTimestamp1)"
        if ($Result) {
            Write-Log "Difference found at $($CSVLeftObject.url)" -Component 'MergeResultFiles'
            $ImportedCSV2[$counter] | Add-Member -Name 'ComputerName' -MemberType NoteProperty -Value "$($Script:MergeCSVComputername2)"
            $ImportedCSV2[$counter] | Add-Member -Name 'TimeStamp' -MemberType NoteProperty -Value "$($Script:MergeCSVTimestamp2)"
            $Script:ComparedResults.add($CSVLeftObject) | Out-Null
            $Script:ComparedResults.add($ImportedCSV2[$counter]) | Out-Null
        } elseif ($MergeShowAllResults) {
            $Script:ComparedResults.add($CSVLeftObject) | Out-Null
        }
        $counter++
    }
    $Script:ComparedResults = $Script:ComparedResults | Sort-Object -Property url, ComputerName
    return $true
}
function Start-Tests {
    <#
    .SYNOPSIS
    Starts either all, specific, or individual tests based on user input.
    #>
    if ($Intune -or $TestAllServiceAreas) {
        Write-Log -Message "Intune result: $(Test-Intune)" -Component 'StartTests'
    }
    if ($Autopilot -or $TestAllServiceAreas) {
        Write-Log -Message "Autopilot result: $(Test-Autopilot)" -Component 'StartTests'
    }
    if ($WindowsActivation -or $TestAllServiceAreas) {
        Write-Log -Message "Windows activation result: $(Test-WindowsActivation)" -Component 'StartTests'
    }
    if ($EntraID -or $TestAllServiceAreas) {
        Write-Log -Message "Entra ID result: $(Test-EntraID)" -Component 'StartTests'
    }
    if ($WindowsUpdate -or $TestAllServiceAreas) {
        Write-Log -Message "Windows Update result: $(Test-WindowsUpdate)" -Component 'StartTests'
    }
    if ($DeliveryOptimization -or $TestAllServiceAreas) {
        Write-Log -Message "Delivery Optimization result: $(Test-DeliveryOptimization)" -Component 'StartTests'
    }
    if ($NTP -or $TestAllServiceAreas) {
        Write-Log -Message "NTP result: $(Test-NTP)" -Component 'StartTests'
    }
    if ($DNS -or $TestAllServiceAreas) {
        Write-Log -Message "DNS result: $(Test-DNSServers)" -Component 'StartTests'
    }
    if ($DiagnosticsData -or $TestAllServiceAreas) {
        Write-Log -Message "Diagnostics Data result: $(Test-DiagnosticsData)" -Component 'StartTests'
    }
    if ($DiagnosticsDataUpload -or $TestAllServiceAreas) {
        Write-Log -Message "Diagnostics Data Upload result: $(Test-DiagnosticsDataUpload)" -Component 'StartTests'
    }
    if ($NCSI -or $TestAllServiceAreas) {
        Write-Log -Message "NCSI result: $(Test-NCSI)" -Component 'StartTests'
    }
    if ($WindowsNotificationService -or $TestAllServiceAreas) {
        Write-Log -Message "WNS result: $(Test-WNS)" -Component 'StartTests'
    }
    if ($WindowsStore -or $TestAllServiceAreas) {
        Write-Log -Message "Windows Store result: $(Test-MicrosoftStore)" -Component 'StartTests'
    }
    if ($M365 -or $TestAllServiceAreas) {
        Write-Log -Message "M365 result: $(Test-M365)" -Component 'StartTests'
    }
    if ($CRLs -or $TestAllServiceAreas) {
        Write-Log -Message "CRLs result: $(Test-CRL)" -Component 'StartTests'
    }
    if ($SelfDeploying -or $TestAllServiceAreas) {
        Write-Log -Message "Self-Deploying result: $(Test-SelfDeploying)" -Component 'StartTests'
    }
    if ($RemoteHelp -or $TestAllServiceAreas) {
        Write-Log -Message "Remote Help result: $(Test-RemoteHelp)" -Component 'StartTests'
    }
    if ($TPMAttestation -or $TestAllServiceAreas) {
        Write-Log -Message "TPM Attestation result: $(Test-TPMAttestation)" -Component 'StartTests'
    }
    if ($DeviceHealth -or $TestAllServiceAreas) {
        Write-Log -Message "Device Health result: $(Test-DeviceHealth)" -Component 'StartTests'
    }
    if ($Apple -or $TestAllServiceAreas) {
        Write-Log -Message "Apple result: $(Test-Apple)" -Component 'StartTests'
    }
    if ($Android -or $TestAllServiceAreas) {
        Write-Log -Message "Android result: $(Test-Android)" -Component 'StartTests'
    }
    if ($EndpointAnalytics -or $TestAllServiceAreas) {
        Write-Log -Message "Endpoint Analytics result: $(Test-EndpointAnalytics)" -Component 'StartTests'
    }
    if ($AppInstaller -or $TestAllServiceAreas) {
        Write-Log -Message "App Installer result: $(Test-AppInstaller)" -Component 'StartTests'
    }
    if ($AuthenticatedProxyOnly -or $TestAllServiceAreas) {
        Write-Log -Message "Authenticated Proxy result: $(Test-AuthenticatedProxy)" -Component 'StartTests'
    }
    if ($TestSSLInspectionOnly -or $TestAllServiceAreas) {
        Write-Log -Message "SSL Inspection result: $(Test-SSLInspection)" -Component 'StartTests'
    }
    if ($Legacy -or $TestAllServiceAreas) {
        Write-Log -Message "Legacy result: $(Test-Legacy)" -Component 'StartTests'
    }
    if ($UniversalPrint -or $TestAllServiceAreas) {
        Write-Log -Message "Universal Print result: $(Test-UniversalPrint)" -Component 'StartTests'
    }
}
function Start-Brienmode {
    $Null = Read-Host -Prompt "Please press any key to continue"
    Initialize-Script
    Start-Tests
}
function Start-ProcessingResults {
    if ($BrienMode) {
        Write-Output "BrienMode is activated: This is an interactive mode that will let you test multiple times on the same box"
        Write-Output "Remember this will only compare the LATEST TWO results"
        for ($i = 1; $i -le $BrienMode; $i++) {
            if ($i -ge 2) {
                Write-Log -Message 'RERUNNING TESTS WITH NEW NETWORK PARAMETERS' -Component 'BrienMode' -Type 2
                Write-Warning "Please change your network now to run the test again - this will always create output CSVs"
            }
            Start-Brienmode
            Build-OutputCSV
            if ($ShowResults) {
                $Script:FinalResultList | Out-GridView -Title "Intune Network test (Brien Mode) $($Script:MergeCSVComputername1) pass $i"
            }
        }
        $MergeCSVs = (Get-ChildItem -Path $WorkingDirectory -Filter *.csv | Sort-Object -Property LastWriteTime -Top 2 -Descending).FullName
        if (-not(Merge-ResultFiles -CSVInput $MergeCSVs)) {
            Write-Log 'Something went wrong while comparing the files, please check the logs' -Component 'ProcessingResults' -Type 2
            return $false
        }
        if (-not($Script:ComparedResults)) {
            Write-Log 'The comparison found no differences between the two provided CSVs' -Component 'ProcessingResults' -Type 2
        } else {
            if ($ShowResults) {
                $Script:ComparedResults | Sort-Object -Property url | Out-GridView -Title "Merge result between: $($Script:MergeCSVComputername1) and $($Script:MergeCSVComputername2)" -Wait
            }
            Build-OutputCSV -InputCSVs $MergeCSVs
        }
    } else {
        if ($OutputCSV -and -not($MergeResults)) {
            Build-OutputCSV
        }
        if ($MergeResults) {
            if (-not(Merge-ResultFiles -CSVInput $MergeCSVs)) {
                Write-Log 'The comparison found no differences between the two provided CSVs' -Component 'ProcessingResults' -Type 2
            } else {
                if ($ShowResults) {
                    $Script:ComparedResults | Sort-Object -Property url | Out-GridView -Title "Merge result between: $($Script:MergeCSVComputername1) and $($Script:MergeCSVComputername2)" -Wait
                }
                if ($OutputCSV) {
                    Build-OutputCSV -InputCSVs $MergeCSVs
                }
            }
        }
        if ($ShowResults) {
            $Script:FinalResultList | Out-GridView -Title 'Intune Network test results' -Wait
        }
    }   
}

#Start coding!
Initialize-Script
if (-not($BrienMode)) {
    Start-Tests
}
Start-ProcessingResults
Write-SettingsToLog
Write-Log 'Thanks for using INR' -Component 'INRMain'
Set-Location $CurrentLocation
Exit 0
