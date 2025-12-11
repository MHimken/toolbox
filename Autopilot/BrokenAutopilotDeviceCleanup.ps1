#Requires -Module Microsoft.Graph.Authentication
#Requires -Version 7.0
<#
.SYNOPSIS
    Removes Autopilot objects or/and their linked Entra or Intune device objects based on their last sign-in date and last sync date.
.DESCRIPTION
    Script heavily focuses on Autopilot objects and their linked Entra and Intune objects.    
    This script will remove Autopilot (if CSV provided), Entra, Intune and device objects based on their last sign-in date and last sync date.
    Actions can be customized based on the age of the devices.
.PARAMETER CSV
    Path to a CSV file containing a list of Autopilot object serial numbers to be deleted.
.PARAMETER NumberOfDaysBeforeDeletion
    Number of days before a device is considered for deletion. Default is -180 days.
.PARAMETER NumberOfDaysBeforeDisable
    Number of days before a device is considered for disabling. Default is -90 days.
.PARAMETER EntraDeviceDisableAction
    Action to take for Entra devices that are older than NumberOfDaysBeforeDisable but younger than NumberOfDaysBeforeDeletion. Default is "Disable".
.PARAMETER EntraDeviceDeleteAction
    Action to take for Entra devices that are older than NumberOfDaysBeforeDeletion. Default is "Remove".
.PARAMETER IntuneDeviceDisableAction
    Action to take for Intune devices that are older than NumberOfDaysBeforeDisable but younger than NumberOfDaysBeforeDeletion. Default is "Retire".
.PARAMETER IntuneDeviceDeleteAction
    Action to take for Intune devices that are older than NumberOfDaysBeforeDeletion. Default is "Remove".
.PARAMETER WorkingDirectory
    Path to the working directory where logs and other files will be stored. Default is "C:\EDC\RemoveAutopilotDevices".
.PARAMETER LogDirectory
    Path to the log directory where log files will be stored. Default is "C:\EDC\RemoveAutopilotDevices\Logs".
.PARAMETER CertificateThumbprint
    Thumbprint of the certificate used for authentication.
.PARAMETER ClientID
    Client ID of the application used for authentication.
.PARAMETER TenantId
    Tenant ID of the Entra tenant.
.PARAMETER TenantAPIToUse
    API version to use for Entra Graph API calls. Default is "beta".
.PARAMETER LogPrefix
    Prefix to use for log files. Default is "BAD-C" (Broken Autopilot Device Cleanup).
.PARAMETER EnableCleanup
    If set, the script will perform the cleanup actions. If not set, it will only analyze and show what would be done.
.PARAMETER ShowResults
    If set, the script will show the results in a grid view.
.PARAMETER OutputCSV
    If set, the script will output the results to a CSV file.
.PARAMETER NoLog
    If set, the script will not create a log file.
.PARAMETER ThrottleLimit
    The maximum number of concurrent requests. Default is 10. DO NOT CHANGE THIS UNLESS YOU KNOW WHAT YOU'RE DOING.
.NOTES
    Version: 1.0
    Versionname: EntraDeviceCleanup.ps1
    Initial creation date: 05.09.2025
    Last change date: 01.12.2025
    Latest changes: Initial Version
    Author: Martin Himken
    To do:
        - Add LAPS and BitLocker key retrieval and storage
        - Add error handling for Graph API calls
        - Add more logging messages
#>
param (
    [System.IO.DirectoryInfo]$CSV,
    [int]$NumberOfDaysBeforeDeletion = -180,
    [int]$NumberOfDaysBeforeDisable = -90,
    # Make these options limited to the allowed values
    [ValidateSet("Retain", "Disable", "Remove")]
    [String]$EntraDeviceDisableAction = "Disable", 
    [ValidateSet("Retain", "Disable", "Remove")]
    [String]$EntraDeviceDeleteAction = "Remove",
    [ValidateSet("Retain", "Retire", "Wipe", "Remove")]
    [String]$IntuneDeviceDisableAction = "Retain",
    [ValidateSet("Retain", "Retire", "Wipe", "Remove")]
    [String]$IntuneDeviceDeleteAction = "Remove",
    [String]$WorkingDirectory,
    [String]$LogDirectory,
    [String]$CertificateThumbprint,
    [String]$ClientID,
    [String]$TenantId,
    [String]$TenantAPIToUse = "beta", # Change to "v1.0" if you want to use the stable API version
    [String]$LogPrefix,
    [Switch]$EnableCleanup,
    [Switch]$ShowResults,
    [Switch]$OutputCSV,
    [Switch]$NoLog,
    [Switch]$ToConsole,
    [int]$ThrottleLimit = 10 
)
if (-not(Get-MgContext)) {
    Write-Output "No existing Microsoft Graph context found. Connecting to Microsoft Graph..."
    if(-not($CertificateThumbprint) -or -not($ClientID) -or -not($TenantId)) {
        Write-Output "CertificateThumbprint, ClientID, and TenantId parameters are required for authentication. Or pre-connect to Microsoft Graph before running the script."
        exit
    }
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
function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to the log file and optionally to the console.
    .DESCRIPTION
        This is a heavily modified version of the script by Ryan Ephgrave.
    .LINK
        https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')][int]$Type,
        [Switch]$Finish,
        [Switch]$ToConsole
    )
    if ($null -eq $Script:LogMessageBuffer) {
        $Script:LogMessageBuffer = [System.Collections.ArrayList]::new()
    }
    if (-not($NoLog)) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($ToConsole)) {
            if ($Message) {
                $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
                $Script:LogMessageBuffer.Add($LogMessage) | Out-Null
            }
            #if ($Script:LogMessageBuffer.count -ge 10 -or $Finish) {
            
                $Script:LogMessageBuffer | Out-File -Append -Encoding UTF8 -FilePath $Script:LogFile
                $Script:LogMessageBuffer.Clear() | Out-Null
            #}
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
function Initialize-Script {
    <#
    .SYNOPSIS
    Will initialize most of the required variables throughout this script.
    #>
    if (-not($LogPrefix)) {
        $Script:LogPrefix = 'BAD-C' # Broken Autopilot Device Cleanup
    } else {
        $Script:LogPrefix = $LogPrefix
    }
    if (-not($WorkingDirectory) ) {
        $WorkingDirectory = "C:\$($Script:LogPrefix)\"
    }
    if (-not($LogDirectory)) {
        $Script:LogDirectory = "C:\$($Script:LogPrefix)\Logs"
    } else {
        $Script:LogDirectory = $LogDirectory
    }
    if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null } 
    $Script:DateTime = Get-Date -Format yyyyMMdd_HHmmss
    if (-not($Script:CurrentLocation)) {
        $Script:CurrentLocation = Get-Location
    }
    if ((Get-Location).path -ne $WorkingDirectory) {
        Set-Location $WorkingDirectory
    }
    Get-ScriptPath
    if (-not($Script:LogFile)) {
        $Script:LogFile = Join-Path -Path $Script:LogDirectory -ChildPath ('{0}_{1}.log' -f $Script:LogPrefix, $Script:DateTime)
        if (-not(Test-Path $Script:LogDirectory)) { New-Item $Script:LogDirectory -ItemType Directory -Force | Out-Null }
    }
    #Define some variables that will be used throughout the script
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
    $Script:DocumentResults = [System.Collections.ArrayList]::new()
    $Script:DateBeforeDeletion = (Get-Date).AddDays($NumberOfDaysBeforeDeletion)
    $Script:DateBeforeDisable = (Get-Date).AddDays($NumberOfDaysBeforeDisable)
    if ($CSV) {
        $Script:IngestedCSV = Import-Csv -Path $CSV.FullName
    } else {
        Write-Log -Message "No CSV file provided." -Component 'InitializeScript'
    }
    #Fill required variables and HashTables
    Get-AutopilotDevices
    Get-EntraDevices
    Get-IntuneDevices
    Get-Users

}
function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to the log file and optionally to the console.
    .DESCRIPTION
        This is a heavily modified version of the script by Ryan Ephgrave.
    .LINK
        https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')][int]$Type,
        [Switch]$Finish,
        [Switch]$ToConsole
    )
    if ($null -eq $Script:LogMessageBuffer) {
        $Script:LogMessageBuffer = [System.Collections.ArrayList]::new()
    }
    if (-not($NoLog)) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($ToConsole)) {
            if ($Message) {
                $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
                $Script:LogMessageBuffer.Add($LogMessage) | Out-Null
            }
            if ($Script:LogMessageBuffer.count -ge 10 -or $Finish) {
                $Script:LogMessageBuffer | Out-File -Append -Encoding UTF8 -FilePath $Script:LogFile
                $Script:LogMessageBuffer.Clear() | Out-Null
            }
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
function Get-AutopilotDevices {
    <#
    .SYNOPSIS
        Get all Autopilot devices in the tenant.
    .DESCRIPTION
        This function retrieves all Autopilot devices in the tenant. It will return a list of devices with their ID, display name, device ID, and physical IDs.
    #>
    $Script:AllAutopilotDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/" -ErrorAction Stop
    if ($Script:AllAutopilotDevices.'@odata.nextLink') {
        Write-Log -Message "Found more than 1000 Autopilot devices, retrieving next link data" -Component 'FindDuplicateDevices' -Type 1
        $Script:AllAutopilotDevices = Get-nextLinkData -OriginalObject $Script:AllAutopilotDevices
    }
    $Script:AllAutopilotDevicesHashTable = @{}
    foreach ($Device in $Script:AllAutopilotDevices.value) {
        $Script:AllAutopilotDevicesHashTable[$($Device.serialNumber.trim())] = $Device
    }
}
function Get-EntraDevices {
    <#
    .SYNOPSIS
        Get all Entra devices in the tenant.
    .DESCRIPTION
        This function retrieves all Entra devices in the tenant. It will return a list of devices with their ID, display name, device ID, approximate last sign-in date, created date, enrollment profile name, and physical IDs.
    #>
    $Script:AllEntraDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/devices/?`$expand=registeredOwners&`$filter=(operatingSystem eq 'Windows' or operatingSystem eq 'Unknown')&`$select=id,displayName,deviceId,approximateLastSignInDateTime,createdDateTime,enrollmentProfileName,physicalIds,accountEnabled" -ErrorAction Stop
    if ($Script:AllEntraDevices.'@odata.nextLink') {
        Write-Log -Message "Found more than 1000 Entra devices, retrieving next link data" -Component 'FindDuplicateDevices' -Type 1
        $Script:AllEntraDevices = Get-nextLinkData -OriginalObject $Script:AllEntraDevices
    }
    $Script:AllEntraDevicesHashTable = @{}
    foreach ($Device in $Script:AllEntraDevices.value) {
        $Script:AllEntraDevicesHashTable[$Device.deviceId] = $Device
    }
    $Script:AllEntraDevicesHashTableByID = @{}
    foreach ($Device in $Script:AllEntraDevices.value) {
        $Script:AllEntraDevicesHashTableByID[$Device.id] = $Device
    }
}
function Get-IntuneDevices {
    <#
    .SYNOPSIS
        Get all Intune managed devices in the tenant.
    .DESCRIPTION
        This function retrieves all Intune managed devices in the tenant. It will return a list of devices with their ID, device name, Azure AD device ID, and serial number.
    #>
    $Script:AllIntuneDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/?`$select=id,deviceName,azureADDeviceId,serialNumber,manufacturer,model,userId,lastSyncDateTime&`$filter=(operatingSystem eq 'Windows')" -ErrorAction Stop
    if ($Script:AllIntuneDevices.'@odata.nextLink') {
        Write-Log -Message "Found more than 1000 Intune devices, retrieving next link data" -Component 'FindDuplicateDevices' -Type 1
        $Script:AllIntuneDevices = Get-nextLinkData -OriginalObject $Script:AllIntuneDevices
    }
    $Script:AllIntuneDevicesHashTable = @{}
    foreach ($Device in $Script:AllIntuneDevices.value) {
        $Script:AllIntuneDevicesHashTable[$Device.azureADDeviceId] = $Device
    }
    $Script:AllIntuneDevicesHashTableBySerialNumber = @{}
    foreach ($Device in $Script:AllIntuneDevices.value) {
        # Trim the serial number to avoid issues with leading/trailing spaces
        $Script:AllIntuneDevicesHashTableBySerialNumber[$Device.serialNumber.trim()] = $Device
    }
}
function Get-Users {
    <#
    .SYNOPSIS
        Get all users in the tenant.
    .DESCRIPTION
        This function retrieves all users in the tenant. It will return a list of users with their ID, display name, email, and other relevant information.
    #>
    $Script:AllUsers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/?`$select=id,displayName,mail,userPrincipalName" -ErrorAction Stop
    if ($Script:AllUsers.'@odata.nextLink') {
        Write-Log -Message "Found more than 1000 users, retrieving next link data" -Component 'FindDuplicateDevices' -Type 1
        $Script:AllUsers = Get-nextLinkData -OriginalObject $Script:AllUsers
    }
    $Script:AllUsersHashTable = @{}
    foreach ($User in $Script:AllUsers.value) {
        $Script:AllUsersHashTable[$User.id] = $User
    }
}
function Save-CurrentDeviceStates {
    foreach ($AutopilotDevice in $Script:AllAutopilotDevices.value) {
        Clear-Variable -Name IntuneDevice, EntraDeviceFromAutopilot, EntraDeviceFromIntune, DetectDeleteAutpilotDeviceFromCSV, AutopilotWhatIf, IntuneEIDMismatch, EIDAutopilotWhatIf, EIDIntuneWhatIf -ErrorAction SilentlyContinue
        #Trim the serial number to avoid issues with leading/trailing spaces
        $AutopilotDeviceSerial = $AutopilotDevice.serialNumber.trim()
        $AutopilotWhatIf = "Retain"
        if ($Script:IngestedCSV) {
            Write-Log -Message "Check if device $AutopilotDeviceSerial exists in CSV file." -Finish -Component 'SaveCurrentDeviceStates'
            $DetectDeleteAutpilotDeviceFromCSV = $Script:IngestedCSV | Where-Object { $_.SerialNumber.trim() -eq $AutopilotDeviceSerial }
            $AutopilotWhatIf = if ($DetectDeleteAutpilotDeviceFromCSV) { "Remove" }
        }
        $IntuneDevice = $Script:AllIntuneDevicesHashTableBySerialNumber[$AutopilotDeviceSerial]
        $EntraDeviceFromAutopilot = $Script:AllEntraDevicesHashTable[$AutopilotDevice.azureAdDeviceId]
        $IntuneEIDisAutpilotEID = $null
        if ($EntraDeviceFromAutopilot.accountEnabled -eq $true) {
            $EIDAutopilotWhatIf = $EntraDeviceDisableAction
        } else {
            $EIDAutopilotWhatIf = "Disabled"
        }
        if ($IntuneDevice) {
            #Default is to retain the EID device from Intune and Autopilot
            $EIDIntuneWhatIf = "Retain"
            $IntuneWhatIf = "Retain"
            $EntraDeviceFromIntune = $Script:AllEntraDevicesHashTable[$IntuneDevice.azureADDeviceId]
            #If the device IDs are different, log a message and set the IntuneEIDisAutpilotEID flag to false
            if ($EntraDeviceFromIntune.deviceId -ne $EntraDeviceFromAutopilot.deviceId) {
                Write-Log -Message "Entra device from Intune and Autopilot have different device IDs for serial number $AutopilotDeviceSerial." -Component 'SaveCurrentDeviceStates' -Type 2
                $IntuneEIDisAutpilotEID = $false
            } else {
                $IntuneEIDisAutpilotEID = $true
            }
            if ($IntuneDevice.lastSyncDateTime -le $Script:DateBeforeDisable -and $IntuneDevice.lastSyncDateTime -gt $Script:DateBeforeDeletion) {
                $IntuneWhatIf = $IntuneDeviceDisableAction
                if ($IntuneEIDisAutpilotEID -eq $false) {
                    $EIDIntuneWhatIf = $EntraDeviceDisableAction
                }
            } elseif ($IntuneDevice.lastSyncDateTime -le $Script:DateBeforeDeletion) {
                $IntuneWhatIf = $IntuneDeviceDeleteAction
                # If EntraDeviceDeleteAction action is remove, the device will be recreated later by the Autopilot object
                $EIDAutopilotWhatIf = $EntraDeviceDeleteAction
                if ($IntuneEIDisAutpilotEID -eq $false) {
                    $EIDIntuneWhatIf = $EntraDeviceDeleteAction
                }
            } else {
                if ($IntuneEIDisAutpilotEID -eq $true) {
                    $EIDAutopilotWhatIf = "Retain"
                }
            }
        } else {
            $IntuneEIDisAutpilotEID = $null
            $IntuneWhatIf = "Not Found"
            $EIDIntuneWhatIf = "Not Applicable"
        }
        $Result = [PSCustomObject]@{
            SerialNumber                                 = $AutopilotDeviceSerial
            AutopilotDeviceName                          = $AutopilotDevice.displayName
            AutopilotDeviceID                            = $AutopilotDevice.id
            SerialShouldBeDeletedFromCSV                 = $DetectDeleteAutpilotDeviceFromCSV
            EIDFromAutopilotEnabled                      = $EntraDeviceFromAutopilot.accountEnabled
            EIDFromAutopilotID                           = $EntraDeviceFromAutopilot.deviceId
            EIDFromAutopilotDisplayName                  = $EntraDeviceFromAutopilot.displayName
            EIDFromAutopilotLastSignInDateTime           = $EntraDeviceFromAutopilot.approximateLastSignInDateTime
            EIDFromIntuneID                              = if ($EntraDeviceFromIntune) { $EntraDeviceFromIntune.deviceId } else { $null }
            EIDFromIntuneDisplayName                     = if ($EntraDeviceFromIntune) { $EntraDeviceFromIntune.displayName } else { $null }
            EIDFromIntuneLastSignInDateTime              = if ($EntraDeviceFromIntune) { $EntraDeviceFromIntune.approximateLastSignInDateTime } else { $null }
            IntuneDeviceID                               = if ($IntuneDevice) { $IntuneDevice.id } else { $null }
            IntuneDeviceName                             = if ($IntuneDevice) { $IntuneDevice.deviceName } else { $null }
            IntuneDeviceManufacturer                     = if ($IntuneDevice) { $IntuneDevice.manufacturer } else { $null }
            IntuneDeviceModel                            = if ($IntuneDevice) { $IntuneDevice.deviceModel } else { $null }
            IntuneLastSignInDate                         = if ($IntuneDevice) { $IntuneDevice.lastSyncDateTime } else { $null }
            IntunePrimaryUser                            = if ($IntuneDevice) { $AllUsersHashTable[$IntuneDevice.userId].DisplayName } else { $null }
            IntunePrimaryUserUPN                         = if ($IntuneDevice) { $AllUsersHashTable[$IntuneDevice.userId].UserPrincipalName } else { $null }
            IntuneWhatIf                                 = $IntuneWhatIf
            IntuneDeviceLinkedToEntraDeviceFromAutopilot = $IntuneEIDisAutpilotEID
            AutopilotWhatIf                              = $AutopilotWhatIf
            EIDFromAutopilotWhatIf                       = $EIDAutopilotWhatIf
            EIDFromIntuneWhatIf                          = $EIDIntuneWhatIf
            #ToDo: Save the LAPS and BitLocker keys if available
        }
        $Script:DocumentResults.Add($Result) | Out-Null
    }
    #Create a hash table for quick access
    $Script:DocumentResultsHashTable = @{}
    foreach ($Result in $Script:DocumentResults) {
        $Script:DocumentResultsHashTable[$Result.SerialNumber] = $Result
    }
}
function Add-BatchRequestObjectToQueue {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body
    )
    $ID = $Script:BatchRequests.count
    $BatchObject = [PSCustomObject]@{
        id      = $ID
        method  = $Method
        URL     = $URL
        headers = $Headers
    }
    if ($Body) {
        #A body is only required for POST, PATCH, and PUT requests
        $BatchObject | Add-Member -MemberType NoteProperty -Name 'body' -Value $null -Force
        $BatchObject.body = $Body
    }
    $Script:BatchRequests.add($BatchObject) | Out-Null
}
function Invoke-BatchRequest {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body,
        [switch]$Finalize
    )
    if ($Method -and $URL) {
        Add-BatchRequestObjectToQueue -Method $method -URL $URL -Headers $Headers -Body $Body
    }
    if ($Script:BatchRequests.count -eq 20 -or $Finalize) {
        $BatchRequestBody = [PSCustomObject]@{ requests = $Script:BatchRequests }
        $JSONRequests = $BatchRequestBody | ConvertTo-Json -Depth 10
        #$Results = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $JSONRequests -ContentType 'application/json' -ErrorAction Stop
        $PrepareJob = [PSCustomObject]@{
            ID                = $Script:BatchRequestsQueue.Count
            Name              = "BatchRequest-$($Script:BatchRequestsQueue.Count)"
            ArgumentToProvide = @($JSONRequests)
        }
        $Script:BatchRequestsQueue.Add($PrepareJob) | Out-Null
        $Script:BatchRequests = [System.Collections.ArrayList]::new()
    }
    return #$Results
}
function Submit-BatchRequests {
    <#
    .SYNOPSIS
        Processes the batch requests in the queue.
    #>
    foreach ($BatchRequest in $Script:BatchRequestsQueue) {
        $Script:BatchJobs = Start-ThreadJob -Name "$($Script:LogPrefix)-$($BatchRequest.Name)" -ThrottleLimit $ThrottleLimit -ScriptBlock {
            param($ArgumentToProvide, $TenantAPIToUse)
            $TenantAPIToUse = if ($TenantAPIToUse) { $TenantAPIToUse } else { 'beta' }
            $URI = "https://graph.microsoft.com/$TenantAPIToUse/`$batch"
            Invoke-MgGraphRequest -Method POST -Uri $URI -Body $ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
        } -ArgumentList @($BatchRequest.ArgumentToProvide,$TenantAPIToUse)
        Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 5000) # Random delay to avoid throttling
    }
    Write-Log -Message "Batch requests submitted." -Component 'SubmitBatch'
}
function Confirm-BatchRequests {
    <#
    .SYNOPSIS
        Confirms the batch requests and processes the results.
    #>
    Write-Log -Message "Analyzing batch requests..." -Component 'ConfirmBatch'
    #Save the current batch requests to retry them later if needed
    $Script:RetryRequests = $Script:BatchRequestsQueue | ForEach-Object { $_ }
    #Clear the current batch requests queue to prepare for the retry batch
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
    #Get the wait time from the batch requests if any requests were throttled
    $Script:MinimumWaitTimeFromBatchRequests = 0
    foreach ($Job in $Script:BatchJobs) {
        $BatchID = $Job.Name -replace "$($Script:LogPrefix)-BatchRequest-", ''
        $JobResponses = $Job.Output.responses
        foreach ($Job in $JobResponses) {
            $RetryRequestFullJSON = ConvertFrom-Json -InputObject ([string]$Script:RetryRequests[$BatchID].ArgumentToProvide) -AsHashtable
            $SingleRetryRequest = $RetryRequestFullJSON.requests[$Job.id]
            if (-not($SingleRetryRequest)) {
                break
            }
            # we matched the request, now process the result depending on the status code and data in the body and method(!)
            # we can probably use a switch case here for different methods and body content - this is only relevant for logging purposes
            # Retry three times
            #$UserName = if ($SingleRetryRequest.body.displayName) { $SingleRetryRequest.body.displayName } else { "N/A" }

            if ($_.status -eq 200 -or $_.status -eq 201 -or $_.status -eq 204) {
                Write-Log -Message "Request $($_.id) for $UserName in batch $BatchID completed successfully." -Component 'ConfirmBatch'
            } elseif ($_.status -eq 429) {
                Write-Log -Message "Request $($_.id) for $UserName in batch $BatchID was throttled." -Component 'ConfirmBatch' -Type 2
                if ($_.headers.'Retry-After') {
                    $RetryAfter = [int]$_.headers.'Retry-After'
                    if ($RetryAfter -gt $Script:MinimumWaitTimeFromBatchRequests) {
                        $Script:MinimumWaitTimeFromBatchRequests = $RetryAfter
                    }
                }
                # ToDo: This is a problem, because creating is different from deleting users and we might be missing information the second time
                # Maybe we need to create a queue for each retry batch?
                # Instead use Write-CreateUserBatchRequests and Write-DeleteUserBatchRequests to feed the queue!
                Invoke-BatchRequest -Method $SingleRetryRequest.method -URL $SingleRetryRequest.URL -Headers $SingleRetryRequest.headers -Body $SingleRetryRequest.body
            } else {
                Write-Log -Message "Request $($_.id) for $UserName in batch $BatchID failed with status $($_.status) and provided the following error:`n $($_.body.error.message)" -Component 'ConfirmBatch' -Type 3
            }
            Clear-Variable -Name SingleRetryRequest, RetryRequestFullJSON -ErrorAction SilentlyContinue
        }
        Remove-Job -Id $Job.Id -Force
    }
}
function Disable-IntuneDevice {
    param (
        [string]$DeviceId
    )
    $Method = 'PATCH'
    $URL = "/deviceManagement/managedDevices/$DeviceId/retire"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers
}
function Remove-IntuneDevice {
    param (
        [string]$DeviceId
    )
    $Method = 'DELETE'
    $URL = "/deviceManagement/managedDevices/$DeviceId"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers
}
function Remove-IntuneDeviceWipe {
    param (
        [string]$DeviceId
    )
    $Method = 'POST'
    $URL = "/deviceManagement/managedDevices/$DeviceId/wipe"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    $Body = @{
        "keepEnrollmentData" = $false
        "keepUserData"       = $false
        "macOsUnlockCode"    = $null
        "persistEsimDataPlan"= $false
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers -Body $Body
}
function Remove-RetireIntuneDevice {
    param (
        [string]$DeviceId
    )
    $Method = 'POST'
    $URL = "/deviceManagement/managedDevices/$DeviceId/retire"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers
}
function Disable-EntraDevice {
    param (
        [string]$ID
    )
    $ObjectID = $Script:AllEntraDevicesHashTable[$ID].id

    $Method = 'PATCH'
    $URL = "/devices/$ObjectID"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    $Body = @{
        "accountEnabled" = $false
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers -Body $Body
}
function Remove-EntraDevice {
    param (
        [string]$ID
    )
    $ObjectID = $Script:AllEntraDevicesHashTable[$ID].id
    $Method = 'DELETE'
    $URL = "/devices/$ObjectID"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers
}
function Remove-AutopilotDevice {
    param (
        [string]$DeviceId
    )
    $Method = 'DELETE'
    $URL = "/deviceManagement/windowsAutopilotDeviceIdentities/$DeviceId"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers
}
function Get-BitLockerKeys {
    param (
        [string]$DeviceId
    )
    $Method = 'GET'
    $URL = "/informationProtection/bitlocker/recoveryKeys?$filter=deviceId eq '{$DeviceId}'"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-MGGraphRequest -Method $Method -Uri $URL -Headers $Headers
}
function Initialize-Cleanup {
    foreach ($Object in $Script:DocumentResults) {
        #ToDo: Add LAPS and BitLocker key export if available
        if ($Object.IntuneWhatIf -eq "Retire" -and $Object.IntuneDeviceID) {
            Write-Log -Message "Retiring Intune device $($Object.IntuneDeviceName) with ID $($Object.IntuneDeviceID) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Disable-IntuneDevice -DeviceId $Object.IntuneDeviceID
        }
        if ($Object.IntuneWhatIf -eq "Remove" -and $Object.IntuneDeviceID) {
            Write-Log -Message "Removing Intune device $($Object.IntuneDeviceName) with ID $($Object.IntuneDeviceID) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Remove-IntuneDevice -DeviceId $Object.IntuneDeviceID
        }
        if ($Object.IntuneWhatIf -eq "Wipe" -and $Object.IntuneDeviceID) {
            Write-Log -Message "Wiping Intune device $($Object.IntuneDeviceName) with ID $($Object.IntuneDeviceID) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Remove-IntuneDeviceWipe -DeviceId $Object.IntuneDeviceID
        }
        if ($Object.EIDFromAutopilotWhatIf -eq "Disable" -and $Object.EIDFromAutopilotID) {
            Write-Log -Message "Disabling Entra device $($Object.EIDFromAutopilotDisplayName) with ID $($Object.EIDFromAutopilotID) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Disable-EntraDevice -ID $Object.EIDFromAutopilotID
        }
        if ($Object.EIDFromAutopilotWhatIf -eq "Remove" -and $Object.EIDFromAutopilotID) {
            Write-Log -Message "Removing Entra device $($Object.EIDFromAutopilotDisplayName) with ID $($Object.EIDFromAutopilotID) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Remove-EntraDevice -ID $Object.EIDFromAutopilotID
        }
        if ($Object.EIDFromIntuneWhatIf -eq "Disable" -and $Object.EIDFromIntuneID) {
            Write-Log -Message "Disabling Entra device $($Object.EIDFromIntuneDisplayName) with ID $($Object.EIDFromIntuneID) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Disable-EntraDevice -ID $Object.EIDFromIntuneID
        }
        if ($Object.EIDFromIntuneWhatIf -eq "Remove" -and $Object.EIDFromIntuneID) {
            Write-Log -Message "Removing Entra device $($Object.EIDFromIntuneDisplayName) with ID $($Object.EIDFromIntuneID) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Remove-EntraDevice -ID $Object.EIDFromIntuneID
        }
        if ($Object.AutopilotWhatIf -eq "Remove" -and $Object.AutopilotDeviceID) {
            Write-Log -Message "Removing Autopilot device with ID $($Object.AutopilotDeviceName) for serial number $($Object.SerialNumber)." -Component 'Initialize-Cleanup' -Type 1
            Remove-AutopilotDevice -ID $Object.AutopilotDeviceID
        }
    }
    if ($Script:BatchRequests.count -gt 0) {
        Invoke-BatchRequest -Finalize
    }
}
# Start coding!
# Initialize script variables
Initialize-Script
# Analyze and save the current device states into the $Script:DocumentResults variable
Save-CurrentDeviceStates
# If cleanup is enabled, perform the cleanup actions
If ($EnableCleanup) {
    Initialize-Cleanup
    # Get user confirmation before submitting batch requests
    $UserInput = Read-Host "Do you want to submit the batch requests now? (Y/N)"
    if ($UserInput -eq "y") {
        Submit-BatchRequests
        # Confirm the batch requests and process the results
        Confirm-BatchRequests
        # If there were throttled requests, wait and retry them
        if ($Script:MinimumWaitTimeFromBatchRequests -gt 0) {
            Write-Log -Message "Waiting $($Script:MinimumWaitTimeFromBatchRequests) seconds before retrying throttled requests." -Component 'Main'
            Start-Sleep -Seconds $Script:MinimumWaitTimeFromBatchRequests
            #Submit the retry batch requests
            Submit-BatchRequests
            #Confirm the retry batch requests
            Confirm-BatchRequests
        }
    } else {
        Write-Log -Message "User chose not to submit the batch requests. Exiting cleanup process." -Component 'Main' -Type 2
    }
}
#Export the results to a CSV file if required
if ($OutputCSV) {
    Write-Log -Message "Exporting results to CSV file." -Component 'Main'
    $Script:DocumentResults | Export-Csv -Path (Join-Path -Path (Get-Location).path -ChildPath "RemovedAutopilotDevicesResults_$($Script:DateTime).csv") -Encoding utf8 -Delimiter ";" -NoTypeInformation -Force
}
# Show or export the results if required
if ($ShowResults) {
    Write-Log -Message "Displaying results in GridView." -Component 'Main'
    $Script:DocumentResults | Out-GridView -Title "Broken Autopilot Device Results (post cleanup)"
}
Write-Log -Message "Finished processing script." -Component 'Main' -Finish
#Return to the original location
Set-Location $Script:CurrentLocation
Write-Log -Message "Thanks for using the script!" -Finish