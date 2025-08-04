#Requires -Module Microsoft.Graph.Authentication
#Requires -Version 7.0
<#
THIS SCRIPT IS NOT DONE!
.SYNOPSIS
This script will find devices in your tenant that exist twice or more by displayName and are hybrid joined or Entra joined.
.DESCRIPTION
If you want to analyse how many devices are hybrid _and_ entra joined and both are linked to an autopilot object in your tenant 
this script is for you. It will go by displayName. The runtime for a tenant with 20.000 devices is roughly 45 seconds. 
.PARAMETER GroupName
The name of the group that will used to remediate the devices that are found. The group will be created if it does not exist.
.PARAMETER NumberOfDays
The number of days that a device has had to be active to be considered for deletion. The default is -365 days, meaning that devices that have not signed in for a year will be considered for deletion.
.PARAMETER AnalyzeOnly
If set, the script will only analyze the devices and not delete them. This is useful for testing purposes.
.PARAMETER Cleanup
If set, the script will delete group memberships for the devices that were successfully remediated.
.PARAMETER CertificateThumbprint
The thumbprint of the certificate that will be used to authenticate to the Microsoft Graph API.
.PARAMETER ClientID
The client ID of the application that will be used to authenticate to the Microsoft Graph API.
.PARAMETER TenantId
The tenant ID of the Azure AD tenant that will be used to authenticate to the Microsoft Graph API.
.PARAMETER TenantAPIToUse
The version of the Microsoft Graph API to use. The default is /beta, but you can change it to /v1.0 if you want to use the stable API version.
.PARAMETER WorkingDirectory
The directory where the script will store its working files. The default is C:\ADDF\
.PARAMETER LogDirectory
The directory where the script will store its log files. The default is C:\ADDF\Logs\
.PARAMETER NoLog
If set, the script will not create a log file. This is useful for testing purposes.
.PARAMETER ToConsole
If set, the script will write the log messages to the console instead of a log file.
.EXAMPLE
.\AutopilotDualDeviceFinder.ps1 -GroupName "Autopilot_Entra_DE_FixAssociation_App" -NumberOfDays -365 -CertificateThumbprint "YOUR_CERT_THUMBPRINT" -ClientID "YOUR_CLIENT_ID" -TenantId "YOUR_TENANT_ID" -WorkingDirectory "C:\ADDF\" -LogDirectory "C:\ADDF\Logs\" -NoLog -ToConsole
This will run the script with all parameters.
.EXAMPLE
.\AutopilotDualDeviceFinder.ps1 -AnalyzeOnly
This will run the script in analyze mode, meaning that it will not delete any devices
.NOTES
Scopes required for this script to run:
    Device.ReadWrite.All
    DeviceManagementServiceConfig.ReadWrite.All
    DeviceManagementManagedDevices.Read.All
    Group.ReadWrite.All
    GroupMember.Read.All
#>
param(
    [string]$GroupName = "Autopilot_Entra_DE_FixAssociation_App",
    [int]$NumberOfDays = -360,
    [boolean]$AnalyzeOnly = $true, #For security reasons we don't delete devices by default. Set to $false if you want to delete devices.
    [boolean]$Cleanup = $true, #ToDo: Set this to SWITCH when done!
    [string]$CertificateThumbprint = "",
    [string]$ClientID = "",
    [string]$TenantId = "",
    [string]$TenantAPIToUse = "/beta", # Change to /v1.0 if you want to use the stable API version
    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\ADDF\",
    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$LogDirectory = "C:\ADDF\Logs\",
    [Parameter(Mandatory = $false)]
    [Switch]$NoLog,
    [Parameter(Mandatory = $false)]
    [Switch]$ToConsole
)

if (-not(Get-MgContext)) {
    Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientID -TenantId $TenantId 
    if (-not(Get-MgContext)) {
        exit
    } else {
        Write-Log -Message "Successfully connected to Microsoft Graph." -Component 'ADDFMain'
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
function Get-IntuneDevices {
    <#
    .SYNOPSIS
        Get all Intune managed devices in the tenant.
    .DESCRIPTION
        This function retrieves all Intune managed devices in the tenant. It will return a list of devices with their ID, device name, Azure AD device ID, and serial number.
    #>

    $Script:AllIntuneDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/?`$select=id,deviceName,azureADDeviceId,serialNumber&`$filter=(operatingSystem eq 'Windows')" -ErrorAction Stop
    if ($Script:AllIntuneDevices.'@odata.nextLink') {
        Write-Log -Message "Found more than 1000 Intune devices, retrieving next link data" -Component 'FindDuplicateDevices' -Type 1
        $Script:AllIntuneDevices = Get-nextLinkData -OriginalObject $Script:AllIntuneDevices
    }
    $Script:AllIntuneDevicesHashTable = @{}
    foreach ($Device in $Script:AllIntuneDevices.value) {
        $Script:AllIntuneDevicesHashTable[$Device.azureADDeviceId] = $Device
    }
}
function Get-EntraDevices {
    <#
    .SYNOPSIS
        Get all Entra devices in the tenant.
    .DESCRIPTION
        This function retrieves all Entra devices in the tenant. It will return a list of devices with their ID, display name, device ID, approximate last sign-in date, created date, enrollment profile name, and physical IDs.
    #>
    $Script:AllEntraDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/devices/?`$expand=registeredOwners&`$filter=(operatingSystem eq 'Windows')&`$select=id,displayName,deviceId,approximateLastSignInDateTime,createdDateTime,enrollmentProfileName,physicalIds" -ErrorAction Stop
    if ($Script:AllEntraDevices.'@odata.nextLink') {
        Write-Log -Message "Found more than 1000 Entra devices, retrieving next link data" -Component 'FindDuplicateDevices' -Type 1
        $Script:AllEntraDevices = Get-nextLinkData -OriginalObject $Script:AllEntraDevices
    }
    $Script:AllEntraDevicesHashTable = @{}
    foreach ($Device in $Script:AllEntraDevices.value) {
        $Script:AllEntraDevicesHashTable[$Device.displayName] = $Device
    }
    $Script:AllEntraDevicesHashTableByID = @{}
    foreach ($Device in $Script:AllEntraDevices.value) {
        $Script:AllEntraDevicesHashTableByID[$Device.id] = $Device
    }
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
        $LogPrefix = 'ADDF' #Autopilot Dual Device Finder
        $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
        if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
    }
    #Initialize variables
    $Script:DateMinusNumberofDays = Get-date (Get-Date).AddDays($NumberOfDays) -Format 'yyyy-MM-ddThh:mm:ssZ'
    if ($GroupName) {
        $GroupInfo = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups?`$filter=(displayName eq '$GroupName')" -ErrorAction SilentlyContinue
        if ($GroupInfo -and $GroupInfo.value) {
            $Script:GroupId = $GroupInfo.value[0].id
        }
    }
    Get-IntuneDevices
    Get-EntraDevices
    #Initialize collections
    $Script:DuplicateDevices = [System.Collections.ArrayList]::new()
    $Script:DevicesToBeDeleted = [System.Collections.ArrayList]::new()
    $Script:DevicesToBeRemediated = [System.Collections.ArrayList]::new()
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsAnalyze = [System.Collections.ArrayList]::new()
    $Script:BatchRetryRequests = [System.Collections.ArrayList]::new()

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
        $BatchObject.body = $Body
    }
    $Script:BatchRequests.add($BatchObject) | Out-Null
}
function Confirm-BatchRequest {
    $Jobs = Get-Job | Where-Object { $_.name -match "ADDF" }
    if ($Jobs.count -gt 0) {
        foreach ($Job in $Jobs) {
            $Script:BatchRequestsAnalyze.add($Job) | Out-Null
            $response = $Job.output.responses
            $JobID = $Job.name.split('-')[2]
            [int]$RetryAfter = 0
            switch ($response.status) {
                200 { Write-Log -Message "Status 200 success." -Component 'ConfirmBatchRequest' -Type 1 }
                204 { Write-Log -Message "Status 204 success." -Component 'ConfirmBatchRequest' -Type 1 }
                400 { Write-Log -Message "Failed with status 400. The Autopilot device probably was already deleted" -Component 'ConfirmBatchRequest' -Type 2 }
                403 { Write-Log -Message "Failed with status 403. You might not have the required permissions to perform this action." -Component 'ConfirmBatchRequest' -Type 3 }
                404 { Write-Log -Message "Failed with status 404. The Entra device probably was already deleted" -Component 'ConfirmBatchRequest' -Type 2 }
                429 {
                    Write-Log -Message "Received 429 Too Many Requests. Please retry after $($response.headers.'Retry-After') seconds." -Component 'ConfirmBatchRequest' -Type 2
                    if ($response.headers.'Retry-After' -ge $RetryAfter) {
                        $RetryAfter = $response.headers.'Retry-After'
                    }
                }
                default { Write-Log -Message "Failed to send batch request - Status: $($response.status), Error: $($response.body.error.message)" -Component 'ConfirmBatchRequest' -Type 3 }
            }
            if ($RetryAfter -gt 0) {
                Write-Log -Message "Retrying batch $($JobID) request ONCE after $($RetryAfter) seconds." -Component 'ConfirmBatchRequest' -Type 1
                Start-Sleep -Seconds $RetryAfter
                try {
                    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $($Script:BatchRequestsQueue[$($JobID)]) -ContentType 'application/json' -ErrorAction Stop
                } catch {
                    Write-Log -Message "Retrying batch $($JobID) request failed: $($_.Exception.Message)" -Component 'ConfirmBatchRequest' -Type 3
                }
            } 
        }
    }
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
            Name              = "BatchRequest-$($Script:BatchRequestsQueue.Count)"
            ArgumentToProvide = @($JSONRequests)
        }
        $Script:BatchRequestsQueue.Add($PrepareJob) | Out-Null
        $Script:BatchRequests = [System.Collections.ArrayList]::new()
    }
    return $Results
}
function Search-DuplicateDevices {
    <#
    .SYNOPSIS
        Find devices with duplicate names in the tenant.
    .DESCRIPTION
        This function searches for devices in the tenant that have duplicate names. It will analyze the devices based on criteria such as
        their last sign-in date and whether they are hybrid or Entra joined. The function will also check for Autopilot IDs associated with the devices.
        It returns a list of devices that are candidates for deletion based on their activity and (approximate) last sign-in date.
    #>
    $DuplicatedNames = ($Script:AllEntraDevices.value | Group-Object -Property displayName | Where-Object { $_.count -gt 1 })
    $DuplicateDevicesSearchResult = [System.Collections.ArrayList]::new()
    foreach ($DuplicatedDevice in $DuplicatedNames) {        
        $DevicesDetails = [System.Collections.ArrayList]::new()
        foreach ($Device in $DuplicatedDevice.Group) {
            $SerialNumber = $Script:AllIntuneDevicesHashTable[$Device.deviceId].serialNumber
            $DeviceDetails = [PSCustomObject]@{
                ID                            = $Device.id
                ApproximateLastSignInDateTime = $Device.approximateLastSignInDateTime
                CreatedDate                   = $Device.createdDateTime
                EnrolledBy                    = $Device.registeredOwners[0].userPrincipalName
                EnrollmentProfileName         = $Device.enrollmentProfileName
            }
            $DevicesDetails.Add($DeviceDetails) | Out-Null
        }
        $DupeObject = [PSCustomObject]@{
            DisplayName        = $DuplicatedDevice.Name
            DeviceDetails      = $DevicesDetails
            SerialNumber       = $SerialNumber
            AutopilotID        = $null
            AutopilotTreatment = $false
        }
        # Get the physical IDs of the devices with duplicate names
        $PhysicalIDs = $Script:AllEntraDevicesHashTable[$DuplicatedDevice.Name] | Select-Object -ExpandProperty physicalIds
        # If devices have Autopilot IDs, we need to treat them differently
        if ($PhysicalIDs | Select-String -Pattern '[ZTDID]:' -SimpleMatch) {
            $AutopilotIDs = ($PhysicalIDs | Select-String -Pattern '[ZTDID]:' -SimpleMatch).line.Substring(8.36) | Select-Object -Unique
        }
        if ($AutopilotIDs) {
            $DupeObject.AutopilotID = $AutopilotIDs
        }
        if ($AutopilotIDs.Count -eq 1) {
            Write-Log -Message "Found matching Autopilot IDs ($($AutopilotIDs)) for devices pointing with duplicate names ($($DuplicatedDevice.Name)) " -Component 'FindDuplicateDevices' -Type 2
            $DupeObject.AutopilotTreatment = $true
        } else {
            Write-Log -Message "Found different Autopilot IDs for devices with duplicate names ($($DuplicatedDevice.Name))" -Component 'FindDuplicateDevices' -Type 1
        }
        $DuplicateDevicesSearchResult.add($DupeObject) | Out-Null
        if ($AutopilotIDs) { Clear-Variable AutopilotIDs }
    }
    $Script:DuplicateDevices = $DuplicateDevicesSearchResult
}
function Select-DevicesToBeDeleted {
    <#
    .SYNOPSIS
    Analyze duplicate devices with duplicate names in the tenant and select candidates for deletion.
    #>
    $DevicesToBeDeleted = [System.Collections.ArrayList]::new()
    foreach ($Device in $Script:DuplicateDevices) {
        $DeviceDetails = $Device.DeviceDetails
        # Sort devices by last sign-in date and created date (should always result being the major factor)
        $SortedDevices = $DeviceDetails | Sort-Object -Property ApproximateLastSignInDateTime, CreatedDate -Descending
        $SelectedDevices = $SortedDevices[1..$($SortedDevices.count - 1)]
        $DeletionDeviceCounter = 0
        foreach ($DeviceToBeDeleted in $SelectedDevices) {
            # For security reasons we only delete devices that have not signed in for a certain amount of time
            if ($DeviceToBeDeleted.ApproximateLastSignInDateTime -lt $Script:DateMinusNumberofDays) {
                $DeletionDeviceCounter++
                $DeletionObject = [PSCustomObject]@{
                    displayName    = $Device.DisplayName
                    ID             = $DeviceToBeDeleted.id
                    AutopilotID    = $Device.AutopilotID
                    SerialNumber   = $Device.SerialNumber
                    CountOfDevices = $DeletionDeviceCounter
                }
                $DevicesToBeDeleted.Add($DeletionObject) | Out-Null
            }
        }
    }
    $Script:DevicesToBeDeleted = $DevicesToBeDeleted
}
function Select-DevicesToBeRemediated {
    <#
    .SYNOPSIS
    Select devices that are candidates for remediation.
    #>
    $DevicesToBeRemediated = [System.Collections.ArrayList]::new()
    $DevicesToBeDeletedHashtable = @{}
    foreach ($Device in $Script:DevicesToBeDeleted) {
        $DevicesToBeDeletedHashtable[$Device.ID] = $Device
    }
    $DuplicateDevicesHashtable = @{}
    foreach ($Device in $Script:DuplicateDevices) {
        $DuplicateDevicesHashtable[$Device.DisplayName] = $Device.DeviceDetails
    }
    foreach ($Device in $Script:DevicesToBeDeleted) {
        if ($Device.AutopilotID) {
            $DeviceToRemediate = $DuplicateDevicesHashtable[$Device.DisplayName] 
        } else {
            continue
        }
        # Sort devices by last sign-in date and created date (should always result being the major factor)
        $SortedDevices = $DeviceToRemediate | Sort-Object -Property ApproximateLastSignInDateTime, CreatedDate -Descending
        $SelectedDevices = $SortedDevices[0]
        $RemediationObject = [PSCustomObject]@{
            ID = $SelectedDevices.id
        }
        $DevicesToBeRemediated.Add($RemediationObject) | Out-Null
    }
    $Script:DevicesToBeRemediated = $DevicesToBeRemediated
}
function Repair-AutopilotDevicesByAddingToGroup {
    <#
    .SYNOPSIS
    Add devices to a group for remediation.
    .NOTES
    ToDo:
        * Rewrite this function to use the new batch request functionality
    #>
    if (-not($Script:GroupId)) {
        Write-Log -Message "Creating group $GroupName" -Component 'RepairAutopilotDevices' -Type 1
        $Group = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/groups/" -Body (@{
                displayName     = $GroupName
                mailEnabled     = $false
                mailNickname    = $GroupName
                securityEnabled = $true
            } | ConvertTo-Json -Depth 10) -ContentType 'application/json' -ErrorAction Stop
        $Script:GroupId = $Group.value.id
    }
    $CurrentGroupMembers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($Script:GroupId)/members/?`$select=id" -ErrorAction Stop
    if ($CurrentGroupMembers.'@odata.nextLink') {
        Write-Log -Message "Found more than 100 members in group $($Group.value.displayName), retrieving next link data" -Component 'RepairAutopilotDevices' -Type 1
        $CurrentGroupMembers = Get-nextLinkData -OriginalObject $CurrentGroupMembers
    }
    $CurrentGroupMembersHashTable = @{}
    foreach ($Member in $CurrentGroupMembers.value) {
        $CurrentGroupMembersHashTable[$Member.id] = $Member
    }
    foreach ($Device in $Script:DevicesToBeRemediated) {
        Write-Log -Message "Adding device with ID: $($Device.ID) and SerialNumber: $($Device.SerialNumber) to group $($Group.value.displayName)" -Component 'RepairAutopilotDevices'
        if ($CurrentGroupMembersHashTable[$Device.ID]) {
            Write-Log -Message "Device with ID: $($Device.ID) is already a member of group $($Group.value.displayName)" -Component 'RepairAutopilotDevices' -Type 2
            continue
        }
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/groups/$($Script:GroupId)/members/`$ref" -Body (@{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/devices/$($Device.ID)"
                } | ConvertTo-Json -Depth 10) -ContentType 'application/json' -ErrorAction Stop
            Write-Log -Message "Successfully added device with ID: $($Device.ID) to group $($Group.value.displayName)" -Component 'RepairAutopilotDevices'
        } catch {
            Write-Log -Message "Failed to add device with ID: $($Device.ID) to group $($Group.value.displayName). Error: $($_)" -Component 'RepairAutopilotDevices' -Type 3
        }
    }
}
function Register-DevicesToBeDeleted {
    <#
    .SYNOPSIS
    Remove the dual device from the tenant.
    #>
    #$script:DevicesToBeDeleted | ForEach-Object -ThrottleLimit 20 -Parallel {
    foreach ($EntraDevice in $Script:DevicesToBeDeleted) {
        Write-Log -Message "Removing device with ID: $($EntraDevice.ID)" -Component 'RemoveDualDevice'
        $params = @{
            Method  = "DELETE"
            URL     = "/devices/$($EntraDevice.ID)"
            Headers = @{
                "Content-Type" = "application/json"
            }
        }
        Invoke-BatchRequest @params
        Write-Log -Message "Successfully added device with ID: $($EntraDevice.ID) and serial number: $($EntraDevice.SerialNumber) to batch queue" -Component 'RemoveDualDevice'
        if ($EntraDevice.AutopilotID) {
            foreach ($AutopilotID in $EntraDevice.AutopilotID) {
                $params = @{
                    Method  = "DELETE"
                    URL     = "/deviceManagement/windowsAutopilotDeviceIdentities/$($AutopilotID)"
                    Headers = @{
                        "Content-Type" = "application/json"
                    }
                }
                Invoke-BatchRequest @params
                Write-Log -Message "Successfully added device with Autopilot ID: $($AutopilotID) and serial number: $($EntraDevice.SerialNumber) to batch queue" -Component 'RemoveDualDevice'

            }
        }
    }
    Invoke-BatchRequest -Finalize
}
function Get-RemediationGroupRemediationStatus {
    $Script:RemediatedDeviceIDs = [System.Collections.ArrayList]::new()
    $GroupMembers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($Script:GroupId)/members/?`$select=id,deviceId" -ErrorAction Stop
    if ($GroupMembers.'@odata.nextLink') {
        Write-Log -Message "Found more than 100 members in group $($GroupName), retrieving next link data" -Component 'GetRemediationGroupRemediationStatus' -Type 1
        $GroupMembers = Get-nextLinkData -OriginalObject $GroupMembers
    }
    if (-not($Script:AllAutopilotDevicesHashTable)) {
        Get-AutopilotDevices
    }
    #Check if the group members are Autopilot devices
    foreach ($GroupMember in $GroupMembers.value) {
        $DeviceSerialNumber = ''
        if ($Script:AllIntuneDevicesHashTable[$GroupMember.deviceId]) {
            $Device = $Script:AllIntuneDevicesHashTable[$GroupMember.deviceId]
            $DeviceSerialNumber = $Device.serialNumber.trim() # Trim to avoid issues with leading/trailing spaces, yes this happens
        }
        $RemediatedDevice = [PSCustomObject]@{
            id           = $GroupMember.id
            displayName  = if($Script:AllEntraDevicesHashTableByID[$GroupMember.id]) { $Script:AllEntraDevicesHashTableByID[$GroupMember.id].displayName } else { $null }
            serialNumber = $DeviceSerialNumber
            autopilotID  = if($Script:AllAutopilotDevicesHashTable[$DeviceSerialNumber]) { $Script:AllAutopilotDevicesHashTable[$DeviceSerialNumber].id } else { $null }
            remediated   = $false
        }
        if ($DeviceSerialNumber -and $Script:AllAutopilotDevicesHashTable[$DeviceSerialNumber]) {
            $RemediatedDevice.remediated = $true
        } else {
            Write-Log -Message "Device with ID: $($GroupMember.id) is not an Autopilot device, assume its not remediated" -Component 'GetRemediationGroupRemediationStatus' -Type 2
        }
        $Script:RemediatedDeviceIDs.Add($RemediatedDevice) | Out-Null
    }
}
function Remove-RemediatedDevicesFromGroup {
    foreach ($RemediatedDevice in $($Script:RemediatedDeviceIDs).Where({ $_.remediated -eq $true })) {
        Invoke-BatchRequest -Method "DELETE" -URL "/groups/$($Script:GroupId)/members/$($RemediatedDevice.id)/`$ref" -Headers @{ "Content-Type" = "application/json" } -Finalize
        Write-Log -Message "Added device $($RemediatedDevice.id) ($($RemediatedDevice.displayName)) to queue for removal from group $GroupName" -Component 'RemoveRemediatedDevicesFromGroup'
    }
}
#Start Coding
Write-Log -Message "Starting Autopilot Dual Device Finder" -Component 'ADDFMain' -Type 1
Initialize-Script
if (-not($Cleanup)) {
    Write-Log -Message "Searching for devices with duplicate names in the tenant" -Component 'ADDFMain'
    Search-DuplicateDevices
    Write-Log -Message "Documenting the results in $($LogDirectory)" -Component 'ADDFMain' -Type 1
    $Script:DuplicateDevices | Select-Object -Property DisplayName, SerialNumber, AutopilotID | Export-Csv -Path $WorkingDirectory\AutopilotDualDeviceFinder$($script:DateTime).csv -NoTypeInformation -Encoding UTF8 -Force -Delimiter ';' 

    Write-Log -Message "Looking for devices that are candidates for deletion" -Component 'ADDFMain'
    Select-DevicesToBeDeleted
    Write-Log -Message "Documenting the results in $($LogDirectory)" -Component 'ADDFMain' -Type 1
    $Script:DevicesToBeDeleted | Select-Object -Property ID, DisplayName, SerialNumber, AutopilotID | Export-Csv -Path $WorkingDirectory\AutopilotDualDeviceFinderToBeDeleted$($script:DateTime).csv -NoTypeInformation -Encoding UTF8 -Force -Delimiter ';' 

    if (-not($AnalyzeOnly)) {
        Write-Log -Message "Selecting devices that are candidates for deletion" -Component 'ADDFMain'
        Select-DevicesToBeRemediated
        Write-Log -Message "Adding remaining devices to group $($GroupName) for remediation" -Component 'ADDFMain'
        Repair-AutopilotDevicesByAddingToGroup
        Write-Log -Message "Devices added to group $($GroupName) for remediation" -Component 'ADDFMain'
        Write-Log -Message "Preparing devices for deletion" -Component 'ADDFMain'
        Register-DevicesToBeDeleted
    }
    if ($DevicesToBeDeleted.count -gt 0 -and -not($AnalyzeOnly)) {
        $confirmation = Read-Host "There are $($DevicesToBeDeleted.count) devices that are candidates for deletion. Do you want to continue? (Y/N)"
        if ($confirmation -eq 'Y') {
            Write-Log -Message "Continuing..." -Component 'ADDFMain'
            foreach ($BatchRequest in $Script:BatchRequestsQueue) {
                Start-ThreadJob -Name "ADDF-$($BatchRequest.Name)" -ThrottleLimit 10 -ScriptBlock {
                    param($ArgumentToProvide, $TenantAPIToUse)
                    Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 5000) # Random delay to avoid throttling
                    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
                } -ArgumentList $BatchRequest.ArgumentToProvide, $TenantAPIToUse | Out-Null
            }
        } else {
            Write-Log -Message "Operation canceled. No devices were deleted." -Component 'ADDFMain'
        }
        while ((Get-Job | Where-Object { $_.name -match "ADDF" }).state -eq "Running") {
            Start-Sleep -Seconds 1
        }
        Confirm-BatchRequest
    } else {
        Write-Log -Message "No devices to delete, skipping batch request sending" -Component 'ADDFMain' -Type 2
    }
    #Log the results
    $AutopilotDevices = $Script:DuplicateDevices | Where-Object { $_.AutopilotID -ne $null }
    $AutopilotDeleteDevices = $Script:DevicesToBeDeleted | Where-Object { $_.AutopilotID -ne $null }
    Write-Log -Message "Found $($Script:DuplicateDevices.count) devices with duplicate names" -Component 'ADDFMain' -Type 1
    Write-Log -Message "Found $($Script:DuplicateDevices.DeviceDetails.count) of those devices had duplicated names" -Component 'ADDFMain' -Type 1
    Write-Log -Message "Found $($Script:DevicesToBeDeleted.count) devices that were candidates for deletion" -Component 'ADDFMain'
    Write-Log -Message "Found $($AutopilotDeleteDevices.count) autopilot devices that were candidates for deletion out of $($AutopilotDevices.count)" -Component 'ADDFMain' -Type 1
} else {
    if (-not($GroupName)) {
        Write-Log -Message "Cleanup mode is enabled, but no group name was provided. Exiting script." -Component 'ADDFMain' -Type 3
    } else {
        Get-RemediationGroupRemediationStatus
        $Script:RemediatedDeviceIDs | Select-Object -Property id, displayName, serialNumber, autopilotID | Export-Csv -Path $WorkingDirectory\AutopilotDualDeviceFinderRemediated$($script:DateTime).csv -NoTypeInformation -Encoding UTF8 -Force -Delimiter ';'
        Write-Log -Message "Found $($Script:RemediatedDeviceIDs.count) devices that were successfully remediated in group $($GroupName)" -Component 'ADDFMain' -Type 1
        Write-Log -Message "Removing remediated devices from group $($GroupName)" -Component 'ADDFMain'
        Remove-RemediatedDevicesFromGroup
        Invoke-BatchRequest -Finalize
        $confirmation = Read-Host "There are $($DevicesToBeDeleted.count) devices that are candidates for deletion. Do you want to continue? (Y/N)"
        if ($confirmation -eq 'Y') {
            Write-Log -Message "Continuing..." -Component 'ADDFMain'
            foreach ($BatchRequest in $Script:BatchRequestsQueue) {
                Start-ThreadJob -Name "ADDF-$($BatchRequest.Name)" -ThrottleLimit 10 -ScriptBlock {
                    param($ArgumentToProvide, $TenantAPIToUse)
                    Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 5000) # Random delay to avoid throttling
                    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
                } -ArgumentList $BatchRequest.ArgumentToProvide, $TenantAPIToUse | Out-Null
            }
        } else {
            Write-Log -Message "Operation canceled. No devices were deleted." -Component 'ADDFMain'
        }
        while ((Get-Job | Where-Object { $_.name -match "ADDF" }).state -eq "Running") {
            Start-Sleep -Seconds 1
        }
        Confirm-BatchRequest
    }
}

#Finish up
Write-Log -Message "Thanks for using ADDF" -Component 'ADDFMain' -Type 1
if ($Script:LogMessageBuffer.count -gt 0) {
    Write-Log -Finish
}
Set-Location $Script:CurrentLocation