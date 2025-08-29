#THIS SCRIPT IS NOT DONE!
#Remove Autopilot devices that are in the group to remediate and assign the app to the group
param (
    [System.IO.DirectoryInfo]$CSV = "C:\Temp\RemovedAutopilotDevices.csv",
    [int]$NumberOfDaysBeforeDeletion = -180,
    [int]$NumberOfDaysBeforeDisable = -90,
    [String]$WorkingDirectory = "C:\Temp\RemoveAutopilotDevices",#ToDo: Change the default!
    [String]$LogDirectory = "C:\Temp\RemoveAutopilotDevices\Logs",#ToDo: Change the default!
    [String]$CertificateThumbprint = "",
    [String]$ClientID = "",
    [String]$TenantId = "",
    [String]$TenantAPIToUse = "beta", # Change to "v1.0" if you want to use the stable API version
    [String]$LogPrefix = "RAD", # Remove Autopilot Device
    [Switch]$AnalyzeOnly = $true, # If set, the script will only analyze the devices and not remove them.
    [Switch]$ShowResults = $true, # If set, the script will show the results in a grid view.
    [Switch]$NoLog = $false # If set, the script will not create a log file.
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
            $Script:LogPrefix = 'RAD'#Remove Autopilot Device
        } else {
            $Script:LogPrefix = $LogPrefix
        }
        $Script:LogFile = Join-Path -Path $Script:LogDirectory -ChildPath ('{0}_{1}.log' -f $Script:LogPrefix, $Script:DateTime)
        if (-not(Test-Path $Script:LogDirectory)) { New-Item $Script:LogDirectory -ItemType Directory -Force | Out-Null }
    }
    #Define some variables that will be used throughout the script
    $Script:DocumentResults = [System.Collections.ArrayList]::new()
    $Script:DateBeforeDeletion = (Get-Date).AddDays($NumberOfDaysBeforeDeletion)
    $Script:DateBeforeDisable = (Get-Date).AddDays($NumberOfDaysBeforeDisable)
    if ($CSV) {
        $Script:IngestedCSV = Import-Csv -Path $CSV.FullName
    } else {
        Write-Output "No CSV file provided"
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
        $Script:AllIntuneDevicesHashTableBySerialNumber[$Device.serialNumber] = $Device
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
        Clear-Variable -Name IntuneDevice, EntraDeviceFromAutopilot, DetectDeleteAutpilotDeviceFromCSV, AutopilotWhatIf, IntuneWhatIf, EIDAutopilotWhatIf, EIDIntuneWhatIf -ErrorAction SilentlyContinue
        $AutopilotDeviceSerial = $AutopilotDevice.serialNumber.trim()
        if ($Script:IngestedCSV) {
            $DetectDeleteAutpilotDeviceFromCSV = $Script:IngestedCSV | Where-Object { $_.SerialNumber.trim() -eq $AutopilotDeviceSerial }
            $AutopilotWhatIf = if ($DetectDeleteAutpilotDeviceFromCSV) { "Remove" } else { "Keep" }
        }
        $IntuneDevice = $Script:AllIntuneDevicesHashTableBySerialNumber[$AutopilotDeviceSerial]
        $EntraDeviceFromAutopilot = $Script:AllEntraDevicesHashTable[$AutopilotDevice.azureAdDeviceId]
        $IntuneDeviceIsEntraDevice = $null

        if ($IntuneDevice) {
            #Default is to keep the EID device from Intune and Autopilot
            $EIDIntuneWhatIf = "Keep"
            $EIDAutopilotWhatIf = "Keep"
            $EntraDeviceFromIntune = $Script:AllEntraDevicesHashTable[$IntuneDevice.azureADDeviceId]
            #If the device IDs are different, log a message and set the IntuneDeviceIsEntraDevice flag to false
            if ($EntraDeviceFromIntune.deviceId -ne $EntraDeviceFromAutopilot.deviceId) {
                Write-Log -Message "Entra device from Intune and Autopilot have different device IDs for serial number $AutopilotDeviceSerial." -Component 'SaveCurrentDeviceStates' -Type 2
                $IntuneDeviceIsEntraDevice = $false
                $IntuneWhatIf = "Mismatched"
                #Mismatched devices
                if ($EntraDeviceFromAutopilot.approximateLastSignInDateTime -le $Script:DateBeforeDisable -and $EntraDeviceFromAutopilot.approximateLastSignInDateTime -gt $Script:DateBeforeDeletion) {
                    $EIDAutopilotWhatIf = "Disable"
                } 
                if ($EntraDeviceFromAutopilot.approximateLastSignInDateTime -le $Script:DateBeforeDeletion) {
                    $EIDAutopilotWhatIf = "Remove"
                }
                if ($EntraDeviceFromIntune.approximateLastSignInDateTime -le $Script:DateBeforeDisable -and $EntraDeviceFromIntune.approximateLastSignInDateTime -gt $Script:DateBeforeDeletion) {
                    $EIDIntuneWhatIf = "Disable"
                } elseif ($EntraDeviceFromIntune.approximateLastSignInDateTime -le $Script:DateBeforeDeletion) {
                    $EIDIntuneWhatIf = "Remove"
                }
            } elseif ($IntuneDevice.lastSyncDateTime -le $Script:DateBeforeDisable -and $IntuneDevice.lastSyncDateTime -gt $Script:DateBeforeDeletion) {
                $IntuneWhatIf = "Retire"
                $EIDAutopilotWhatIf = "Disable"
            } elseif ($IntuneDevice.lastSyncDateTime -le $Script:DateBeforeDeletion) {
                $IntuneWhatIf = "Remove"
                $EIDAutopilotWhatIf = "Remove"
            }
        } else {
            $IntuneWhatIf = "Not Found"
            if ($EntraDeviceFromAutopilot.accountEnabled -eq $true) {
                $EIDAutopilotWhatIf = "Disable"
            } else {
                $EIDAutopilotWhatIf = "Disabled"
            }
        }

        $Result = [PSCustomObject]@{
            SerialNumber                                 = $AutopilotDeviceSerial
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
            IntuneDeviceLinkedToEntraDeviceFromAutopilot = $IntuneDeviceIsEntraDevice
            AutopilotWhatIf                              = $AutopilotWhatIf
            EIDFromAutopilotWhatIf                       = $EIDAutopilotWhatIf
            EIDFromIntuneWhatIf                          = $EIDIntuneWhatIf
            IntuneWhatIf                                 = $IntuneWhatIf
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
function Remove-EvaluatedDeviceObjects {
    
}
# Start coding!
# Initialize script variables
Initialize-Script
Write-Log -Message "Starting to remove removed Autopilot devices from CSV file." -Finish
Save-CurrentDeviceStates
If (-not($AnalyzeOnly)) {
    Remove-EvaluatedObjects
}
if ($ShowResults) {
    $Script:DocumentResults | Out-GridView -Title "Removed Autopilot Devices Results"
}
#Document the results
$Script:DocumentResults | Export-Csv -Path (Join-Path -Path $WorkingDirectory -ChildPath "RemovedAutopilotDevicesResults_$($Script:DateTime).csv") -Delimiter ";" -NoTypeInformation -Force
Write-Log -Message "Finished removing Autopilot devices from CSV file."
Set-Location $Script:CurrentLocation
Write-Log -Message "Thanks for using the script!" -Finish