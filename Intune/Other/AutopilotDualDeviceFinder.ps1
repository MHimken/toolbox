<#
THIS SCRIPT IS NOT DONE!
.SYNOPSIS
This script will find devices in your tenant that exist twice.
.DESCRIPTION
If you want to analyse how many devices are hybrid _and_ entra joined and both are linked to an autopilot object in your tenant 
this script is for you. It will go by displayName. The runtime for a tenant with 20.000 devices is roughly 45 seconds. 
.NOTES
ToDo:
    * Autopilot devices might be associated with another device than it should altogether 
    (meaning the current results don't have the device because the name is different)
    * If an object is deleted, does the Autopilot object then correctly associate with the remaining device?
    This is mainly relevant, if the other bullet point isn't also true.
    * If the device that is connected to the Autopilot object is deleted Autopilot will create a new object. The impact of this
    needs to be worked in the script.
#>
param(
    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\ADDF\",
    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$LogDirectory = "C:\ADDF\Logs\",
    [Parameter(Mandatory = $false)]
    [Switch]$NoLog,
    [Parameter(Mandatory = $false)]
    [Switch]$ToConsole
)
$CertificateThumbprint = ""
$ClientID = ""
$TenantId = ""
$NumberOfDays = "-360" #Number of days that a machine has had to been active (total timespan to observe)
$MinimumTimeSpan = "30" #Number of days that the old machine and the new machines activity must be apart
if (-not(Get-MgContext)) {
    Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientID -TenantId $TenantId
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

function Remove-DualDevice {
    <#
    .SYNOPSIS
    Remove the dual device from the tenant.
    .PARAMETER DeviceID
    The device ID of the device to be removed.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceID
    )
    Write-Log -Message "Removing device with ID: $DeviceID" -Component 'RemoveDualDevice'
    try {
        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/devices/$DeviceID" -Method DELETE
        Write-Log -Message "Successfully removed device with ID: $DeviceID" -Component 'RemoveDualDevice'
    } catch {
        Write-Log -Message "Failed to remove device with ID: $DeviceID. Error: $($_)" -Component 'RemoveDualDevice' -Type 3
        return $false
    }
    return $true
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
    $DateMinusNumberofDays = Get-date (Get-Date).AddDays($NumberOfDays) -Format 'yyyy-MM-ddThh:mm:ssZ'
    $AllDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/devices/?`$filter=(operatingSystem eq 'Windows') and (approximateLastSignInDateTime ge $DateMinusNumberofDays)"
    if ($AllDevices.'@odata.nextLink') {
        $AllDevices = Get-nextLinkData -OriginalObject $AllDevices
    }
    $DuplicatedNames = ($AllDevices.value | Group-Object -Property displayName | Where-Object { $_.count -gt 1 })
    $ToBeDeleted = [System.Collections.ArrayList]::new()
    foreach ($DuplicatedDevice in $DuplicatedNames) {
        #ToDo here!
        foreach($DuplicatedDevice in $DuplicatedNames){}
        $DupeObject = [PSCustomObject]@{
            MainID                        = $DuplicatedDevice.id
            DisplayName                   = $DuplicatedDevice.displayName
            approximateLastSignInDateTime = $DuplicatedDevice.approximateLastSignInDateTime
            CreatedDate                   = $DuplicatedDevice.createdDateTime
            enrolledBy                    = $DuplicatedDevice.
            enrollmentProfileName         = $dupeName.enrollmentProfileName
            Assignments                   = @()
            AutopilotTreatment            = $false
        }
        # Get the physical IDs of the devices with duplicate names
        $PhysicalIDs = $AllDevices.value | Where-Object { $_.displayName -eq $DuplicatedDevice } | Select-Object -ExpandProperty physicalIds
        # If devices have Autopilot IDs, we need to treat them differently
        $AutopilotIDs = ($PhysicalIDs | Select-String -Pattern '[ZTDID]:' -SimpleMatch).line.Substring(8.36) | Select-Object -Unique
        if ($AutopilotIDs.Count -eq 1) {
            Write-Log -Message "Found matching Autopilot IDs ($($AutopilotIDs)) for devices pointing with duplicate names ($($DuplicatedDevice)) " -Component 'FindDuplicateDevices' -Type 2
            $DupeObject.AutopilotTreatment = $true
        } else {
            Write-Log -Message "Found different Autopilot IDs for devices with duplicate names ($($DuplicatedDevice))" -Component 'FindDuplicateDevices' -Type 1
        }
        #$Assignments = Invoke-MgGraphRequest -Uri ""
        <#
        if ($AutopilotIDs.Count -eq 2) {
            $EntraDevice = $AllDevices.value | Where-Object { $_.displayname -eq $DuplicatedDevice -and $_.trustType -eq 'AzureAd' }
            $HybridDevice = $AllDevices.value | Where-Object { $_.displayname -eq $DuplicatedDevice -and $_.trustType -eq 'ServerAd' }
            if ($HybridDevice.approximateLastSignInDateTime -ge $EntraDevice.approximateLastSignInDateTime) {
                if ($HybridDevice.deviceId.count -eq 2) {
                    $TimeSpan = [math]::abs(($HybridDevice[0].approximateLastSignInDateTime - $HybridDevice[1].approximateLastSignInDateTime).days)
                    $MinimumTimeSpanReached = $TimeSpan -ge $MinimumTimeSpan
                    $DeviceIdToBeRemoved = if ($MinimumTimeSpanReached) { if ($TimeSpan -ge 0) { $HybridDevice[1].deviceId } else { $HybridDevice[0].deviceId } }
                    $ToBeDeleteObject = [PSCustomObject]@{
                        DeviceName              = $HybridDevice[0].displayName
                        HybridDeviceID0         = $HybridDevice[0].deviceId
                        HybridDeviceLastSignIn0 = $HybridDevice[0].approximateLastSignInDateTime
                        HybridDeviceID1         = $HybridDevice[1].deviceId
                        HybridDeviceLastSignIn1 = $HybridDevice[1].approximateLastSignInDateTime
                        ActivityDistance        = $TimeSpan 
                        MinimumTimeSpanReached  = $MinimumTimeSpanReached
                        DeviceIDToBeRemoved     = $DeviceIdToBeRemoved 
                    }
                } else {
                    $TimeSpan = [math]::abs(($EntraDevice.approximateLastSignInDateTime - $HybridDevice.approximateLastSignInDateTime).days)
                    $MinimumTimeSpanReached = $TimeSpan -ge $MinimumTimeSpan
                    $DeviceIdToBeRemoved = if ($MinimumTimeSpanReached) { if ( $TimeSpan -ge 0) { $EntraDevice.deviceId } else { $HybridDevice.deviceId } }
                    $ToBeDeleteObject = [PSCustomObject]@{
                        DeviceName             = if (-not($EntraDevice.displayName)) { $HybridDevice.displayName }else { $EntraDevice.displayName }
                        EntraDeviceID          = $EntraDevice.deviceId
                        EntraDeviceLastSignIn  = $EntraDevice.approximateLastSignInDateTime
                        HybridDeviceID         = $HybridDevice.deviceId
                        HybridDeviceLastSignIn = $HybridDevice.approximateLastSignInDateTime
                        ActivityDistance       = $TimeSpan
                        MinimumTimeSpanReached = $MinimumTimeSpanReached
                        DeviceIDToBeRemoved    = $DeviceIdToBeRemoved
                    }
                }
                $ToBeDeleted.add($ToBeDeleteObject) | Out-Null
            }
        }#>
    }
    return $ToBeDeleted
}
function Select-DevicesToBeDeleted {
    <#
    .SYNOPSIS
        Analyze duplicate devices with duplicate names in the tenant.
    #>    
}
#Start Coding
$Script:DuplicateDevices = Search-DuplicateDevices
Write-Log -Message "Found $($DuplicatedNames.count) devices with duplicate names" -Component 'ADDFMain' -Type 1
Write-Log -Message "Found $($ToBeDeleted.count) devices that are hybrid and Entra joined with duplicate names" -Component 'ADDFMain' -Type 1
Write-Log -Message "Documenting the results in $($LogFile)" -Component 'ADDFMain' -Type 1
Export-Csv -Path $WorkingDirectory\AutopilotDualDeviceFinder.csv -NoTypeInformation -Encoding UTF8 -Force -Delimiter ';' -InputObject $ToBeDeleted

