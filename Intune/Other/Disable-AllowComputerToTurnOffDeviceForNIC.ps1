<#
.SYNOPSIS
    Disables the "Allow the computer to turn off this device to save power" setting for network adapters that support it.
.DESCRIPTION
    This script will check for network adapters that have the "Allow the computer to turn off this  device to save power" setting enabled and disable it. This is useful for devices that are enrolled in Intune and are experiencing connectivity issues due to the network adapter being turned off to save power.
.NOTES
    Version: 1.0
    Versionname: Delete-DevicesOlderThanDays
    Initial creation date: 20.03.2026
    Last change date: 28.04.2026
    Latest changes:
    * Added function to check if the device is in the Enrollment Status Page (ESP) and exit if it is not. This is to prevent the script from running on devices that are not enrolled in Intune or are not in the ESP, which could cause issues with the enrollment process.
#>
function Test-IfInESP {
    $ErrorActionPreference = "Stop"
    Try {
        $HasProvisioningCompleted = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\Device\Setup" ).HasProvisioningCompleted -eq 4294967295
        if (-not($HasProvisioningCompleted)) {
            exit 1;
        }
    } catch {
        exit 2;
    }
}

# Start coding!
Test-IfInESP

$Adapters = Get-NetAdapterPowerManagement -ErrorAction SilentlyContinue | Where-Object { $null -ne $_.AllowComputerToTurnOffDevice -and $_.AllowComputerToTurnOffDevice -ne 'Unsupported' -and $_.AllowComputerToTurnOffDevice -ne 'Disabled' }

If ($Adapters) {
    # There should only be one, but looping just in case.
    try {
        foreach ($Adapter in $Adapters) {
            $Adapter.AllowComputerToTurnOffDevice = 'Disabled'
            $Adapter | Set-NetAdapterPowerManagement
        }
    } catch {
        Write-Output "An error occurred while trying to disable power management for the network adapter(s). Please review the error message below and try again."
        Write-Output $_.Exception.Message
    }
}