<#
.SYNOPSIS
Script detects new Outlook installation for DEVICE assignments
.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Detect-NewOutlookDevice

Run this script using the logged-on credentials: No
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes
#> 
$DetectNewOutlookDEVICE = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "Microsoft.OutlookForWindows" }

if ($DetectNewOutlookDEVICE) {
    Exit 1
} else {
    Write-Host "New Outlook seems to not be installed for this device"
    Exit 0
}