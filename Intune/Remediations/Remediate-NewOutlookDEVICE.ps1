<#
.SYNOPSIS
Script removes new Outlook installation for DEVICE assignments
.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Remediate-NewOutlookDEVICE

Run this script using the logged-on credentials: No
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes
#> 

try {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "Microsoft.OutlookForWindows" } | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq "Microsoft.OutlookForWindows" } | Remove-AppxPackage -ErrorAction Stop
    Write-Host "Removal of new Outlook app successful"

} catch {
    Write-Error "Removal of new Outlook app failed"
}
