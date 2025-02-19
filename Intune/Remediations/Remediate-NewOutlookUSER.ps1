<#
.SYNOPSIS
Script removes new Outlook installation for USER assignments
.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Remediate-NewOutlookUSER

Run this script using the logged-on credentials: Yes
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes
#> 

try {
    Get-AppxPackage | Where-Object { $_.Name -eq "Microsoft.OutlookForWindows" } | Remove-AppxPackage -ErrorAction SilentlyContinue
    Write-Host "Removal of new Outlook app successful"

} catch {
    Write-Error "Removal of new Outlook app failed"
}
