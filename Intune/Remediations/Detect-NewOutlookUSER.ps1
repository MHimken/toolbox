<#
.SYNOPSIS
Script detects new Outlook installation for USER assignments
.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Detect-NewOutlookUSER

Run this script using the logged-on credentials: Yes
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes
#> 
$DetectNewOutlook =  Get-AppxPackage | Where-Object { $_.Name -eq "Microsoft.OutlookForWindows" } -ErrorAction SilentlyContinue

if ($DetectNewOutlook) {
    Exit 1
} else {
    Write-Host "New Outlook seems to not be installed for this user"
    Exit 0
}